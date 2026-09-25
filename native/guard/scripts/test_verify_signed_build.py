"""Tests for verify_signed_build.py.

Unit tests use synthetic bundles in a private temporary directory, a fake command runner
with canned codesign/security output, and Mach-O images with code-signature blobs built
here. Team IDs, bundle IDs, certificates and device IDs are fabricated. The integration
test only reads the local unsigned build, if one exists, and requires the tool to reject it.
"""
import contextlib
from dataclasses import dataclass, field
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_signed_build as tool


TEAM = 'ABCDE12345'
OTHER_TEAM = 'ZYXWV98765'
APP_ID = 'dev.example.agentbelt'
SYSEXT_ID = APP_ID + '.fileguard'
SUPERVISOR_ID = APP_ID + '.supervisor'
SERVICE = f'{TEAM}.{SYSEXT_ID}.control'
NOW = datetime.datetime(2026, 9, 24, 12, 0, 0)
EXPIRES = datetime.datetime(2027, 9, 24, 12, 0, 0)
MH_DYLIB = 0x6
# Sentinels that must never reach the report.
DEVICE_UDIDS = ['SYNTHETIC-UDID-0001', 'SYNTHETIC-UDID-0002', 'SYNTHETIC-UDID-0003']
CERTIFICATE_MARKER = b'SYNTHETIC-CERTIFICATE-DER'
LEAF_DER = b'SYNTHETIC-LEAF-CERTIFICATE-DER'
INTERMEDIATE_DER = b'SYNTHETIC-INTERMEDIATE-DER'
PERSON = 'Synthetic Tester'
DEVELOPMENT_AUTHORITY = f'Apple Development: {PERSON} (QQQQQ11111)'
DEVELOPER_ID_AUTHORITY = f'Developer ID Application: {PERSON} ({TEAM})'
KEYCHAIN_GROUPS = 'keychain-access-groups'
# The reviewer's bypass: newlines in a name forge a signed-looking codesign display.
FORGED_LINES = ['CodeDirectory v=20500 size=900 flags=0x10000(runtime) hashes=20+7 location=embedded',
                'Signature size=4790', f'Authority={DEVELOPMENT_AUTHORITY}', f'TeamIdentifier={TEAM}']

REAL_PRODUCTS = Path(__file__).resolve().parents[1] / 'build' / 'Build' / 'Products' / 'Debug'


# --- Mach-O and signature builders ----------------------------------------------------------

def code_directory(identifier: str, team: Optional[str], flags: int) -> bytes:
    """A CodeDirectory header (version 0x20200, with teamOffset) followed by its strings."""
    identifier_bytes = identifier.encode() + b'\0'
    team_bytes = team.encode() + b'\0' if team else b''
    header_size = tool.CODE_DIRECTORY_TEAM_FIELD_END
    length = header_size + len(identifier_bytes) + len(team_bytes)
    team_offset = header_size + len(identifier_bytes) if team else 0
    header = struct.pack('>IIIIIIIIIBBBBIII', tool.CSMAGIC_CODEDIRECTORY, length, tool.CS_SUPPORTSTEAMID, flags,
                         length, header_size, 0, 0, 0, 32, 2, 0, 12, 0, 0, team_offset)
    return header + identifier_bytes + team_bytes


def superblob(entries: List[tuple]) -> bytes:
    offset = 12 + 8 * len(entries)
    index, payload = b'', b''
    for slot, blob in entries:
        index += struct.pack('>II', slot, offset + len(payload))
        payload += blob
    return struct.pack('>III', tool.CSMAGIC_EMBEDDED_SIGNATURE, offset + len(payload), len(entries)) + index + payload


def entitlements_blob(entitlements: dict) -> bytes:
    xml = plistlib.dumps(entitlements)
    return struct.pack('>II', tool.CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(xml)) + xml


def signature(identifier: str, team: Optional[str], flags: int, entitlements: dict,
              alternate: Optional[bytes] = None) -> bytes:
    entries = [(tool.CSSLOT_CODEDIRECTORY, code_directory(identifier, team, flags))]
    if entitlements:
        entries.append((tool.CSSLOT_ENTITLEMENTS, entitlements_blob(entitlements)))
    if alternate is not None:
        entries.append((0x1000, alternate))
    return superblob(entries)


def build_macho(section: bytes = b'code', segment: bytes = b'__TEXT', name: bytes = b'__info_plist',
                code_signature: Optional[bytes] = None, filetype: int = tool.MH_EXECUTE) -> bytes:
    """A minimal arm64 image: one LC_SEGMENT_64 with one section, and optionally LC_CODE_SIGNATURE."""
    segment_size = tool.SEGMENT_COMMAND_64_SIZE + tool.SECTION_64_SIZE
    commands_size = segment_size + (tool.LINKEDIT_DATA_COMMAND_SIZE if code_signature is not None else 0)
    data_offset = tool.MACH_HEADER_64_SIZE + commands_size
    command_count = 2 if code_signature is not None else 1
    header = struct.pack('<IiiIIIII', tool.MH_MAGIC_64, 0x0100000c, 0, filetype, command_count, commands_size, 0, 0)
    command = struct.pack('<II16sQQQQiiII', tool.LC_SEGMENT_64, segment_size, segment, 0x100000000,
                          data_offset + len(section), 0, data_offset + len(section), 5, 5, 1, 0)
    section_header = struct.pack('<16s16sQQIIIIIIII', name, segment, 0x100000000 + data_offset, len(section),
                                 data_offset, 0, 0, 0, 0, 0, 0, 0)
    image = header + command + section_header
    if code_signature is not None:
        image += struct.pack('<IIII', tool.LC_CODE_SIGNATURE, 16, data_offset + len(section), len(code_signature))
    return image + section + (code_signature or b'')


def build_fat(images: List[bytes]) -> bytes:
    alignment = 0x4000
    offsets, cursor = [], alignment
    for image in images:
        offsets.append(cursor)
        cursor += -(-len(image) // alignment) * alignment
    header = struct.pack('>II', tool.FAT_MAGIC, len(images))
    header += b''.join(struct.pack('>iiIII', 0x0100000c, 0, offset, len(image), 14)
                       for offset, image in zip(offsets, images))
    data = bytearray(header.ljust(alignment, b'\0'))
    for offset, image in zip(offsets, images):
        data[len(data):offset] = b'\0' * (offset - len(data))
        data[offset:offset + len(image)] = image
    return bytes(data)


# --- Synthetic build ------------------------------------------------------------------------

@dataclass
class CodeFixture:
    """One code object: its real signature blob plus what the fake codesign says about it."""
    identifier: str
    entitlements: dict
    team: Optional[str] = TEAM
    flags: int = tool.CS_RUNTIME
    filetype: int = tool.MH_EXECUTE
    authority: Optional[str] = DEVELOPMENT_AUTHORITY
    leaf: Optional[bytes] = LEAF_DER
    timestamp: bool = False
    info_bound: bool = True
    requirement_satisfied: bool = True
    display_error: Optional[str] = None
    verify_error: Optional[str] = None
    entitlements_error: Optional[str] = None
    entitlements_raw: Optional[bytes] = None
    text_overrides: Dict[str, str] = field(default_factory=dict)
    injected_lines: List[str] = field(default_factory=list)
    slice_flags: Optional[List[int]] = None

    def make_adhoc(self) -> None:
        self.flags, self.team, self.authority, self.leaf = 0x20002, None, None, None
        self.requirement_satisfied = False

    def binary(self, section: bytes = b'code') -> bytes:
        flags_per_slice = self.slice_flags or [self.flags]
        images = [build_macho(section, code_signature=signature(self.identifier, self.team, flags, self.entitlements),
                              filetype=self.filetype) for flags in flags_per_slice]
        return images[0] if len(images) == 1 else build_fat(images)

    def display(self, path: str, executable: str) -> tool.CommandResult:
        if self.display_error:
            return tool.CommandResult(1, b'', f'{path}: {self.display_error}\n')
        lines = [f'Executable={executable}'] + self.injected_lines + [
            f'{key}={value}' for key, value in self.display_fields().items() if value is not None]
        lines[len(self.injected_lines) + 1:len(self.injected_lines) + 1] = [f'Authority={self.authority}'] if self.authority else []
        return tool.CommandResult(0, b'', '\n'.join(lines) + '\n')

    def display_fields(self) -> Dict[str, Optional[str]]:
        values = {'Identifier': self.identifier, 'Format': 'Mach-O thin (arm64)',
                  'CodeDirectory v': f'20500 size=900 flags={hex(self.flags)}(synthetic) hashes=20+7 location=embedded',
                  'Hash type': 'sha256 size=32', 'Signature size': '4790' if self.authority else None,
                  'Signature': None if self.authority else 'adhoc',
                  'Timestamp' if self.timestamp else 'Signed Time': 'Sep 24, 2026',
                  'Info.plist entries' if self.info_bound else 'Info.plist': '20' if self.info_bound else 'not bound',
                  'TeamIdentifier': self.team or 'not set', 'Sealed Resources': 'none'}
        values.update(self.text_overrides)
        return values

    def verify(self, path: str) -> tool.CommandResult:
        return tool.CommandResult(1 if self.verify_error else 0, b'', f'{path}: {self.verify_error}\n' if self.verify_error else '')

    def requirement(self, path: str) -> tool.CommandResult:
        if self.requirement_satisfied:
            return tool.CommandResult(0, b'', '')
        return tool.CommandResult(3, b'', 'test-requirement: code failed to satisfy specified code requirement(s)\n')

    def extract(self, prefix: str) -> tool.CommandResult:
        if self.leaf is not None:
            Path(prefix + '0').write_bytes(self.leaf)
            Path(prefix + '1').write_bytes(INTERMEDIATE_DER)
        return tool.CommandResult(0, b'', '')

    def entitlements_output(self, path: str) -> tool.CommandResult:
        if self.entitlements_error:
            return tool.CommandResult(1, b'', f'{path}: {self.entitlements_error}\n')
        if self.entitlements_raw is not None:
            return tool.CommandResult(0, self.entitlements_raw, f'Executable={path}\n')
        payload = plistlib.dumps(self.entitlements) if self.entitlements else b''
        return tool.CommandResult(0, payload, f'Executable={path}\n')


def signed_entitlements(identifier: str, capability: str) -> dict:
    return {capability: True, tool.APPLICATION_IDENTIFIER: f'{TEAM}.{identifier}', tool.TEAM_ENTITLEMENT: TEAM}


def profile_content(identifier: str, grant_key: str, kind: str = 'development') -> dict:
    content = {
        'AppIDName': 'synthetic', 'Name': 'synthetic profile', 'UUID': '00000000-0000-0000-0000-000000000000',
        'Platform': ['OSX'], 'TeamIdentifier': [TEAM], 'TeamName': 'Synthetic Team',
        'CreationDate': datetime.datetime(2026, 9, 1), 'ExpirationDate': EXPIRES,
        'DeveloperCertificates': [CERTIFICATE_MARKER, LEAF_DER],
        'Entitlements': {tool.APPLICATION_IDENTIFIER: f'{TEAM}.{identifier}', tool.TEAM_ENTITLEMENT: TEAM,
                         KEYCHAIN_GROUPS: [f'{TEAM}.*'], grant_key: True},
    }
    if kind == 'development':
        content['ProvisionedDevices'] = list(DEVICE_UDIDS)
        content['Entitlements'][tool.GET_TASK_ALLOW] = True
    else:
        content['ProvisionsAllDevices'] = True
    return content


@dataclass
class ProfileFixture:
    content: Optional[dict]
    decode_error: Optional[str] = None
    present: bool = True


def default_code() -> Dict[str, CodeFixture]:
    sysext_entitlements = signed_entitlements(SYSEXT_ID, tool.ES_CLIENT)
    sysext_entitlements[KEYCHAIN_GROUPS] = [f'{TEAM}.{SYSEXT_ID}']
    return {'app': CodeFixture(APP_ID, signed_entitlements(APP_ID, tool.SYSEXT_INSTALL)),
            'sysext': CodeFixture(SYSEXT_ID, sysext_entitlements),
            'supervisor': CodeFixture(SUPERVISOR_ID, {})}


@dataclass
class SyntheticBuild:
    """Everything the tool reads; tests mutate one field and expect one failure."""
    app_plist: dict = field(default_factory=lambda: {'CFBundleIdentifier': APP_ID, 'CFBundleExecutable': 'AgentbeltGuard'})
    sysext_plist: dict = field(default_factory=lambda: {
        'CFBundleIdentifier': SYSEXT_ID, 'CFBundleExecutable': SYSEXT_ID, 'NSEndpointSecurityMachServiceName': SERVICE,
        'AGBTeamIdentifier': TEAM, 'AGBApproverSigningIdentifier': APP_ID, 'AGBSupervisorSigningIdentifier': SUPERVISOR_ID})
    supervisor_plist: dict = field(default_factory=lambda: {
        'CFBundleIdentifier': SUPERVISOR_ID, 'CFBundleName': 'agentbelt-supervisor', 'AGBMachServiceName': SERVICE,
        'AGBTeamIdentifier': TEAM, 'AGBFileGuardSigningIdentifier': SYSEXT_ID})
    supervisor_binary: Optional[bytes] = None
    sysext_names: List[str] = field(default_factory=lambda: [SYSEXT_ID + '.systemextension'])
    code: Dict[str, CodeFixture] = field(default_factory=default_code)
    # Extra Mach-O files, keyed by (bundle label, path relative to that bundle).
    nested: Dict[tuple, CodeFixture] = field(default_factory=dict)
    profiles: Dict[str, ProfileFixture] = field(default_factory=lambda: {
        'app': ProfileFixture(profile_content(APP_ID, tool.SYSEXT_INSTALL)),
        'sysext': ProfileFixture(profile_content(SYSEXT_ID, tool.ES_CLIENT)),
    })

    def use_developer_id(self) -> None:
        for label, (identifier, key) in {'app': (APP_ID, tool.SYSEXT_INSTALL), 'sysext': (SYSEXT_ID, tool.ES_CLIENT)}.items():
            self.profiles[label] = ProfileFixture(profile_content(identifier, key, 'developer-id'))
        for fixture in self.code.values():
            fixture.authority, fixture.timestamp = DEVELOPER_ID_AUTHORITY, True

    def write(self, root: Path) -> 'Written':
        # main() resolves paths (/var -> /private/var), so the fake runner must see the same form.
        root = root.resolve()
        written = Written()
        app = root / 'AgentbeltGuard.app'
        self.write_bundle(written, 'app', app, self.app_plist)
        for index, name in enumerate(self.sysext_names):
            sysext = app.joinpath(*tool.SYSEXT_DIRECTORY, name)
            self.write_bundle(written, 'sysext' if index == 0 else f'sysext{index}', sysext, self.sysext_plist)
        for (label, relative), fixture in self.nested.items():
            path = written.bundles[label] / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(fixture.binary())
            written.add(path, fixture, path)
        supervisor = root / 'agentbelt-supervisor'
        fixture = self.code['supervisor']
        binary = self.supervisor_binary
        supervisor.write_bytes(binary if binary is not None else fixture.binary(plistlib.dumps(self.supervisor_plist)))
        written.add(supervisor, fixture, supervisor)
        written.bundles['supervisor'] = supervisor
        return written

    def write_bundle(self, written: 'Written', label: str, bundle: Path, plist: dict) -> None:
        write_plist(bundle / 'Contents' / 'Info.plist', plist)
        fixture = self.code.get(label, self.code['sysext'])
        executable = bundle / 'Contents' / 'MacOS' / str(plist.get('CFBundleExecutable'))
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(fixture.binary())
        written.add(bundle, fixture, executable)
        # A rejected executable name leaves the file to the nested-code scan, which sees the resolved path.
        written.add(executable.resolve(), fixture, executable.resolve())
        written.bundles[label] = bundle
        profile = self.profiles.get(label)
        if profile is not None and profile.present:
            (bundle / 'Contents' / 'embedded.provisionprofile').write_bytes(b'synthetic-cms:' + label.encode())
            written.profiles[str(bundle / 'Contents' / 'embedded.provisionprofile')] = profile


@dataclass
class Written:
    bundles: Dict[str, Path] = field(default_factory=dict)
    fixtures: Dict[str, CodeFixture] = field(default_factory=dict)
    executables: Dict[str, str] = field(default_factory=dict)
    profiles: Dict[str, ProfileFixture] = field(default_factory=dict)

    def add(self, path: Path, fixture: CodeFixture, executable: Path) -> None:
        self.fixtures[str(path)] = fixture
        self.executables[str(path)] = str(executable)


def write_plist(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))


class FakeRunner:
    """Serves canned output and records every command, which must be read-only."""

    def __init__(self, written: Written):
        self.written = written
        self.commands: List[List[str]] = []
        self.requirements: Dict[str, str] = {}
        self.extraction_directories: List[str] = []

    def __call__(self, argv: List[str]) -> tool.CommandResult:
        self.commands.append(list(argv))
        path = argv[-1]
        if argv[0] == tool.SECURITY:
            return self.profile(path)
        fixture = self.written.fixtures[path]
        if '-dvvv' in argv:
            return fixture.display(path, self.written.executables[path])
        if '-R' in argv:
            self.requirements[path] = argv[argv.index('-R') + 1]
            return fixture.requirement(path)
        if '--verify' in argv:
            return fixture.verify(path)
        extract = [argument for argument in argv if argument.startswith('--extract-certificates=')]
        if extract:
            prefix = extract[0].split('=', 1)[1]
            self.extraction_directories.append(str(Path(prefix).parent))
            return fixture.extract(prefix)
        return fixture.entitlements_output(path)

    def profile(self, path: str) -> tool.CommandResult:
        fixture = self.written.profiles[path]
        if fixture.decode_error:
            return tool.CommandResult(1, b'', f'security: {fixture.decode_error}\n')
        return tool.CommandResult(0, plistlib.dumps(fixture.content), '')


class SyntheticCase(unittest.TestCase):
    def setUp(self):
        self.build = SyntheticBuild()

    def run_tool(self, expect_team=TEAM, distribution=None):
        with tempfile.TemporaryDirectory() as directory:
            written = self.build.write(Path(directory))
            self.written = written
            self.runner = FakeRunner(written)
            options = tool.Options(written.bundles['app'], written.bundles['supervisor'], expect_team, distribution,
                                   self.runner, NOW)
            report = tool.verify(options)
            self.rendered = tool.render_json(report, options) + tool.render_text(report, options)
        self.checks = {check.name: check for check in report.checks}
        return report

    def assert_fails(self, name, fragment, **options):
        report = self.run_tool(**options)
        self.assertFalse(report.ok)
        self.assertIn(name, self.checks, sorted(self.checks))
        self.assertEqual(self.checks[name].status, tool.FAIL, self.checks[name].reason)
        self.assertIn(fragment, self.checks[name].reason)
        return report

    def assert_status(self, name, status):
        self.assertEqual(self.checks[name].status, status, f'{name}: {self.checks[name].reason}')

    def unmet(self):
        return sorted(f'{name}: {check.reason}' for name, check in self.checks.items() if not check.satisfied)


class PassingBuildTests(SyntheticCase):
    def test_development_build_passes_every_required_check(self):
        report = self.run_tool(distribution='development')
        self.assertTrue(report.ok, self.unmet())
        self.assert_status('sysext.profile.type', tool.PASS)
        self.assert_status('app.profile.certificate', tool.PASS)
        self.assert_status('app.secure-timestamp', tool.SKIP)

    def test_developer_id_build_passes(self):
        self.build.use_developer_id()
        report = self.run_tool(distribution='developer-id')
        self.assertTrue(report.ok, self.unmet())
        self.assert_status('supervisor.secure-timestamp', tool.PASS)

    def test_optional_checks_skip_without_distribution(self):
        report = self.run_tool()
        self.assertTrue(report.ok, self.unmet())
        for name in ('app.certificate-kind', 'sysext.profile.type'):
            self.assert_status(name, tool.SKIP)
            self.assertFalse(self.checks[name].required)
        self.assert_status('team.expected', tool.PASS)

    def test_clean_nested_library_passes(self):
        self.build.nested[('app', 'Contents/Frameworks/Lib.framework/Versions/A/Lib')] = CodeFixture(
            'dev.example.lib', {}, flags=0, filetype=MH_DYLIB)
        report = self.run_tool()
        self.assertTrue(report.ok, self.unmet())
        self.assertIn('1 nested', self.checks['app.nested-code'].reason)

    def test_universal_binary_with_matching_slices_passes(self):
        self.build.code['supervisor'].slice_flags = [tool.CS_RUNTIME, tool.CS_RUNTIME]
        report = self.run_tool()
        self.assertTrue(report.ok, self.unmet())

    def test_requirements_bind_identifier_team_and_distribution(self):
        self.build.use_developer_id()
        self.build.nested[('app', 'Contents/MacOS/helper.dylib')] = CodeFixture('helper', {}, flags=0, filetype=MH_DYLIB)
        self.run_tool(distribution='developer-id')
        by_name = {Path(path).name: requirement for path, requirement in self.runner.requirements.items()}
        developer_id = tool.DISTRIBUTION_CLAUSES['developer-id']
        self.assertEqual(by_name['AgentbeltGuard.app'], f'=anchor apple generic and identifier "{APP_ID}" and '
                         f'certificate leaf[subject.OU] = "{TEAM}" and {developer_id}')
        self.assertIn(f'identifier "{SUPERVISOR_ID}"', by_name['agentbelt-supervisor'])
        self.assertIn(f'identifier "{SYSEXT_ID}"', by_name[f'{SYSEXT_ID}.systemextension'])
        self.assertEqual(by_name['helper.dylib'], f'=anchor apple generic and certificate leaf[subject.OU] = "{TEAM}"')

    def test_only_read_only_commands_run(self):
        self.run_tool()
        for argv in self.runner.commands:
            self.assertIn(argv[0], (tool.CODESIGN, tool.SECURITY))
            self.assertFalse({'-s', '--sign', '-f', '--force', '--remove-signature'} & set(argv), argv)
            if argv[0] == tool.SECURITY:
                self.assertEqual(argv[1:4], ['cms', '-D', '-i'])
            else:
                self.assertTrue({'-d', '-dvvv', '--verify'} & set(argv), argv)

    def test_certificate_extraction_uses_private_directory_that_is_removed(self):
        modes = []
        original = CodeFixture.extract

        def recording_extract(fixture, prefix):
            modes.append(stat.S_IMODE(os.stat(Path(prefix).parent).st_mode))
            return original(fixture, prefix)

        CodeFixture.extract = recording_extract
        try:
            self.run_tool()
        finally:
            CodeFixture.extract = original
        self.assertEqual(modes, [0o700, 0o700])
        for directory in self.runner.extraction_directories:
            self.assertFalse(Path(directory).exists())

    def test_report_never_contains_devices_certificates_digests_or_signer_names(self):
        self.run_tool(distribution='development')
        secrets = DEVICE_UDIDS + [CERTIFICATE_MARKER.decode(), LEAF_DER.decode(), PERSON]
        secrets += [hashlib.sha256(value).hexdigest() for value in (LEAF_DER, CERTIFICATE_MARKER)]
        for secret in secrets:
            self.assertNotIn(secret, self.rendered)
        self.assertIn('3 provisioned device(s)', self.checks['app.profile.type'].reason)


class HostileOutputTests(SyntheticCase):
    def test_reviewer_bypass_with_forged_display_text_fails(self):
        for label in ('app', 'sysext', 'supervisor'):
            self.build.code[label].make_adhoc()
            self.build.code[label].injected_lines = list(FORGED_LINES)
        self.build.app_plist['CFBundleExecutable'] = 'AgentbeltGuard\n' + '\n'.join(FORGED_LINES)
        report = self.run_tool(distribution='development')
        self.assertFalse(report.ok)
        for label in ('app', 'sysext', 'supervisor'):
            for suffix in ('signature', 'requirement', 'signature-blob', 'not-adhoc', 'team', 'hardened-runtime'):
                self.assert_status(f'{label}.{suffix}', tool.FAIL)
            self.assertIn('repeats', self.checks[f'{label}.signature'].reason)
        self.assertIn('control characters', self.checks['app.executable'].reason)
        self.assertIn('no certificate', self.checks['sysext.profile.certificate'].reason)

    def test_duplicate_display_key_fails(self):
        self.build.code['sysext'].injected_lines = [f'TeamIdentifier={TEAM}']
        self.assert_fails('sysext.signature', "repeats 'TeamIdentifier'")
        self.assert_status('sysext.signature-blob', tool.FAIL)

    def test_second_codedirectory_line_fails(self):
        self.build.code['app'].injected_lines = [FORGED_LINES[0]]
        self.assert_fails('app.signature', 'repeats')

    def test_text_flags_cannot_claim_hardened_runtime(self):
        fixture = self.build.code['supervisor']
        fixture.flags = 0
        fixture.text_overrides['CodeDirectory v'] = '20500 size=900 flags=0x10000(runtime) hashes=20+7 location=embedded'
        self.assert_fails('supervisor.hardened-runtime', 'missing')
        self.assertIn('flags differs', self.checks['supervisor.signature-blob'].reason)

    def test_text_team_must_match_blob(self):
        self.build.code['app'].text_overrides['TeamIdentifier'] = OTHER_TEAM
        self.assert_fails('app.signature-blob', 'team differs')

    def test_text_identifier_must_match_blob(self):
        self.build.code['sysext'].text_overrides['Identifier'] = 'forged'
        self.assert_fails('sysext.signature-blob', 'identifier differs')

    def test_codesign_entitlements_must_match_blob(self):
        extra = dict(self.build.code['app'].entitlements, extra=True)
        self.build.code['app'].entitlements_raw = plistlib.dumps(extra)
        self.assert_fails('app.signature-blob', 'entitlements differs')

    def test_universal_slices_that_disagree_fail(self):
        self.build.code['supervisor'].slice_flags = [tool.CS_RUNTIME, 0]
        self.assert_fails('supervisor.signature-blob', 'slices disagree on flags')

    def test_control_characters_in_sysext_bundle_name_fail(self):
        self.build.sysext_names = [f'{SYSEXT_ID} .systemextension']
        self.assert_fails('sysext.present', 'control characters')

    def test_executable_with_path_separator_fails(self):
        self.build.sysext_plist['CFBundleExecutable'] = '../escape'
        self.assert_fails('sysext.executable', 'path separators')


class SignatureFailureTests(SyntheticCase):
    def test_adhoc_signature_fails(self):
        self.build.code['app'].make_adhoc()
        self.assert_fails('app.not-adhoc', 'ad-hoc')
        self.assert_status('app.requirement', tool.FAIL)

    def test_unsigned_code_fails(self):
        self.build.code['supervisor'].display_error = 'code object is not signed at all'
        self.assert_fails('supervisor.signature', 'not signed')
        self.assert_status('supervisor.not-adhoc', tool.FAIL)

    def test_unsigned_binary_without_signature_blob_fails(self):
        self.build.supervisor_binary = build_macho(plistlib.dumps(self.build.supervisor_plist))
        self.assert_fails('supervisor.signature-blob', 'no LC_CODE_SIGNATURE')

    def test_invalid_signature_fails(self):
        self.build.code['sysext'].verify_error = 'a sealed resource is missing or invalid'
        self.assert_fails('sysext.signature', 'sealed resource')

    def test_unsatisfied_requirement_fails(self):
        self.build.code['app'].requirement_satisfied = False
        self.assert_fails('app.requirement', 'NOT satisfied')

    def test_requirement_needs_a_safe_identifier(self):
        self.build.app_plist['CFBundleIdentifier'] = 'dev.example" or anchor apple'
        self.assert_fails('app.requirement', 'cannot build a requirement')
        self.assert_status('app.bundle-id', tool.FAIL)

    def test_missing_team_fails(self):
        self.build.code['supervisor'].team = None
        self.assert_fails('supervisor.team', 'not set')
        self.assert_status('team.consistent', tool.FAIL)

    def test_team_mismatch_across_components_fails(self):
        self.build.code['sysext'].team = OTHER_TEAM
        self.assert_fails('team.consistent', f'sysext={OTHER_TEAM}')

    def test_expected_team_mismatch_fails(self):
        self.assert_fails('team.expected', OTHER_TEAM, expect_team=OTHER_TEAM)
        self.assert_status('app.team', tool.FAIL)

    def test_missing_hardened_runtime_fails(self):
        self.build.code['supervisor'].flags = 0
        self.assert_fails('supervisor.hardened-runtime', 'missing')

    def test_get_task_allow_fails(self):
        self.build.code['supervisor'].entitlements = {tool.GET_TASK_ALLOW: True}
        self.assert_fails('supervisor.no-get-task-allow', 'present')
        self.assert_status('supervisor.entitlements', tool.FAIL)

    def test_unreadable_codesign_entitlements_fail(self):
        self.build.code['app'].entitlements_error = 'invalid entitlements blob'
        self.assert_fails('app.no-get-task-allow', 'unreadable')
        self.assert_status('app.signature-blob', tool.FAIL)

    def test_garbage_entitlements_output_fails(self):
        self.build.code['sysext'].entitlements_raw = b'\xfa\xde\x71\x71not a plist'
        self.assert_fails('sysext.no-get-task-allow', 'unparseable')

    def test_unbound_info_plist_fails(self):
        self.build.code['sysext'].info_bound = False
        self.assert_fails('sysext.info-plist-bound', 'not bound')

    def test_app_identifier_mismatch_fails(self):
        self.build.code['app'].identifier = 'AgentbeltGuard'
        self.assert_fails('app.identifier', "'AgentbeltGuard'")

    def test_sysext_identifier_mismatch_fails(self):
        self.build.code['sysext'].identifier = APP_ID + '.other'
        self.assert_fails('sysext.identifier', SYSEXT_ID)

    def test_supervisor_identifier_mismatch_names_open_question(self):
        self.build.code['supervisor'].identifier = 'agentbelt-supervisor'
        self.assert_fails('supervisor.identifier', 'open question')

    def test_certificate_kind_must_match_distribution(self):
        self.build.use_developer_id()
        self.build.code['app'].authority = DEVELOPMENT_AUTHORITY
        self.assert_fails('app.certificate-kind', 'development', distribution='developer-id')

    def test_developer_id_requires_secure_timestamp(self):
        self.build.use_developer_id()
        self.build.code['sysext'].timestamp = False
        self.assert_fails('sysext.secure-timestamp', 'no secure timestamp', distribution='developer-id')


class EntitlementAndProfileFailureTests(SyntheticCase):
    def test_app_without_install_entitlement_fails(self):
        del self.build.code['app'].entitlements[tool.SYSEXT_INSTALL]
        self.assert_fails('app.entitlement.system-extension-install', 'absent')

    def test_sysext_without_es_entitlement_fails(self):
        self.build.code['sysext'].entitlements[tool.ES_CLIENT] = False
        self.assert_fails('sysext.entitlement.endpoint-security-client', 'False')

    def test_signed_application_identifier_is_required(self):
        del self.build.code['app'].entitlements[tool.APPLICATION_IDENTIFIER]
        self.assert_fails('app.entitlement.application-identifier', 'absent')

    def test_signed_application_identifier_must_name_the_bundle(self):
        self.build.code['sysext'].entitlements[tool.APPLICATION_IDENTIFIER] = f'{TEAM}.{APP_ID}'
        self.assert_fails('sysext.entitlement.application-identifier', f'{TEAM}.{SYSEXT_ID}')

    def test_signed_team_identifier_must_match(self):
        self.build.code['sysext'].entitlements[tool.TEAM_ENTITLEMENT] = OTHER_TEAM
        self.assert_fails('sysext.entitlement.team-identifier', OTHER_TEAM)
        self.assert_status('sysext.profile.entitlements', tool.FAIL)

    def test_profile_team_identifier_must_match(self):
        self.build.profiles['app'].content['Entitlements'][tool.TEAM_ENTITLEMENT] = OTHER_TEAM
        self.assert_fails('app.profile.team-identifier', OTHER_TEAM)

    def test_signing_certificate_missing_from_profile_fails(self):
        self.build.profiles['sysext'].content['DeveloperCertificates'] = [CERTIFICATE_MARKER]
        self.assert_fails('sysext.profile.certificate', 'is NOT one of')

    def test_certificate_without_leaf_fails(self):
        self.build.code['app'].leaf = None
        self.assert_fails('app.profile.certificate', 'no certificate')

    def test_missing_profile_fails_and_skips_dependents(self):
        self.build.profiles['sysext'].present = False
        self.assert_fails('sysext.profile.present', 'missing')
        self.assert_status('sysext.profile.entitlements', tool.SKIP)
        self.assertTrue(self.checks['sysext.profile.entitlements'].required)

    def test_undecodable_profile_fails(self):
        self.build.profiles['app'].decode_error = 'unable to decode'
        report = self.run_tool()
        self.assertFalse(report.ok)
        self.assertIn('security cms -D failed', self.checks['app.profile.decodes'].reason)

    def test_profile_team_mismatch_fails(self):
        self.build.profiles['app'].content['TeamIdentifier'] = [OTHER_TEAM]
        self.assert_fails('app.profile.team', OTHER_TEAM)

    def test_wildcard_profile_app_id_fails(self):
        self.build.profiles['sysext'].content['Entitlements'][tool.APPLICATION_IDENTIFIER] = f'{TEAM}.*'
        self.assert_fails('sysext.profile.app-id', f'{TEAM}.{SYSEXT_ID}')

    def test_profile_without_es_capability_fails(self):
        del self.build.profiles['sysext'].content['Entitlements'][tool.ES_CLIENT]
        self.assert_fails('sysext.profile.grants-required', 'None')
        self.assertIn(f'{tool.ES_CLIENT} not granted', self.checks['sysext.profile.entitlements'].reason)

    def test_signed_entitlement_not_in_profile_fails(self):
        self.build.code['app'].entitlements['com.apple.security.cs.disable-library-validation'] = True
        self.assert_fails('app.profile.entitlements', 'disable-library-validation not granted')

    def test_signed_entitlement_value_mismatch_fails(self):
        self.build.code['sysext'].entitlements[KEYCHAIN_GROUPS] = [f'{OTHER_TEAM}.{SYSEXT_ID}']
        self.assert_fails('sysext.profile.entitlements', 'profile grants')

    def test_expired_profile_fails(self):
        self.build.profiles['app'].content['ExpirationDate'] = NOW - datetime.timedelta(seconds=1)
        self.assert_fails('app.profile.not-expired', 'expires')

    def test_profile_type_must_match_distribution(self):
        self.assert_fails('app.profile.type', 'profile type development', distribution='developer-id')

    def test_value_granted_rules(self):
        self.assertTrue(tool.value_granted('T.a.b', 'T.*'))
        self.assertTrue(tool.value_granted(['T.a'], ['X', 'T.*']))
        self.assertFalse(tool.value_granted(['T.a', 'U.b'], ['T.*']))
        self.assertFalse(tool.value_granted(1, True))
        self.assertFalse(tool.value_granted(True, 'true'))
        self.assertTrue(tool.value_granted(True, True))


class NestedCodeFailureTests(SyntheticCase):
    def add(self, label='app', relative='Contents/MacOS/AgentbeltGuard.debug.dylib', **changes):
        fixture = CodeFixture('dev.example.nested', {}, flags=0, filetype=MH_DYLIB)
        for key, value in changes.items():
            setattr(fixture, key, value)
        self.build.nested[(label, relative)] = fixture
        return fixture

    def test_adhoc_nested_library_fails(self):
        self.add().make_adhoc()
        self.assert_fails('app.nested-code', 'ad-hoc signature')
        self.assertIn('does not satisfy the team requirement', self.checks['app.nested-code'].reason)

    def test_nested_library_from_another_team_fails(self):
        self.add(team=OTHER_TEAM)
        self.assert_fails('app.nested-code', f'team {OTHER_TEAM}')

    def test_nested_executable_without_runtime_fails(self):
        self.add(relative='Contents/Helpers/helper', filetype=tool.MH_EXECUTE)
        self.assert_fails('app.nested-code', 'executable without hardened runtime')

    def test_nested_get_task_allow_fails(self):
        self.add(entitlements={tool.GET_TASK_ALLOW: True})
        self.assert_fails('app.nested-code', 'get-task-allow')

    def test_nested_requirement_failure_fails(self):
        self.add(requirement_satisfied=False)
        self.assert_fails('app.nested-code', 'team requirement')

    def test_code_nested_in_sysext_is_checked(self):
        self.add(label='sysext', relative='Contents/Frameworks/libx.dylib', team=None)
        self.assert_fails('sysext.nested-code', 'team not set')


class BundleAndTrustRootFailureTests(SyntheticCase):
    def test_placeholder_app_id_fails(self):
        self.build.app_plist['CFBundleIdentifier'] = 'invalid.agentbelt.unconfigured'
        self.assert_fails('app.bundle-id', 'placeholder')

    def test_missing_sysext_fails(self):
        self.build.sysext_names = []
        self.assert_fails('sysext.present', '0 system extension')
        self.assert_status('sysext.signature', tool.SKIP)

    def test_two_sysexts_fail(self):
        self.build.sysext_names.append('extra.systemextension')
        self.assert_fails('sysext.present', '2 system extension')

    def test_sysext_bundle_name_mismatch_fails(self):
        self.build.sysext_names = ['FileGuard.systemextension']
        self.assert_fails('sysext.bundle-name', 'FileGuard.systemextension')

    def test_sysext_bundle_id_mismatch_fails(self):
        self.build.sysext_plist['CFBundleIdentifier'] = 'com.other.fileguard'
        self.build.sysext_names = ['com.other.fileguard.systemextension']
        self.assert_fails('sysext.bundle-id', SYSEXT_ID)

    def test_mach_service_without_team_prefix_fails(self):
        self.build.sysext_plist['NSEndpointSecurityMachServiceName'] = f'.{SYSEXT_ID}.control'
        self.assert_fails('sysext.mach-service', f'{TEAM}.')

    def test_placeholder_agb_values_fail(self):
        self.build.sysext_plist['AGBSupervisorSigningIdentifier'] = 'invalid.agentbelt.unconfigured.supervisor'
        self.assert_fails('sysext.plist.AGBSupervisorSigningIdentifier', 'placeholder')

    def test_agb_team_mismatch_fails(self):
        self.build.sysext_plist['AGBTeamIdentifier'] = OTHER_TEAM
        self.assert_fails('sysext.plist.AGBTeamIdentifier', OTHER_TEAM)

    def test_agb_approver_mismatch_fails(self):
        self.build.sysext_plist['AGBApproverSigningIdentifier'] = SUPERVISOR_ID
        self.assert_fails('sysext.plist.AGBApproverSigningIdentifier', SUPERVISOR_ID)

    def test_supervisor_service_name_mismatch_fails(self):
        self.build.supervisor_plist['AGBMachServiceName'] = f'{TEAM}.com.other.control'
        self.assert_fails('supervisor.plist.AGBMachServiceName', SERVICE)

    def test_supervisor_fileguard_identifier_mismatch_fails(self):
        self.build.supervisor_plist['AGBFileGuardSigningIdentifier'] = APP_ID
        self.assert_fails('supervisor.plist.AGBFileGuardSigningIdentifier', SYSEXT_ID)

    def test_supervisor_team_mismatch_fails(self):
        self.build.supervisor_plist['AGBTeamIdentifier'] = ''
        self.assert_fails('supervisor.plist.AGBTeamIdentifier', 'placeholder')

    def test_supervisor_without_info_plist_section_fails(self):
        fixture = self.build.code['supervisor']
        self.build.supervisor_binary = build_macho(b'data', name=b'__cstring', code_signature=signature(
            fixture.identifier, fixture.team, fixture.flags, fixture.entitlements))
        self.assert_fails('supervisor.info-plist-section', 'no __TEXT,__info_plist')

    def test_supervisor_not_macho_fails(self):
        self.build.supervisor_binary = b'#!/bin/sh\nexit 0\n'
        self.assert_fails('supervisor.info-plist-section', 'Mach-O')
        self.assert_status('supervisor.signature-blob', tool.FAIL)


class MachOReaderTests(unittest.TestCase):
    PAYLOAD = plistlib.dumps({'CFBundleIdentifier': SUPERVISOR_ID})
    SIGNATURE = signature(SUPERVISOR_ID, TEAM, tool.CS_RUNTIME, {'k': True})

    def with_file(self, data: bytes, reader):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            path.write_bytes(data)
            return reader(path)

    def read(self, data: bytes) -> bytes:
        return self.with_file(data, tool.read_info_plist_section)

    def facts(self, data: bytes) -> tool.SignatureFacts:
        return self.with_file(data, tool.read_signature_facts)

    def test_thin_image(self):
        self.assertEqual(self.read(build_macho(self.PAYLOAD)), self.PAYLOAD)

    def test_universal_image(self):
        image = build_macho(self.PAYLOAD)
        self.assertEqual(self.read(build_fat([image, image])), self.PAYLOAD)

    def test_universal_slices_must_agree(self):
        other = build_macho(plistlib.dumps({'CFBundleIdentifier': 'forged'}))
        with self.assertRaisesRegex(tool.MachOError, 'different'):
            self.read(build_fat([build_macho(self.PAYLOAD), other]))

    def test_other_segment_is_ignored(self):
        with self.assertRaisesRegex(tool.MachOError, 'no __TEXT'):
            self.read(build_macho(self.PAYLOAD, segment=b'__DATA'))

    def test_malformed_images_raise(self):
        image = bytearray(build_macho(self.PAYLOAD))
        truncated = bytes(image[:40])
        bad_command = bytes(image[:36]) + struct.pack('<I', 4) + bytes(image[40:])
        bad_offset = bytearray(image)
        struct.pack_into('<I', bad_offset, 32 + 72 + 48, 0xFFFFFF)
        empty_fat = struct.pack('>II', tool.FAT_MAGIC, 0) + b'\0' * 32
        for data in (b'', truncated, bad_command, bytes(bad_offset), empty_fat, b'\x7fELF' + b'\0' * 60):
            with self.subTest(data=data[:8]), self.assertRaises(tool.MachOError):
                self.read(data)

    def test_signature_facts_from_blob(self):
        facts = self.facts(build_macho(code_signature=self.SIGNATURE))
        self.assertEqual(facts, tool.SignatureFacts(SUPERVISOR_ID, TEAM, tool.CS_RUNTIME, {'k': True}, True))

    def test_signature_facts_from_universal_image(self):
        image = build_macho(code_signature=self.SIGNATURE)
        self.assertEqual(self.facts(build_fat([image, image])).team, TEAM)

    def test_alternate_code_directory_must_agree(self):
        forged = code_directory(SUPERVISOR_ID, OTHER_TEAM, tool.CS_RUNTIME)
        blob = signature(SUPERVISOR_ID, TEAM, tool.CS_RUNTIME, {}, alternate=forged)
        with self.assertRaisesRegex(tool.MachOError, 'code directories disagree'):
            self.facts(build_macho(code_signature=blob))

    def test_malformed_signatures_raise(self):
        directory = code_directory(SUPERVISOR_ID, TEAM, tool.CS_RUNTIME)
        unterminated = directory[:-1] + b'X'
        cases = {
            'no LC_CODE_SIGNATURE': build_macho(),
            'SuperBlob': build_macho(code_signature=b'\0' * 16),
            'duplicate': build_macho(code_signature=superblob([(0, directory), (0, directory)])),
            'unterminated': build_macho(code_signature=superblob([(0, unterminated)])),
            'no CodeDirectory': build_macho(code_signature=superblob([(5, entitlements_blob({}))])),
            'outside': build_macho(code_signature=struct.pack('>III', tool.CSMAGIC_EMBEDDED_SIGNATURE, 20, 1)
                                   + struct.pack('>II', 0, 400)),
        }
        for message, data in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(tool.MachOError, message):
                self.facts(data)


class CommandLineTests(unittest.TestCase):
    def invoke(self, extra: List[str], build: Optional[SyntheticBuild] = None):
        build = build or SyntheticBuild()
        with tempfile.TemporaryDirectory() as directory:
            written = build.write(Path(directory))
            argv = ['--app', str(written.bundles['app']), '--supervisor', str(written.bundles['supervisor'])] + extra
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = tool.main(argv, runner=FakeRunner(written), now=NOW)
        return code, output.getvalue()

    def test_passing_build_exits_zero_with_json(self):
        code, output = self.invoke(['--json', '--expect-team', TEAM, '--distribution', 'development'])
        self.assertEqual(code, 0, output)
        self.assertTrue(json.loads(output)['ok'])

    def test_failing_build_exits_one(self):
        build = SyntheticBuild()
        build.code['app'].flags = 0
        code, output = self.invoke(['--expect-team', TEAM], build)
        self.assertEqual(code, 1)
        self.assertIn('RESULT: FAIL', output)
        self.assertIn('FAIL  app.hardened-runtime', output)

    def test_wrong_team_cannot_pass(self):
        code, _ = self.invoke(['--expect-team', OTHER_TEAM])
        self.assertEqual(code, 1)

    def test_usage_errors_exit_two(self):
        for extra in ([], ['--expect-team', 'not-a-team'], ['--expect-team', TEAM, '--distribution', 'app-store']):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    self.invoke(extra)
                self.assertEqual(raised.exception.code, 2)

    def test_paths_with_control_characters_are_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            tool.main(['--app', 'x\nTeamIdentifier=Y.app', '--supervisor', __file__, '--expect-team', TEAM],
                      runner=None, now=NOW)
        self.assertEqual(raised.exception.code, 2)

    def test_app_path_must_be_an_app_bundle(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                tool.main(['--app', directory, '--supervisor', __file__, '--expect-team', TEAM], runner=None, now=NOW)
        self.assertEqual(raised.exception.code, 2)


@unittest.skipUnless((REAL_PRODUCTS / 'AgentbeltGuard.app').is_dir() and (REAL_PRODUCTS / 'agentbelt-supervisor').is_file(),
                     'unsigned build not present at native/guard/build/Build/Products/Debug')
class UnsignedBuildIntegrationTests(unittest.TestCase):
    """The real unsigned (ad-hoc, linker-signed) build must never pass."""

    def run_real(self, *extra: str):
        script = Path(tool.__file__).resolve()
        argv = ['/usr/bin/python3', '-I', str(script), '--app', str(REAL_PRODUCTS / 'AgentbeltGuard.app'),
                '--supervisor', str(REAL_PRODUCTS / 'agentbelt-supervisor'), '--json', '--expect-team', TEAM, *extra]
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
        return completed.returncode, json.loads(completed.stdout)

    def test_unsigned_build_fails_as_adhoc_and_teamless(self):
        code, document = self.run_real()
        self.assertEqual(code, 1)
        self.assertFalse(document['ok'])
        checks = {check['name']: check for check in document['checks']}
        for label in ('app', 'sysext', 'supervisor'):
            for suffix in ('not-adhoc', 'team', 'requirement', 'hardened-runtime'):
                self.assertEqual(checks[f'{label}.{suffix}']['status'], tool.FAIL, suffix)
            self.assertIn('ad-hoc', checks[f'{label}.not-adhoc']['reason'])
            # The blob reader must agree with the real codesign on real binaries.
            self.assertEqual(checks[f'{label}.signature-blob']['status'], tool.PASS,
                             checks[f'{label}.signature-blob']['reason'])
        self.assertEqual(checks['sysext.profile.present']['status'], tool.FAIL)
        self.assertEqual(checks['app.nested-code']['status'], tool.FAIL)

    def test_unsigned_build_fails_with_distribution(self):
        code, document = self.run_real('--distribution', 'development')
        self.assertEqual(code, 1)
        self.assertFalse(document['ok'])

    def test_real_supervisor_blob_and_info_plist_section(self):
        supervisor = REAL_PRODUCTS / 'agentbelt-supervisor'
        plist = plistlib.loads(tool.read_info_plist_section(supervisor))
        self.assertEqual(plist.get('CFBundleName'), 'agentbelt-supervisor')
        facts = tool.read_signature_facts(supervisor)
        self.assertTrue(facts.flags & tool.CS_ADHOC)
        self.assertIsNone(facts.team)


if __name__ == '__main__':
    unittest.main()
