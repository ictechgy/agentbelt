#!/usr/bin/python3 -I
"""Read-only verifier for a signed agentbelt Guard build (the R3 signing gate).

It checks that AgentbeltGuard.app, its embedded File Guard system extension and the
agentbelt-supervisor tool are signed by the expected team with the hardened runtime, carry
only entitlements that their provisioning profiles grant, and agree on the trust roots
sealed into their Info.plists. See docs/design/native-guard.md.

Trust is bound by Security requirement evaluation (`codesign --verify -R`) and by reading
the signature blob out of each Mach-O directly. The text of `codesign -dvvv` is only
cross-checked, because it echoes attacker-chosen names (paths, identifiers) verbatim.

Only local read-only commands run: `codesign -d`, `codesign --verify` and
`security cms -D` (which decodes a profile; it does not evaluate certificate trust).
Nothing is signed, installed or activated, and no network is used. Profile certificates,
certificate digests, device lists and signer names are never printed.

Exit status: 0 when every required check passes, 1 otherwise, 2 on usage errors.
"""
import argparse
from dataclasses import dataclass, field, fields as dataclass_fields
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Callable, Dict, FrozenSet, Iterator, List, Optional, Tuple
import unicodedata

CODESIGN = '/usr/bin/codesign'
SECURITY = '/usr/bin/security'
# A fixed PATH and locale keep output parseable; HOME is left out on purpose.
COMMAND_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
COMMAND_TIMEOUT_SECONDS = 60

# Code-directory flags from xnu cs_blobs.h.
CS_ADHOC = 0x2
CS_RUNTIME = 0x10000

GET_TASK_ALLOW = 'com.apple.security.get-task-allow'
ES_CLIENT = 'com.apple.developer.endpoint-security.client'
SYSEXT_INSTALL = 'com.apple.developer.system-extension.install'
APPLICATION_IDENTIFIER = 'com.apple.application-identifier'
TEAM_ENTITLEMENT = 'com.apple.developer.team-identifier'

SYSEXT_SUFFIX = '.fileguard'
SUPERVISOR_SUFFIX = '.supervisor'
SYSEXT_DIRECTORY = ('Contents', 'Library', 'SystemExtensions')
# Values from Config/Signing.xcconfig placeholders or unexpanded build settings.
PLACEHOLDER_MARKERS = ('invalid.', '$(')
TEAM_PATTERN = re.compile(r'^[A-Z0-9]{10}$')
# Identifiers are interpolated into requirement text, so only these characters are allowed.
IDENTIFIER_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$')
DISTRIBUTIONS = ('development', 'developer-id')
# Certificate marker OIDs as used in Xcode designated requirements: the Apple WWDR
# intermediate for development, and the Developer ID intermediate plus leaf.
DISTRIBUTION_CLAUSES = {
    'development': 'certificate 1[field.1.2.840.113635.100.6.2.1]',
    'developer-id': ('certificate 1[field.1.2.840.113635.100.6.2.6] and '
                     'certificate leaf[field.1.2.840.113635.100.6.1.13]'),
}
# Leaf certificate common-name prefixes; only the kind is reported, never the name.
CERTIFICATE_KINDS = (
    ('Apple Development:', 'development'),
    ('Mac Developer:', 'development'),
    ('Developer ID Application:', 'developer-id'),
    ('Apple Distribution:', 'app-store'),
    ('3rd Party Mac Developer Application:', 'app-store'),
)
SUPERVISOR_IDENTIFIER_NOTE = (
    'open question in docs/design/native-guard.md: the signed supervisor must carry '
    '<prefix>.supervisor, but Xcode may sign a tool with its product name instead')
# codesign repeats only these keys; any other repeat means injected text.
REPEATABLE_DISPLAY_KEYS = frozenset({'Authority'})

PASS, FAIL, SKIP = 'PASS', 'FAIL', 'SKIP'
MAX_TEXT_CHARS = 240
MAX_NESTED_CODE = 256
MAX_LISTED_PROBLEMS = 8

# Mach-O constants (mach-o/loader.h, mach-o/fat.h).
MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
FAT_MAGIC = 0xcafebabe
FAT_MAGIC_64 = 0xcafebabf
MH_EXECUTE = 0x2
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1d
MACH_HEADER_64_SIZE = 32
SEGMENT_COMMAND_64_SIZE = 72
SECTION_64_SIZE = 80
LINKEDIT_DATA_COMMAND_SIZE = 16
MAX_FAT_ARCHS = 16
MAX_MACHO_BYTES = 512 * 2**20

# Code-signing blob constants (xnu cs_blobs.h); blobs are big-endian.
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSMAGIC_CODEDIRECTORY = 0xfade0c02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171
CSSLOT_CODEDIRECTORY = 0
CSSLOT_ENTITLEMENTS = 5
CSSLOT_ALTERNATE_CODEDIRECTORIES = range(0x1000, 0x1005)
CS_SUPPORTSTEAMID = 0x20200
CODE_DIRECTORY_MIN_SIZE = 44
CODE_DIRECTORY_TEAM_FIELD_END = 52
MAX_SIGNATURE_BLOBS = 64


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one local command. codesign writes its display output to stderr."""
    returncode: int
    stdout: bytes
    stderr: str


Runner = Callable[[List[str]], CommandResult]


def run_command(argv: List[str]) -> CommandResult:
    """Run a fixed local tool without a shell, stdin or the caller's environment."""
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=COMMAND_ENV,
                                   timeout=COMMAND_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return CommandResult(-1, b'', f'{Path(argv[0]).name} did not run: {error.__class__.__name__}')
    return CommandResult(completed.returncode, completed.stdout, completed.stderr.decode('utf-8', 'replace'))


@dataclass
class Check:
    """One reported check. A SKIP counts as a failure only when the check is required."""
    name: str
    status: str
    reason: str
    required: bool = True

    @property
    def satisfied(self) -> bool:
        return self.status == PASS or (self.status == SKIP and not self.required)


@dataclass
class Report:
    checks: List[Check] = field(default_factory=list)

    def result(self, name: str, passed: bool, reason: str) -> None:
        self.checks.append(Check(name, PASS if passed else FAIL, reason))

    def skip(self, name: str, reason: str, required: bool = True) -> None:
        self.checks.append(Check(name, SKIP, reason, required))

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(check.satisfied for check in self.checks)


def first_line(text: str) -> str:
    """Shortest useful error text; tool output can be long and is not echoed in full."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return brief(lines[0] if lines else 'no output')


def brief(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= MAX_TEXT_CHARS else text[:MAX_TEXT_CHARS] + '...'


def has_control_characters(text: str) -> bool:
    """Line breaks and invisible format characters let a name forge report or codesign lines."""
    return any(unicodedata.category(character) in ('Cc', 'Cf', 'Zl', 'Zp') for character in text)


def is_placeholder(value: object) -> bool:
    return not isinstance(value, str) or not value or any(marker in value for marker in PLACEHOLDER_MARKERS)


def matches(actual: object, expected: Optional[str]) -> bool:
    """Equal to a known expectation, and never a placeholder even if both sides are."""
    return expected is not None and actual == expected and not is_placeholder(actual)


def child(base: Optional[str], suffix: str) -> Optional[str]:
    return None if base is None else base + suffix


def expectation(actual: object, expected: Optional[str]) -> str:
    """Explain a comparison; equal placeholders still fail, so say why."""
    reason = f'{actual!r}, expected {expected!r}' if expected is not None else f'{actual!r}, expected value unknown'
    return reason + (' (placeholder or empty)' if is_placeholder(actual) else '')


# --- Mach-O reader -------------------------------------------------------------------------

class MachOError(ValueError):
    pass


def read_bounded(path: Path) -> bytes:
    if path.stat().st_size > MAX_MACHO_BYTES:
        raise MachOError('file too large for a Mach-O check')
    return path.read_bytes()


def macho_slices(data: bytes) -> List[bytes]:
    if len(data) < 8:
        raise MachOError('file too short for a Mach-O header')
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        return fat_slices(data, magic == FAT_MAGIC_64)
    return [data]


def fat_slices(data: bytes, is_64: bool) -> List[bytes]:
    count = struct.unpack_from('>I', data, 4)[0]
    entry_format = '>iiQQII' if is_64 else '>iiIII'
    entry_size = struct.calcsize(entry_format)
    if not 0 < count <= MAX_FAT_ARCHS or 8 + count * entry_size > len(data):
        raise MachOError('malformed universal header')
    slices = []
    for index in range(count):
        offset, size = struct.unpack_from(entry_format, data, 8 + index * entry_size)[2:4]
        if offset + size > len(data):
            raise MachOError('universal slice outside the file')
        slices.append(data[offset:offset + size])
    return slices


def load_commands(image: bytes) -> Iterator[Tuple[int, int, int]]:
    """Yield (command, offset, size) for each bounds-checked load command."""
    if len(image) < MACH_HEADER_64_SIZE or struct.unpack_from('<I', image, 0)[0] != MH_MAGIC_64:
        raise MachOError('not a 64-bit little-endian Mach-O image')
    command_count, commands_size = struct.unpack_from('<II', image, 16)
    offset, end = MACH_HEADER_64_SIZE, MACH_HEADER_64_SIZE + commands_size
    if end > len(image):
        raise MachOError('load commands extend past the image')
    for _ in range(command_count):
        if offset + 8 > end:
            raise MachOError('truncated load command')
        command, command_size = struct.unpack_from('<II', image, offset)
        if command_size < 8 or offset + command_size > end:
            raise MachOError('malformed load command size')
        yield command, offset, command_size
        offset += command_size


def read_info_plist_section(path: Path) -> bytes:
    """Return __TEXT,__info_plist, the plist the supervisor trusts because its signature covers it."""
    sections = [find_section(image, b'__TEXT', b'__info_plist') for image in macho_slices(read_bounded(path))]
    if any(section is None for section in sections):
        raise MachOError('no __TEXT,__info_plist section')
    if len(set(sections)) != 1:
        raise MachOError('architecture slices carry different __info_plist sections')
    return sections[0]


def find_section(image: bytes, segment_name: bytes, section_name: bytes) -> Optional[bytes]:
    for command, offset, command_size in load_commands(image):
        if command == LC_SEGMENT_64:
            section = segment_section(image, offset, command_size, segment_name, section_name)
            if section is not None:
                return section
    return None


def segment_section(image: bytes, offset: int, command_size: int, segment_name: bytes,
                    section_name: bytes) -> Optional[bytes]:
    if command_size < SEGMENT_COMMAND_64_SIZE:
        raise MachOError('segment command too short')
    if c_string(image[offset + 8:offset + 24]) != segment_name:
        return None
    section_count = struct.unpack_from('<I', image, offset + 64)[0]
    if SEGMENT_COMMAND_64_SIZE + section_count * SECTION_64_SIZE > command_size:
        raise MachOError('segment sections extend past the command')
    for index in range(section_count):
        base = offset + SEGMENT_COMMAND_64_SIZE + index * SECTION_64_SIZE
        if c_string(image[base:base + 16]) == section_name and c_string(image[base + 16:base + 32]) == segment_name:
            return section_bytes(image, base)
    return None


def section_bytes(image: bytes, base: int) -> bytes:
    size = struct.unpack_from('<Q', image, base + 40)[0]
    file_offset = struct.unpack_from('<I', image, base + 48)[0]
    if file_offset + size > len(image):
        raise MachOError('section data outside the image')
    return image[file_offset:file_offset + size]


def c_string(raw: bytes) -> bytes:
    return raw.split(b'\0', 1)[0]


def is_macho_file(path: Path) -> bool:
    with path.open('rb') as handle:
        head = handle.read(4)
    if len(head) < 4:
        return False
    return struct.unpack('<I', head)[0] in (MH_MAGIC, MH_MAGIC_64) or struct.unpack('>I', head)[0] in (FAT_MAGIC, FAT_MAGIC_64)


# --- Signature blob reader -----------------------------------------------------------------

@dataclass(frozen=True)
class SignatureFacts:
    """Identity facts read from the embedded signature itself, identical in every slice."""
    identifier: str
    team: Optional[str]
    flags: int
    entitlements: dict
    is_executable: bool


def read_signature_facts(path: Path) -> SignatureFacts:
    facts = [slice_signature_facts(image) for image in macho_slices(read_bounded(path))]
    differing = sorted({item.name for fact in facts[1:] for item in dataclass_fields(SignatureFacts)
                        if getattr(fact, item.name) != getattr(facts[0], item.name)})
    if differing:
        raise MachOError(f'architecture slices disagree on {", ".join(differing)}')
    return facts[0]


def slice_signature_facts(image: bytes) -> SignatureFacts:
    blobs = superblob_entries(code_signature_blob(image))
    directories = {code_directory_facts(blob) for slot, blob in blobs
                   if slot == CSSLOT_CODEDIRECTORY or slot in CSSLOT_ALTERNATE_CODEDIRECTORIES}
    if len(directories) != 1:
        raise MachOError('no CodeDirectory' if not directories else 'code directories disagree')
    identifier, team, flags = directories.pop()
    entitlement_blobs = [blob for slot, blob in blobs if slot == CSSLOT_ENTITLEMENTS]
    entitlements = entitlements_from_blob(entitlement_blobs[0]) if entitlement_blobs else {}
    is_executable = struct.unpack_from('<I', image, 12)[0] == MH_EXECUTE
    return SignatureFacts(identifier, team, flags, entitlements, is_executable)


def code_signature_blob(image: bytes) -> bytes:
    for command, offset, command_size in load_commands(image):
        if command == LC_CODE_SIGNATURE:
            if command_size < LINKEDIT_DATA_COMMAND_SIZE:
                raise MachOError('LC_CODE_SIGNATURE too short')
            data_offset, data_size = struct.unpack_from('<II', image, offset + 8)
            if data_offset + data_size > len(image):
                raise MachOError('code signature outside the image')
            return image[data_offset:data_offset + data_size]
    raise MachOError('no LC_CODE_SIGNATURE: the image is not signed')


def superblob_entries(blob: bytes) -> List[Tuple[int, bytes]]:
    if len(blob) < 12:
        raise MachOError('code signature too short')
    magic, length, count = struct.unpack_from('>III', blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE or length > len(blob) or count > MAX_SIGNATURE_BLOBS \
            or 12 + count * 8 > length:
        raise MachOError('malformed code signature SuperBlob')
    entries: List[Tuple[int, bytes]] = []
    for index in range(count):
        slot, offset = struct.unpack_from('>II', blob, 12 + index * 8)
        if any(slot == seen for seen, _ in entries):
            raise MachOError('duplicate code signature slot')
        entries.append((slot, sub_blob(blob, offset, length)))
    return entries


def sub_blob(blob: bytes, offset: int, limit: int) -> bytes:
    if offset + 8 > limit:
        raise MachOError('code signature blob outside the SuperBlob')
    size = struct.unpack_from('>I', blob, offset + 4)[0]
    if size < 8 or offset + size > limit:
        raise MachOError('code signature blob size out of range')
    return blob[offset:offset + size]


def code_directory_facts(directory: bytes) -> Tuple[str, Optional[str], int]:
    if len(directory) < CODE_DIRECTORY_MIN_SIZE:
        raise MachOError('CodeDirectory too short')
    magic, _, version, flags = struct.unpack_from('>IIII', directory, 0)
    if magic != CSMAGIC_CODEDIRECTORY:
        raise MachOError('bad CodeDirectory magic')
    identifier = blob_string(directory, struct.unpack_from('>I', directory, 20)[0])
    team_offset = 0
    if version >= CS_SUPPORTSTEAMID and len(directory) >= CODE_DIRECTORY_TEAM_FIELD_END:
        team_offset = struct.unpack_from('>I', directory, 48)[0]
    team = blob_string(directory, team_offset) if team_offset else None
    return identifier, team or None, flags


def blob_string(blob: bytes, offset: int) -> str:
    end = blob.find(b'\0', offset)
    if offset >= len(blob) or end < 0:
        raise MachOError('unterminated string in CodeDirectory')
    try:
        return blob[offset:end].decode('utf-8')
    except UnicodeDecodeError as error:
        raise MachOError('CodeDirectory string is not UTF-8') from error


def entitlements_from_blob(blob: bytes) -> dict:
    if struct.unpack_from('>I', blob, 0)[0] != CSMAGIC_EMBEDDED_ENTITLEMENTS:
        raise MachOError('bad entitlements blob magic')
    try:
        value = plistlib.loads(blob[8:])
    except (ValueError, plistlib.InvalidFileException) as error:
        raise MachOError('entitlements blob is not a plist') from error
    if not isinstance(value, dict):
        raise MachOError('entitlements blob is not a dictionary')
    return value


# --- Collected facts -------------------------------------------------------------------------

@dataclass
class CodeInfo:
    """Facts for one code object: codesign text, requirement evaluation and the signature blob."""
    label: str
    path: Path
    executable: Optional[Path]
    deep: bool
    display_error: Optional[str]
    fields: Dict[str, str]
    authorities: List[str]
    verify_error: Optional[str]
    requirement: Optional[str]
    requirement_error: Optional[str]
    codesign_entitlements: Optional[dict]
    entitlements_error: Optional[str]
    facts: Optional[SignatureFacts]
    facts_error: Optional[str]

    @property
    def identifier(self) -> Optional[str]:
        return self.facts.identifier if self.facts else None

    @property
    def team(self) -> Optional[str]:
        return self.facts.team if self.facts else None

    @property
    def flags(self) -> Optional[int]:
        return self.facts.flags if self.facts else None

    @property
    def entitlements(self) -> Optional[dict]:
        return self.facts.entitlements if self.facts else None

    @property
    def is_adhoc(self) -> bool:
        return (self.facts is None or bool(self.facts.flags & CS_ADHOC)
                or self.fields.get('Signature') == 'adhoc' or not self.authorities)


def collect_code_info(label: str, path: Path, executable: Optional[Path], deep: bool,
                      requirement: Tuple[Optional[str], Optional[str]], runner: Runner) -> CodeInfo:
    display = runner([CODESIGN, '-dvvv', str(path)])
    fields, authorities, parse_error = parse_display(display.stderr + display.stdout.decode('utf-8', 'replace'))
    display_error = tool_error(display, path) if display.returncode != 0 else parse_error
    verify = runner([CODESIGN, '--verify', '--strict'] + (['--deep'] if deep else []) + [str(path)])
    requirement_text, requirement_error = requirement
    if requirement_text is not None:
        requirement_error = evaluate_requirement(path, requirement_text, deep, runner)
    entitlements, entitlements_error = read_entitlements(path, runner)
    facts, facts_error = signature_facts_or_error(executable)
    return CodeInfo(label, path, executable, deep, display_error, fields, authorities,
                    None if verify.returncode == 0 else tool_error(verify, path), requirement_text,
                    requirement_error, entitlements, entitlements_error, facts, facts_error)


def signature_facts_or_error(executable: Optional[Path]) -> Tuple[Optional[SignatureFacts], Optional[str]]:
    if executable is None:
        return None, 'no executable to read'
    try:
        return read_signature_facts(executable), None
    except (OSError, MachOError) as error:
        return None, brief(str(error))


def evaluate_requirement(path: Path, requirement: str, deep: bool, runner: Runner) -> Optional[str]:
    """codesign reads a requirement argument starting with '=' as requirement text."""
    result = runner([CODESIGN, '--verify', '--strict'] + (['--deep'] if deep else []) + ['-R', '=' + requirement, str(path)])
    return None if result.returncode == 0 else tool_error(result, path)


def code_requirement(identifier: Optional[str], team: str,
                     distribution: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Return (requirement, None) or (None, why it cannot be built)."""
    if identifier is None or not IDENTIFIER_PATTERN.match(identifier) or is_placeholder(identifier):
        return None, f'cannot build a requirement: expected identifier {identifier!r} unknown, invalid or placeholder'
    return team_requirement(team, identifier, distribution), None


def team_requirement(team: str, identifier: Optional[str] = None, distribution: Optional[str] = None) -> str:
    parts = ['anchor apple generic']
    if identifier is not None:
        parts.append(f'identifier "{identifier}"')
    parts.append(f'certificate leaf[subject.OU] = "{team}"')
    if distribution is not None:
        parts.append(DISTRIBUTION_CLAUSES[distribution])
    return ' and '.join(parts)


def tool_error(result: CommandResult, path: Path) -> str:
    """codesign prefixes errors with the path, which the report already shows."""
    return first_line(result.stderr.replace(f'{path}: ', ''))


def parse_display(text: str) -> Tuple[Dict[str, str], List[str], Optional[str]]:
    """Parse codesign -dvvv; a repeated key or a second CodeDirectory line means forged text."""
    fields: Dict[str, str] = {}
    authorities: List[str] = []
    for line in text.split('\n'):
        key, separator, value = line.partition('=')
        if not separator:
            continue
        if key in REPEATABLE_DISPLAY_KEYS:
            authorities.append(value)
        elif key in fields:
            return {}, [], f'codesign output repeats {brief(key)!r}; refusing possibly injected text'
        else:
            fields[key] = value
    return fields, authorities, None


def text_flags(fields: Dict[str, str]) -> Optional[int]:
    found = re.search(r'\bflags=(0x[0-9a-fA-F]+)', fields.get('CodeDirectory v', ''))
    return int(found.group(1), 16) if found else None


def text_team(fields: Dict[str, str]) -> Optional[str]:
    value = fields.get('TeamIdentifier')
    return None if value in (None, '', 'not set') else value


def read_entitlements(path: Path, runner: Runner) -> Tuple[Optional[dict], Optional[str]]:
    result = runner([CODESIGN, '-d', '--entitlements', '-', '--xml', str(path)])
    if result.returncode != 0:
        return None, tool_error(result, path)
    try:
        return parse_entitlements(result.stdout), None
    except ValueError as error:
        return None, f'unparseable entitlements: {brief(str(error))}'


def parse_entitlements(output: bytes) -> dict:
    """codesign prints nothing when there are no entitlements, and XML otherwise."""
    if not output.strip():
        return {}
    starts = [index for index in (output.find(b'<?xml'), output.find(b'<plist')) if index >= 0]
    if not starts:
        raise ValueError('no XML plist in codesign output')
    value = plistlib.loads(output[min(starts):])
    if not isinstance(value, dict):
        raise ValueError('entitlements are not a dictionary')
    return value


def leaf_certificate_digest(path: Path, runner: Runner) -> Tuple[Optional[str], Optional[str]]:
    """SHA-256 of the signing leaf's DER, extracted into a private directory that is always removed."""
    directory = tempfile.mkdtemp(prefix='agentbelt-verify-')
    try:
        result = runner([CODESIGN, '-d', f'--extract-certificates={directory}/certificate', str(path)])
        leaf = Path(directory) / 'certificate0'
        if result.returncode != 0:
            return None, f'certificate extraction failed: {tool_error(result, path)}'
        if not leaf.is_file():
            return None, 'signature carries no certificate (ad-hoc or unsigned)'
        return hashlib.sha256(leaf.read_bytes()).hexdigest(), None
    finally:
        remove_directory(directory)


def remove_directory(directory: str) -> None:
    try:
        shutil.rmtree(directory)
    except OSError as error:
        print(f'warning: could not remove temporary directory {directory}: {error}', file=sys.stderr)


@dataclass
class Profile:
    """The parts of a provisioning profile the checks need; certificates become digests, UDIDs a count."""
    team_ids: List[str]
    entitlements: dict
    expiration: Optional[datetime.datetime]
    kind: str
    device_count: int
    certificate_digests: FrozenSet[str]


def load_profile(path: Path, runner: Runner) -> Tuple[Optional[Profile], Optional[str]]:
    result = runner([SECURITY, 'cms', '-D', '-i', str(path)])
    if result.returncode != 0:
        return None, f'security cms -D failed: {first_line(result.stderr)}'
    try:
        content = plistlib.loads(result.stdout)
    except (ValueError, plistlib.InvalidFileException) as error:
        return None, f'decoded profile is not a plist: {brief(str(error))}'
    if not isinstance(content, dict) or not isinstance(content.get('Entitlements'), dict):
        return None, 'decoded profile has no Entitlements dictionary'
    return profile_from_content(content), None


def profile_from_content(content: dict) -> Profile:
    teams = content.get('TeamIdentifier')
    expiration = content.get('ExpirationDate')
    devices = content.get('ProvisionedDevices')
    certificates = content.get('DeveloperCertificates')
    digests = frozenset(hashlib.sha256(item).hexdigest() for item in certificates
                        if isinstance(item, bytes)) if isinstance(certificates, list) else frozenset()
    return Profile(team_ids=[team for team in teams if isinstance(team, str)] if isinstance(teams, list) else [],
                   entitlements=content['Entitlements'],
                   expiration=expiration if isinstance(expiration, datetime.datetime) else None,
                   kind=profile_kind(content), device_count=len(devices) if isinstance(devices, list) else 0,
                   certificate_digests=digests)


def profile_kind(content: dict) -> str:
    """Development profiles list devices; Developer ID profiles provision all devices."""
    if isinstance(content.get('ProvisionedDevices'), list):
        return 'development'
    if content.get('ProvisionsAllDevices') is True:
        return 'developer-id'
    return 'app-store-or-unknown'


def read_plist(path: Path) -> Tuple[Optional[dict], Optional[str]]:
    try:
        with path.open('rb') as handle:
            value = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        return None, f'{path.name} unreadable: {brief(str(error))}'
    return (value, None) if isinstance(value, dict) else (None, f'{path.name} is not a dictionary')


# --- Component checks ------------------------------------------------------------------------

@dataclass
class Options:
    app: Path
    supervisor: Path
    expect_team: str
    distribution: Optional[str]
    runner: Runner
    now: datetime.datetime


def check_signature(report: Report, info: CodeInfo, expected_identifier: Optional[str], team: str) -> None:
    label = info.label
    report.result(f'{label}.signature', info.display_error is None and info.verify_error is None,
                  signature_reason(info))
    report.result(f'{label}.requirement', info.requirement is not None and info.requirement_error is None,
                  requirement_reason(info))
    problems = blob_problems(info)
    report.result(f'{label}.signature-blob', not problems,
                  '; '.join(problems) if problems else 'signature blob of every slice agrees with codesign output')
    report.result(f'{label}.not-adhoc', not info.is_adhoc, adhoc_reason(info))
    report.result(f'{label}.team', info.team == team, f'signature team {info.team or "not set"}, expected {team}')
    report.result(f'{label}.hardened-runtime', bool((info.flags or 0) & CS_RUNTIME), flags_reason(info))
    check_no_get_task_allow(report, info)
    check_identifier(report, info, expected_identifier)
    bound = 'Info.plist entries' in info.fields
    report.result(f'{label}.info-plist-bound', bound, 'Info.plist sealed by the signature' if bound
                  else f'Info.plist={info.fields.get("Info.plist", "absent")}')


def signature_reason(info: CodeInfo) -> str:
    command = 'codesign --verify --strict' + (' --deep' if info.deep else '')
    if info.display_error is not None:
        return f'not signed or unreadable: {info.display_error}'
    return f'{command} failed: {info.verify_error}' if info.verify_error else f'{command} ok'


def requirement_reason(info: CodeInfo) -> str:
    if info.requirement is None:
        return info.requirement_error or 'no requirement'
    verdict = 'satisfied' if info.requirement_error is None else f'NOT satisfied ({info.requirement_error})'
    return f'{verdict}: {info.requirement}'


def blob_problems(info: CodeInfo) -> List[str]:
    """codesign text must describe the same signature the Mach-O actually carries."""
    if info.facts is None:
        return [f'signature blob unreadable: {info.facts_error}']
    if info.display_error is not None:
        return [f'codesign display unusable: {info.display_error}']
    comparisons = (('identifier', info.fields.get('Identifier'), info.facts.identifier),
                   ('team', text_team(info.fields), info.facts.team),
                   ('flags', text_flags(info.fields), info.facts.flags),
                   ('executable', info.fields.get('Executable'), str(info.executable)),
                   ('entitlements', info.codesign_entitlements, info.facts.entitlements))
    problems = [f'codesign {name} differs from the signature blob' for name, text, blob in comparisons if text != blob]
    if info.codesign_entitlements is None:
        problems.append(f'codesign entitlements unreadable: {info.entitlements_error}')
    return problems


def adhoc_reason(info: CodeInfo) -> str:
    if info.facts is None:
        return f'no signature blob: {info.facts_error}'
    if info.is_adhoc:
        return f'ad-hoc signature (flags={flags_text(info)}): unsigned build, no signing certificate'
    return f'signed by a certificate ({certificate_kind(info)})'


def flags_reason(info: CodeInfo) -> str:
    state = 'set' if (info.flags or 0) & CS_RUNTIME else 'missing'
    return f'hardened runtime (0x10000) {state}; flags={flags_text(info)}'


def flags_text(info: CodeInfo) -> str:
    return 'unknown' if info.flags is None else hex(info.flags)


def check_no_get_task_allow(report: Report, info: CodeInfo) -> None:
    name = f'{info.label}.no-get-task-allow'
    if info.entitlements is None or info.codesign_entitlements is None:
        report.result(name, False, f'entitlements unreadable: {info.facts_error or info.entitlements_error}')
        return
    present = GET_TASK_ALLOW in info.entitlements or GET_TASK_ALLOW in info.codesign_entitlements
    report.result(name, not present, f'{GET_TASK_ALLOW} {"present" if present else "absent"}')


def check_identifier(report: Report, info: CodeInfo, expected: Optional[str]) -> None:
    reason = f'signing identifier {expectation(info.identifier, expected)}'
    if info.label == 'supervisor' and not matches(info.identifier, expected):
        reason += f' ({SUPERVISOR_IDENTIFIER_NOTE})'
    report.result(f'{info.label}.identifier', matches(info.identifier, expected), reason)


def certificate_kind(info: CodeInfo) -> str:
    leaf = info.authorities[0] if info.authorities else ''
    return next((kind for prefix, kind in CERTIFICATE_KINDS if leaf.startswith(prefix)),
                'unknown' if leaf else 'none')


def check_distribution_signing(report: Report, info: CodeInfo, distribution: Optional[str]) -> None:
    name, kind = f'{info.label}.certificate-kind', certificate_kind(info)
    if distribution is None:
        report.skip(name, f'detected {kind}; pass --distribution to enforce', required=False)
    else:
        report.result(name, kind == distribution, f'leaf certificate kind {kind}, expected {distribution}')
    stamp_name = f'{info.label}.secure-timestamp'
    if distribution != 'developer-id':
        report.skip(stamp_name, 'required only for --distribution developer-id', required=False)
    else:
        report.result(stamp_name, 'Timestamp' in info.fields,
                      'secure timestamp present' if 'Timestamp' in info.fields else 'no secure timestamp')


def check_teams(report: Report, infos: List[CodeInfo], expect_team: str) -> None:
    teams = {info.label: info.team for info in infos}
    values = set(teams.values())
    report.result('team.consistent', len(values) == 1 and None not in values,
                  ', '.join(f'{label}={team or "not set"}' for label, team in teams.items()))
    report.result('team.expected', values == {expect_team},
                  f'teams {sorted(team or "not set" for team in values)}, expected {expect_team}')


def check_signed_entitlement(report: Report, info: CodeInfo, name: str, key: str, expected: object) -> None:
    if info.entitlements is None:
        report.result(name, False, f'entitlements unreadable: {info.facts_error}')
        return
    value = info.entitlements.get(key)
    shown = brief(value) if key in info.entitlements else 'absent'
    report.result(name, expected is not None and type(value) is type(expected) and value == expected,
                  f'{key}={shown}, expected {brief(expected)}')


def check_supervisor_entitlements(report: Report, info: CodeInfo) -> None:
    """The tool cannot embed a provisioning profile, so it must not claim any entitlement."""
    if info.entitlements is None:
        report.result('supervisor.entitlements', False, f'entitlements unreadable: {info.facts_error}')
        return
    keys = sorted(info.entitlements)
    report.result('supervisor.entitlements', not keys,
                  'no entitlements' if not keys else f'unexpected entitlements: {", ".join(keys)}')


# --- Profile checks --------------------------------------------------------------------------

PROFILE_CHECKS = ('decodes', 'team', 'certificate', 'app-id', 'team-identifier', 'grants-required',
                  'entitlements', 'not-expired', 'type')


def check_profile(report: Report, info: CodeInfo, required_key: str, expected_id: Optional[str],
                  options: Options) -> None:
    path = info.path / 'Contents' / 'embedded.provisionprofile'
    prefix, team = f'{info.label}.profile', options.expect_team
    report.result(f'{prefix}.present', path.is_file(),
                  f'{"found" if path.is_file() else "missing"}: Contents/embedded.provisionprofile')
    profile, error = load_profile(path, options.runner) if path.is_file() else (None, 'no profile')
    if profile is None:
        for suffix in PROFILE_CHECKS:
            report.skip(f'{prefix}.{suffix}', f'profile unavailable: {error}')
        return
    report.result(f'{prefix}.decodes', True, f'decoded; {profile.device_count} provisioned device(s)')
    report.result(f'{prefix}.team', team in profile.team_ids, f'profile teams {profile.team_ids}, expected {team}')
    check_profile_certificate(report, prefix, info, profile, options.runner)
    check_profile_value(report, f'{prefix}.app-id', profile, APPLICATION_IDENTIFIER,
                        None if expected_id is None else f'{team}.{expected_id}')
    check_profile_value(report, f'{prefix}.team-identifier', profile, TEAM_ENTITLEMENT, team)
    check_profile_value(report, f'{prefix}.grants-required', profile, required_key, True)
    check_entitlement_coverage(report, prefix, info, profile)
    check_profile_dates_and_type(report, prefix, profile, options)


def check_profile_certificate(report: Report, prefix: str, info: CodeInfo, profile: Profile, runner: Runner) -> None:
    """Only membership is reported; digests and certificate contents stay private."""
    digest, error = leaf_certificate_digest(info.path, runner)
    if digest is None:
        report.result(f'{prefix}.certificate', False, error or 'no signing certificate')
        return
    listed = digest in profile.certificate_digests
    report.result(f'{prefix}.certificate', listed,
                  f'signing certificate {"is" if listed else "is NOT"} one of the profile\'s '
                  f'{len(profile.certificate_digests)} developer certificate(s)')


def check_profile_value(report: Report, name: str, profile: Profile, key: str, expected: object) -> None:
    """Exact value; restricted capabilities need an explicit App ID, so wildcards do not pass."""
    actual = profile.entitlements.get(key)
    report.result(name, expected is not None and type(actual) is type(expected) and actual == expected,
                  f'profile {key}={brief(actual)}, expected {brief(expected)}')


def check_entitlement_coverage(report: Report, prefix: str, info: CodeInfo, profile: Profile) -> None:
    name = f'{prefix}.entitlements'
    if info.entitlements is None:
        report.result(name, False, f'signed entitlements unreadable: {info.facts_error}')
        return
    problems = [coverage_problem(key, value, profile.entitlements) for key, value in sorted(info.entitlements.items())]
    problems = [problem for problem in problems if problem]
    report.result(name, not problems, '; '.join(problems) if problems else
                  f'all {len(info.entitlements)} signed entitlement(s) granted: {", ".join(sorted(info.entitlements))}')


def coverage_problem(key: str, value: object, granted: dict) -> Optional[str]:
    if key not in granted:
        return f'{key} not granted by profile'
    if not value_granted(value, granted[key]):
        return f'{key} signed {brief(value)} but profile grants {brief(granted[key])}'
    return None


def value_granted(signed: object, granted: object) -> bool:
    """Profiles may grant a list or a trailing-* wildcard; each signed value must fall inside it."""
    if isinstance(granted, list):
        items = signed if isinstance(signed, list) else [signed]
        return all(any(value_granted(item, option) for option in granted) for item in items)
    if isinstance(granted, str) and isinstance(signed, str):
        return signed == granted or (granted.endswith('*') and signed.startswith(granted[:-1]))
    return type(signed) is type(granted) and signed == granted


def check_profile_dates_and_type(report: Report, prefix: str, profile: Profile, options: Options) -> None:
    expiration = profile.expiration
    report.result(f'{prefix}.not-expired', expiration is not None and expiration > options.now,
                  f'expires {expiration.isoformat() if expiration else "never stated"} (UTC)')
    detail = f'profile type {profile.kind}, {profile.device_count} provisioned device(s)'
    if options.distribution is None:
        report.skip(f'{prefix}.type', f'{detail}; pass --distribution to enforce', required=False)
    else:
        report.result(f'{prefix}.type', profile.kind == options.distribution, f'{detail}, expected {options.distribution}')


# --- Nested code -----------------------------------------------------------------------------

def check_nested_code(report: Report, label: str, bundle: Path, excluded: List[Path], options: Options) -> None:
    """Every other Mach-O in the bundle must be team-signed and non-debuggable.

    Hardened runtime is a property of the process, taken from its main executable, so it is
    required of nested executables but not of libraries (real Developer ID apps ship
    frameworks without the flag).
    """
    files, problems = nested_code_files(bundle, excluded)
    for path in files[:MAX_NESTED_CODE]:
        problems.extend(nested_code_problems(path, bundle, options.expect_team, options.runner))
    if len(files) > MAX_NESTED_CODE:
        problems.append(f'more than {MAX_NESTED_CODE} nested Mach-O files; not all checked')
    listed = '; '.join(problems[:MAX_LISTED_PROBLEMS]) + (' ...' if len(problems) > MAX_LISTED_PROBLEMS else '')
    report.result(f'{label}.nested-code', not problems,
                  f'{len(problems)} problem(s) in {len(files)} nested Mach-O file(s): {listed}' if problems
                  else f'{len(files)} nested Mach-O file(s) team-signed; executables hardened; no get-task-allow')


def nested_code_files(bundle: Path, excluded: List[Path]) -> Tuple[List[Path], List[str]]:
    found: List[Path] = []
    problems: List[str] = []
    for directory, subdirectories, files in os.walk(bundle / 'Contents', onerror=lambda error: problems.append(
            f'unreadable directory: {brief(str(error))}')):
        here = Path(directory)
        subdirectories[:] = sorted(name for name in subdirectories if here / name not in excluded)
        for name in sorted(files):
            path = here / name
            if path in excluded or path.is_symlink():
                continue
            try:
                if is_macho_file(path):
                    found.append(path)
            except OSError as error:
                problems.append(f'{relative_name(path, bundle)}: unreadable ({error.__class__.__name__})')
    return found, problems


def relative_name(path: Path, bundle: Path) -> str:
    return repr(str(path.relative_to(bundle)))


def nested_code_problems(path: Path, bundle: Path, team: str, runner: Runner) -> List[str]:
    name = relative_name(path, bundle)
    if has_control_characters(str(path)):
        return [f'{name}: control characters in path']
    problems = []
    if evaluate_requirement(path, team_requirement(team), False, runner) is not None:
        problems.append(f'{name}: does not satisfy the team requirement')
    facts, error = signature_facts_or_error(path)
    if facts is None:
        return problems + [f'{name}: {error}']
    checks = ((bool(facts.flags & CS_ADHOC), 'ad-hoc signature'), (facts.team != team, f'team {facts.team or "not set"}'),
              (facts.is_executable and not facts.flags & CS_RUNTIME, 'executable without hardened runtime'),
              (GET_TASK_ALLOW in facts.entitlements, 'get-task-allow'))
    return problems + [f'{name}: {message}' for failed, message in checks if failed]


# --- Bundle layout and trust roots -----------------------------------------------------------

def find_sysext(report: Report, app: Path) -> Optional[Path]:
    directory = app.joinpath(*SYSEXT_DIRECTORY)
    found = sorted(directory.glob('*.systemextension')) if directory.is_dir() else []
    hostile = [path.name for path in found if has_control_characters(path.name)]
    report.result('sysext.present', len(found) == 1 and not hostile,
                  f'control characters in bundle name {hostile[0]!r}' if hostile else
                  f'{len(found)} system extension bundle(s) in {"/".join(SYSEXT_DIRECTORY)}')
    return found[0] if len(found) == 1 and not hostile else None


def resolve_executable(report: Report, label: str, bundle: Path, plist: Optional[dict]) -> Optional[Path]:
    """CFBundleExecutable must be a plain file name: codesign echoes it into the text it prints."""
    name = plist.get('CFBundleExecutable') if plist else None
    path = bundle / 'Contents' / 'MacOS' / name if isinstance(name, str) and name else None
    problem = executable_problem(name, path)
    report.result(f'{label}.executable', problem is None, problem or f'Contents/MacOS/{name} is a Mach-O file')
    return path if problem is None else None


def executable_problem(name: object, path: Optional[Path]) -> Optional[str]:
    if path is None or not isinstance(name, str):
        return f'CFBundleExecutable {name!r} missing'
    if has_control_characters(name) or '/' in name or name in ('.', '..'):
        return f'CFBundleExecutable {name!r} contains control characters or path separators'
    try:
        return None if path.is_file() and not path.is_symlink() and is_macho_file(path) \
            else f'Contents/MacOS/{name} is not a regular Mach-O file'
    except OSError as error:
        return f'Contents/MacOS/{name} unreadable ({error.__class__.__name__})'


def check_bundle_ids(report: Report, app_plist: dict, sysext: Path, sysext_plist: dict) -> Optional[str]:
    app_id = app_plist.get('CFBundleIdentifier')
    valid = isinstance(app_id, str) and bool(IDENTIFIER_PATTERN.match(app_id)) and not is_placeholder(app_id)
    report.result('app.bundle-id', valid, f'CFBundleIdentifier {expectation(app_id, None)}'
                  if not valid else f'CFBundleIdentifier {app_id!r}')
    app_id = app_id if valid else None
    sysext_id = sysext_plist.get('CFBundleIdentifier')
    report.result('sysext.bundle-id', matches(sysext_id, child(app_id, SYSEXT_SUFFIX)),
                  f'CFBundleIdentifier {expectation(sysext_id, child(app_id, SYSEXT_SUFFIX))}')
    expected_name = f'{sysext_id}.systemextension'
    report.result('sysext.bundle-name', sysext.name == expected_name,
                  f'bundle file name {sysext.name!r}, expected {expected_name!r}')
    return app_id


def check_sysext_plist(report: Report, sysext_plist: dict, team: str, app_id: Optional[str]) -> None:
    service = sysext_plist.get('NSEndpointSecurityMachServiceName')
    prefix = f'{team}.'
    placeholder = ' (placeholder or empty)' if is_placeholder(service) else ''
    report.result('sysext.mach-service', not is_placeholder(service) and str(service).startswith(prefix),
                  f'NSEndpointSecurityMachServiceName {service!r} must start with {prefix!r}{placeholder}')
    expectations = {'AGBTeamIdentifier': team, 'AGBApproverSigningIdentifier': app_id,
                    'AGBSupervisorSigningIdentifier': child(app_id, SUPERVISOR_SUFFIX)}
    check_plist_values(report, 'sysext.plist', sysext_plist, expectations)


def check_plist_values(report: Report, prefix: str, plist: dict, expectations: Dict[str, Optional[str]]) -> None:
    for key, expected in expectations.items():
        actual = plist.get(key)
        report.result(f'{prefix}.{key}', matches(actual, expected), expectation(actual, expected))


def check_supervisor_plist(report: Report, supervisor: Path, sysext_plist: dict, team: str,
                           app_id: Optional[str]) -> None:
    try:
        plist = plistlib.loads(read_info_plist_section(supervisor))
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        report.result('supervisor.info-plist-section', False, f'__TEXT,__info_plist unreadable: {brief(str(error))}')
        return
    if not isinstance(plist, dict):
        report.result('supervisor.info-plist-section', False, '__TEXT,__info_plist is not a dictionary')
        return
    report.result('supervisor.info-plist-section', True, f'__TEXT,__info_plist parsed ({len(plist)} keys)')
    service = sysext_plist.get('NSEndpointSecurityMachServiceName')
    expectations = {'CFBundleIdentifier': child(app_id, SUPERVISOR_SUFFIX),
                    'AGBMachServiceName': service if isinstance(service, str) else None,
                    'AGBFileGuardSigningIdentifier': child(app_id, SYSEXT_SUFFIX), 'AGBTeamIdentifier': team}
    check_plist_values(report, 'supervisor.plist', plist, expectations)


# --- Orchestration ---------------------------------------------------------------------------

@dataclass
class Layout:
    app_id: Optional[str]
    sysext: Optional[Path]
    sysext_plist: dict
    app_executable: Optional[Path]
    sysext_executable: Optional[Path]


def verify(options: Options) -> Report:
    report = Report()
    layout = check_layout(report, options)
    infos = collect_components(options, layout)
    expected = {'app': layout.app_id, 'sysext': child(layout.app_id, SYSEXT_SUFFIX),
                'supervisor': child(layout.app_id, SUPERVISOR_SUFFIX)}
    for info in infos:
        check_signature(report, info, expected[info.label], options.expect_team)
        check_distribution_signing(report, info, options.distribution)
    if layout.sysext is None:
        report.skip('sysext.signature', 'no system extension bundle to check')
    check_teams(report, infos, options.expect_team)
    verify_entitlements_and_profiles(report, options, infos, expected)
    check_nested(report, options, layout)
    if layout.sysext is not None:
        check_sysext_plist(report, layout.sysext_plist, options.expect_team, layout.app_id)
    check_supervisor_plist(report, options.supervisor, layout.sysext_plist, options.expect_team, layout.app_id)
    return report


def check_layout(report: Report, options: Options) -> Layout:
    app_plist, error = read_plist(options.app / 'Contents' / 'Info.plist')
    report.result('app.info-plist', app_plist is not None, error or 'Contents/Info.plist read')
    sysext = find_sysext(report, options.app)
    sysext_plist, sysext_error = read_plist(sysext / 'Contents' / 'Info.plist') if sysext else (None, 'no bundle')
    if sysext is not None:
        report.result('sysext.info-plist', sysext_plist is not None, sysext_error or 'Contents/Info.plist read')
    app_id = check_bundle_ids(report, app_plist, sysext, sysext_plist) if app_plist and sysext_plist else None
    app_executable = resolve_executable(report, 'app', options.app, app_plist)
    sysext_executable = resolve_executable(report, 'sysext', sysext, sysext_plist) if sysext else None
    return Layout(app_id, sysext, sysext_plist or {}, app_executable, sysext_executable)


def collect_components(options: Options, layout: Layout) -> List[CodeInfo]:
    team, distribution, runner = options.expect_team, options.distribution, options.runner
    targets = [('app', options.app, layout.app_executable, True, layout.app_id)]
    if layout.sysext is not None:
        targets.append(('sysext', layout.sysext, layout.sysext_executable, True, child(layout.app_id, SYSEXT_SUFFIX)))
    targets.append(('supervisor', options.supervisor, options.supervisor, False, child(layout.app_id, SUPERVISOR_SUFFIX)))
    return [collect_code_info(label, path, executable, deep, code_requirement(identifier, team, distribution), runner)
            for label, path, executable, deep, identifier in targets]


def verify_entitlements_and_profiles(report: Report, options: Options, infos: List[CodeInfo],
                                     expected: Dict[str, Optional[str]]) -> None:
    capabilities = {'app': (SYSEXT_INSTALL, 'system-extension-install'), 'sysext': (ES_CLIENT, 'endpoint-security-client')}
    team = options.expect_team
    for info in infos:
        if info.label == 'supervisor':
            check_supervisor_entitlements(report, info)
            continue
        key, short_name = capabilities[info.label]
        identifier = expected[info.label]
        check_signed_entitlement(report, info, f'{info.label}.entitlement.{short_name}', key, True)
        check_signed_entitlement(report, info, f'{info.label}.entitlement.application-identifier',
                                 APPLICATION_IDENTIFIER, None if identifier is None else f'{team}.{identifier}')
        check_signed_entitlement(report, info, f'{info.label}.entitlement.team-identifier', TEAM_ENTITLEMENT, team)
        check_profile(report, info, key, identifier, options)


def check_nested(report: Report, options: Options, layout: Layout) -> None:
    sysext_root = options.app.joinpath(*SYSEXT_DIRECTORY)
    app_excluded = [path for path in (layout.app_executable, sysext_root) if path is not None]
    check_nested_code(report, 'app', options.app, app_excluded, options)
    if layout.sysext is not None:
        excluded = [layout.sysext_executable] if layout.sysext_executable else []
        check_nested_code(report, 'sysext', layout.sysext, excluded, options)


# --- Command line ------------------------------------------------------------------------------

def parse_arguments(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Read-only verification of a signed agentbelt Guard build.')
    parser.add_argument('--app', required=True, type=Path, help='path to AgentbeltGuard.app')
    parser.add_argument('--supervisor', required=True, type=Path, help='path to agentbelt-supervisor')
    parser.add_argument('--expect-team', required=True, help='Team ID every component must be signed by')
    parser.add_argument('--distribution', choices=DISTRIBUTIONS, help='required signing and profile type')
    parser.add_argument('--json', action='store_true', help='print a JSON report')
    arguments = parser.parse_args(argv)
    if not TEAM_PATTERN.match(arguments.expect_team):
        parser.error('--expect-team must be 10 uppercase letters or digits')
    for option, path in (('--app', arguments.app), ('--supervisor', arguments.supervisor)):
        if has_control_characters(str(path)):
            parser.error(f'{option} path contains control characters')
    if not (arguments.app.is_dir() and arguments.app.suffix == '.app'):
        parser.error(f'--app is not an .app bundle: {arguments.app}')
    if not arguments.supervisor.is_file():
        parser.error(f'--supervisor is not a file: {arguments.supervisor}')
    return arguments


def render_text(report: Report, options: Options) -> str:
    lines = ['agentbelt Guard signed-build verification', f'  app:        {options.app}',
             f'  supervisor: {options.supervisor}', f'  team:       {options.expect_team}', '']
    for check in report.checks:
        optional = '' if check.required else ' (optional)'
        lines.append(f'{check.status}  {check.name}{optional}: {check.reason}')
    unmet = sum(not check.satisfied for check in report.checks)
    lines.append('')
    lines.append('RESULT: PASS' if report.ok else f'RESULT: FAIL ({unmet} required check(s) not passed)')
    return '\n'.join(lines)


def render_json(report: Report, options: Options) -> str:
    document = {'ok': report.ok, 'app': str(options.app), 'supervisor': str(options.supervisor),
                'expect_team': options.expect_team,
                'checks': [{'name': check.name, 'status': check.status, 'required': check.required,
                            'reason': check.reason} for check in report.checks]}
    return json.dumps(document, indent=2)


def main(argv: Optional[List[str]] = None, runner: Runner = run_command,
         now: Optional[datetime.datetime] = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    # plistlib returns naive UTC datetimes for profile dates, so compare against naive UTC.
    options = Options(arguments.app.resolve(), arguments.supervisor.resolve(), arguments.expect_team,
                      arguments.distribution, runner, now or datetime.datetime.utcnow())
    report = verify(options)
    print(render_json(report, options) if arguments.json else render_text(report, options))
    return 0 if report.ok else 1


if __name__ == '__main__':
    sys.exit(main())
