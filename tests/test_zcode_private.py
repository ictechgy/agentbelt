"""Pure, offline checks for the private ZCode bundle builder.

These tests inspect public extracted bytes and synthetic ASAR/manifest data.
They never copy, sign, install, or launch an application.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adapters import zcode_privacy as privacy  # noqa: E402

PUBLIC_PROOF_ROOT = Path(os.environ["AGENTBELT_ZCODE_PROOF_ROOT"]) if os.environ.get("AGENTBELT_ZCODE_PROOF_ROOT") else None
PUBLIC_HOST_SOURCE = (
    PUBLIC_PROOF_ROOT / "agent-updates-2026-09-23/zcode-source/out/host/index.js"
    if PUBLIC_PROOF_ROOT
    else Path("/missing-public-zcode-host")
)
PUBLIC_MAIN_SOURCE = (
    PUBLIC_PROOF_ROOT / "agent-updates-2026-09-23/zcode-source/out/main/index.js"
    if PUBLIC_PROOF_ROOT
    else Path("/missing-public-zcode-main")
)
PUBLIC_SCHEDULER_SOURCE = (
    PUBLIC_PROOF_ROOT / "agent-updates-2026-09-23/zcode-source/out/scheduler/index.js"
    if PUBLIC_PROOF_ROOT
    else Path("/missing-public-zcode-scheduler")
)
HAS_PUBLIC_SOURCE = (
    PUBLIC_HOST_SOURCE.is_file()
    and PUBLIC_MAIN_SOURCE.is_file()
    and PUBLIC_SCHEDULER_SOURCE.is_file()
)


def synthetic_asar(
    host: bytes = b"host",
    main: bytes = b"main",
    scheduler: bytes = b"scheduler",
) -> bytes:
    """Build the minimum valid ASAR shape needed by verify_asar_bytes."""

    def entry(payload: bytes, offset: int) -> dict:
        digest = hashlib.sha256(payload).hexdigest()
        return {
            "size": len(payload),
            "offset": str(offset),
            "integrity": {
                "algorithm": "SHA256",
                "hash": digest,
                "blockSize": 4096,
                "blocks": [digest],
            },
        }

    files = {
        "out": {
            "files": {
                "host": {"files": {"index.js": entry(host, 0)}},
                "main": {"files": {"index.js": entry(main, len(host))}},
                "scheduler": {
                    "files": {"index.js": entry(scheduler, len(host) + len(main))}
                },
            }
        }
    }
    header = json.dumps({"files": files}, separators=(",", ":")).encode()
    padding = b"\0" * 3
    data_start = 16 + len(header) + len(padding)
    prefix = b"".join(
        struct.pack("<I", value)
        for value in (4, data_start - 8, data_start - 12, len(header))
    )
    return prefix + header + padding + host + main + scheduler


class ZcodePrivatePureTests(unittest.TestCase):
    def test_public_api_paths_are_private_and_stable(self):
        root = Path("/synthetic/agentbelt")
        self.assertEqual(
            privacy.private_app(root),
            root / "state/zcode-private/ZCode.app",
        )
        self.assertEqual(
            privacy.manifest_path(root),
            root / "state/zcode-private/manifest.json",
        )

    @unittest.skipUnless(HAS_PUBLIC_SOURCE, "set AGENTBELT_ZCODE_PROOF_ROOT for public extracted bytes")
    def test_host_patch_matches_public_proof_without_mutating_source(self):
        source = PUBLIC_HOST_SOURCE.read_bytes()
        patched = privacy.patch_host_payload(source, require_reviewed=True)
        self.assertEqual(len(source), len(patched))
        self.assertEqual(
            hashlib.sha256(patched).hexdigest(), privacy.PATCHED_HOST_SHA256
        )
        self.assertNotEqual(source, patched)
        self.assertEqual(
            hashlib.sha256(source).hexdigest(), privacy.ORIGINAL_HOST_SHA256
        )

    @unittest.skipUnless(HAS_PUBLIC_SOURCE, "set AGENTBELT_ZCODE_PROOF_ROOT for public extracted bytes")
    def test_main_patch_is_length_preserving_and_binds_generation(self):
        source = PUBLIC_MAIN_SOURCE.read_bytes()
        root = Path("/synthetic/private root")
        generation = "0123456789abcdef0123456789abcdef"
        patched = privacy.patch_main_payload(source, root, generation)
        self.assertEqual(len(source), len(patched))
        self.assertIn(b'function Mn(){return !1', patched)
        self.assertIn(b'H={kind:"idle",enabled:!1}', patched)
        self.assertIn(generation.encode(), patched)
        self.assertIn(b'vr="ZCode Snapshot Blocked"', patched)
        self.assertIn(b"Hc=!1", patched)
        self.assertIn(b"ZCODE_AGENT_SERVER_COMMAND", patched)
        self.assertIn(b"zcode-private-backend", patched)
        self.assertNotIn(b'xb(w,{iconPath:qz});', patched)

    @staticmethod
    def _updater_gate_spy(payload, name, marker, invocation, bindings):
        def function(function_name, function_marker):
            start = payload.index(("function " + function_name + "(").encode())
            end = payload.index(("}s(" + function_name + ',"' + function_marker + '")').encode(), start)
            return payload[start : end + 1].decode("utf-8")

        script = """
const calls = [];
const g = {info(){}, warn(){}, error(){}};
const tr = {isPackaged:true};
function yi(){return false;}
const ve = {
  checkForUpdates(){ calls.push("check"); return Promise.resolve(); },
  downloadUpdate(){ calls.push("download"); return Promise.resolve(); }
};
const Ee = ve;
const w = g;
const s = (value) => value;
""" + bindings + "\n" + function("Mn", "canUseAutoUpdaterInCurrentRuntime") \
            + "\n" + function(name, marker) + "\nconst gate = Mn();\n" + invocation + "\n" + """
setTimeout(() => process.stdout.write(JSON.stringify({gate, calls})), 0);
"""
        result = subprocess.run(
            ["node", "-e", script], capture_output=True, text=True, timeout=10
        )
        if result.returncode:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @unittest.skipUnless(HAS_PUBLIC_SOURCE, "set AGENTBELT_ZCODE_PROOF_ROOT for public extracted bytes")
    def test_main_patch_existing_gate_blocks_every_updater_entry(self):
        source = PUBLIC_MAIN_SOURCE.read_bytes()
        patched = privacy.patch_main_payload(source, Path("/synthetic/root"), "a" * 32)
        self.assertEqual(patched.count(b"Ee.checkForUpdates()"), 5)
        self.assertEqual(patched.count(b"Ee.downloadUpdate(t)"), 1)
        self.assertIn(b"function Mn(){return !1", patched)
        cases = (
            (
                "Ny", "checkForUpdateMenuClick",
                'Ny({isDestroyed(){return false;},webContents:{id:7,send(){}}});',
                """
const xn = {getFocusedWindow(){return null;}, getAllWindows(){return [];}};
const k = {UpdateCheckResult:"update"}; const H = {kind:"idle"};
let Gd = false, rr = false, fi = null, ct = null, Y = null;
function Cy(){return "stable";} function we(){} function bi(){return 1;}
async function XM(){} function _r(){} function vi(){} const wi = {};
""",
                ["check"],
            ),
            (
                "By", "requestForceAutoUpdate", "By(() => {});",
                """
const H = {kind:"idle"}; let it = null, qd = null, rr = false, Y = null;
function bi(){return 1;} function we(){} function vi(){} function Pt(){return H;}
""",
                ["check"],
            ),
            (
                "Xd", "refreshAutoUpdaterReleaseChannel", "Xd(true);",
                """
const H = {kind:"idle"}; let rr = false, gi = null, ne = "stable", Y = null;
function Cy(){return "stable";} function er(){} function we(){} function bi(){return 1;}
function vi(){} function Pt(){return H;}
""",
                ["check"],
            ),
            (
                "_n", "downloadAvailableUpdate", '_n("test");',
                """
const H = {kind:"update-available",version:"1",releaseNotes:null,channel:"stable"};
let at = null, ct = null, nr = null, It = null, Lt = null, ne = "stable";
function fo(){} class pM {dispose(){}} function ZM(){return false;} function An(){}
""",
                ["download"],
            ),
        )
        for name, marker, invocation, bindings, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    self._updater_gate_spy(source, name, marker, invocation, bindings),
                    {"gate": True, "calls": expected},
                )
                self.assertEqual(
                    self._updater_gate_spy(patched, name, marker, invocation, bindings),
                    {"gate": False, "calls": []},
                )

    @unittest.skipUnless(HAS_PUBLIC_SOURCE, "set AGENTBELT_ZCODE_PROOF_ROOT for public extracted bytes")
    def test_scheduler_patch_matches_public_proof_without_mutating_source(self):
        source = PUBLIC_SCHEDULER_SOURCE.read_bytes()
        patched = privacy.patch_scheduler_payload(source, require_reviewed=True)
        self.assertEqual(len(source), len(patched))
        self.assertEqual(
            hashlib.sha256(patched).hexdigest(), privacy.PATCHED_SCHEDULER_SHA256
        )
        self.assertNotEqual(source, patched)
        self.assertEqual(
            hashlib.sha256(source).hexdigest(), privacy.ORIGINAL_SCHEDULER_SHA256
        )
        self.assertNotIn(b"this.client.uploadArtifact(", patched)
        self.assertNotIn(b"this.client.createPreparation(", patched)
        self.assertIn(b'throw new re("share_disabled"', patched)

    @staticmethod
    def _share_method(payload, opening, closing):
        start = payload.index(opening)
        end = payload.index(closing, start) + 1
        return payload[start:end].decode("utf-8")

    @unittest.skipUnless(HAS_PUBLIC_SOURCE, "set AGENTBELT_ZCODE_PROOF_ROOT for public extracted bytes")
    def test_share_patches_fail_closed_before_service_access(self):
        """Both private bundles reject publish before touching agent services."""

        cases = (
            (
                PUBLIC_HOST_SOURCE,
                privacy.patch_host_payload,
                b"async publishWithAgent(t,n,r){",
                b"}async publishInternal(",
                b"Le",
            ),
            (
                PUBLIC_SCHEDULER_SOURCE,
                privacy.patch_scheduler_payload,
                b"async publishWithAgent(n,o,i){",
                b"}async publishInternal(",
                b"re",
            ),
        )
        for source_path, patcher, opening, closing, error_name in cases:
            with self.subTest(source=source_path.parent.parent.name):
                source = source_path.read_bytes()
                patched = patcher(source, require_reviewed=True)
                self.assertEqual(patched.count(opening), 1)
                self.assertEqual(
                    patched.count(b'throw new ' + error_name + b'("share_disabled"'),
                    2,
                )
                self.assertNotIn(b"this.client.uploadArtifact(", patched)
                self.assertNotIn(b"this.client.createPreparation(", patched)
                publish = self._share_method(patched, opening, closing)
                internal = self._share_method(
                    patched,
                    b"async publishInternal(",
                    b"}getProgressEmitter(",
                )
                script = f"""
class Le extends Error {{ constructor(kind) {{ super(kind); this.kind = kind; }} }}
class re extends Error {{ constructor(kind) {{ super(kind); this.kind = kind; }} }}
class ShareService {{ {publish} {internal} }}
const accesses = [];
const service = new ShareService();
const agent = new Proxy({{}}, {{
  get(_target, property) {{
    accesses.push(String(property));
    throw new Error("service access: " + String(property));
  }}
}});
const results = [];
for (const method of ["publishWithAgent", "publishInternal"]) {{
  try {{
    await service[method](
      {{accessMode:"all", selection:{{kind:"all"}}}},
      "operation",
      agent,
    );
    results.push({{method, error:null}});
  }} catch (error) {{
    results.push({{method, error:error.kind || error.message}});
  }}
}}
console.log(JSON.stringify({{results, accesses}}));
"""
                result = subprocess.run(
                    ["node", "--input-type=module", "-e", script],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout),
                    {
                        "results": [
                            {"method": "publishWithAgent", "error": "share_disabled"},
                            {"method": "publishInternal", "error": "share_disabled"},
                        ],
                        "accesses": [],
                    },
                )

    def test_synthetic_asar_integrity_and_tamper_detection(self):
        archive = synthetic_asar()
        details = privacy.verify_asar_bytes(archive)
        self.assertEqual(
            set(details),
            {privacy.HOST_PATH, privacy.MAIN_PATH, privacy.SCHEDULER_PATH},
        )
        tampered = bytearray(archive)
        tampered[-1] ^= 1
        with self.assertRaises(privacy.ZcodePrivacyError):
            privacy.verify_asar_bytes(bytes(tampered))

    def test_malformed_asar_fails_closed(self):
        with self.assertRaises(privacy.ZcodePrivacyError):
            privacy.verify_asar_bytes(b"not an asar")
        archive = bytearray(synthetic_asar())
        archive[16] = ord("[")
        with self.assertRaises(privacy.ZcodePrivacyError):
            privacy.verify_asar_bytes(bytes(archive))

    def test_manifest_missing_fields_fails_before_any_app_operation(self):
        with tempfile.TemporaryDirectory(prefix="zcode-private-test-", dir=Path.home()) as raw:
            root = Path(raw)
            state = root / "state" / "zcode-private"
            state.mkdir(parents=True, mode=0o700)
            state.chmod(0o700)
            manifest = privacy.manifest_path(root)
            manifest.write_text("{}\n", encoding="utf-8")
            manifest.chmod(0o600)
            with self.assertRaises(privacy.ZcodePrivacyError):
                privacy.verify(root)

    def test_info_patch_preserves_electron_helper_name(self):
        with tempfile.TemporaryDirectory(prefix="zcode-info-test-", dir=Path.home()) as raw:
            info_path = Path(raw) / "Info.plist"
            info_path.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": privacy.ORIGINAL_BUNDLE_ID,
                        "CFBundleName": privacy.ORIGINAL_APP_NAME,
                        "CFBundleDisplayName": privacy.ORIGINAL_APP_NAME,
                        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["zcode"]}],
                        "ElectronAsarIntegrity": {
                            "Resources/app.asar": {"algorithm": "SHA256", "hash": "old"}
                        },
                    }
                )
            )
            privacy._patch_info(info_path, "a" * 64)
            info = plistlib.loads(info_path.read_bytes())
            self.assertEqual(info["CFBundleName"], privacy.ORIGINAL_APP_NAME)
            self.assertEqual(info["CFBundleDisplayName"], privacy.PRIVATE_APP_NAME)
            self.assertNotIn("CFBundleURLTypes", info)

    def test_bundle_digest_rejects_external_symlink(self):
        with tempfile.TemporaryDirectory(prefix="zcode-private-test-", dir=Path.home()) as raw:
            root = Path(raw) / "ZCode.app"
            root.mkdir(mode=0o700)
            outside = Path(raw) / "outside"
            outside.write_bytes(b"outside")
            (root / "escape").symlink_to(outside)
            with self.assertRaises(privacy.ZcodePrivacyError):
                privacy.bundle_digest(root)

    def test_source_bundle_allows_root_or_current_owner_but_rejects_foreign_owner(self):
        with tempfile.TemporaryDirectory(prefix="zcode-owner-test-", dir=Path.home()) as raw:
            app = Path(raw) / "ZCode.app"
            app.mkdir(mode=0o700)
            entry = app / "payload"
            entry.write_bytes(b"reviewed")
            original_lstat = Path.lstat

            def inspect_as(root_owner, entry_owner, source=True, digest=False):
                def synthetic_lstat(path):
                    info = original_lstat(path)
                    owner = root_owner if path == app else entry_owner if path == entry else info.st_uid
                    if path in (app, entry):
                        return SimpleNamespace(
                            st_mode=info.st_mode,
                            st_uid=owner,
                            st_nlink=info.st_nlink,
                            st_size=info.st_size,
                            st_dev=info.st_dev,
                            st_ino=info.st_ino,
                        )
                    return info

                with patch.object(Path, "lstat", synthetic_lstat):
                    if digest:
                        return privacy.bundle_digest(app, source=source)
                    return privacy._validate_bundle_tree(app, source=source)

            self.assertEqual(len(inspect_as(0, os.getuid(), digest=True)), 64)
            inspect_as(os.getuid(), 0)
            foreign = next(uid for uid in (1, 2, 12345) if uid not in (0, os.getuid()))
            with self.assertRaisesRegex(privacy.ZcodePrivacyError, "untrusted owner"):
                inspect_as(0, foreign)
            if os.getuid() != 0:
                with self.assertRaisesRegex(privacy.ZcodePrivacyError, "untrusted owner"):
                    inspect_as(os.getuid(), 0, source=False)

    @unittest.skipUnless(HAS_PUBLIC_SOURCE, "set AGENTBELT_ZCODE_PROOF_ROOT for public extracted bytes")
    def test_generation_must_be_explicitly_32_lowercase_hex(self):
        for generation in ("", "0" * 31, "0" * 33, "G" * 32):
            with self.assertRaises(privacy.ZcodePrivacyError):
                privacy.patch_main_payload(
                    PUBLIC_MAIN_SOURCE.read_bytes(),
                    Path("/synthetic/root"),
                    generation,
                )

    def test_install_publishes_staged_manifest_path_without_codesigning(self):
        """The transaction hashes the staged app before moving it into place."""

        with tempfile.TemporaryDirectory(prefix="zcode-private-install-", dir=Path.home()) as raw:
            root = Path(raw) / "guard"
            source = Path(raw) / "source" / "ZCode.app"
            source.parent.mkdir()
            source.mkdir()
            info = {
                "CFBundleIdentifier": privacy.ORIGINAL_BUNDLE_ID,
                "CFBundleShortVersionString": privacy.VERSION,
                "CFBundleVersion": privacy.BUILD,
            }
            source_info = dict(info)
            generation = "0123456789abcdef0123456789abcdef"
            details = {
                "host_sha256": "a" * 64,
                "main_sha256": "b" * 64,
                "scheduler_sha256": "e" * 64,
                "header_sha256": "c" * 64,
                "asar_sha256": "d" * 64,
            }

            def fake_clone(_source, parent):
                app = parent / "ZCode.app"
                (app / "Contents/MacOS").mkdir(parents=True)
                (app / "Contents/Resources/glm").mkdir(parents=True)
                (app / "Contents/Info.plist").write_bytes(b"synthetic-info")
                (app / "Contents/Resources/app.asar").write_bytes(b"synthetic-asar")
                (app / "Contents/Resources/glm/zcode.cjs").write_bytes(b"synthetic-cli")
                return app

            def fake_entitlements(_source, staging):
                path = staging / "entitlements.plist"
                path.write_bytes(b"synthetic-entitlements")
                return path

            def fake_verify(published_root, _generation=None):
                return json.loads(
                    privacy.manifest_path(published_root).read_text(encoding="utf-8")
                )

            with patch.object(
                privacy,
                "_verified_source_info",
                return_value=(source_info, privacy.ORIGINAL_ASAR_SHA256, privacy.ORIGINAL_CLI_SHA256, "sig", "tree"),
            ), patch.object(privacy, "_main_entitlements", side_effect=fake_entitlements), \
                    patch.object(privacy, "_copy_bundle", side_effect=fake_clone), \
                    patch.object(privacy, "_verify_signature"), \
                    patch.object(privacy, "_signature_fingerprint", return_value="sig"), \
                    patch.object(privacy, "_preserve_cua_signature"), \
                    patch.object(privacy, "_replace_asar_file", return_value=details), \
                    patch.object(privacy, "_patch_info"), \
                    patch.object(privacy, "_remove_quarantine"), \
                    patch.object(privacy, "_codesign_outer"), \
                    patch.object(privacy, "_sha256_file", return_value=privacy.ORIGINAL_CLI_SHA256), \
                    patch.object(privacy, "_read_asar", return_value=(b"synthetic-asar", {}, 0, 0)), \
                    patch.object(privacy, "verify_asar_bytes", return_value={}), \
                    patch.object(privacy, "_cua_team_id", return_value=privacy.CUA_TEAM_ID), \
                    patch.object(privacy, "verify", side_effect=fake_verify):
                manifest = privacy.install(root, source, generation=generation)

            destination = privacy.private_app(root)
            self.assertTrue(destination.is_dir())
            self.assertEqual(manifest["app_path"], str(destination))
            self.assertEqual(
                json.loads(privacy.manifest_path(root).read_text(encoding="utf-8"))["app_path"],
                str(destination),
            )


if __name__ == "__main__":
    unittest.main()
