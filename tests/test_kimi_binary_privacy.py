"""Synthetic planner and identity tests for the staged Kimi binary hardener."""
import hashlib
from pathlib import Path
import os
import shutil
import subprocess
from types import SimpleNamespace
import tempfile
import json
import unittest
from unittest.mock import patch

from adapters import kimi_privacy


def fixture_binary():
    def function(signature, body):
        return signature + b' {\n' + body + b'\n}\n'

    body = b'  ' + (b'ordinary(); ' * 80)

    parts = [b'header\0']
    parts.append(function(b'async function fetchSubmitFeedback(url, accessToken, body, opts = {})', body))
    parts.append(function(b'async function fetchCreateFeedbackUploadUrl(accessToken, body, opts = {})', body))
    parts.append(function(b'async function fetchCompleteFeedbackUpload(accessToken, body, opts = {})', body))
    parts.append(function(b'async function fetchClientConfig(name, schema, options = {})',
                          b'\tconst fetchFn = options.fetchImpl ?? fetch;\n'
                          b'\tconst headers = {};\n'
                          b'\ttry {\n'
                          b'\t\tconst response = await fetchFn(name, { headers });\n'
                          b'\t\tif (!response.ok) return;\n'
                          b'\t\tconst body = await response.json();\n'
                          b'\t\treturn body.config;\n'
                          b'\t} catch {\n'
                          b'\t\treturn;\n'
                          b'\t}\n' + (b'\tvoid 0;\n' * 30)))
    parts.append(function(b'async function uploadArchive(api, archive, feedbackId, options)', body))
    parts.append(function(b'function startServer(opts)',
                          b'  const exposureClass = classify(host, { bindClass: opts.bindClass });\n'
                          b'  if (exposureClass !== "loopback" && opts.insecureNoTls !== true) {\n'
                          b'    throw new Error(`Refusing to bind ${host} (${exposureClass}) without TLS; terminate TLS at a reverse proxy or pass --insecure-no-tls.`);\n'
                          b'  }'))
    return b''.join(parts)


class KimiBinaryPrivacyTests(unittest.TestCase):
    def test_actual_signed_copy_keeps_policy_without_preload(self):
        import agentbelt as g
        root = Path(__file__).resolve().parents[1]
        if not g.KIMI.is_file() or not (root / 'runtime/node_modules').is_dir():
            self.skipTest('requires installed Kimi and the pinned sandbox runtime')
        original_hash = g.file_sha256(g.KIMI)
        with tempfile.TemporaryDirectory(prefix='kp-', dir=Path.home()) as tmp:
            base = Path(tmp).resolve()
            guard = base / 'g'
            guard.mkdir(mode=0o700)
            (guard / 'runtime').symlink_to(root / 'runtime', target_is_directory=True)
            (guard / 'sandbox_runner.mjs').symlink_to(root / 'sandbox_runner.mjs')
            stage = guard / 'state/kimi-runtime/launch-proof'
            stage.mkdir(mode=0o700, parents=True)
            for directory in (guard / 'state', stage.parent):
                directory.chmod(0o700)
            binary = stage / 'kimi'
            shutil.copyfile(g.KIMI, binary)
            binary.chmod(0o500)
            kimi_privacy.harden_staged(binary)
            work = base / 'w'
            work.mkdir()
            def prepare(home, env):
                env.update({'KIMI_CODE_HOME': str(home / '.kimi-code'),
                            'KIMI_DISABLE_TELEMETRY': '1', 'KIMI_CODE_NO_AUTO_UPDATE': '1',
                            'KIMI_CLI_NO_AUTO_UPDATE': '1'})
                env.pop('NODE_OPTIONS', None)
                env.pop('AGENTBELT_KIMI_BINARY', None)
            for arguments in (['--version'], ['web', '--host', '--insecure-no-tls', '--no-open']):
                with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, patch.object(g, 'ROOT', guard):
                    status = g.run_confined('kimi-privacy-test', work, [str(binary), *arguments],
                                            domains=[], ephemeral=True, extra_reads=[binary], prepare_home=prepare,
                                            stdout=output, stderr=errors, timeout=25)
                    output.seek(0); errors.seek(0)
                    text = (output.read() + errors.read()).decode(errors='replace')
                if arguments == ['--version']:
                    self.assertEqual(status, 0)
                    self.assertIn('2.1.0', text)
                else:
                    self.assertNotEqual(status, 0)
                    self.assertIn('Refusing non-loopback Kimi server bind by local policy.', text)
            self.assertEqual(g.file_sha256(g.KIMI), original_hash)

    def test_patch_planner_rewrites_reviewed_regions_without_changing_length(self):
        source = fixture_binary()
        patched = kimi_privacy._patch_bytes(source)
        self.assertEqual(len(patched), len(source))
        self.assertNotEqual(patched, source)
        kimi_privacy._assert_patched(patched)
        self.assertEqual(patched.count(b'Diagnostic feedback is disabled by local policy.'), 4)
        self.assertIn(b'if (name === "client_banner") return;', patched)

    def test_patched_client_config_function_preserves_ordinary_fetch(self):
        patched = kimi_privacy._patch_bytes(fixture_binary())
        start, end = kimi_privacy._find_function_region(patched, b'async function fetchClientConfig')
        function_source = patched[start:end].decode()
        script = r'''
const calls = [];
const fake = async (name) => { calls.push(name); return { ok: true, json: async () => ({ config: "parsed" }) }; };
''' + function_source + r'''
(async () => {
  const ordinary = await fetchClientConfig("models", {}, { fetchImpl: fake });
  const banner = await fetchClientConfig("client_banner", {}, { fetchImpl: fake });
  process.stdout.write(JSON.stringify({ calls, ordinary, banner: banner === undefined ? null : banner }));
})().catch((error) => { process.stderr.write(String(error)); process.exitCode = 1; });
'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '{"calls":["models"],"ordinary":"parsed","banner":null}')

    def test_upload_archive_stub_keeps_void_or_throw_contract(self):
        patched = kimi_privacy._patch_bytes(fixture_binary())
        start, end = kimi_privacy._find_function_region(patched, b'async function uploadArchive')
        function_source = patched[start:end].decode()
        script = function_source + r'''
uploadArchive({}, {}, 1, {}).then(
  () => process.exitCode = 2,
  (error) => process.stdout.write(error.message)
);
'''
        result = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'Diagnostic feedback is disabled by local policy.')

    def test_planner_rejects_missing_or_duplicate_anchors(self):
        source = fixture_binary()
        missing = source.replace(b'async function uploadArchive', b'async function uploadArchive_removed', 1)
        with self.assertRaises(kimi_privacy.KimiPrivacyError):
            kimi_privacy._patch_bytes(missing)
        duplicate = source + b'async function fetchSubmitFeedback(url, accessToken, body, opts = {})'
        with self.assertRaises(kimi_privacy.KimiPrivacyError):
            kimi_privacy._patch_bytes(duplicate)

    def make_staged(self, data=None):
        root = Path(tempfile.mkdtemp(prefix='kimi-privacy-test-'))
        state = root / 'state'
        runtime = state / 'kimi-runtime' / 'launch-test'
        runtime.mkdir(parents=True)
        state.chmod(0o700)
        (state / 'kimi-runtime').chmod(0o700)
        runtime.chmod(0o700)
        binary = runtime / 'kimi'
        binary.write_bytes(fixture_binary() if data is None else data)
        binary.chmod(0o500)
        self.addCleanup(shutil.rmtree, root, True)
        return binary

    def test_harden_rejects_unreviewed_hash_before_signature_or_write(self):
        binary = self.make_staged()
        before = binary.read_bytes()
        with patch.object(kimi_privacy, '_codesign_verify') as verify:
            with self.assertRaises(kimi_privacy.KimiPrivacyError):
                kimi_privacy.harden_staged(binary)
        verify.assert_not_called()
        self.assertEqual(binary.read_bytes(), before)

    def test_harden_rejects_signature_failure_without_writing(self):
        source = fixture_binary()
        binary = self.make_staged(source)
        before = binary.read_bytes()
        with patch.object(kimi_privacy, 'EXPECTED_ORIGINAL_SHA256', hashlib.sha256(source).hexdigest()), \
                patch.object(kimi_privacy.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as run:
            with self.assertRaises(kimi_privacy.KimiPrivacyError):
                kimi_privacy.harden_staged(binary)
        run.assert_called_once()
        self.assertEqual(binary.read_bytes(), before)

    def test_harden_restores_bytes_when_ad_hoc_signing_fails(self):
        source = fixture_binary()
        binary = self.make_staged(source)
        before = binary.read_bytes()
        calls = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=1)]
        with patch.object(kimi_privacy, 'EXPECTED_ORIGINAL_SHA256', hashlib.sha256(source).hexdigest()), \
                patch.object(kimi_privacy.subprocess, 'run', side_effect=calls):
            with self.assertRaises(kimi_privacy.KimiPrivacyError):
                kimi_privacy.harden_staged(binary)
        self.assertEqual(binary.read_bytes(), before)

    def test_path_identity_rejects_symlink_hardlink_and_wrong_owner(self):
        source = fixture_binary()
        binary = self.make_staged(source)
        state = binary.parent.parent.parent
        outside = state / 'outside-kimi'
        outside.write_bytes(source)
        hardlink_launch = state / 'kimi-runtime' / 'launch-hardlink'
        hardlink_launch.mkdir()
        hardlink_launch.chmod(0o700)
        linked = hardlink_launch / 'kimi'
        os.link(outside, linked)
        with self.assertRaises(kimi_privacy.KimiPrivacyError):
            kimi_privacy._check_path(linked)

        symlink_launch = state / 'kimi-runtime' / 'launch-symlink'
        symlink_launch.mkdir()
        symlink_launch.chmod(0o700)
        symlink_root = symlink_launch / 'kimi'
        symlink_root.symlink_to(outside)
        with self.assertRaises(kimi_privacy.KimiPrivacyError):
            kimi_privacy._check_path(symlink_root)

        with patch.object(kimi_privacy.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaises(kimi_privacy.KimiPrivacyError):
                kimi_privacy._check_path(binary)

    def test_reviewed_original_sha_pin_is_current(self):
        import agentbelt
        candidate = agentbelt.KIMI
        if not candidate.is_file():
            self.skipTest('Kimi binary is not installed')
        self.assertEqual(hashlib.sha256(candidate.read_bytes()).hexdigest(), kimi_privacy.EXPECTED_ORIGINAL_SHA256)


if __name__ == '__main__':
    unittest.main()
