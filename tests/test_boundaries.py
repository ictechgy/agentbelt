"""Use only synthetic data; never read actual user credentials."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import socket

ROOT = Path(__file__).resolve().parents[1]
PYTHON = '/usr/bin/python3'


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='agentbelt-test-', dir=Path.home())
        cls.base = Path(cls.temp.name)
        cls.work = cls.base / 'work'
        cls.work.mkdir()
        cls.outside = cls.base / 'private-marker.txt'
        cls.outside.write_text('SYNTHETIC_PRIVATE_MARKER')
        (cls.work / '.env').write_text('SYNTHETIC_SECRET=not-a-real-key')
        (cls.work / 'source.txt').write_text('public source')
        (cls.work / 'escape-link').symlink_to(cls.outside)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_guard(self, *command, extra_env=None):
        env = dict(os.environ)
        env.update(extra_env or {})
        return subprocess.run(
            [PYTHON, str(ROOT / 'agentbelt.py'), 'exec', str(self.work), '--', *command],
            env=env, capture_output=True, text=True, timeout=30,
        )

    @unittest.skipUnless(Path('/Library/Apple/usr/libexec/oah/libRosettaRuntime').exists(), 'Rosetta is not installed')
    def test_translated_shell_starts_without_escaping_file_boundary(self):
        result = self.run_guard('/usr/bin/arch', '-x86_64', '/bin/bash', '-c',
                                'if cat "$1"; then exit 9; fi; printf TRANSLATED_OK', 'bash', str(self.outside))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'TRANSLATED_OK')
        self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', result.stdout)

    def test_source_remains_readable(self):
        result = self.run_guard('/bin/cat', 'source.txt')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'public source')

    def test_private_file_is_denied(self):
        result = self.run_guard('/bin/cat', str(self.outside))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', result.stdout)

    def test_project_env_is_denied(self):
        result = self.run_guard('/bin/cat', '.env')
        self.assertNotEqual(result.returncode, 0)

    def test_symlink_does_not_escape(self):
        result = self.run_guard('/bin/cat', 'escape-link')
        self.assertNotEqual(result.returncode, 0)

    def test_parent_secret_environment_is_not_inherited(self):
        result = self.run_guard('/usr/bin/printenv', 'AGENTBELT_SYNTHETIC_SECRET',
                                extra_env={'AGENTBELT_SYNTHETIC_SECRET': 'synthetic-only'})
        self.assertNotEqual(result.returncode, 0)

    def test_writes_outside_workspace_are_denied(self):
        result = self.run_guard('/bin/sh', '-c', 'echo modified > "$1"', 'sh', str(self.outside))
        self.assertNotEqual(result.returncode, 0)

    def test_workspace_writes_still_work(self):
        result = self.run_guard('/bin/sh', '-c', 'printf edited > allowed-output.txt')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / 'allowed-output.txt').read_text(), 'edited')

    def test_writable_home_root_cannot_be_replaced(self):
        result = self.run_guard('/bin/bash', '-c', 'mv "$HOME" "$PWD/stolen-home"')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / 'stolen-home').exists())

    def test_python_child_cannot_read_private_file(self):
        code = 'import pathlib,sys\ntry: pathlib.Path(sys.argv[1]).read_bytes()\nexcept PermissionError: sys.exit(42)\nsys.exit(0)'
        result = self.run_guard(PYTHON, '-I', '-c', code, str(self.outside))
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_secret_cannot_be_renamed_to_public_name(self):
        result = self.run_guard('/bin/mv', '.env', 'renamed-secret.txt')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.work / '.env').exists())

    def test_existing_hardlink_is_rejected_before_launch(self):
        link = self.work / 'hardlink-marker'
        os.link(self.outside, link)
        try:
            result = self.run_guard('/bin/cat', str(link))
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', result.stdout)
        finally:
            link.unlink()

    def test_nested_sandbox_does_not_remove_restrictions(self):
        result = self.run_guard('/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)',
                                '/bin/cat', str(self.outside))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('SYNTHETIC_PRIVATE_MARKER', result.stdout)

    def test_node_arguments_are_not_evaluated_by_host_shell(self):
        injected = '$(touch ' + str(self.base / 'injection-marker') + ')'
        result = self.run_guard('/usr/bin/printf', '%s', injected)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, injected)
        self.assertFalse((self.base / 'injection-marker').exists())

    def test_direct_loopback_network_is_denied(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            port = server.getsockname()[1]
            # Positive control: the endpoint exists and the unconfined host can connect.
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                connection, _ = server.accept()
                connection.close()
            code = ('import socket,sys\ntry: socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=2)'
                    '\nexcept PermissionError: sys.exit(42)\nsys.exit(0)')
            result = self.run_guard(PYTHON, '-I', '-c', code, str(port))
            self.assertEqual(result.returncode, 42, result.stderr)

    def test_keychain_service_lookup_is_denied_without_reading_keys(self):
        code = '''import ctypes,sys
lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
port=ctypes.c_uint.in_dll(lib,'bootstrap_port')
out=ctypes.c_uint()
rc=lib.bootstrap_look_up(port,b'com.apple.SecurityServer',ctypes.byref(out))
sys.exit(42 if rc != 0 else 0)
'''
        result = self.run_guard(PYTHON, '-I', '-c', code)
        self.assertEqual(result.returncode, 42, result.stderr)


if __name__ == '__main__':
    unittest.main()
