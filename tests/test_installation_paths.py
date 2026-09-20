"""Synthetic installation-root and Safe launcher update coverage."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_installer():
    spec = importlib.util.spec_from_file_location('installation_paths_installer', ROOT / 'adapters/install_profiles.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load_installer()


class InstallationPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='install-paths-', dir=Path.home())
        base = Path(self.tmp.name)
        self.home = base / 'home with spaces'
        self.root = base / 'guard root with spaces'
        self.state = self.root / 'state'
        self.bin = self.home / 'bin with spaces'
        self.state.mkdir(parents=True)
        self.bin.mkdir(parents=True)
        (self.root / 'native').mkdir(parents=True)
        (self.root / 'native/ZcodeSafeLauncher').write_bytes(b'new native launcher')
        (self.root / 'native/SafeIcon.icns').write_bytes(b'icon')
        (self.root / 'config.json').write_text(json.dumps({'node': '/usr/bin/node', 'bin': str(self.bin)}))

    def tearDown(self):
        self.tmp.cleanup()

    def patched_installer(self):
        return patch.multiple(installer, HOME=self.home, ROOT=self.root, STATE=self.state,
                              _codesign_bundle=lambda app: None)

    def _fake_install_environment(self, base):
        tools = base / 'fake-tools'
        tools.mkdir()

        def write_tool(name, body):
            path = tools / name
            path.write_text('#!/bin/sh\n' + body)
            path.chmod(0o700)

        write_tool('node', 'if [ "$1" = "-p" ]; then echo 22; fi\n')
        write_tool('npm', 'exit 0\n')
        write_tool('rsync', 'exit 0\n')
        write_tool('codesign', 'exit 0\n')
        write_tool('swiftc', 'last=""; for arg in "$@"; do last="$arg"; done; : > "$last"\n')
        env = os.environ.copy()
        env.update({'HOME': str(base / 'home'), 'AGENTBELT_BIN': str(base / 'bin'),
                    'AGENTBELT_NODE': str(tools / 'node'),
                    'PATH': str(tools) + ':/usr/bin:/bin'})
        return env

    def _run_install_script(self, root, env):
        env = dict(env)
        env['AGENTBELT_ROOT'] = str(root)
        return subprocess.run([str(ROOT / 'install.sh')], cwd=str(ROOT), env=env,
                              capture_output=True, text=True, timeout=30)

    def test_install_rejects_relative_root_before_canonicalization(self):
        with tempfile.TemporaryDirectory(prefix='install-preflight-', dir=Path.home()) as raw:
            base = Path(raw)
            result = self._run_install_script('relative-agentbelt-root', self._fake_install_environment(base))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('AGENTBELT_ROOT must be an absolute path', result.stderr)

    def test_install_rejects_raw_leaf_symlinks_before_canonicalization(self):
        with tempfile.TemporaryDirectory(prefix='install-preflight-', dir=Path.home()) as raw:
            base = Path(raw)
            real_root = base / 'real root'
            real_root.mkdir()
            linked_root = base / 'root link'
            linked_root.symlink_to(real_root, target_is_directory=True)
            result = self._run_install_script(linked_root, self._fake_install_environment(base))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('refusing symlinked directory', result.stderr)
            self.assertFalse((real_root / 'agentbelt.py').exists())

    def test_failed_runtime_install_keeps_previous_path_metadata(self):
        with tempfile.TemporaryDirectory(prefix='install-failure-', dir=Path.home()) as raw:
            base = Path(raw)
            env = self._fake_install_environment(base)
            target = base / 'target'
            target.mkdir()
            before = json.dumps({'root': str(target), 'bin': str(base / 'old-bin')})
            (target / 'installation.json').write_text(before)
            npm = base / 'fake-tools/npm'
            npm.write_text('#!/bin/sh\nexit 12\n')
            result = self._run_install_script(target, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((target / 'installation.json').read_text(), before)

    def test_failed_wrapper_publication_keeps_previous_path_metadata(self):
        with tempfile.TemporaryDirectory(prefix='install-failure-', dir=Path.home()) as raw:
            base = Path(raw)
            env = self._fake_install_environment(base)
            target = base / 'target'
            target.mkdir()
            before = json.dumps({'root': str(target), 'bin': str(base / 'old-bin')})
            (target / 'installation.json').write_text(before)
            (base / 'bin/safecode').mkdir(parents=True)
            result = self._run_install_script(target, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((target / 'installation.json').read_text(), before)
            self.assertEqual(list((base / 'bin/safecode').iterdir()), [])

    def test_fresh_install_records_root_and_bin_and_uses_bin_with_spaces(self):
        with self.patched_installer():
            installer.main()
        app = self.home / 'Applications/Zcode Safe.app'
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        self.assertEqual(info['AgentbeltRoot'], str(self.root))
        self.assertEqual(info['AgentbeltBin'], str(self.bin))
        launcher = self.bin / 'zcode-backend-safe'
        self.assertTrue(launcher.is_file())
        self.assertIn(str(self.root / 'agentbelt.py'), launcher.read_text())
        self.assertFalse((self.home / '.local/bin/zcode-backend-safe').exists())

    def test_malformed_installation_metadata_does_not_fall_back_to_default_bin(self):
        (self.root / 'installation.json').write_text(json.dumps({'root': str(self.root), 'bin': 'relative/bin'}))
        with self.patched_installer(), self.assertRaises(RuntimeError):
            installer.main()
        self.assertFalse((self.home / '.local/bin/zcode-backend-safe').exists())

    def _create_managed_app(self, bundle_id='local.agentbelt.zcode.safe-launcher'):
        app = self.home / 'Applications/Zcode Safe.app'
        contents = app / 'Contents'
        (contents / 'MacOS').mkdir(parents=True)
        (contents / 'Resources').mkdir()
        (contents / 'MacOS/launch').write_bytes(b'old native launcher')
        (contents / 'Resources/SafeIcon.icns').write_bytes(b'old icon')
        (contents / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': bundle_id,
            'CFBundleExecutable': 'launch',
            'CFBundlePackageType': 'APPL',
            'CFBundleName': 'Zcode Safe',
        }))
        signature = contents / '_CodeSignature'
        signature.mkdir()
        (signature / 'CodeResources').write_bytes(b'old code resources')
        for path in [app, contents, contents / 'MacOS', contents / 'Resources']:
            path.chmod(0o700)
        signature.chmod(0o700)
        (contents / 'Info.plist').chmod(0o600)
        (contents / 'MacOS/launch').chmod(0o700)
        (contents / 'Resources/SafeIcon.icns').chmod(0o600)
        (signature / 'CodeResources').chmod(0o600)
        return app

    def test_upgrade_replaces_only_native_and_metadata_and_preserves_profiles(self):
        app = self._create_managed_app()
        profile = self.state / 'zcode-profile.json'
        credentials = self.state / 'credential-marker'
        profile.write_text('profile stays')
        credentials.write_text('credentials stay')
        with self.patched_installer():
            installer.main(upgrade_launcher=True)
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        self.assertEqual(info['AgentbeltRoot'], str(self.root))
        self.assertEqual(info['AgentbeltBin'], str(self.bin))
        self.assertEqual((app / 'Contents/MacOS/launch').read_bytes(), b'new native launcher')
        self.assertEqual(profile.read_text(), 'profile stays')
        self.assertEqual(credentials.read_text(), 'credentials stay')

    def test_upgrade_refuses_foreign_bundle_without_writing(self):
        app = self._create_managed_app(bundle_id='com.example.foreign')
        before = (app / 'Contents/MacOS/launch').read_bytes(), (app / 'Contents/Info.plist').read_bytes()
        with self.patched_installer(), self.assertRaises(RuntimeError):
            installer.main(upgrade_launcher=True)
        self.assertEqual((app / 'Contents/MacOS/launch').read_bytes(), before[0])
        self.assertEqual((app / 'Contents/Info.plist').read_bytes(), before[1])

    def test_upgrade_refuses_symlinked_launcher_without_following_it(self):
        app = self._create_managed_app()
        launcher = app / 'Contents/MacOS/launch'
        victim = self.root / 'victim'
        victim.write_bytes(b'victim')
        launcher.unlink()
        launcher.symlink_to(victim)
        with self.patched_installer(), self.assertRaises(RuntimeError):
            installer.main(upgrade_launcher=True)
        self.assertEqual(victim.read_bytes(), b'victim')

    def test_upgrade_restores_native_when_metadata_publish_fails(self):
        app = self._create_managed_app()
        launch = app / 'Contents/MacOS/launch'
        info_path = app / 'Contents/Info.plist'
        before_launch, before_info = launch.read_bytes(), info_path.read_bytes()
        original_replace = installer.os.replace
        calls = []

        def fail_metadata(src, dst):
            calls.append(dst)
            if len(calls) == 2:
                raise OSError('synthetic metadata publication failure')
            return original_replace(src, dst)

        with self.patched_installer(), patch.object(installer.os, 'replace', side_effect=fail_metadata), \
             self.assertRaises(RuntimeError):
            installer.main(upgrade_launcher=True)
        self.assertEqual(launch.read_bytes(), before_launch)
        self.assertEqual(info_path.read_bytes(), before_info)

    def test_upgrade_retains_recovery_copy_when_publication_and_restore_fail(self):
        app = self._create_managed_app()
        before = (app / 'Contents/MacOS/launch').read_bytes(), (app / 'Contents/Info.plist').read_bytes()
        original_replace = installer.os.replace
        calls = []

        def fail_publication_and_restore(src, dst):
            calls.append((Path(src), Path(dst)))
            if len(calls) in (4, 5):
                raise OSError('synthetic publication/restore failure')
            return original_replace(src, dst)

        with self.patched_installer(), patch.object(installer.os, 'replace',
                                                     side_effect=fail_publication_and_restore), \
             self.assertRaises(RuntimeError) as caught:
            installer.main(upgrade_launcher=True)
        message = str(caught.exception)
        self.assertIn('recovery copy:', message)
        recovery = Path(message.split('recovery copy: ', 1)[1])
        self.assertTrue(recovery.is_dir())
        self.assertEqual((recovery / 'Contents/MacOS/launch').read_bytes(), before[0])
        self.assertFalse(app.exists())

    def test_upgrade_restores_signature_when_codesign_fails(self):
        app = self._create_managed_app()
        launch = app / 'Contents/MacOS/launch'
        info_path = app / 'Contents/Info.plist'
        resources = app / 'Contents/_CodeSignature/CodeResources'
        before = launch.read_bytes(), info_path.read_bytes(), resources.read_bytes()
        with self.patched_installer(), patch.object(installer, '_codesign_bundle',
                                                     side_effect=RuntimeError('synthetic signing failure')), \
             self.assertRaises(RuntimeError):
            installer.main(upgrade_launcher=True)
        self.assertEqual((launch.read_bytes(), info_path.read_bytes(), resources.read_bytes()), before)


class BackendRoutingTests(unittest.TestCase):
    def test_custom_root_cannot_bypass_gui_privacy_block(self):
        import agentbelt as g
        from types import SimpleNamespace
        root = Path('/synthetic/custom root')
        with patch.object(g, 'ROOT', root), patch.object(g, 'verify_zcode_binary'), \
             patch.object(g, 'runtime_status'), \
             patch.object(g.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='synthetic-start')), \
             patch.object(g.os, 'execve') as launch:
            with self.assertRaisesRegex(g.GuardError, 'GUI.*upload'):
                g.launch_zcode_app()
        launch.assert_not_called()


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'requires macOS swiftc')
class SwiftPathResolverTests(unittest.TestCase):
    def compile_probe(self):
        source = (ROOT / 'ZcodeSafe.swift').read_text()
        prefix = source.split('let guardRoot =', 1)[0]
        harness = prefix + r'''
let argument = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "<missing>"
let supplied: Any? = argument == "<missing>" ? nil : argument
print(resolveInstalledPath(supplied, key: "AgentbeltRoot", fallback: "/default/root"))
'''
        probe = Path(self.tmp.name) / 'resolver.swift'
        binary = Path(self.tmp.name) / 'resolver'
        probe.write_text(harness)
        result = subprocess.run(['/usr/bin/swiftc', '-framework', 'AppKit', str(probe), '-o', str(binary)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return binary

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='swift-paths-', dir=Path.home())

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_absolute_path_with_spaces_and_missing_key_default(self):
        binary = self.compile_probe()
        valid = str(Path(self.tmp.name) / 'root with spaces')
        result = subprocess.run([str(binary), valid], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), valid)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '/default/root')

    def test_malformed_present_path_fails_closed_without_default(self):
        binary = self.compile_probe()
        for malformed in ['relative/root', '/tmp/../root', '']:
            with self.subTest(malformed=malformed):
                result = subprocess.run([str(binary), malformed], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('/default/root', result.stdout + result.stderr)

    def test_native_backend_arguments_do_not_require_a_custom_bin_wrapper(self):
        prefix = (ROOT / 'ZcodeSafe.swift').read_text().split('let guardRoot =', 1)[0]
        probe = Path(self.tmp.name) / 'backend.swift'
        binary = Path(self.tmp.name) / 'backend'
        probe.write_text(prefix + "\nlet env = backendEnvironment(root: CommandLine.arguments[1])\n"
                         + 'print(String(decoding: try! JSONSerialization.data(withJSONObject: env), as: UTF8.self))\n')
        result = subprocess.run(['/usr/bin/swiftc', '-framework', 'AppKit', str(probe), '-o', str(binary)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = '/synthetic/root with spaces'
        run = subprocess.run([str(binary), root], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        env = json.loads(run.stdout)
        self.assertEqual(env['ZCODE_AGENT_SERVER_COMMAND'], '/usr/bin/python3')
        self.assertEqual(json.loads(env['ZCODE_AGENT_SERVER_ARGS_JSON']),
                         ['-I', root + '/agentbelt.py', 'zcode-backend', 'app-server', '--stdio'])

    def test_full_launcher_compiles_and_can_be_signed_without_launching(self):
        source_binary = Path(self.tmp.name) / 'ZcodeSafeLauncher'
        result = subprocess.run(['/usr/bin/swiftc', '-O', '-framework', 'AppKit', str(ROOT / 'ZcodeSafe.swift'),
                                 '-o', str(source_binary)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        app = Path(self.tmp.name) / 'Zcode Safe.app'
        launch = app / 'Contents/MacOS/launch'
        launch.parent.mkdir(parents=True)
        shutil.copy2(source_binary, launch)
        launch.chmod(0o700)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': installer.BUNDLE_IDENTIFIER,
            'CFBundleExecutable': 'launch',
            'CFBundlePackageType': 'APPL',
        }))
        installer._codesign_bundle(app)
        verified = subprocess.run(['/usr/bin/codesign', '-v', '--strict', str(app)],
                                  capture_output=True, text=True, timeout=10)
        self.assertEqual(verified.returncode, 0, verified.stderr)


if __name__ == '__main__':
    unittest.main()
