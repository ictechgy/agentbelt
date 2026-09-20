"""Synthetic checks for the private Zcode Safe native launcher contract."""
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_installer():
    spec = importlib.util.spec_from_file_location('private_launcher_installer', ROOT / 'adapters/install_profiles.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load_installer()


class PrivateLauncherTests(unittest.TestCase):
    def test_manager_plist_declares_only_bounded_zcode_protocol(self):
        plist = installer.bundle_plist(Path('/synthetic/bin'))
        self.assertEqual(plist['CFBundleIdentifier'], 'local.agentbelt.zcode.safe-launcher')
        self.assertEqual(plist['CFBundleURLTypes'], [
            {'CFBundleURLName': 'local.agentbelt.zcode.safe-launcher', 'CFBundleURLSchemes': ['zcode']}
        ])

    def test_upgrade_merges_manager_protocol_declaration(self):
        with tempfile.TemporaryDirectory(prefix='private-launcher-', dir=Path.home()) as raw:
            base = Path(raw)
            home = base / 'home'
            root = base / 'root'
            state = root / 'state'
            app = home / 'Applications/Zcode Safe.app'
            (root / 'native').mkdir(parents=True)
            state.mkdir(parents=True)
            (root / 'native/ZcodeSafeLauncher').write_bytes(b'native')
            (root / 'config.json').write_text(json.dumps({'bin': str(base / 'bin')}))
            contents = app / 'Contents'
            (contents / 'MacOS').mkdir(parents=True)
            (contents / 'Resources').mkdir()
            (contents / 'MacOS/launch').write_bytes(b'old')
            (contents / 'Resources/SafeIcon.icns').write_bytes(b'icon')
            (contents / 'Info.plist').write_bytes(plistlib.dumps({
                'CFBundleIdentifier': installer.BUNDLE_IDENTIFIER,
                'CFBundleExecutable': 'launch', 'CFBundlePackageType': 'APPL',
            }))
            for path in [app, contents, contents / 'MacOS', contents / 'Resources']:
                path.chmod(0o700)
            (contents / 'Info.plist').chmod(0o600)
            (contents / 'MacOS/launch').chmod(0o700)
            (contents / 'Resources/SafeIcon.icns').chmod(0o600)
            with patch.multiple(installer, HOME=home, ROOT=root, STATE=state,
                                _codesign_bundle=lambda app: None):
                installer._upgrade_launcher()
            info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
            self.assertEqual(info['CFBundleURLTypes'], installer.BUNDLE_URL_TYPES)

    @unittest.skipUnless(shutil.which('/usr/bin/swiftc'), 'requires macOS swiftc')
    def test_decoder_accepts_verified_synthetic_response_and_rejects_missing_flags(self):
        source = (ROOT / 'ZcodeSafe.swift').read_text()
        prefix = source.split('let guardRoot =', 1)[0]
        with tempfile.TemporaryDirectory(prefix='private-launcher-swift-', dir=Path.home()) as raw:
            base = Path(raw)
            probe = base / 'decoder.swift'
            binary = base / 'decoder'
            probe.write_text(prefix + r'''
let input = FileHandle.standardInput.readDataToEndOfFile()
if let launch = verifiedPrivateLaunch(from: input, status: 0, root: CommandLine.arguments[1]) { print(launch.appPath + "|" + launch.generation + "|" + String(launch.privatePID ?? 0)) } else { print("rejected") }
''')
            compiled = subprocess.run(['/usr/bin/swiftc', '-framework', 'AppKit', str(probe), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            root = str(base / 'guard root')
            private_app = Path(root) / 'state/zcode-private/ZCode.app'
            generation = '0123456789abcdef0123456789abcdef'
            valid = {
                'app_path': str(private_app),
                'bundle_id': 'local.agentbelt.zcode.snapshot-blocked',
                'generation': generation,
                'private_gui_pid': 12345,
                'environment': {
                    'ZCODE_AGENT_SERVER_COMMAND': '/usr/bin/python3',
                    'ZCODE_AGENT_SERVER_ARGS_JSON': json.dumps([
                        '-I', root + '/agentbelt.py', 'zcode-private-backend', '--generation', generation,
                        'app-server', '--stdio'
                    ]),
                    'ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT': '1',
                    'ZCODE_DESKTOP_APPLICATION_NAME': 'ZCode Snapshot Blocked',
                    'ZCODE_DESKTOP_USER_DATA_DIR': root + '/state/zcode-private/user-data',
                    'ZCODE_DESKTOP_SESSION_DATA_DIR': root + '/state/zcode-private/session',
                },
                'snapshot_uploads_blocked': True,
                'auto_updates_blocked': True,
                'gui_egress_confined': False,
            }
            accepted = subprocess.run([str(binary), root], input=json.dumps(valid), capture_output=True, text=True, timeout=10)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.strip(), valid['app_path'] + '|' + generation + '|12345')
            for field in ('snapshot_uploads_blocked', 'auto_updates_blocked'):
                invalid = dict(valid)
                invalid[field] = False
                rejected = subprocess.run([str(binary), root], input=json.dumps(invalid), capture_output=True, text=True, timeout=10)
                self.assertEqual(rejected.returncode, 0, rejected.stderr)
                self.assertEqual(rejected.stdout.strip(), 'rejected')
            invalid = dict(valid)
            invalid['app_path'] = '/tmp/untrusted/ZCode.app'
            rejected = subprocess.run([str(binary), root], input=json.dumps(invalid), capture_output=True, text=True, timeout=10)
            self.assertEqual(rejected.stdout.strip(), 'rejected')
            for value in (0, -1, '12345'):
                invalid = dict(valid)
                invalid['private_gui_pid'] = value
                rejected = subprocess.run([str(binary), root], input=json.dumps(invalid), capture_output=True, text=True, timeout=10)
                self.assertEqual(rejected.stdout.strip(), 'rejected')
            invalid = dict(valid)
            invalid['private_gui_pid'] = None
            accepted = subprocess.run([str(binary), root], input=json.dumps(invalid), capture_output=True, text=True, timeout=10)
            self.assertEqual(accepted.stdout.strip(), invalid['app_path'] + '|' + generation + '|0')

    def test_source_has_no_original_gui_launch_and_keeps_registration_explicit(self):
        source = (ROOT / 'ZcodeSafe.swift').read_text()
        self.assertNotIn('NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/Applications/ZCode.app")', source)
        self.assertIn('check-zcode-private', source)
        self.assertIn('--register-zcode-protocol', source)
        self.assertIn('CFBundleURLSchemes', (ROOT / 'adapters/install_profiles.py').read_text())

    @unittest.skipUnless(shutil.which('/usr/bin/swiftc'), 'requires macOS swiftc')
    def test_protocol_registration_arguments_are_scheme_then_bundle_id(self):
        source = (ROOT / 'ZcodeSafe.swift').read_text()
        prefix = source.split('let guardRoot =', 1)[0]
        with tempfile.TemporaryDirectory(prefix='private-protocol-swift-', dir=Path.home()) as raw:
            base = Path(raw)
            probe = base / 'protocol.swift'
            binary = base / 'protocol'
            probe.write_text(prefix + r'''
print(protocolRegistrationArguments().joined(separator: "|"))
''')
            compiled = subprocess.run(['/usr/bin/swiftc', '-framework', 'AppKit', str(probe), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'zcode|local.agentbelt.zcode.safe-launcher')


if __name__ == '__main__':
    unittest.main()
