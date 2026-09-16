import copy
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
config = module('repair_config', 'configure_existing.py')
installer = module('repair_installer', 'install_profiles.py')

class RepairTests(unittest.TestCase):
    def test_unreviewed_https_override_is_rejected(self):
        auth = {'deepseek': {'type': 'api', 'key': 'SYNTHETIC'}}
        for endpoint in ['https://attacker.invalid/v1', 'https://api.deepseek.com.attacker.invalid/v1']:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                config.opencode_assets(auth, {'provider': {'deepseek': {'options': {'baseURL': endpoint}}}},
                                       {'deepseek': 'https://api.deepseek.com'})

    def test_provider_origin_override_preserves_valid_path(self):
        source = {'provider': {'deepseek': {'options': {'baseURL': 'https://api.deepseek.com/v1'}}}}
        result, _, profile = config.opencode_assets({'deepseek': {'type': 'api', 'key': 'SYNTHETIC'}},
                                                   source, {'deepseek': 'https://api.deepseek.com'})
        self.assertEqual(result['provider'], source['provider'])
        self.assertEqual(profile['domains'], ['api.deepseek.com:443'])

    def test_disabled_or_wrong_hook_is_replaced_without_losing_other_hooks(self):
        other = {'type': 'process', 'command': '/example/other', 'args': []}
        for change in [{'enabled': False}, {'command': '/wrong'}, {'type': 'wrong'}]:
            bad = {'type': 'process', 'command': '/usr/bin/python3', 'args': ['-I', str(config.ROOT/'zcode_hook.py')], 'enabled': True}
            bad.update(change)
            source = {'hooks': {'events': {'PreToolUse': [{'matcher': 'Read', 'hooks': [bad, other]}]}}}
            before = copy.deepcopy(source)
            result = config.add_zcode_hook(source)
            events = result['hooks']['events']['PreToolUse']
            self.assertEqual(events[0]['matcher'], '*')
            self.assertEqual(events[0]['hooks'][0]['command'], '/usr/bin/python3')
            self.assertEqual(events[0]['hooks'][0]['type'], 'process')
            self.assertTrue(events[0]['hooks'][0]['enabled'])
            self.assertIn(other, [h for e in events for h in e['hooks']])
            self.assertEqual(config.add_zcode_hook(result), result)
            self.assertEqual(source, before)

    def test_install_conflict_leaves_no_partial_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); state = home/'guard/state'; state.mkdir(parents=True)
            (home/'.local/bin').mkdir(parents=True)
            app = home/'Applications/Zcode Safe.app'; app.mkdir(parents=True)
            marker = app/'existing'; marker.write_text('keep')
            with patch.object(installer, 'HOME', home), patch.object(installer, 'STATE', state):
                with self.assertRaises((OSError, RuntimeError)):
                    installer.main()
                self.assertEqual(list(state.iterdir()), [])
                self.assertEqual(list((home/'.local/bin').iterdir()), [])
                self.assertEqual(marker.read_text(), 'keep')

    def test_install_publication_failure_can_be_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); state = home/'guard/state'; state.mkdir(parents=True)
            (home/'.local/bin').mkdir(parents=True)
            original = os.open
            def fail_launcher(path, flags, *args, **kwargs):
                if str(path).endswith('/zcode-backend-safe'):
                    raise OSError('synthetic publication failure')
                return original(path, flags, *args, **kwargs)
            with patch.object(installer, 'HOME', home), patch.object(installer, 'STATE', state):
                with patch.object(installer.os, 'open', side_effect=fail_launcher), self.assertRaises(OSError):
                    installer.main()
                self.assertEqual(list(state.iterdir()), [])
                installer.main()
                self.assertTrue((state/'zcode-profile.json').is_file())
                self.assertTrue((home/'Applications/Zcode Safe.app/Contents/MacOS/launch').is_file())

    def test_import_failure_restores_all_previous_files_and_allows_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); root = home/'guard'; state = root/'state'; state.mkdir(parents=True)
            fixtures = {home/'.local/share/opencode/auth.json': {'deepseek': {'type': 'api', 'key': 'SYNTHETIC'}},
                        home/'.config/opencode/opencode.jsonc': {}, home/'.zcode/cli/config.json': {'existing': True}}
            for path, value in fixtures.items():
                path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value))
            binary = home/'.opencode/bin/opencode'; binary.parent.mkdir(parents=True); binary.write_bytes(b'fake')
            previous = {}
            for name in ['opencode-config.json', 'opencode-auth.json', 'opencode-profile.json']:
                path = state/name; path.write_text('{"old": "'+name+'"}\n'); path.chmod(0o600); previous[path] = path.read_bytes()
            previous[home/'.zcode/cli/config.json'] = (home/'.zcode/cli/config.json').read_bytes()
            original = os.replace; calls = []
            def fail_third(src, dst):
                calls.append(dst)
                if len(calls) == 3: raise OSError('synthetic third publication failure')
                return original(src, dst)
            with patch.object(config, 'HOME', home), patch.object(config, 'ROOT', root), \
                 patch.object(config, 'embedded_endpoints', return_value={'deepseek': 'https://api.deepseek.com'}), \
                 patch.object(sys, 'argv', ['configure_existing', '--authorized-live-settings']):
                with patch.object(config.os, 'replace', side_effect=fail_third), self.assertRaises(OSError):
                    config.main()
                for path, contents in previous.items(): self.assertEqual(path.read_bytes(), contents)
                config.main()
                self.assertEqual(json.loads((state/'opencode-profile.json').read_text())['domains'], ['api.deepseek.com:443'])
                self.assertFalse(list(state.glob('.guard-config-*')))

    def test_import_staging_failure_does_not_publish_anything(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp)/'first.json', Path(tmp)/'second.json'
            first.write_text('old')
            with self.assertRaises(TypeError):
                config.publish_settings({first: {'new': True}, second: {'bad': object()}})
            self.assertEqual(first.read_text(), 'old')
            self.assertFalse(second.exists())
            self.assertFalse(list(Path(tmp).glob('.guard-config-*')))

    def test_failed_initial_import_removes_newly_published_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp)/'first.json', Path(tmp)/'second.json'
            original = os.replace
            def fail_second(src, dst):
                if dst == second: raise OSError('synthetic failure')
                return original(src, dst)
            with patch.object(config.os, 'replace', side_effect=fail_second), self.assertRaises(OSError):
                config.publish_settings({first: {}, second: {}})
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_fresh_install_creates_private_parents_and_valid_app(self):
        import plistlib
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); state = home/'guard/state'
            with patch.object(installer, 'HOME', home), patch.object(installer, 'STATE', state):
                installer.main()
            app = home/'Applications/Zcode Safe.app'
            info = plistlib.loads((app/'Contents/Info.plist').read_bytes())
            self.assertTrue((app/'Contents/MacOS'/info['CFBundleExecutable']).is_file())
            for path in [state/'zcode-agent-config.json', state/'zcode-profile.json', app/'Contents/Info.plist']:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((app/'Contents/MacOS/launch').stat().st_mode), 0o700)

    def test_unsupported_packet_version_never_imports_package(self):
        touched = []
        class WatchImports:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == 'packet_ask' or fullname.startswith('packet_ask.'):
                    touched.append(fullname)
                    raise AssertionError('unreviewed package was imported')
        watcher = WatchImports()
        sys.meta_path.insert(0, watcher)
        try:
            with patch('importlib.metadata.version', return_value='999.0'), self.assertRaises(SystemExit):
                runpy.run_path(str(ROOT/'packet_entry.py'), run_name='__main__')
        finally:
            sys.meta_path.remove(watcher)
        self.assertEqual(touched, [])

if __name__ == '__main__': unittest.main()
