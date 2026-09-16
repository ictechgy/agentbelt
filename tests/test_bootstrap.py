"""`agentbelt init` on a fresh installation: creates only what is missing, records baselines for installed agents,
and leaves a machine without any agent in a state where `doctor` explains that instead of crashing."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g
from adapters import bootstrap, compatibility_check as check, configure_existing


class FreshInstall:
    """A synthetic install root with an examples/ directory and a synthetic owner home (no riskgate policy)."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-init-', dir=Path.home())
        base = Path(self.tmp.name)
        self.root = base / 'install'
        (self.root / 'examples').mkdir(parents=True)
        (self.root / 'examples/riskgate.yaml').write_text('version: 1\ndefaults: prompt\nrules: []\n')
        self.home = base / 'home'
        self.home.mkdir()
        self.venv = base / 'no-packet-ask'
        self.patches = [patch.object(g, 'ROOT', self.root), patch.object(bootstrap, 'ROOT', self.root),
                        patch.object(bootstrap, 'EXAMPLE_RISKGATE_POLICY', self.root / 'examples/riskgate.yaml'),
                        patch.object(g, 'OWNER_HOME', self.home), patch.object(g, 'PACKET_VENV', self.venv),
                        patch.object(check, 'candidate', lambda: {}), patch('sys.stdout', new_callable=io.StringIO)]

    def __enter__(self):
        for item in self.patches:
            item.start()
        return self

    def __exit__(self, *exc):
        for item in self.patches:
            item.stop()
        self.tmp.cleanup()


class InitTests(unittest.TestCase):
    def test_fresh_install_without_agents_gets_defaults_and_a_closed_riskgate_manifest(self):
        with FreshInstall() as fresh:
            self.assertEqual(bootstrap.initialize(), 0)
            state = fresh.root / 'state'
            development = json.loads((state / 'development.json').read_text())
            self.assertEqual(development['devPorts'], [])
            self.assertEqual(set(development['packageDomains']), set(g.PUBLIC_PACKAGE_DOMAINS))
            self.assertEqual((state / 'development.json').stat().st_mode & 0o777, 0o600)
            policy = fresh.home / '.config/riskgate/riskgate.yaml'
            self.assertTrue(policy.is_file())
            self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
            manifest = json.loads((state / 'riskgate.json').read_text())
            self.assertEqual(manifest, {'enabled': True, 'policy': str(policy)})
            self.assertEqual(g.riskgate_policy(), policy)
            self.assertFalse((state / 'compatibility.json').exists())  # nothing installed, nothing recorded
            self.assertFalse((state / 'packet-ask-version.json').exists())

    def test_init_is_idempotent_and_never_overwrites_operator_edits(self):
        with FreshInstall() as fresh:
            bootstrap.initialize()
            state = fresh.root / 'state'
            (state / 'development.json').write_text(json.dumps({'devPorts': [3000], 'packageDomains': []}))
            (fresh.home / '.config/riskgate/riskgate.yaml').write_text('version: 1\ndefaults: allow\nrules: []\n')
            before = {p: p.read_text() for p in state.glob('*.json')}
            self.assertEqual(bootstrap.initialize(), 0)
            self.assertEqual({p: p.read_text() for p in state.glob('*.json')}, before)
            self.assertIn('defaults: allow', (fresh.home / '.config/riskgate/riskgate.yaml').read_text())

    def test_baseline_records_installed_agents_and_keeps_reviewed_entries(self):
        with FreshInstall() as fresh:
            with patch.object(check, 'candidate', lambda: {'kimi': {'version': '0.43.1', 'sha256': 'k'}}):
                bootstrap.initialize()
                baseline = json.loads((fresh.root / 'state/compatibility.json').read_text())
                self.assertEqual(baseline, {'kimi': {'version': '0.43.1', 'sha256': 'k'}})
            # A later init sees a new agent and a *changed* known one: the new one is added, the known one is untouched.
            with patch.object(check, 'candidate', lambda: {'kimi': {'version': '0.44.0', 'sha256': 'changed'},
                                                            'opencode': {'version': '1.0', 'sha256': 'o'}}):
                bootstrap.initialize()
                baseline = json.loads((fresh.root / 'state/compatibility.json').read_text())
                self.assertEqual(baseline['kimi'], {'version': '0.43.1', 'sha256': 'k'})
                self.assertEqual(baseline['opencode'], {'version': '1.0', 'sha256': 'o'})

    def test_packet_ask_version_is_pinned_from_the_installed_tool(self):
        with FreshInstall() as fresh:
            (fresh.venv / 'lib/python3.12/site-packages/packet_ask-0.12.0.dist-info').mkdir(parents=True)
            bootstrap.initialize()
            self.assertEqual(json.loads((fresh.root / 'state/packet-ask-version.json').read_text()), {'version': '0.12.0'})
            with patch.object(g, 'ROOT', fresh.root):
                self.assertEqual(g.packet_ask_pinned_version(), '0.12.0')

    def test_symlinked_state_file_is_refused(self):
        with FreshInstall() as fresh:
            state = fresh.root / 'state'
            state.mkdir(mode=0o700)
            outside = fresh.root / 'outside.json'
            outside.write_text('{}')
            (state / 'development.json').symlink_to(outside)
            with self.assertRaises(g.GuardError):
                bootstrap.initialize()
            self.assertEqual(outside.read_text(), '{}')


class DoctorAndBaselineTests(unittest.TestCase):
    def test_candidate_and_doctor_work_without_opencode_and_zcode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            missing = root / 'missing'
            with patch.object(g, 'ROOT', root), patch.object(g, 'OPENCODE', missing), patch.object(g, 'KIMI', missing), \
                 patch.object(check, 'APP', missing), patch.object(check, 'AUTOCLAW_APP', missing), \
                 patch.object(check, 'autoclaw_candidate', lambda app=None: None), \
                 patch.object(g, 'riskgate_policy', lambda: (_ for _ in ()).throw(g.GuardError('none'))), \
                 patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                 patch('sys.stdout', new_callable=io.StringIO) as out, patch('sys.stderr', new_callable=io.StringIO):
                self.assertEqual(check.candidate(), {})
                self.assertEqual(g.doctor(), 2)  # nothing installed is reported, not a traceback
                report = json.loads(out.getvalue())
                self.assertIsNone(report['opencode'])
                self.assertIsNone(report['zcode'])
                self.assertFalse(report['baseline_present'])

    def test_doctor_passes_with_only_kimi_installed_and_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            (root / 'state/compatibility.json').write_text(json.dumps({'kimi': {'version': '0.43.1', 'sha256': 'k'}}))
            fake = type(sys)('adapters.compatibility_check')
            fake.candidate = lambda: {'kimi': {'version': '0.43.1', 'sha256': 'k'}}
            with patch.object(g, 'ROOT', root), patch.dict(sys.modules, {'adapters.compatibility_check': fake}), \
                 patch.object(g, 'riskgate_policy', lambda: (_ for _ in ()).throw(g.GuardError('none'))), \
                 patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(g.doctor(), 0)

    def test_merged_baseline_keeps_every_optional_entry(self):
        saved = {'opencode': {'version': 'o'}, 'zcode': {'version': 'z'}, 'mobile': 'm', 'autoclaw': {'version': 'a'}, 'kimi': {'version': 'k'}}
        self.assertEqual(check.merged_baseline({'kimi': {'version': 'k2'}}, saved), dict(saved, kimi={'version': 'k2'}))


class ImportWithoutZcodeTests(unittest.TestCase):
    def test_credential_import_works_on_an_opencode_only_mac(self):
        with tempfile.TemporaryDirectory(prefix='import-', dir=Path.home()) as tmp:
            base = Path(tmp)
            home = base / 'home'
            (home / '.local/share/opencode').mkdir(parents=True)
            (home / '.local/share/opencode/auth.json').write_text(json.dumps({'deepseek': {'type': 'api', 'key': 'SYNTHETIC'}}))
            binary = base / 'opencode'
            binary.write_bytes(b'prefix id:"deepseek",env:["X"],npm:"@ai-sdk/openai-compatible",api:"https://api.deepseek.com" suffix')
            root = base / 'root'
            (root / 'state').mkdir(parents=True)
            with patch.object(configure_existing, 'HOME', home), patch.object(configure_existing, 'ROOT', root), \
                 patch.object(configure_existing, 'opencode_binary', lambda: binary), \
                 patch('sys.stdout', new_callable=io.StringIO) as out:
                configure_existing.import_settings()
            self.assertEqual(json.loads((root / 'state/opencode-auth.json').read_text()), {'deepseek': {'type': 'api', 'key': 'SYNTHETIC'}})
            self.assertEqual(json.loads((root / 'state/opencode-profile.json').read_text())['domains'], ['api.deepseek.com:443'])
            self.assertFalse((home / '.zcode').exists())
            self.assertIn('Zcode is not set up', out.getvalue())


if __name__ == '__main__':
    unittest.main()
