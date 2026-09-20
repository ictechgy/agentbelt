"""`agentbelt init` on a fresh installation: creates only what is missing, records baselines for installed agents,
and leaves a machine without any agent in a state where `doctor` explains that instead of crashing."""
import hashlib
import io
import json
from pathlib import Path
import plistlib
import struct
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


class ZcodeRoutingTests(unittest.TestCase):
    HOST = 'ZCODE_AGENT_SERVER_COMMAND ZCODE_AGENT_SERVER_ARGS_JSON resolveDefaultZCodeAgentCommand workspacePath'
    DESKTOP = 'createWebRemoteControlManager relayWsUrl'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def app(self, name='ZCode.app', host=None, desktop=None, extra=None, overrides=None):
        app = self.root / name
        resources = app / 'Contents/Resources'
        (resources / 'glm').mkdir(parents=True)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': 'test'}))
        (resources / 'glm/zcode.cjs').write_bytes(b'// synthetic CLI')
        files = {'out/host/index.js': self.HOST if host is None else host,
                 'out/main/index.js': self.DESKTOP if desktop is None else desktop}
        files.update(extra or {})
        index, payload = {'files': {}}, bytearray()
        for path, text in files.items():
            node = index
            parts = path.split('/')
            for part in parts[:-1]:
                node = node['files'].setdefault(part, {'files': {}})
            body = text.encode()
            node['files'][parts[-1]] = (overrides or {}).get(path, {'size': len(body), 'offset': str(len(payload))})
            payload.extend(body)
        raw = json.dumps(index, separators=(',', ':')).encode()
        padding = bytes((-len(raw)) % 4)
        header = struct.pack('<4I', 4, len(raw) + len(padding) + 8,
                             len(raw) + len(padding) + 4, len(raw))
        (resources / 'app.asar').write_bytes(header + raw + padding + payload)
        return app

    def candidate(self, app):
        with patch.object(check, 'APP', app):
            return check.zcode_candidate(app)

    def test_monolithic_bundle_keeps_existing_hash_contract(self):
        app = self.app()
        self.assertEqual(self.candidate(app), {'version': 'test',
            'asarSha256': check.digest(app / 'Contents/Resources/app.asar'),
            'agentSha256': check.digest(app / 'Contents/Resources/glm/zcode.cjs')})

    def test_static_chunk_contains_moved_backend_routing(self):
        app = self.app(host='import { route as r } from "./chunk-ABC.js"; r();',
                       extra={'out/host/chunk-ABC.js': self.HOST})
        self.assertEqual(self.candidate(app)['version'], 'test')

    def test_transitive_imports_and_cycle_are_bounded_by_unique_modules(self):
        app = self.app(host='import{r}from"./a.js";import{q}from"./a.js";', extra={
            'out/host/a.js': 'import "./b.js";',
            'out/host/b.js': 'import "./index.js";' + self.HOST})
        self.assertEqual(self.candidate(app)['version'], 'test')

    def test_split_desktop_relay_is_checked_separately(self):
        app = self.app(desktop="import './chunk-relay.js';", extra={'out/main/chunk-relay.js': self.DESKTOP})
        self.assertEqual(self.candidate(app)['version'], 'test')

    def test_bare_runtime_import_does_not_hide_local_import(self):
        app = self.app(host='/* banner */\nimport fs from "node:fs";\nimport * as r from "./routing.js"\nr();',
                       extra={'out/host/routing.js': self.HOST})
        self.assertEqual(self.candidate(app)['version'], 'test')

    def test_directive_and_default_plus_named_import(self):
        app = self.app(host='"use strict"; import r,{helper as h}from"./routing.js";r();',
                       extra={'out/host/routing.js': self.HOST})
        self.assertEqual(self.candidate(app)['version'], 'test')

    def test_minified_namespace_imports(self):
        app = self.app(host='import*as fs from"node:fs";import r,*as ns from"./routing.js";',
                       extra={'out/host/routing.js': self.HOST})
        self.assertEqual(self.candidate(app)['version'], 'test')

    def test_unreferenced_or_nonstatic_decoy_does_not_satisfy_routing(self):
        for number, source in enumerate(('const x = 1;', '// import "./decoy.js";\nconst x=1;',
                '/* import "./decoy.js"; */ const x=1;',
                'const text = "import \'./decoy.js\';";', 'import("./decoy.js");')):
            with self.subTest(source=source):
                app = self.app(str(number), host=source, extra={'out/host/decoy.js': self.HOST})
                with self.assertRaisesRegex(ValueError, 'backend routing'):
                    self.candidate(app)

    def test_required_markers_cannot_be_assembled_from_unrelated_modules(self):
        app = self.app(host='import "./a.js";import "./b.js";', extra={
            'out/host/a.js': 'ZCODE_AGENT_SERVER_COMMAND ZCODE_AGENT_SERVER_ARGS_JSON',
            'out/host/b.js': 'resolveDefaultZCodeAgentCommand workspacePath'})
        with self.assertRaisesRegex(ValueError, 'backend routing'):
            self.candidate(app)

    def test_missing_referenced_chunk_fails_even_if_entry_has_markers(self):
        app = self.app(host='import "./missing.js";' + self.HOST)
        with self.assertRaises(ValueError):
            self.candidate(app)

    def test_parent_traversal_and_escaped_specifier_are_rejected(self):
        for number, specifier in enumerate(('../outside.js', './nested/../routing.js', './%2e%2e/outside.js')):
            with self.subTest(specifier=specifier):
                app = self.app(str(number), host='import "' + specifier + '";' + self.HOST)
                with self.assertRaises(ValueError):
                    self.candidate(app)

    def test_link_unpacked_and_out_of_range_entries_are_rejected(self):
        for number, entry in enumerate(({'link': '/outside', 'offset': '0', 'size': 12}, {'unpacked': True, 'size': 12},
                {'offset': '-1', 'size': 12}, {'offset': '99999999', 'size': 12},
                {'offset': '0', 'size': True})):
            with self.subTest(entry=entry):
                app = self.app(str(number), host='import "./routing.js";', extra={'out/host/routing.js': self.HOST},
                               overrides={'out/host/routing.js': entry})
                with self.assertRaises(ValueError):
                    self.candidate(app)

    def test_module_and_aggregate_byte_limits_fail_closed(self):
        app = self.app(host='import "./routing.js";', extra={'out/host/routing.js': self.HOST})
        for limit, value in (('_MAX_JS_MODULES', 1), ('_MAX_JS_BYTES', len(self.HOST))):
            with self.subTest(limit=limit), patch.object(check, limit, value):
                with self.assertRaisesRegex(ValueError, 'module budget'):
                    self.candidate(app)

    def test_truncated_archive_is_rejected(self):
        app = self.app()
        archive = app / 'Contents/Resources/app.asar'
        archive.write_bytes(archive.read_bytes()[:12])
        with self.assertRaises(ValueError):
            self.candidate(app)

    def test_explicit_app_is_used_instead_of_global_default(self):
        default = self.app('default.app')
        alternate = self.app('alternate.app', host='no routing here')
        with patch.object(check, 'APP', default):
            with self.assertRaisesRegex(ValueError, 'backend routing'):
                check.zcode_candidate(alternate)

    def test_desktop_relay_markers_are_still_required(self):
        app = self.app(desktop='const noRelay = true;')
        with self.assertRaisesRegex(ValueError, 'mobile relay routing'):
            self.candidate(app)

    def test_doctor_rejects_hash_drift_without_rewriting_baseline(self):
        app = self.app(host='import "./routing.js";', extra={'out/host/routing.js': self.HOST})
        current = {'zcode': self.candidate(app)}
        state = self.root / 'state'
        state.mkdir()
        baseline = state / 'compatibility.json'
        baseline.write_text(json.dumps(current))
        before = baseline.read_bytes()
        with patch.object(g, 'ROOT', self.root), patch.object(check, 'candidate', return_value=current), \
             patch.object(g, 'riskgate_policy', return_value=self.root / 'missing-policy'), \
             patch.object(g, 'development_options', return_value={'devPorts': [], 'packageDomains': []}), \
             patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(g.doctor(), 0)
            current['zcode']['asarSha256'] = 'changed'
            self.assertEqual(g.doctor(), 2)
        self.assertEqual(baseline.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
