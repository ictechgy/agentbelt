"""Regressions for routing Node's global fetch through the supervisor's proxy."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g

DISPATCHER = ('const {getGlobalDispatcher} = await import('
              'new URL("runtime/node_modules/undici/index.js", "file://' + str(ROOT) + '/x"));'
              'console.log(getGlobalDispatcher().constructor.name);')


class ProxyBootstrapTests(unittest.TestCase):
    def dispatcher_name(self, proxy):
        """Report which dispatcher global fetch would use under this environment."""
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()),
               'NODE_OPTIONS': '--import ' + (ROOT / 'proxy_bootstrap.mjs').as_uri()}
        if proxy:
            env['HTTPS_PROXY'] = proxy
        result = subprocess.run([str(g.NODE), '--input-type=module', '-e', DISPATCHER],
                                capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        return result.stdout.strip()

    def test_configured_proxy_becomes_the_global_dispatcher(self):
        # The generated proxy carries percent-encoded credentials in the URL.
        name = self.dispatcher_name('http://srt.YWdlbnQtZ3VhcmQ%3D:abc123@localhost:49355')
        self.assertEqual(name, 'ProxyAgent')

    def test_without_a_proxy_the_default_dispatcher_is_left_alone(self):
        self.assertNotEqual(self.dispatcher_name(None), 'ProxyAgent')

    def test_zcode_backend_launch_wires_the_bootstrap_and_its_reads(self):
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, mode=mode)
            return 0

        with tempfile.TemporaryDirectory(prefix='zcode-wiring-', dir=Path.home()) as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'verify_zcode_binary', lambda: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}):
                    self.assertEqual(g.main(['zcode-backend', 'app-server', '--stdio']), 0)
            finally:
                os.chdir(previous)

        self.assertEqual(captured['mode'], 'zcode')
        reads = [str(path) for path in captured['extra_reads']]
        self.assertIn(str(ROOT / 'proxy_bootstrap.mjs'), reads)
        self.assertIn(str(ROOT / 'runtime/node_modules/undici'), reads)

        # prepare_home is what actually publishes NODE_OPTIONS to the child.
        with tempfile.TemporaryDirectory(prefix='zcode-home-', dir=Path.home()) as home:
            env = {}
            captured['prepare_home'](Path(home), env)
        self.assertEqual(env['NODE_OPTIONS'],
                         '--import ' + (ROOT / 'proxy_bootstrap.mjs').as_uri())
        self.assertEqual(env['AGENT_GUARD_BOOTSTRAP'], 'zcode')

    def test_pinned_runtime_still_provides_undici(self):
        manifest = json.loads((ROOT / 'runtime/node_modules/undici/package.json').read_text())
        self.assertEqual(manifest['name'], 'undici')
        self.assertEqual(json.loads((ROOT / 'runtime/package.json').read_text())
                         ['dependencies']['undici'], manifest['version'])


if __name__ == '__main__': unittest.main()
