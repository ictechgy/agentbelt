"""Regressions for relaying OpenCode status to Orca through a supervisor broker."""
import http.server
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g
from adapters import orca_broker


class FakeOrca:
    """Stand-in for Orca's hook server; records exactly what the broker sends."""

    def __init__(self):
        self.received = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                outer.received.append({'path': self.path,
                                       'token': self.headers.get('X-Orca-Agent-Hook-Token'),
                                       'body': json.loads(self.rfile.read(length))})
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *arguments):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *details):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def coordinates(port):
    return {'port': str(port), 'token': 'synthetic-orca-token', 'env': 'production', 'version': '1',
            'paneKey': 'real-pane', 'tabId': 'real-tab', 'worktreeId': 'real-worktree',
            'launchToken': 'real-launch'}


class BrokerTests(unittest.TestCase):
    def post(self, broker, body, token=None, path=orca_broker.HOOK_PATH):
        request = urllib.request.Request(
            'http://127.0.0.1:%d%s' % (broker.port, path), data=json.dumps(body).encode(),
            headers={'Content-Type': 'application/json',
                     'X-Orca-Agent-Hook-Token': broker.token if token is None else token})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_status_is_relayed_but_the_child_cannot_claim_another_pane(self):
        with FakeOrca() as orca, orca_broker.StatusBroker(coordinates(orca.port)) as broker:
            status = self.post(broker, {'paneKey': 'spoofed', 'tabId': 'spoofed',
                                        'worktreeId': 'spoofed', 'launchToken': 'spoofed',
                                        'payload': {'hook_event_name': 'PermissionRequest'}})
            self.assertEqual(status, 200)
            self.assertEqual(len(orca.received), 1)
            forwarded = orca.received[0]
            self.assertEqual(forwarded['token'], 'synthetic-orca-token')
            self.assertEqual(forwarded['body']['paneKey'], 'real-pane')
            self.assertEqual(forwarded['body']['tabId'], 'real-tab')
            self.assertEqual(forwarded['body']['worktreeId'], 'real-worktree')
            self.assertEqual(forwarded['body']['launchToken'], 'real-launch')
            self.assertEqual(forwarded['body']['payload']['hook_event_name'], 'PermissionRequest')

    def test_orca_credentials_are_never_handed_to_the_child(self):
        with FakeOrca() as orca, orca_broker.StatusBroker(coordinates(orca.port)) as broker:
            child = broker.child_environment()
            self.assertNotEqual(child['ORCA_AGENT_HOOK_TOKEN'], 'synthetic-orca-token')
            self.assertEqual(child['ORCA_AGENT_HOOK_PORT'], str(broker.port))
            self.assertNotIn('ORCA_AGENT_HOOK_ENDPOINT', child)
            self.assertNotIn('ORCA_AGENT_LAUNCH_TOKEN', child)

    def test_malformed_or_unauthenticated_requests_are_refused(self):
        with FakeOrca() as orca, orca_broker.StatusBroker(coordinates(orca.port)) as broker:
            good = {'payload': {'hook_event_name': 'SessionIdle'}}
            self.assertEqual(self.post(broker, good, token='wrong-token'), 403)
            self.assertEqual(self.post(broker, good, path='/hook/anything-else'), 404)
            self.assertEqual(self.post(broker, {'payload': {'hook_event_name': 5}}), 400)
            self.assertEqual(self.post(broker, {'payload': 'not-an-object'}), 400)
            self.assertEqual(self.post(broker, {'payload': {'hook_event_name': 'x',
                                                            'pad': 'a' * (orca_broker.MAX_BODY + 10)}}), 413)
            self.assertEqual(orca.received, [])

    def test_orca_being_down_never_fails_the_relay(self):
        with orca_broker.StatusBroker(coordinates(1)) as broker:
            self.assertEqual(self.post(broker, {'payload': {'hook_event_name': 'SessionIdle'}}), 200)


class BrokerNoiseTests(unittest.TestCase):
    def test_a_dropped_connection_stays_off_the_operators_terminal(self):
        """This server's stderr is the terminal the operator is working in."""
        import contextlib, io, socket, time
        with FakeOrca() as orca, orca_broker.StatusBroker(coordinates(orca.port)) as broker:
            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                for _ in range(3):
                    client = socket.create_connection(('127.0.0.1', broker.port), timeout=5)
                    client.sendall(b'POST /hook/opencode HTTP/1.1\r\nHost: x\r\n'
                                   b'Content-Length: 500\r\n\r\n{"partial"')
                    client.close()
                    time.sleep(0.15)
                time.sleep(0.4)
            self.assertEqual(captured.getvalue(), '')


class IntegrationGateTests(unittest.TestCase):
    def test_relay_stays_off_until_it_is_explicitly_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            with patch.object(g, 'ROOT', root):
                self.assertIsNone(g.orca_integration())
                (root / 'state/orca-integration.json').write_text(json.dumps({'enabled': False}))
                self.assertIsNone(g.orca_integration())
                (root / 'state/orca-integration.json').write_text(json.dumps({'enabled': True}))
                with patch.dict(os.environ, {}, clear=True):
                    self.assertIsNone(g.orca_integration(), 'outside Orca there is nothing to relay')


class SandboxReachabilityTests(unittest.TestCase):
    def test_only_the_broker_port_is_reachable_from_inside(self):
        with FakeOrca() as reachable, FakeOrca() as blocked, \
                tempfile.TemporaryDirectory(prefix='orca-reach-', dir=Path.home()) as tmp:
            work = Path(tmp)
            probe = work / 'probe.py'
            probe.write_text(
                'import json, socket, sys\n'
                'out = {}\n'
                'for name, port in [("broker", int(sys.argv[1])), ("other", int(sys.argv[2]))]:\n'
                '    try:\n'
                '        socket.create_connection(("127.0.0.1", port), timeout=5).close()\n'
                '        out[name] = "CONNECTED"\n'
                '    except Exception as error: out[name] = type(error).__name__\n'
                'print(json.dumps(out))\n')
            with tempfile.TemporaryFile() as output:
                status = g.run_confined(
                    'opencode', work,
                    ['/usr/bin/python3', '-I', str(probe), str(reachable.port), str(blocked.port)],
                    extra_env={'AGENT_GUARD_BROKER_PORT': str(reachable.port)},
                    ephemeral=True, stdout=output)
                output.seek(0)
                result = json.loads(output.read().decode().splitlines()[-1])
            self.assertEqual(status, 0)
            self.assertEqual(result['broker'], 'CONNECTED')
            self.assertNotEqual(result['other'], 'CONNECTED')


class LaunchWiringTests(unittest.TestCase):
    def test_safecode_seeds_the_orca_plugin_and_broker_environment(self):
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, extra_env=args[1] if len(args) > 1 else kwargs.get('extra_env'))
            return 0

        with tempfile.TemporaryDirectory(prefix='orca-wiring-', dir=Path.home()) as tmp:
            work = Path(tmp) / 'project'
            work.mkdir()
            plugin = work / 'hooks/plugins/orca-opencode-status.js'
            plugin.parent.mkdir(parents=True)
            plugin.write_text('export default {id: "synthetic", server: async () => ({})};\n')
            # A synthetic install root: the safecode path requires an imported auth store, which a CI runner lacks.
            root = Path(tmp) / 'guard'
            (root / 'state').mkdir(parents=True)
            (root / 'state/opencode-auth.json').write_text('{}')
            (root / 'state/opencode-config.json').write_text('{}')
            previous = os.getcwd()
            os.chdir(work)
            try:
                with FakeOrca() as orca, \
                     patch.object(g, 'ROOT', root), \
                     patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'verify_opencode_binary', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                     patch.object(g, 'load_opencode_profile', lambda: {'domains': []}), \
                     patch.object(g, 'orca_integration', lambda: (plugin, coordinates(orca.port))):
                    self.assertEqual(g.main(['safecode', '--', 'debug', 'config']), 0)
            finally:
                os.chdir(previous)

        self.assertEqual([Path(p).name for p in captured['opencode_plugins']],
                         ['orca-opencode-status.js'])
        child = captured['extra_env']
        self.assertEqual(child['ORCA_PANE_KEY'], 'real-pane')
        self.assertEqual(child['AGENT_GUARD_BROKER_PORT'], child['ORCA_AGENT_HOOK_PORT'])
        self.assertNotEqual(child['ORCA_AGENT_HOOK_TOKEN'], 'synthetic-orca-token')


if __name__ == '__main__': unittest.main()
