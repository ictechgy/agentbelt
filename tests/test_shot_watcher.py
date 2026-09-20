"""Security and compatibility regressions for the host-side screenshot watcher."""

import base64
import json
import http.client
import http.server
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shot_queue  # noqa: E402
import shot_watcher  # noqa: E402


REPOSITORY = Path(__file__).resolve().parents[1]
_ORIGINAL_READ_TEXT = Path.read_text


def _load_agentbelt_without_host_config():
    """Load the launcher while making its optional real config unavailable."""
    specification = importlib.util.spec_from_file_location('agentbelt_shot_test', REPOSITORY / 'agentbelt.py')
    module = importlib.util.module_from_spec(specification)

    def synthetic_read(path, *args, **kwargs):
        if path == REPOSITORY / 'config.json':
            raise OSError('real config intentionally unavailable to this test')
        return _ORIGINAL_READ_TEXT(path, *args, **kwargs)

    with patch.object(Path, 'read_text', synthetic_read):
        specification.loader.exec_module(module)
    return module


agentbelt = _load_agentbelt_without_host_config()


def result(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class EnsureShotWatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'root'
        self.workspace = Path(self.tmp.name) / 'workspace'
        self.root.mkdir()
        (self.workspace / 'shots').mkdir(parents=True)
        self.script = self.root / 'shot_watcher.py'
        self.script.write_text('# synthetic watcher\n')
        self.popen_calls = []

    def record(self, *args, **kwargs):
        self.popen_calls.append((args, kwargs))
        return object()

    def ensure(self, popen=None):
        with patch.object(agentbelt, 'ROOT', self.root), \
             patch.object(agentbelt.subprocess, 'Popen', side_effect=popen or self.record):
            agentbelt.ensure_shot_watcher(str(self.workspace))

    def test_launcher_uses_isolated_python_trusted_cwd_and_clean_environment(self):
        self.ensure()
        self.assertEqual(len(self.popen_calls), 1)
        argv = self.popen_calls[0][0][0]
        kwargs = self.popen_calls[0][1]
        self.assertEqual(argv, ['/usr/bin/python3', '-I', str(self.script), str(self.workspace)])
        self.assertEqual(kwargs['cwd'], self.root)
        self.assertTrue(kwargs['close_fds'])
        self.assertEqual(set(kwargs['env']), {'PATH', 'LANG'})

    def test_live_lock_skips_spawn(self):
        (self.workspace / 'shots' / '.watcher.lock').write_text(str(os.getpid()))
        self.ensure()
        self.assertEqual(self.popen_calls, [])

    def test_stale_and_corrupt_locks_are_replaced(self):
        lock = self.workspace / 'shots' / '.watcher.lock'
        for value in ('424242', 'not-a-pid'):
            with self.subTest(value=value):
                lock.write_text(value)
                with patch.object(agentbelt.os, 'kill', side_effect=ProcessLookupError):
                    self.ensure()
                self.assertEqual(len(self.popen_calls), 1)
                self.popen_calls.clear()
                lock.unlink(missing_ok=True)

    def test_log_symlink_and_hardlink_never_change_outside_target(self):
        outside = Path(self.tmp.name) / 'outside.log'
        outside.write_bytes(b'ORIGINAL')
        log = self.workspace / 'shots' / '.watcher.log'
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    log.symlink_to(outside)
                else:
                    os.link(outside, log)
                self.ensure()
                self.assertEqual(self.popen_calls, [])
                self.assertEqual(outside.read_bytes(), b'ORIGINAL')
                log.unlink()

    def test_queue_swap_cannot_redirect_launcher_log(self):
        queue = self.workspace / 'shots'
        held = self.workspace / 'held-shots'
        replacement = self.workspace / 'shots-replacement'
        replacement.mkdir()
        original_open = shot_queue.open_queue_log

        def swap_then_open(queue_fd):
            queue.rename(held)
            replacement.rename(queue)
            return original_open(queue_fd)

        def write_log(*args, **kwargs):
            kwargs['stdout'].write(b'PINNED')
            return self.record(*args, **kwargs)

        with patch('shot_queue.open_queue_log', side_effect=swap_then_open):
            self.ensure(popen=write_log)
        self.assertEqual((held / '.watcher.log').read_bytes(), b'PINNED')
        self.assertFalse((queue / '.watcher.log').exists())

    def test_watcher_imports_sibling_helper_under_isolated_python(self):
        completed = subprocess.run(
            ['/usr/bin/python3', '-I', str(Path(shot_watcher.__file__))],
            cwd=self.tmp.name, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn('usage: shot_watcher.py', completed.stderr)
        self.assertNotIn('ModuleNotFoundError', completed.stderr)


class HTTPServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name).resolve() / 'workspace'
        (self.workspace / 'shots').mkdir(parents=True)
        self.workspace_fd = shot_queue.open_directory(self.workspace)
        self.server = shot_watcher.WorkspaceHTTPServer(('127.0.0.1', 0), self.workspace_fd)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._close_server)

    def _close_server(self):
        self.server.shutdown()
        self.server.server_close()
        os.close(self.workspace_fd)

    def get(self, path):
        url = 'http://127.0.0.1:' + str(self.server.server_address[1]) + path
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            try:
                return error.code, error.read()
            finally:
                error.close()

    def test_actual_get_denies_secrets_and_git_configuration(self):
        (self.workspace / '.env').write_text('SYNTHETIC_SECRET_MARKER')
        (self.workspace / 'nested').mkdir()
        (self.workspace / 'nested' / 'auth.json').write_text('SYNTHETIC_AUTH_MARKER')
        (self.workspace / '.git').mkdir()
        (self.workspace / '.git' / 'config').write_text('SYNTHETIC_GIT_MARKER')
        for path in ('/.env', '/.EnV', '/nested/auth.json', '/.git/config', '/.GIT/CONFIG'):
            status, body = self.get(path)
            self.assertEqual(status, 404)
            self.assertNotIn(b'SYNTHETIC_', body)

    def test_surviving_watcher_denies_every_backend_configuration_root(self):
        self.assertTrue(set(agentbelt.SECRET_NAMES).issubset(shot_watcher._SECRET_PATTERNS))
        for relative in agentbelt.ZCODE_WORKSPACE_CONFIG_PATHS:
            self.assertTrue(shot_watcher._forbidden_source(relative.split('/')), relative)
        for relative in ('.zcode/config.json', 'zcode.json', '.agents/mcp.json'):
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('SYNTHETIC_BACKEND_CONFIG_MARKER')
            status, body = self.get('/' + relative)
            self.assertEqual(status, 404, relative)
            self.assertNotIn(b'SYNTHETIC_BACKEND_CONFIG_MARKER', body)

    def test_actual_get_preserves_html_css_images_and_fonts(self):
        fixtures = {
            'shots/page.html': b'<link rel="stylesheet" href="/assets/site.css">',
            'assets/site.css': b'body { color: green; }',
            'assets/pixel.png': b'\x89PNG\r\nsynthetic',
            'assets/font.woff2': b'wOF2synthetic',
        }
        for relative, data in fixtures.items():
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            status, body = self.get('/' + relative)
            self.assertEqual((status, body), (200, data))

    def test_directory_traversal_listing_symlink_and_hardlink_are_denied(self):
        outside = Path(self.tmp.name) / 'outside.txt'
        outside.write_text('SYNTHETIC_OUTSIDE_MARKER')
        (self.workspace / 'shots' / 'symlink.css').symlink_to(outside)
        os.link(outside, self.workspace / 'shots' / 'hardlink.css')
        for path in ('/', '/shots/', '/%2e%2e/outside.txt', '/shots/symlink.css', '/shots/hardlink.css'):
            status, body = self.get(path)
            self.assertEqual(status, 404)
            self.assertNotIn(b'SYNTHETIC_OUTSIDE_MARKER', body)

    def test_server_keeps_the_opened_workspace_when_path_is_replaced(self):
        source = self.workspace / 'shots' / 'page.html'
        source.write_text('PINNED_WORKSPACE')
        moved = self.workspace.with_name('moved-workspace')
        self.workspace.rename(moved)
        (self.workspace / 'shots').mkdir(parents=True)
        (self.workspace / 'shots' / 'page.html').write_text('SWAPPED_WORKSPACE')
        status, body = self.get('/shots/page.html')
        self.assertEqual((status, body), (200, b'PINNED_WORKSPACE'))

    def test_unrelated_host_header_is_denied_without_cors(self):
        (self.workspace / 'shots' / 'page.html').write_text('SAFE')
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=2)
        try:
            connection.request('GET', '/shots/page.html', headers={'Host': 'attacker.example'})
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 404)
            self.assertNotIn(b'SAFE', body)
            self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
        finally:
            connection.close()

    def test_foreign_proxy_target_connect_and_upgrade_are_denied(self):
        expected = shot_watcher.SHOT_HOST + ':' + str(self.server.server_address[1])
        cases = [
            ('GET', 'http://127.0.0.1:9/shots/page.html', {'Host': expected}, 404),
            ('CONNECT', 'example.invalid:443', {'Host': 'example.invalid:443'}, 403),
            ('GET', '/shots/page.html', {'Host': expected, 'Connection': 'Upgrade', 'Upgrade': 'websocket'}, 403),
        ]
        (self.workspace / 'shots' / 'page.html').write_text('SAFE')
        for method, target, headers, status in cases:
            with self.subTest(method=method, target=target):
                connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=2)
                try:
                    connection.request(method, target, headers=headers)
                    response = connection.getresponse()
                    response.read()
                    self.assertEqual(response.status, status)
                finally:
                    connection.close()

    def test_allowed_response_has_restrictive_browser_policies(self):
        (self.workspace / 'shots' / 'page.html').write_text('SAFE')
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=2)
        try:
            connection.request('GET', '/shots/page.html')
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
            self.assertIn("connect-src 'none'", response.getheader('Content-Security-Policy'))
            permissions = response.getheader('Permissions-Policy')
            self.assertIn('clipboard-read=()', permissions)
            self.assertIn('camera=()', permissions)
            self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
        finally:
            connection.close()


class WatcherFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name) / 'workspace'
        self.workspace.mkdir()
        self.watcher = shot_watcher.ShotWatcher(self.workspace)
        self.watcher.server_port = 41234
        self.watcher.debug_port = 41235
        self.addCleanup(self.watcher.cleanup)
        self.queue = self.workspace / 'shots'

    def successful_browser(self, calls):
        def run(*args, **_kwargs):
            calls.append(args)
            if args and args[0] == 'screenshot':
                Path(args[-1]).write_bytes(b'PNG-SYNTHETIC')
            return result()
        return run


class WatcherLockTests(unittest.TestCase):
    def test_second_constructor_in_same_process_does_not_remove_first_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / 'workspace'
            workspace.mkdir()
            first = shot_watcher.ShotWatcher(workspace)
            try:
                with self.assertRaisesRegex(SystemExit, 'already running'):
                    shot_watcher.ShotWatcher(workspace)
                self.assertEqual((workspace / 'shots' / '.watcher.lock').read_text(), str(os.getpid()))
            finally:
                first.cleanup()


class RenderOutputTests(WatcherFixture):
    def test_error_output_replaces_symlink_without_touching_target(self):
        outside = Path(self.tmp.name) / 'outside.txt'
        outside.write_text('ORIGINAL')
        (self.queue / 'page.html').write_text('<p>test</p>')
        (self.queue / 'page.err.txt').symlink_to(outside)
        self.watcher.run_ab = lambda *_args, **_kwargs: result(1, stderr='synthetic failure')
        self.watcher.render('page.html')
        self.assertEqual(outside.read_text(), 'ORIGINAL')
        self.assertFalse((self.queue / 'page.err.txt').is_symlink())
        self.assertIn('synthetic failure', (self.queue / 'page.err.txt').read_text())

    def test_error_output_replaces_hardlink_without_touching_target(self):
        outside = Path(self.tmp.name) / 'outside.txt'
        outside.write_text('ORIGINAL')
        (self.queue / 'page.html').write_text('<p>test</p>')
        os.link(outside, self.queue / 'page.err.txt')
        self.watcher.run_ab = lambda *_args, **_kwargs: result(1, stderr='synthetic failure')
        self.watcher.render('page.html')
        self.assertEqual(outside.read_text(), 'ORIGINAL')
        self.assertEqual((self.queue / 'page.err.txt').stat().st_nlink, 1)

    def test_png_publication_replaces_links_without_touching_targets(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                outside = Path(self.tmp.name) / ('outside-' + kind + '.png')
                outside.write_bytes(b'ORIGINAL')
                output = self.queue / (kind + '.png')
                (self.queue / (kind + '.html')).write_text('<p>test</p>')
                if kind == 'symlink':
                    output.symlink_to(outside)
                else:
                    os.link(outside, output)
                calls = []
                self.watcher.run_ab = self.successful_browser(calls)
                self.watcher.render(kind + '.html')
                self.assertEqual(outside.read_bytes(), b'ORIGINAL')
                self.assertEqual(output.read_bytes(), b'PNG-SYNTHETIC')
                self.assertEqual(output.stat().st_nlink, 1)

    def test_queue_directory_swap_cannot_redirect_publication(self):
        (self.queue / 'page.html').write_text('<p>test</p>')
        held_queue = self.workspace / 'held-shots'
        self.queue.rename(held_queue)
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        self.queue.symlink_to(outside, target_is_directory=True)
        calls = []
        self.watcher.run_ab = self.successful_browser(calls)
        self.watcher.render('page.html')
        self.assertEqual((held_queue / 'page.png').read_bytes(), b'PNG-SYNTHETIC')
        self.assertFalse((outside / 'page.png').exists())

    def test_orphan_png_is_not_auto_deleted(self):
        orphan = self.queue / 'input.png'
        orphan.write_bytes(b'USER_INPUT')
        self.watcher.poll_once()
        self.assertEqual(orphan.read_bytes(), b'USER_INPUT')

    def test_viewport_full_delay_and_sidecar_defaults_remain(self):
        (self.queue / 'page.html').write_text('<p>test</p>')
        (self.queue / 'page.json').write_text(json.dumps({
            'width': 390, 'height': 844, 'full': False, 'delayMs': 125,
        }))
        calls = []
        self.watcher.run_ab = self.successful_browser(calls)
        self.watcher.render('page.html')
        self.assertEqual(calls[0], ('connect', '41235'))
        self.assertEqual(calls[1], ('set', 'viewport', '390', '844'))
        self.assertEqual(calls[3], ('wait', '125'))
        self.assertEqual(calls[4][0], 'screenshot')
        self.assertNotIn('--full', calls[4])
        self.assertEqual(self.watcher.view_options('missing'), {})


class FakeChrome:
    def __init__(self):
        self.terminated = False
        self.killed = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


class ReadyResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


class BrowserIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.chrome = Path(self.tmp.name) / 'chrome'
        self.chrome.write_text('synthetic binary placeholder')

    def watcher(self, name):
        workspace = Path(self.tmp.name) / name
        workspace.mkdir()
        watcher = shot_watcher.ShotWatcher(workspace)
        watcher.chrome_bin = str(self.chrome)
        watcher.agent_browser = '/synthetic/agent-browser'
        watcher.server_port = 41000 if name == 'one' else 41001
        self.addCleanup(watcher.cleanup)
        return watcher

    def test_two_watchers_use_distinct_sessions_homes_and_sandboxed_chrome(self):
        with patch.dict(os.environ, {
            'AGENT_BROWSER_SESSION': 'ambient-default',
            'AGENT_BROWSER_PROFILE': '/ambient/profile',
            'AGENT_BROWSER_CONFIG': '/ambient/config',
        }, clear=False):
            first = self.watcher('one')
            second = self.watcher('two')
        processes = []
        commands = []

        def popen(*args, **kwargs):
            processes.append((args, kwargs, FakeChrome()))
            return processes[-1][2]

        def run(*args, **kwargs):
            commands.append((args, kwargs))
            return result()

        with patch('shot_watcher.subprocess.Popen', side_effect=popen), \
             patch('shot_watcher.subprocess.run', side_effect=run), \
             patch('shot_watcher.urllib.request.urlopen', return_value=ReadyResponse()), \
             patch('shot_watcher.free_port', side_effect=[42000, 42001]):
            first.start_browser()
            second.start_browser()
            first.run_ab('wait', '0')
            second.run_ab('wait', '0')
            first.cleanup()
            second.cleanup()

        self.assertNotEqual(first.session, second.session)
        self.assertNotEqual(first.driver_env['HOME'], second.driver_env['HOME'])
        for watcher in (first, second):
            self.assertNotIn('AGENT_BROWSER_SESSION', watcher.driver_env)
            self.assertNotIn('AGENT_BROWSER_PROFILE', watcher.driver_env)
            self.assertNotIn('AGENT_BROWSER_CONFIG', watcher.driver_env)
        sessions = [call[0][0][call[0][0].index('--session') + 1] for call in commands]
        self.assertEqual(sessions, [first.session, second.session, first.session, second.session,
                                    first.session, second.session])
        for call, expected_port in zip(commands, ('42000', '42001', '42000', '42001', '42000', '42001')):
            self.assertEqual(call[0][0][call[0][0].index('--cdp') + 1], expected_port)
        self.assertIn('--init-script', commands[0][0][0])
        self.assertIn('--init-script', commands[1][0][0])
        self.assertNotIn('--init-script', commands[2][0][0])
        self.assertNotIn('--init-script', commands[3][0][0])
        self.assertIn('close', commands[4][0][0])
        self.assertIn('close', commands[5][0][0])
        for args, kwargs, _process in processes:
            argv = args[0]
            self.assertEqual(argv[0], str(self.chrome))
            for weakened in ('--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security',
                             '--allow-file-access-from-files', '--disable-site-isolation-trials'):
                self.assertNotIn(weakened, argv)
            self.assertIn('--remote-debugging-address=127.0.0.1', argv)
            self.assertIn('--proxy-bypass-list=<-loopback>', argv)
            self.assertIn('--disable-quic', argv)
            self.assertIn('--use-mock-keychain', argv)
            self.assertEqual(kwargs['env']['HOME'], str(kwargs['cwd'] / 'driver-home'))

    def test_connect_failure_stops_and_cleanup_never_closes_a_session(self):
        watcher = self.watcher('one')
        chrome = FakeChrome()
        calls = []

        def run(*args, **kwargs):
            calls.append((args, kwargs))
            return result(2, stderr='synthetic connect failure')

        with patch('shot_watcher.subprocess.Popen', return_value=chrome), \
             patch('shot_watcher.subprocess.run', side_effect=run), \
             patch('shot_watcher.urllib.request.urlopen', return_value=ReadyResponse()), \
             patch('shot_watcher.free_port', return_value=42000):
            with self.assertRaisesRegex(SystemExit, 'could not connect'):
                watcher.start_browser()
            watcher.cleanup()
        self.assertEqual(len(calls), 1)
        self.assertIn('connect', calls[0][0][0])
        self.assertTrue(chrome.terminated)


@unittest.skipUnless(
    sys.platform == 'darwin'
    and Path(shot_watcher.CHROME_DEFAULT).is_file()
    and shutil.which('agent-browser'),
    'requires local Chrome and agent-browser',
)
class LiveBrowserEgressTests(unittest.TestCase):
    def test_fresh_private_browser_renders_assets_without_direct_network_routes(self):
        hits = []

        class Endpoint(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append((self.command, self.path, self.headers.get('Upgrade')))
                self.send_response(204)
                self.end_headers()

            def log_message(self, _format, *_args):
                pass

        with tempfile.TemporaryDirectory(prefix='shot-browser-test-') as temporary:
            workspace = Path(temporary) / 'workspace'
            queue = workspace / 'shots'
            queue.mkdir(parents=True)
            assets = workspace / 'assets'
            assets.mkdir()
            (assets / 'site.css').write_text('body { color: rgb(1, 2, 3); }')
            (assets / 'pixel.png').write_bytes(base64.b64decode(
                'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAHnOcQAAAAABJRU5ErkJggg=='
            ))
            blocked_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
            thread = threading.Thread(target=blocked_server.serve_forever, daemon=True)
            thread.start()
            blocked_port = blocked_server.server_address[1]
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', 0))
            udp.settimeout(0.1)
            stun_port = udp.getsockname()[1]
            (queue / 'network.html').write_text(
                '<link rel="stylesheet" href="/assets/site.css">'
                '<body>WAIT<img id="local" src="/assets/pixel.png"><script>'
                "local.onload=()=>document.body.dataset.image='loaded';"
                "setTimeout(()=>document.body.dataset.style=getComputedStyle(document.body).color,200);"
                "fetch('http://127.0.0.1:" + str(blocked_port) + "/',{mode:'no-cors'})"
                ".then(()=>document.body.dataset.fetch='leak')"
                ".catch(()=>document.body.dataset.fetch='blocked');"
                "const ws=new WebSocket('ws://127.0.0.1:" + str(blocked_port) + "/socket');"
                "ws.onopen=()=>document.body.dataset.ws='leak';ws.onerror=()=>document.body.dataset.ws='blocked';"
                "const pc=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:" + str(stun_port) + "'}]});"
                "pc.createDataChannel('x');pc.createOffer().then(o=>pc.setLocalDescription(o));"
                '</script>'
            )
            watcher = shot_watcher.ShotWatcher(workspace)
            try:
                watcher.start_server()
                watcher.start_browser()
                watcher.render('network.html')
                watcher.run_ab('wait', '1000', timeout=15)
                state = watcher.run_ab(
                    'eval',
                    "document.body.dataset.image+'|'+document.body.dataset.style+'|'"
                    "+document.body.dataset.fetch+'|'+document.body.dataset.ws",
                    timeout=15,
                )
                self.assertEqual(state.returncode, 0, state.stderr)
                self.assertIn('loaded|rgb(1, 2, 3)|blocked|blocked', state.stdout)
                self.assertGreater((queue / 'network.png').stat().st_size, 0)
                navigation = watcher.run_ab('open', 'http://127.0.0.1:' + str(blocked_port) + '/foreign', timeout=15)
                if navigation.returncode == 0:
                    denied_page = watcher.run_ab('get', 'text', 'body', timeout=15)
                    self.assertIn('File not found', denied_page.stdout)
                self.assertEqual(hits, [])
                with self.assertRaises(socket.timeout):
                    udp.recvfrom(2048)
                for number, relative in enumerate(('.zcode/config.json', 'zcode.json', '.agents/mcp.json')):
                    target = workspace / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('SYNTHETIC_BACKEND_CONFIG_MARKER')
                    name = 'blocked-config-' + str(number) + '.html'
                    (queue / name).write_text('<script>location.href=' + json.dumps('/' + relative) + '</script>')
                    watcher.render(name)
                    page = watcher.run_ab('eval', 'document.body.textContent', timeout=15)
                    self.assertEqual(page.returncode, 0, page.stderr)
                    self.assertNotIn('SYNTHETIC_BACKEND_CONFIG_MARKER', page.stdout)
            finally:
                watcher.cleanup()
                blocked_server.shutdown()
                blocked_server.server_close()
                udp.close()


if __name__ == '__main__':
    unittest.main()
