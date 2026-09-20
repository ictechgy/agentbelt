#!/usr/bin/env python3
"""Host-side screenshot queue for sandboxed agents.

The child writes HTML under ``<workspace>/shots`` and this host process returns
a PNG beside it.  Two boundaries matter here:

* the HTTP server opens every source through held, no-follow directory
  descriptors and refuses project secret names, protected git configuration,
  links, special files, and directory listings;
* the private Chrome keeps its native process sandbox and sends all browser
  traffic to this same server as a non-forwarding proxy.  Foreign targets,
  tunnels, and upgrades are rejected.  The profile, agent-browser HOME,
  config, and session are unique to this watcher.

Usage: ``shot_watcher.py <workspace>``

Queue protocol:
  write  shots/<name>.html            -> get shots/<name>.png
  write  shots/<name>.json (optional) -> {"width":1440,"height":900,"full":true,"delayMs":300}
  read   shots/<name>.err.txt         -> present only when the render failed
"""

import fnmatch
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# The launcher intentionally uses ``python -I``.  Isolated mode removes the
# script directory from sys.path, so restore only this trusted sibling path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import shot_queue  # noqa: E402


SHOT_HOST = '127.0.0.1'
CHROME_DEFAULT = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
POLL_SECONDS = 0.6
RENDER_TIMEOUT = 45.0
VALID_EXTENSIONS = {'.html', '.htm'}
IDLE_LIMIT_SECONDS = 6 * 3600
_INTERNAL_NAMES = {'.watcher.lock', '.watcher.log', 'README.md'}
_SECRET_PATTERNS = (
    '.env*', '.ENV*', '*.env', '*.env.*', '*.pem', '*.key', '*.p12', '*.pfx', '*.keystore',
    'id_rsa*', 'id_ed25519*', 'auth.json', 'credentials', 'credentials.*',
    'secrets', 'secrets.*', '.ssh', '.aws', '.azure', '.kube', '.gnupg',
    '.npmrc', '.netrc', '.pypirc', '*.sqlite', '*.sqlite3', '*.db', '*.dump',
)

README = """# Screenshot queue

This directory is watched by a host-side renderer (`shot_watcher.py`).
Drop `<name>.html` here and a rendered `<name>.png` appears next to it;
editing the file re-renders automatically. `<name>.err.txt` explains failures.

Optional `shots/<name>.json` adjusts the render:

```json
{"width": 1440, "height": 900, "full": true, "delayMs": 300}
```

Rules: ordinary HTML, CSS, images, and fonts in this workspace are available.
Project secrets, agent configuration and protected git configuration are not. The renderer
cannot reach other local ports, the LAN, or the external network.
"""


def free_port():
    listener = socket.socket()
    try:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]
    finally:
        listener.close()


def _forbidden_source(parts):
    # A detached watcher may outlive the Kimi/OpenCode session that created it.
    # Apply the stricter Zcode/AutoClaw root exclusions for every renderer.
    folded_parts = [part.casefold() for part in parts]
    if (folded_parts and folded_parts[0] in ('.zcode', 'zcode.json')) \
            or folded_parts[:2] == ['.agents', 'mcp.json']:
        return True
    for name in parts:
        folded = name.casefold()
        if any(fnmatch.fnmatchcase(folded, pattern.casefold()) for pattern in _SECRET_PATTERNS):
            return True
    for index, name in enumerate(parts[:-1]):
        if name.casefold() != '.git':
            continue
        tail = [part.casefold() for part in parts[index + 1:]]
        if tail[0] in ('config', 'config.worktree', 'hooks'):
            return True
        if tail[:2] == ['info', 'attributes']:
            return True
    return False


def _request_parts(path):
    raw = urllib.parse.urlsplit(path).path
    try:
        decoded = urllib.parse.unquote(raw, errors='strict')
    except UnicodeError:
        raise OSError('invalid URL encoding') from None
    if '\x00' in decoded:
        raise OSError('NUL in URL path')
    parts = [part for part in decoded.split('/') if part not in ('', '.')]
    if not parts or any(part == '..' for part in parts) or _forbidden_source(parts):
        raise OSError('forbidden source path')
    return parts


def open_workspace_request(workspace_fd, path):
    """Open the requested regular single-link file beneath a pinned workspace."""
    parts = _request_parts(path)
    descriptor = os.dup(workspace_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        result = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=descriptor,
        )
        try:
            info = os.fstat(result)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError('source must be a regular single-link file')
            return result, info, parts[-1]
        except BaseException:
            os.close(result)
            raise
    finally:
        os.close(descriptor)


class WorkspaceHandler(SimpleHTTPRequestHandler):
    """GET/HEAD-only descriptor-relative workspace server with no listings."""

    def send_head(self):
        expected_host = SHOT_HOST + ':' + str(self.server.server_address[1])
        if self.headers.get('Host') != expected_host:
            self.send_error(404, 'File not found')
            return None
        target = urllib.parse.urlsplit(self.path)
        if target.scheme or target.netloc:
            if target.scheme != 'http' or target.netloc != expected_host:
                self.send_error(404, 'File not found')
                return None
        if self.headers.get('Upgrade') or 'upgrade' in self.headers.get('Connection', '').casefold():
            self.send_error(403, 'Protocol upgrade denied')
            return None
        try:
            descriptor, info, name = open_workspace_request(self.server.workspace_fd, self.path)
        except (OSError, ValueError):
            self.send_error(404, 'File not found')
            return None
        try:
            self.send_response(200)
            self.send_header('Content-Type', self.guess_type(name))
            self.send_header('Content-Length', str(info.st_size))
            self.send_header('Last-Modified', self.date_time_string(info.st_mtime))
            self.end_headers()
            return os.fdopen(descriptor, 'rb')
        except BaseException:
            os.close(descriptor)
            raise

    def list_directory(self, _path):
        self.send_error(404, 'File not found')
        return None

    def do_CONNECT(self):
        try:
            self.send_response(403, 'Proxy tunnels are denied')
            self.send_header('Content-Length', '0')
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; "
            "connect-src 'none'; form-action 'none'; worker-src 'none'; "
            "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; media-src 'self' data:",
        )
        self.send_header(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), display-capture=(), '
            'clipboard-read=(), clipboard-write=(), usb=(), serial=(), payment=(), '
            'local-network-access=()',
        )
        super().end_headers()

    def log_message(self, _fmt, *_args):
        pass


class WorkspaceHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, workspace_fd):
        self.workspace_fd = os.dup(workspace_fd)
        try:
            super().__init__(address, WorkspaceHandler)
        except BaseException:
            os.close(self.workspace_fd)
            raise

    def server_close(self):
        try:
            super().server_close()
        finally:
            if self.workspace_fd is not None:
                os.close(self.workspace_fd)
                self.workspace_fd = None


class ShotWatcher:
    def __init__(self, workspace):
        self.workspace = Path(workspace).resolve(strict=True)
        if not self.workspace.is_dir():
            raise SystemExit('workspace is not a directory: ' + str(workspace))
        self.workspace_fd = None
        self.queue_fd = None
        self.tmpdir = None
        self.chrome = None
        self.server = None
        self.server_thread = None
        self.server_port = None
        self.debug_port = None
        self.browser_connected = False
        self.stopping = False
        self.lock_acquired = False
        try:
            self.workspace_fd = shot_queue.open_directory(self.workspace)
            self.queue_fd = shot_queue.open_child_directory(self.workspace_fd, 'shots', create=True)
            if not shot_queue.acquire_lock(self.queue_fd, os.getpid()):
                raise SystemExit('a shot watcher is already running for ' + str(self.workspace))
            self.lock_acquired = True
            temporary_parent = '/private/tmp' if Path('/private/tmp').is_dir() else None
            self.tmpdir = Path(tempfile.mkdtemp(prefix='shot-watcher-', dir=temporary_parent))
            self.driver_home = self.tmpdir / 'driver-home'
            self.driver_home.mkdir(mode=0o700)
            self.driver_socket_dir = self.tmpdir / 's'
            self.driver_socket_dir.mkdir(mode=0o700)
            self.driver_config = self.tmpdir / 'agent-browser.json'
            self.driver_config.write_text('{}\n')
            self.browser_guard = self.tmpdir / 'browser-guard.js'
            self.browser_guard.write_text(
                "for (const name of ['RTCPeerConnection','webkitRTCPeerConnection']) {"
                "Object.defineProperty(globalThis,name,{value:undefined,writable:false,configurable:false});}"
            )
            self.session = 'shot-' + secrets.token_hex(8)
            self.chrome_bin = os.environ.get('SHOT_WATCHER_CHROME', CHROME_DEFAULT)
            self.agent_browser = shutil.which('agent-browser')
            self.driver_env = {key: value for key, value in os.environ.items()
                               if not key.startswith('AGENT_BROWSER_')}
            self.driver_env.update({
                'HOME': str(self.driver_home),
                'XDG_CONFIG_HOME': str(self.driver_home / '.config'),
                'XDG_CACHE_HOME': str(self.driver_home / '.cache'),
                'XDG_STATE_HOME': str(self.driver_home / '.state'),
                'TMPDIR': str(self.tmpdir),
                'AGENT_BROWSER_IDLE_TIMEOUT_MS': '5000',
                'AGENT_BROWSER_SOCKET_DIR': str(self.driver_socket_dir),
            })
        except BaseException:
            if (self.lock_acquired and self.queue_fd is not None
                    and shot_queue.read_lock_pid(self.queue_fd) == os.getpid()):
                shot_queue.unlink_name(self.queue_fd, '.watcher.lock')
            if self.queue_fd is not None:
                os.close(self.queue_fd)
            if self.workspace_fd is not None:
                os.close(self.workspace_fd)
            if self.tmpdir is not None:
                shutil.rmtree(self.tmpdir, ignore_errors=True)
            raise

    def log(self, message):
        print('[shot-watcher] ' + message, flush=True)

    def start_server(self):
        self.server = WorkspaceHTTPServer(('127.0.0.1', 0), self.workspace_fd)
        self.server_port = self.server.server_address[1]
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.log('file server on 127.0.0.1:' + str(self.server_port) + ' for ' + str(self.workspace))

    def start_browser(self):
        if self.agent_browser is None:
            raise SystemExit('agent-browser CLI not found in PATH')
        if not Path(self.chrome_bin).is_file():
            raise SystemExit('chrome not found at ' + self.chrome_bin)
        if self.server_port is None:
            raise SystemExit('screenshot file server is not running')
        self.debug_port = free_port()
        chrome_profile = self.tmpdir / 'chrome-profile'
        command = [
            self.chrome_bin,
            '--headless=new', '--disable-gpu', '--disable-background-networking',
            '--disable-component-update', '--disable-sync', '--no-first-run',
            '--no-default-browser-check', '--use-mock-keychain', '--password-store=basic',
            '--user-data-dir=' + str(chrome_profile),
            '--remote-debugging-address=127.0.0.1',
            '--remote-debugging-port=' + str(self.debug_port),
            '--proxy-server=http://127.0.0.1:' + str(self.server_port),
            '--proxy-bypass-list=<-loopback>',
            '--disable-quic',
            '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--host-resolver-rules=EXCLUDE 127.0.0.1, MAP * ~NOTFOUND',
            'about:blank',
        ]
        self.chrome = subprocess.Popen(
            command,
            cwd=self.tmpdir,
            env=self.driver_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                    'http://127.0.0.1:' + str(self.debug_port) + '/json/version', timeout=1
                ) as response:
                    if response.status == 200:
                        break
            except Exception:
                if self.chrome.poll() is not None:
                    raise SystemExit('sandboxed chrome exited before its debug port came up')
                time.sleep(0.25)
        else:
            raise SystemExit('chrome debug port did not come up')
        try:
            self.connect_browser()
        except RuntimeError as error:
            raise SystemExit(str(error)) from None
        self.log('sandboxed headless chrome attached (private session ' + self.session + ')')

    def run_ab(self, *args, timeout=RENDER_TIMEOUT, initialize=False):
        if self.agent_browser is None:
            raise RuntimeError('agent-browser CLI not found')
        command = [
            self.agent_browser,
            '--session', self.session,
            '--config', str(self.driver_config),
            *(['--init-script', str(self.browser_guard)] if initialize else []),
            '--cdp', str(self.debug_port),
            *args,
        ]
        return subprocess.run(
            command,
            cwd=self.tmpdir,
            env=self.driver_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def connect_browser(self):
        """Attach this named driver and reinstall the guard after daemon restarts."""
        result = self.run_ab('connect', str(self.debug_port), timeout=15, initialize=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:300]
            raise RuntimeError('agent-browser could not connect to private chrome'
                               + (': ' + detail if detail else ''))
        self.browser_connected = True

    def page_url(self, html_name):
        relative = 'shots/' + html_name
        return 'http://' + SHOT_HOST + ':' + str(self.server_port) + '/' + urllib.parse.quote(relative)

    def view_options(self, stem):
        try:
            raw = shot_queue.read_bytes(self.queue_fd, stem + '.json', shot_queue.MAX_OPTIONS_BYTES)
            data = json.loads(raw.decode('utf-8'))
            return data if isinstance(data, dict) else {}
        except (OSError, UnicodeError, ValueError):
            return {}

    def render(self, html_name):
        stem = Path(html_name).stem
        options = self.view_options(stem)
        width = options.get('width') if isinstance(options.get('width'), int) else 1280
        height = options.get('height') if isinstance(options.get('height'), int) else 800
        width = max(200, min(width, 4096))
        height = max(200, min(height, 4096))
        delay_ms = options.get('delayMs') if isinstance(options.get('delayMs'), int) else 350
        delay_ms = max(0, min(delay_ms, 10000))
        full = options.get('full', True) is not False
        temporary_name = hashlib.sha256(html_name.encode('utf-8', 'surrogatepass')).hexdigest() + '.png'
        tmp_png = self.tmpdir / temporary_name
        try:
            tmp_png.unlink()
        except FileNotFoundError:
            pass
        steps = [
            ('set', 'viewport', str(width), str(height)),
            ('open', self.page_url(html_name)),
            ('wait', str(delay_ms)),
        ]
        shot_args = ['screenshot'] + (['--full'] if full else []) + [str(tmp_png)]
        try:
            self.connect_browser()
            for step in steps:
                result = self.run_ab(*step)
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout).strip()[:300] or 'browser command failed')
            result = self.run_ab(*shot_args)
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout).strip()[:300] or 'screenshot failed')
            info = tmp_png.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size == 0:
                raise RuntimeError('empty or unsafe screenshot output')
            shot_queue.publish_file(self.queue_fd, stem + '.png', tmp_png)
            shot_queue.unlink_name(self.queue_fd, stem + '.err.txt')
            self.log('rendered shots/' + html_name + ' -> shots/' + stem + '.png')
        except Exception as error:
            message = ('render failed: ' + str(error)[:300] + '\n').encode('utf-8', 'replace')
            try:
                shot_queue.atomic_write(self.queue_fd, stem + '.err.txt', message)
            except OSError as write_error:
                self.log('FAILED to record shots/' + stem + '.err.txt: ' + str(write_error)[:160])
            self.log('FAILED shots/' + html_name + ': ' + str(error)[:200])

    def poll_once(self):
        try:
            names = sorted(os.listdir(self.queue_fd))
        except OSError:
            return
        for html_name in names:
            if Path(html_name).suffix.lower() not in VALID_EXTENSIONS:
                continue
            html_info = shot_queue.regular_stat(self.queue_fd, html_name)
            if html_info is None:
                continue
            stem = Path(html_name).stem
            png_info = shot_queue.regular_stat(self.queue_fd, stem + '.png', shot_queue.MAX_PNG_BYTES)
            view_info = shot_queue.regular_stat(self.queue_fd, stem + '.json', shot_queue.MAX_OPTIONS_BYTES)
            needs = (png_info is None
                     or png_info.st_mtime_ns < html_info.st_mtime_ns
                     or (view_info is not None and png_info.st_mtime_ns < view_info.st_mtime_ns))
            if needs:
                self.render(html_name)

    def run(self):
        if shot_queue.regular_stat(self.queue_fd, 'README.md', len(README.encode()) * 2) is None:
            shot_queue.atomic_write(self.queue_fd, 'README.md', README, maximum=len(README.encode()) * 2)
        self.start_server()
        self.start_browser()
        self.log('watching ' + str(self.workspace / 'shots') + ' -- drop <name>.html to get <name>.png')
        last_activity = time.time()
        while not self.stopping:
            try:
                self.poll_once()
                for name in os.listdir(self.queue_fd):
                    if name in _INTERNAL_NAMES:
                        continue
                    info = shot_queue.regular_stat(self.queue_fd, name)
                    if info is not None:
                        last_activity = max(last_activity, info.st_mtime)
                if time.time() - last_activity > IDLE_LIMIT_SECONDS:
                    self.log('idle limit reached -- exiting')
                    break
            except Exception as error:
                self.log('poll error: ' + str(error)[:200])
            time.sleep(POLL_SECONDS)

    def stop(self, *_args):
        self.stopping = True

    def cleanup(self):
        if self.browser_connected and self.chrome is not None and self.chrome.poll() is None:
            try:
                self.run_ab('close', timeout=5)
            except Exception:
                pass
        self.browser_connected = False
        if self.chrome is not None:
            self.chrome.terminate()
            try:
                self.chrome.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.chrome.kill()
                self.chrome.wait(timeout=5)
            self.chrome = None
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.queue_fd is not None:
            if self.lock_acquired and shot_queue.read_lock_pid(self.queue_fd) == os.getpid():
                shot_queue.unlink_name(self.queue_fd, '.watcher.lock')
            self.lock_acquired = False
            os.close(self.queue_fd)
            self.queue_fd = None
        if self.workspace_fd is not None:
            os.close(self.workspace_fd)
            self.workspace_fd = None
        if self.tmpdir is not None:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
            self.tmpdir = None


def main():
    if len(sys.argv) != 2:
        print('usage: shot_watcher.py <workspace>', file=sys.stderr)
        return 2
    watcher = ShotWatcher(Path(sys.argv[1]))
    signal.signal(signal.SIGINT, watcher.stop)
    signal.signal(signal.SIGTERM, watcher.stop)
    try:
        watcher.run()
    finally:
        watcher.cleanup()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
