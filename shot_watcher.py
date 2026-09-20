#!/usr/bin/env python3
"""Host-side screenshot queue for sandboxed agents (safekimi/safecode/zcode backend).

Why this exists. The confined child cannot run a browser: Chrome needs font/GPU
mach services the Seatbelt profile denies, and widening the profile to admit a
browser would expose the isolated home (including provider credentials) to the
renderer.  Instead the child writes HTML into <workspace>/shots/ and this
host-side watcher renders it and writes <name>.png back where the child can
read it -- the same artifact-exchange shape as the packet relay.

Egress rules, enforced on the host so the render channel cannot widen the
child's boundary:

- Pages are served to the browser over http://<SHOT_HOST>:<port>/... only.
  The local server answers GET/HEAD for paths that resolve inside the
  workspace and refuses symlink escapes, so the browser can never read files
  outside the workspace.
- Chrome itself is launched with --host-resolver-rules mapping every name to
  NOTFOUND except the internal shot host.  http(s) subresources die at DNS,
  and because the page origin is http (not file://), Chrome also refuses
  file:// subresources (credentials, /etc, home files) on its own.
- The render browser uses a fresh throwaway profile; nothing from the user's
  real browsing (cookies, cache) can leak into a shot.

Usage: shot_watcher.py <workspace>   (leave running while the session works)

Protocol for the child:
  write  shots/<name>.html            -> get shots/<name>.png
  write  shots/<name>.json (optional) -> {"width":1440,"height":900,"full":true,"delayMs":300}
  read   shots/<name>.err.txt         -> present only when the render failed
"""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Internal host name that Chrome's resolver rules map to 127.0.0.1.  Every
# other name -- including "localhost" and IP literals -- resolves to NOTFOUND,
# so a page can only ever reach the confined file server.
SHOT_HOST = 'agentbelt-shots.internal'
CHROME_DEFAULT = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
POLL_SECONDS = 0.6
RENDER_TIMEOUT = 45.0
VALID_EXTENSIONS = {'.html', '.htm'}
# 세션이 끝난 뒤 워처가 영원히 상주하지 않도록, 큐에 활동이 없으면 스스로 종료한다.
IDLE_LIMIT_SECONDS = 6 * 3600
_INTERNAL_NAMES = {'.watcher.lock', '.watcher.log', 'README.md'}

README = """# Screenshot queue

This directory is watched by a host-side renderer (`shot_watcher.py`).
Drop `<name>.html` here and a rendered `<name>.png` appears next to it;
editing the file re-renders automatically. `<name>.err.txt` explains failures.

Optional `shots/<name>.json` adjusts the render:

```json
{"width": 1440, "height": 900, "full": true, "delayMs": 300}
```

Rules: only files inside this workspace can be rendered, and the browser
cannot reach the network or local files -- external `http(s)` images,
`file://` references, and link previews all fail by design.
"""


def free_port():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


class WorkspaceHandler(SimpleHTTPRequestHandler):
    """GET/HEAD-only server confined to the workspace tree; symlinks may not escape it."""

    workspace = None  # Path, set before serve()

    def translate_path(self, path):
        # Resolve the URL path against the workspace and refuse escapes --
        # SimpleHTTPRequestHandler would happily follow a symlink out of the tree.
        raw = urllib.parse.urlsplit(path).path
        relative = urllib.parse.unquote(raw).lstrip('/')
        candidate = (self.workspace / relative).resolve()
        if candidate != self.workspace and self.workspace not in candidate.parents:
            return str(self.workspace / '__forbidden__')
        return str(candidate)

    def log_message(self, fmt, *args):
        pass


class ShotWatcher:
    def __init__(self, workspace):
        self.workspace = workspace.resolve()
        if not self.workspace.is_dir():
            raise SystemExit('workspace is not a directory: ' + str(workspace))
        self.queue = self.workspace / 'shots'
        self.queue.mkdir(exist_ok=True)
        self.lock_path = self.queue / '.watcher.lock'
        try:
            descriptor = os.open(str(self.lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            os.write(descriptor, str(os.getpid()).encode())
            os.close(descriptor)
        except FileExistsError:
            raise SystemExit('a shot watcher is already running for ' + str(self.workspace))
        self.tmpdir = Path(tempfile.mkdtemp(prefix='shot-watcher-'))
        self.chrome = None
        self.browser = None
        self.server = None
        self.server_port = None
        self.chrome_bin = os.environ.get('SHOT_WATCHER_CHROME', CHROME_DEFAULT)
        self.agent_browser = shutil.which('agent-browser')
        self.stopping = False

    def log(self, message):
        print('[shot-watcher] ' + message, flush=True)

    def start_server(self):
        WorkspaceHandler.workspace = self.workspace
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), WorkspaceHandler)
        self.server_port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.log('file server on 127.0.0.1:' + str(self.server_port) + ' for ' + str(self.workspace))

    def start_browser(self):
        if self.agent_browser is None:
            raise SystemExit('agent-browser CLI not found in PATH')
        if not Path(self.chrome_bin).is_file():
            raise SystemExit('chrome not found at ' + self.chrome_bin)
        debug_port = free_port()
        self.debug_port = debug_port
        profile = self.tmpdir / 'chrome-profile'
        self.chrome = subprocess.Popen(
            [self.chrome_bin, '--headless=new', '--disable-gpu', '--no-first-run',
             '--no-default-browser-check', '--user-data-dir=' + str(profile),
             '--remote-debugging-port=' + str(debug_port),
             '--host-resolver-rules=MAP ' + SHOT_HOST + ' 127.0.0.1, MAP * ~NOTFOUND',
             'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with urllib.request.urlopen('http://127.0.0.1:' + str(debug_port) + '/json/version', timeout=1) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.25)
        else:
            raise SystemExit('chrome debug port did not come up')
        self.run_ab('connect', str(debug_port), timeout=15)
        self.log('headless chrome attached (debug port ' + str(debug_port) + ', resolver: ' + SHOT_HOST + ' only)')

    def run_ab(self, *args, timeout=RENDER_TIMEOUT):
        result = subprocess.run([self.agent_browser, *args], capture_output=True, text=True, timeout=timeout)
        return result

    def page_url(self, relative):
        return 'http://' + SHOT_HOST + ':' + str(self.server_port) + '/' + urllib.parse.quote(relative)

    def view_options(self, stem):
        view = self.queue / (stem + '.json')
        if not view.is_file():
            return {}
        try:
            data = json.loads(view.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def render(self, html_path):
        stem = html_path.stem
        relative = html_path.relative_to(self.workspace).as_posix()
        options = self.view_options(stem)
        width = options.get('width') if isinstance(options.get('width'), int) else 1280
        height = options.get('height') if isinstance(options.get('height'), int) else 800
        width = max(200, min(width, 4096))
        height = max(200, min(height, 4096))
        delay_ms = options.get('delayMs') if isinstance(options.get('delayMs'), int) else 350
        delay_ms = max(0, min(delay_ms, 10000))
        full = options.get('full', True) is not False
        tmp_png = self.tmpdir / (stem + '.png')
        steps = [
            ('set', 'viewport', str(width), str(height)),
            ('open', self.page_url(relative)),
            ('wait', str(delay_ms)),
        ]
        shot_args = ['screenshot'] + (['--full'] if full else []) + [str(tmp_png)]
        try:
            for step in steps:
                result = self.run_ab(*step)
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout).strip()[:300])
            result = self.run_ab(*shot_args)
            if result.returncode != 0 or not tmp_png.is_file() or tmp_png.stat().st_size == 0:
                raise RuntimeError((result.stderr or result.stdout).strip()[:300] or 'empty screenshot')
            os.replace(tmp_png, self.queue / (stem + '.png'))
            err = self.queue / (stem + '.err.txt')
            if err.exists():
                err.unlink()
            self.log('rendered ' + relative + ' -> shots/' + stem + '.png')
        except Exception as error:
            (self.queue / (stem + '.err.txt')).write_text('render failed: ' + str(error) + '\n')
            self.log('FAILED ' + relative + ': ' + str(error)[:200])

    def stale_pngs(self):
        for png in self.queue.glob('*.png'):
            if not (self.queue / (png.stem + '.html')).exists() and not (self.queue / (png.stem + '.htm')).exists():
                png.unlink()

    def poll_once(self):
        self.stale_pngs()
        for html_path in sorted(self.queue.iterdir()):
            if html_path.suffix.lower() not in VALID_EXTENSIONS or not html_path.is_file():
                continue
            stem = html_path.stem
            png = self.queue / (stem + '.png')
            view = self.queue / (stem + '.json')
            # 요청 파일이 workspace를 벗어나면 렌더 자체를 거부한다 (서버의
            # translate_path 차단과 별개의 사전 방어선).
            resolved = html_path.resolve()
            if resolved != self.workspace and self.workspace not in resolved.parents:
                err = self.queue / (stem + '.err.txt')
                if not err.exists():
                    err.write_text('render refused: file resolves outside the workspace\n')
                if png.exists():
                    png.unlink()
                continue
            try:
                html_mtime = html_path.stat().st_mtime
            except OSError:
                continue
            needs = (not png.exists()
                     or png.stat().st_mtime < html_mtime
                     or (view.exists() and png.stat().st_mtime < view.stat().st_mtime))
            if needs:
                self.render(html_path)

    def run(self):
        readme = self.queue / 'README.md'
        if not readme.exists():
            readme.write_text(README)
        self.start_server()
        self.start_browser()
        self.log('watching ' + str(self.queue) + ' -- drop <name>.html to get <name>.png')
        last_activity = time.time()
        while not self.stopping:
            try:
                self.poll_once()
                for entry in self.queue.iterdir():
                    if entry.name not in _INTERNAL_NAMES:
                        try:
                            last_activity = max(last_activity, entry.stat().st_mtime)
                        except OSError:
                            pass
                if time.time() - last_activity > IDLE_LIMIT_SECONDS:
                    self.log('idle limit reached -- exiting')
                    break
            except Exception as error:
                self.log('poll error: ' + str(error)[:200])
            time.sleep(POLL_SECONDS)

    def stop(self, *_args):
        self.stopping = True

    def cleanup(self):
        try:
            self.run_ab('close', timeout=5)
        except Exception:
            pass
        if self.chrome is not None:
            self.chrome.terminate()
            try:
                self.chrome.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.chrome.kill()
        if self.server is not None:
            self.server.shutdown()
        if self.lock_path.exists():
            self.lock_path.unlink()
        shutil.rmtree(self.tmpdir, ignore_errors=True)


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
