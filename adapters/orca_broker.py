"""Relay OpenCode status to Orca without letting the sandbox reach Orca itself.

The child is given this broker's port and a per-launch token; Orca's real port,
token and pane identity never enter the sandbox. Identity fields are rewritten
from the launcher's own environment, so a compromised agent can report status
only for its own pane and cannot address Orca's hook API directly.
"""
import http.server
import json
import os
from pathlib import Path
import secrets
import threading
import urllib.error
import urllib.request

MAX_BODY = 64 * 1024
FORWARD_TIMEOUT = 3
HOOK_PATH = '/hook/opencode'


def host_coordinates():
    """Read Orca's endpoint from this launcher's environment, never the child's."""
    values = {}
    endpoint = os.environ.get('ORCA_AGENT_HOOK_ENDPOINT')
    if endpoint:
        try:
            for line in Path(endpoint).read_text().splitlines():
                name, separator, value = line.partition('=')
                if separator:
                    values[name.strip()] = value.strip()
        except OSError:
            values = {}
    def pick(name):
        return values.get(name) or os.environ.get(name) or ''
    return {'port': pick('ORCA_AGENT_HOOK_PORT'), 'token': pick('ORCA_AGENT_HOOK_TOKEN'),
            'env': pick('ORCA_AGENT_HOOK_ENV'), 'version': pick('ORCA_AGENT_HOOK_VERSION'),
            'paneKey': os.environ.get('ORCA_PANE_KEY', ''),
            'tabId': os.environ.get('ORCA_TAB_ID', ''),
            'worktreeId': os.environ.get('ORCA_WORKTREE_ID', ''),
            'launchToken': os.environ.get('ORCA_AGENT_LAUNCH_TOKEN', '')}


def usable(coordinates):
    """Orca is reachable only when a port, a token and this pane's key are known."""
    return bool(coordinates['port'] and coordinates['token'] and coordinates['paneKey'])


class QuietServer(http.server.ThreadingHTTPServer):
    """A relay whose clients disappear mid-request as a matter of course.

    socketserver's default handler prints a traceback for every dropped
    connection, and this server's stderr is the operator's terminal, so the
    noise lands on their screen. A client going away is not an error here.
    """

    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class StatusBroker:
    """A loopback listener the sandbox may reach, forwarding only vetted status."""

    def __init__(self, coordinates):
        self.coordinates = coordinates
        self.token = secrets.token_hex(16)
        self.server = QuietServer(('127.0.0.1', 0), self.handler())
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def child_environment(self):
        """What the sandbox is told: this broker, and identity it already owns."""
        return {'ORCA_AGENT_HOOK_PORT': str(self.port), 'ORCA_AGENT_HOOK_TOKEN': self.token,
                'ORCA_AGENT_HOOK_ENV': self.coordinates['env'],
                'ORCA_AGENT_HOOK_VERSION': self.coordinates['version'],
                'ORCA_PANE_KEY': self.coordinates['paneKey'],
                'ORCA_TAB_ID': self.coordinates['tabId'],
                'ORCA_WORKTREE_ID': self.coordinates['worktreeId']}

    def forward(self, payload):
        """Rebuild the envelope from host state; the child only supplies payload."""
        body = json.dumps({'paneKey': self.coordinates['paneKey'],
                           'launchToken': self.coordinates['launchToken'],
                           'tabId': self.coordinates['tabId'],
                           'worktreeId': self.coordinates['worktreeId'],
                           'env': self.coordinates['env'],
                           'version': self.coordinates['version'],
                           'payload': payload}).encode()
        request = urllib.request.Request(
            'http://127.0.0.1:' + self.coordinates['port'] + HOOK_PATH, data=body,
            headers={'Content-Type': 'application/json',
                     'X-Orca-Agent-Hook-Token': self.coordinates['token']})
        try:
            with urllib.request.urlopen(request, timeout=FORWARD_TIMEOUT):
                return True
        except (urllib.error.URLError, OSError):
            # Orca being unavailable must never disturb the agent run.
            return False

    def handler(self):
        broker = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def reply(self, status):
                self.send_response(status)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_POST(self):
                if self.path != HOOK_PATH:
                    return self.reply(404)
                # The per-launch token proves the caller is this sandbox, not
                # another local process that happened to find the port.
                if self.headers.get('X-Orca-Agent-Hook-Token') != broker.token:
                    return self.reply(403)
                try:
                    length = int(self.headers.get('Content-Length', 0))
                except ValueError:
                    return self.reply(400)
                if length <= 0 or length > MAX_BODY:
                    return self.reply(413)
                try:
                    message = json.loads(self.rfile.read(length))
                except (ValueError, OSError):
                    return self.reply(400)
                payload = message.get('payload') if isinstance(message, dict) else None
                if not isinstance(payload, dict) or not isinstance(payload.get('hook_event_name'), str):
                    return self.reply(400)
                # Never hand Orca's response back; the child learns only that
                # the status was accepted for relay.
                broker.forward(payload)
                return self.reply(200)

            def log_message(self, *arguments):
                pass

        return Handler

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *details):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
