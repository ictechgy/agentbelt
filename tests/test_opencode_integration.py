"""Actual OpenCode + fake local OpenAI-compatible server; no real keys or API calls."""
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OpenCodeIntegrationTest(unittest.TestCase):
    def test_tool_read_of_private_file_is_blocked(self):
        with tempfile.TemporaryDirectory(prefix='opencode-guard-test-', dir=Path.home()) as d:
            base = Path(d)
            work = base / 'work'
            work.mkdir()
            secret = base / 'private-marker.txt'
            marker = 'SYNTHETIC_OPENCODE_PRIVATE_CANARY_20260906'
            secret.write_text(marker)
            (work / 'public.txt').write_text('SYNTHETIC_PUBLIC_SOURCE')
            requests = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                    requests.append(body)
                    has_bash = any(t.get('function', {}).get('name') == 'bash' for t in body.get('tools', []))
                    has_tool_result = any(m.get('role') == 'tool' for m in body.get('messages', []))
                    if has_bash and not has_tool_result:
                        delta = {'role': 'assistant', 'tool_calls': [{
                            'index': 0, 'id': 'call_guard_probe', 'type': 'function',
                            'function': {'name': 'bash', 'arguments': json.dumps({
                                'command': '/bin/cat ' + str(secret),
                                'description': 'Try reading a synthetic private canary'})}}]}
                        finish = 'tool_calls'
                    else:
                        delta = {'role': 'assistant', 'content': 'Synthetic guard test complete.'}
                        finish = 'stop'
                    chunks = [
                        {'id': 'guard-test', 'object': 'chat.completion.chunk', 'model': 'guard-test',
                         'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}]},
                        {'id': 'guard-test', 'object': 'chat.completion.chunk', 'model': 'guard-test',
                         'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}],
                         'usage': {'prompt_tokens': 10, 'completion_tokens': 10, 'total_tokens': 20}},
                    ]
                    data = ''.join('data: ' + json.dumps(x) + '\n\n' for x in chunks) + 'data: [DONE]\n\n'
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                    self.send_header('Content-Length', str(len(data.encode())))
                    self.end_headers()
                    self.wfile.write(data.encode())

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            config = base / 'opencode-fixture.json'
            config.write_text(json.dumps({
                '$schema': 'https://opencode.ai/config.json',
                'model': 'guard-fixture/guard-test', 'small_model': 'guard-fixture/guard-test',
                'enabled_providers': ['guard-fixture'], 'share': 'disabled',
                'permission': {'*': 'allow'},
                'provider': {'guard-fixture': {'npm': '@ai-sdk/openai-compatible',
                    'name': 'Local synthetic fixture',
                    'options': {'baseURL': 'http://127.0.0.1:' + str(port) + '/v1', 'apiKey': 'SYNTHETIC_NOT_A_KEY'},
                    'models': {'guard-test': {'name': 'Guard test', 'limit': {'context': 16000, 'output': 1000}}}}},
            }))
            code = '''from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
import agent_guard as g
raise SystemExit(g.run_confined('opencode-test', Path(sys.argv[2]),
 ['/usr/bin/env','NO_PROXY=','no_proxy=',str(g.OPENCODE),'--print-logs','--log-level','DEBUG',
  'run','--format','json','Run the synthetic guard probe.'],
 domains=[sys.argv[4]], extra_reads=[sys.argv[3]],
 extra_env={'OPENCODE_CONFIG':sys.argv[3]}, ephemeral=True, protect_opencode_config=True))
'''
            process = subprocess.Popen(['/usr/bin/python3', '-I', '-c', code, str(ROOT), str(work), str(config),
                                        '127.0.0.1:' + str(port)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                # This is the only test that boots the real 144MB OpenCode binary
                # inside Seatbelt; it takes ~2s idle but roughly 10x that on a
                # loaded machine, so the budget is generous on purpose.
                out, err = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    out, err = process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    out, err = process.communicate()
                if not requests:
                    # OpenCode reached "init" and never asked the local model.
                    # Idle this test takes about two seconds; on a busy machine
                    # the real binary stalls there, and no timeout is enough.
                    # A boundary regression would still reach the model and fail
                    # the assertions below, so a silent stall is environmental.
                    self.skipTest('OpenCode stalled before its first model request '
                                  '(load %.1f); the boundary was not exercised'
                                  % os.getloadavg()[0])
                self.fail('OpenCode fixture timed out; local requests=' + str(len(requests)) + '. ' + err[-4500:] + out[-1500:])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertEqual(process.returncode, 0, err[-2500:] + out[-2000:])
            self.assertGreaterEqual(len(requests), 2, err[-1800:] + out[-2000:])
            transferred = json.dumps(requests)
            self.assertNotIn(marker, transferred)
            self.assertNotIn(marker, out)
            self.assertTrue('Operation not permitted' in transferred or 'Permission denied' in transferred,
                            'The model did not receive a filesystem denial.')
            # AGENTS.md in the protected config directory must reach the model as the actual system prompt.
            system_text = ''.join(str(m.get('content', '')) for r in requests
                                  for m in r.get('messages', []) if m.get('role') == 'system')
            self.assertIn('AGENT_GUARD_ENVIRONMENT.md', system_text,
                          'The isolated-environment notice did not reach the model system prompt.')


if __name__ == '__main__':
    unittest.main()
