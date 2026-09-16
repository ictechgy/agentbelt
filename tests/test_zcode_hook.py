import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ZcodeHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zcode-hook-test-', dir=Path.home())
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        self.work.mkdir()
        (self.work / 'source.py').write_text('print("synthetic")\n')
        (self.work / '.env').write_text('SYNTHETIC_SECRET=only-a-test')
        self.outside = self.base / 'private.txt'
        self.outside.write_text('SYNTHETIC_PRIVATE')

    def tearDown(self):
        self.temp.cleanup()

    def hook(self, tool, data, cwd=None, raw=None):
        payload = {'hook_event_name': 'PreToolUse', 'cwd': str(cwd or self.work),
                   'tool_name': tool, 'tool_input': data}
        result = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / 'zcode_hook.py')],
                                input=raw if raw is not None else json.dumps(payload)+'\n',
                                capture_output=True, text=True, timeout=10)
        return result, json.loads(result.stdout)['hookSpecificOutput']

    def test_public_read_allowed(self):
        result, decision = self.hook('Read', {'file_path': 'source.py'})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(decision['permissionDecision'], 'allow')

    def test_outside_read_denied(self):
        _, decision = self.hook('Read', {'file_path': str(self.outside)})
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_env_read_denied(self):
        _, decision = self.hook('Read', {'file_path': '.env'})
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_symlink_escape_denied(self):
        (self.work / 'link.py').symlink_to(self.outside)
        _, decision = self.hook('Read', {'file_path': 'link.py'})
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_hardlink_escape_denied(self):
        os.link(self.outside, self.work / 'link.py')
        _, decision = self.hook('Read', {'file_path': 'link.py'})
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_bash_is_rewritten_without_interpreting_payload(self):
        original = 'printf "%s" "$(cat ~/.ssh/test-key)"; echo done'
        _, decision = self.hook('Bash', {'command': original, 'timeout': 1000})
        self.assertEqual(decision['permissionDecision'], 'ask')
        updated = decision['updatedInput']
        argv = shlex.split(updated['command'])
        self.assertEqual(argv[:2], ['/usr/bin/python3', '-I'])
        self.assertEqual(argv[2], str(ROOT / 'agent_guard.py'))
        self.assertEqual(argv[3], 'zcode-shell')
        self.assertEqual(argv[4], str(self.work))
        self.assertEqual(base64.b64decode(argv[5]).decode(), original)
        self.assertEqual(updated['timeout'], 1000)
        self.assertFalse(updated['dangerouslyDisableSandbox'])

    def test_explicit_sandbox_bypass_denied(self):
        _, decision = self.hook('Bash', {'command': 'echo test', 'dangerouslyDisableSandbox': True})
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_global_search_without_backend_confinement_denied(self):
        _, decision = self.hook('Grep', {'pattern': 'SYNTHETIC'})
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_arbitrary_js_and_mcp_denied(self):
        for name in ['js', 'js_add_node_module_dir', 'mcp__anything', 'CronCreate']:
            with self.subTest(name=name):
                _, decision = self.hook(name, {})
                self.assertEqual(decision['permissionDecision'], 'deny')

    def test_home_cannot_be_treated_as_project(self):
        _, decision = self.hook('Read', {'file_path': str(self.work / 'source.py')}, cwd=Path.home())
        self.assertEqual(decision['permissionDecision'], 'deny')

    def test_invalid_json_fails_closed_without_echo(self):
        result, decision = self.hook('Read', {}, raw='INVALID_SYNTHETIC_SECRET\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(decision['permissionDecision'], 'deny')
        self.assertNotIn('INVALID_SYNTHETIC_SECRET', result.stdout+result.stderr)

    def test_environment_marker_alone_does_not_enable_search(self):
        payload = {'hook_event_name': 'PreToolUse', 'cwd': str(self.work),
                   'tool_name': 'Grep', 'tool_input': {'pattern': 'test'}}
        result = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / 'zcode_hook.py')],
                                input=json.dumps(payload)+'\n', capture_output=True, text=True,
                                env=dict(os.environ, AGENT_GUARD_BACKEND='zcode-v1'), timeout=10)
        self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_rewritten_bash_really_blocks_outside_file(self):
        _, decision = self.hook('Bash', {'command': '/bin/cat ' + shlex.quote(str(self.outside))})
        result = subprocess.run(shlex.split(decision['updatedInput']['command']),
                                cwd=self.work, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Operation not permitted', result.stderr)
        self.assertNotIn('SYNTHETIC_PRIVATE', result.stdout)


if __name__ == '__main__':
    unittest.main()
