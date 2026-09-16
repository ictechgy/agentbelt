"""Regressions for the shared-temp guidance and the measured allow-rule gaps."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'vendor'))
from riskgate import judge, load_policy

POLICY = Path.home() / '.config/riskgate/riskgate.yaml'


class SharedTempGuidanceTests(unittest.TestCase):
    def hook(self, command, work):
        payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                   'cwd': str(work), 'tool_input': {'command': command}}
        result = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / 'zcode_hook.py')],
                                input=json.dumps(payload), capture_output=True, text=True, timeout=20)
        return json.loads(result.stdout)['hookSpecificOutput']

    def test_the_shared_temp_directory_is_refused_with_a_usable_alternative(self):
        """An opaque EPERM makes the agent ask a human; name TMPDIR instead."""
        with tempfile.TemporaryDirectory(prefix='temp-guidance-', dir=Path.home()) as tmp:
            work = Path(tmp)
            for command in ['mkdir -p /tmp/build', 'echo hi > /tmp/out.txt', 'cd /tmp',
                            'cat /private/tmp/x', 'tar -C /tmp -xzf p.tgz']:
                with self.subTest(command=command):
                    body = self.hook(command, work)
                    self.assertEqual(body['permissionDecision'], 'deny')
                    self.assertIn('TMPDIR', body['permissionDecisionReason'])

    def test_the_private_temp_directory_is_not_caught_by_that_rule(self):
        with tempfile.TemporaryDirectory(prefix='temp-guidance-', dir=Path.home()) as tmp:
            for command in ['mkdir -p "$TMPDIR/build"', 'echo hi > "$TMPDIR/out.txt"']:
                with self.subTest(command=command):
                    body = self.hook(command, Path(tmp))
                    self.assertNotEqual(body['permissionDecision'], 'deny')


class ScopedAllowRuleTests(unittest.TestCase):
    """The gaps were measured, not guessed: these verbs prompted even on relative paths."""

    def setUp(self):
        self.policy = load_policy(str(POLICY))
        self.cwd = str(Path.home() / 'Desktop')

    def verdict(self, command):
        return judge(self.policy, 'Bash', {'command': command}, cwd=self.cwd).verdict

    def test_ordinary_workspace_copies_no_longer_prompt(self):
        for command in ['cp src/a.js dist/', 'mv build/a build/b', 'cp src/a.js "$TMPDIR/"',
                        'mv "$TMPDIR/a" "$TMPDIR/b"', 'tar -C dist -xzf pkg.tgz',
                        'tar -C "$TMPDIR" -xzf pkg.tgz', 'mktemp', 'mktemp -d']:
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')

    def test_anything_reaching_outside_still_prompts(self):
        for command in ['cp /etc/passwd .', 'cp ~/.ssh/id_rsa dist/',
                        'cp "$HOME/.ssh/id_rsa" dist/', 'mv dist ~/Downloads/',
                        'mv ' + str(Path.home()) + '/Documents/x .', 'cp a /tmp/x',
                        'mktemp -p /etc', 'tar --absolute-names -xzf p.tgz']:
            with self.subTest(command=command):
                self.assertNotEqual(self.verdict(command), 'allow')

    def test_local_git_changes_no_longer_prompt(self):
        for command in ['git add -A', 'git add .', 'git add src/a.js', 'git commit -m "x"',
                        'git commit -am "x"', 'git add -A && git commit -m "x"',
                        'git checkout -b feat', 'git switch -c feat', 'git branch']:
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')

    def test_history_rewriting_and_publishing_still_prompt(self):
        for command in ['git push', 'git push --force', 'git reset --hard',
                        'git clean -fd', 'git commit --amend -m "x"',
                        'git checkout -- src/a.js', 'git checkout main', 'git branch -D feat']:
            with self.subTest(command=command):
                self.assertNotEqual(self.verdict(command), 'allow')

    def test_a_dangerous_overlay_still_beats_the_new_safe_rules(self):
        # The engine adopts the most severe verdict across matching rules.
        self.assertNotEqual(self.verdict('rm -rf "$TMPDIR/build"'), 'allow')
        self.assertNotEqual(self.verdict('cp a b && git push'), 'allow')


class AgentStatePathTests(unittest.TestCase):
    """The agent's own notes live in the isolated home, not the project."""

    def setUp(self):
        sys.path.insert(0, str(ROOT))
        import zcode_hook
        self.hook = zcode_hook

    def test_memory_under_the_isolated_home_is_writable_when_confined(self):
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='agent-state-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'
            work = Path(tmp) / 'work'
            (home / '.zcode/cli/memories').mkdir(parents=True)
            work.mkdir()
            target = home / '.zcode/cli/memories/note.md'
            with patch.dict(os.environ, {'HOME': str(home)}):
                resolved = self.hook.safe_path(str(target), work.resolve(), agent_state=True)
                self.assertEqual(resolved, target.resolve())
                with self.assertRaises(self.hook.GuardError):
                    self.hook.safe_path(str(target), work.resolve(), agent_state=False)

    def test_the_exception_does_not_open_the_rest_of_the_home(self):
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='agent-state-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'
            work = Path(tmp) / 'work'
            (home / '.ssh').mkdir(parents=True)
            (home / '.zcode').mkdir()
            work.mkdir()
            with patch.dict(os.environ, {'HOME': str(home)}):
                for outside in [home / '.ssh/id_rsa', home / 'notes.txt', Path('/etc/passwd')]:
                    with self.subTest(path=str(outside)), self.assertRaises(self.hook.GuardError):
                        self.hook.safe_path(str(outside), work.resolve(), agent_state=True)


if __name__ == '__main__': unittest.main()


class DevPortLoopbackTests(unittest.TestCase):
    def test_child_can_connect_to_its_own_development_port(self):
        """dart test --coverage connects to its own VM service port over a websocket. Allowing only bind makes it hang."""
        import json as _json, socket, subprocess as _sp, tempfile as _tf
        from pathlib import Path as _P
        import agentbelt as _g
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        script = ('/Library/Developer/CommandLineTools/usr/bin/python3 -I - <<PY\n'
                  'import socket, threading\n'
                  's = socket.socket(); s.bind(("127.0.0.1", %d)); s.listen(1)\n'
                  'def serve():\n'
                  '    c, _ = s.accept(); c.sendall(b"HELLO_FROM_SELF"); c.close()\n'
                  'threading.Thread(target=serve, daemon=True).start()\n'
                  'k = socket.create_connection(("127.0.0.1", %d), timeout=5); print(k.recv(64).decode())\n'
                  'PY\n') % (port, port)
        with _tf.TemporaryDirectory(prefix='devport-loop-', dir=_P.home()) as tmp:
            work = _P(tmp); (work / 'p.sh').write_text(script)
            with _tf.TemporaryFile() as out:
                status = _g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')], ephemeral=True,
                                         dev_ports=[port], stdout=out)
                out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('HELLO_FROM_SELF', text)

    def test_agent_sessions_get_a_private_loopback_port(self):
        """safecode and zcode each get a dedicated loopback port per session, and can bind to and self-connect on that port."""
        import tempfile as _tf
        from pathlib import Path as _P
        import agentbelt as _g
        script = ('echo "PORT=$AGENTBELT_LOOPBACK_PORT"; echo "DEV=$AGENTBELT_DEV_PORTS"\n'
                  '/Library/Developer/CommandLineTools/usr/bin/python3 -I - <<PY\n'
                  'import os, socket, threading\n'
                  'p = int(os.environ["AGENTBELT_LOOPBACK_PORT"])\n'
                  's = socket.socket(); s.bind(("127.0.0.1", p)); s.listen(1)\n'
                  'threading.Thread(target=lambda: s.accept()[0].sendall(b"SELF_OK"), daemon=True).start()\n'
                  'print(socket.create_connection(("127.0.0.1", p), timeout=5).recv(16).decode())\n'
                  'PY\n')
        with _tf.TemporaryDirectory(prefix='loopback-', dir=_P.home()) as tmp:
            work = _P(tmp); (work / 'p.sh').write_text(script)
            with _tf.TemporaryFile() as out:
                status = _g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')], ephemeral=True,
                                         loopback_port=True, stdout=out)
                out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertRegex(text, r'PORT=\d{4,5}')
        self.assertIn('SELF_OK', text)

