"""AutoClaw 세션-워크스페이스 바인딩 파일을 호스트에서 쓰는 도구의 회귀.

플러그인(session-workspace-binding.js)은 `<state>/autoclaw/coding-workspaces/v1/<sha256("local\\0"+sessionKey)>.json` 을
읽으며 키 집합·해시·0600·일반 파일·경로 inode 를 검사한다. 여기서 쓰는 파일은 그 검증을 그대로 통과해야 한다.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bind_autoclaw_workspace as binder

SESSION = 'agent:auto-coder:discord:channel:1548737346780921939'


class BindingFileTests(unittest.TestCase):
    def test_writes_a_binding_the_plugin_would_accept(self):
        with tempfile.TemporaryDirectory(prefix='bind-', dir=Path.home()) as tmp:
            state = Path(tmp) / 'state'; state.mkdir()
            workspace = Path(tmp) / 'project'; workspace.mkdir()
            with patch.object(binder, 'OPENCLAW_STATE', state):
                path = binder.bind(SESSION, workspace)
            expected_name = hashlib.sha256(b'local\0' + SESSION.encode()).hexdigest() + '.json'
            self.assertEqual(path, state / 'autoclaw/coding-workspaces/v1' / expected_name)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            data = json.loads(path.read_text())
            real = str(workspace.resolve())
            self.assertEqual(sorted(data), ['bindingRevision', 'boundAt', 'pathIdentity', 'realPath', 'schemaVersion', 'sessionKeyHash', 'updatedAt', 'workspaceId'])
            self.assertEqual(data['schemaVersion'], 1)
            self.assertEqual(data['sessionKeyHash'], expected_name[:-5])
            self.assertEqual(data['realPath'], real)
            self.assertEqual(data['workspaceId'], hashlib.sha256(b'workspace\0' + real.encode()).hexdigest())
            info = os.stat(real)
            self.assertEqual(data['pathIdentity'], {'dev': str(info.st_dev), 'ino': str(info.st_ino)})
            self.assertEqual(data['bindingRevision'], 1)
            self.assertTrue(data['updatedAt'] >= data['boundAt'] > 1_700_000_000_000)

    def test_rebinding_bumps_the_revision_and_keeps_bound_at(self):
        with tempfile.TemporaryDirectory(prefix='bind-', dir=Path.home()) as tmp:
            state = Path(tmp) / 'state'; state.mkdir()
            first = Path(tmp) / 'one'; first.mkdir()
            second = Path(tmp) / 'two'; second.mkdir()
            with patch.object(binder, 'OPENCLAW_STATE', state):
                path = binder.bind(SESSION, first)
                before = json.loads(path.read_text())
                binder.bind(SESSION, second)
            after = json.loads(path.read_text())
            self.assertEqual(after['bindingRevision'], 2)
            self.assertEqual(after['boundAt'], before['boundAt'])
            self.assertEqual(after['realPath'], str(second.resolve()))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_refuses_paths_the_guard_would_reject_and_linked_destinations(self):
        with tempfile.TemporaryDirectory(prefix='bind-', dir=Path.home()) as tmp:
            state = Path(tmp) / 'state'; state.mkdir()
            hidden = Path(tmp) / '.hidden'; hidden.mkdir()
            with patch.object(binder, 'OPENCLAW_STATE', state):
                with self.assertRaises(Exception):
                    binder.bind(SESSION, Path.home())
                with self.assertRaises(Exception):
                    binder.bind('', Path(tmp))
                project = Path(tmp) / 'p'; project.mkdir()
                directory = state / 'autoclaw/coding-workspaces/v1'; directory.mkdir(parents=True)
                victim = Path(tmp) / 'victim.json'; victim.write_text('{}')
                name = hashlib.sha256(b'local\0' + SESSION.encode()).hexdigest() + '.json'
                os.symlink(str(victim), str(directory / name))
                with self.assertRaises(RuntimeError):
                    binder.bind(SESSION, project)
                self.assertEqual(victim.read_text(), '{}')

    def test_discord_channel_session_key_shape(self):
        self.assertEqual(binder.discord_channel_session_key('auto-coder', '1548737346780921939'), SESSION)
        for bad in [('auto-coder', 'general'), ('auto coder', '1548737346780921939'), ('', '1548737346780921939')]:
            with self.assertRaises(RuntimeError, msg=bad):
                binder.discord_channel_session_key(*bad)


if __name__ == '__main__':
    unittest.main()
