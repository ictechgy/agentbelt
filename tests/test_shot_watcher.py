"""Regression tests for the host-side screenshot queue and its session auto-start."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agentbelt  # noqa: E402
import shot_watcher  # noqa: E402


class EnsureShotWatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'root'
        self.workspace = Path(self.tmp.name) / 'workspace'
        (self.root).mkdir(parents=True)
        (self.workspace / 'shots').mkdir(parents=True)
        self.script = self.root / 'shot_watcher.py'
        self.script.write_text('# stub\n')
        self.lock = self.workspace / 'shots' / '.watcher.lock'
        self.popen_calls = []

    def _ensure(self):
        with patch.object(agentbelt, 'ROOT', self.root), \
             patch('agentbelt.subprocess.Popen', side_effect=self._record) as popen:
            agentbelt.ensure_shot_watcher(str(self.workspace))
            return popen

    def _record(self, *args, **kwargs):
        self.popen_calls.append((args, kwargs))
        return object()

    def test_starts_watcher_when_no_lock(self):
        popen = self._ensure()
        self.assertEqual(len(self.popen_calls), 1)
        argv = self.popen_calls[0][0][0]
        self.assertIn('shot_watcher.py', argv[1])
        self.assertEqual(argv[2], str(self.workspace))
        self.assertTrue((self.workspace / 'shots' / '.watcher.log').exists())

    def test_live_lock_skips_spawn(self):
        self.lock.write_text(str(os.getpid()))
        self._ensure()
        self.assertEqual(self.popen_calls, [])
        self.assertTrue(self.lock.exists())

    def test_stale_lock_is_replaced(self):
        self.lock.write_text('424242')
        with patch('agentbelt.os.kill', side_effect=ProcessLookupError):
            self._ensure()
        self.assertEqual(len(self.popen_calls), 1)

    def test_corrupt_lock_is_replaced(self):
        self.lock.write_text('not-a-pid')
        self._ensure()
        self.assertEqual(len(self.popen_calls), 1)

    def test_missing_script_never_spawns(self):
        self.script.unlink()
        self._ensure()
        self.assertEqual(self.popen_calls, [])

    def test_spawn_failure_is_swallowed(self):
        with patch.object(agentbelt, 'ROOT', self.root), \
             patch('agentbelt.subprocess.Popen', side_effect=OSError('no fork')):
            agentbelt.ensure_shot_watcher(str(self.workspace))  # must not raise


class TranslatePathTests(unittest.TestCase):
    """The file server must answer only inside the workspace (symlink and .. escapes refused)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name).resolve()
        (self.workspace / 'shots').mkdir()
        shot_watcher.WorkspaceHandler.workspace = self.workspace
        self.handler = shot_watcher.WorkspaceHandler.__new__(shot_watcher.WorkspaceHandler)

    def test_inside_path_maps(self):
        out = self.handler.translate_path('/shots/a.html')
        self.assertEqual(out, str(self.workspace / 'shots/a.html'))

    def test_dotdot_escape_refused(self):
        out = self.handler.translate_path('/../secret.txt')
        self.assertNotEqual(out, str((self.workspace / '../secret.txt').resolve()))
        self.assertTrue(out.endswith('__forbidden__'))

    def test_url_encoded_escape_refused(self):
        out = self.handler.translate_path('/shots/%2e%2e/%2e%2e/etc/passwd')
        self.assertTrue(out.endswith('__forbidden__'))

    def test_symlink_escape_refused(self):
        link = self.workspace / 'shots' / 'evil.html'
        link.symlink_to('/etc/passwd')
        out = self.handler.translate_path('/shots/evil.html')
        self.assertTrue(out.endswith('__forbidden__'))


class ViewOptionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.queue = Path(self.tmp.name)
        self.watcher = shot_watcher.ShotWatcher.__new__(shot_watcher.ShotWatcher)
        self.watcher.queue = self.queue

    def test_missing_sidecar_defaults(self):
        self.assertEqual(self.watcher.view_options('page'), {})

    def test_valid_sidecar(self):
        (self.queue / 'page.json').write_text(json.dumps({'width': 390, 'height': 844, 'full': False}))
        self.assertEqual(self.watcher.view_options('page')['width'], 390)

    def test_malformed_sidecar_ignored(self):
        (self.queue / 'page.json').write_text('{oops')
        self.assertEqual(self.watcher.view_options('page'), {})

    def test_non_dict_sidecar_ignored(self):
        (self.queue / 'page.json').write_text('[1,2]')
        self.assertEqual(self.watcher.view_options('page'), {})


if __name__ == '__main__':
    unittest.main()
