"""Regressions for the hook's deny-on-import contract and control directory cleanup."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g


class HookImportFailureTests(unittest.TestCase):
    def test_missing_policy_module_denies_instead_of_exiting_on_a_traceback(self):
        """A partial installation must still answer deny, not exit on an import error."""
        with tempfile.TemporaryDirectory(prefix='hook-import-', dir=Path.home()) as tmp:
            base = Path(tmp)
            work = base / 'work'
            work.mkdir()
            # The vendored riskgate package is deliberately absent, so the bridge
            # import chain fails the way a broken installation would.
            for name in ['zcode_hook.py', 'agentbelt.py', 'riskgate_bridge.py']:
                shutil.copy(ROOT / name, base)
            payload = json.dumps({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                                  'cwd': str(work), 'tool_input': {'command': 'printf synthetic'}})
            result = subprocess.run(['/usr/bin/python3', '-I', str(base / 'zcode_hook.py')],
                                    input=payload, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')
            self.assertNotIn('Traceback', result.stderr)
            self.assertNotIn(str(base), result.stdout + result.stderr)


class ControlDirectoryCleanupTests(unittest.TestCase):
    def guard_root(self, base):
        """A private guard root that borrows only the pinned sandbox runtime."""
        root = base / 'guard'
        root.mkdir()
        (root / 'runtime').symlink_to(ROOT / 'runtime', target_is_directory=True)
        (root / 'sandbox_runner.mjs').symlink_to(ROOT / 'sandbox_runner.mjs')
        return root

    def test_failure_before_launch_leaves_no_control_directory(self):
        with tempfile.TemporaryDirectory(prefix='guard-cleanup-', dir=Path.home()) as tmp:
            base = Path(tmp)
            work = base / 'work'
            work.mkdir()
            root = self.guard_root(base)
            with patch.object(g, 'ROOT', root), self.assertRaises(g.GuardError):
                g.run_confined('exec', work, ['/bin/echo', 'synthetic'], ephemeral=True, dev_ports=[80])
            self.assertEqual(list((root / 'state').glob('control-*')), [])

    def test_reaper_removes_dead_owners_and_keeps_live_or_unmarked_ones(self):
        with tempfile.TemporaryDirectory(prefix='guard-reap-', dir=Path.home()) as tmp:
            root = self.guard_root(Path(tmp))
            state = g.private_dir(root / 'state')
            live, recycled, legacy = (state / 'control-live', state / 'control-recycled', state / 'control-legacy')
            for directory in (live, recycled, legacy):
                g.private_dir(directory / 'home')
            started = g.process_started_at(os.getpid())
            self.assertTrue(started)
            (live / 'owner.json').write_text(json.dumps({'pid': os.getpid(), 'started': started}))
            # A live pid with a different start time is a recycled pid, not the owner.
            (recycled / 'owner.json').write_text(json.dumps({'pid': os.getpid(), 'started': started + ' synthetic'}))
            g.reap_control_directories(state)
            self.assertTrue(live.is_dir())
            self.assertTrue(legacy.is_dir(), 'unmarked directories may still belong to a running launcher')
            self.assertFalse(recycled.exists())

    def test_owner_marker_is_reaped_next_run_and_never_readable_by_the_child(self):
        with tempfile.TemporaryDirectory(prefix='guard-owner-', dir=Path.home()) as tmp:
            base = Path(tmp)
            work = base / 'work'
            work.mkdir()
            root = self.guard_root(base)
            state = g.private_dir(root / 'state')
            stale = g.private_dir(state / 'control-stale')
            (stale / 'owner.json').write_text(json.dumps({'pid': os.getpid(), 'started': 'synthetic stale start'}))
            probe = work / 'probe.py'
            probe.write_text('import json, os\n'
                             'from pathlib import Path\n'
                             'marker = Path(os.environ["HOME"]).parent / "owner.json"\n'
                             'try:\n'
                             '    marker.read_text(); print(json.dumps("READ_OK"))\n'
                             'except PermissionError: print(json.dumps("DENIED"))\n'
                             'except OSError as error: print(json.dumps("OSERR:%d" % error.errno))\n')
            with tempfile.TemporaryFile() as output:
                with patch.object(g, 'ROOT', root):
                    status = g.run_confined('exec', work, ['/usr/bin/python3', '-I', str(probe)],
                                            ephemeral=True, stdout=output)
                output.seek(0)
                lines = output.read().decode().splitlines()
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(lines[-1]), 'DENIED')
            self.assertFalse(stale.exists())
            self.assertEqual(list(state.glob('control-*')), [])


if __name__ == '__main__': unittest.main()
