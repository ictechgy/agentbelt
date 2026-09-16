import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard_safecode', ROOT / 'agent_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class SafecodeTests(unittest.TestCase):
    def test_current_directory_and_arguments_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix='safecode-test-', dir=Path.home()) as d:
            base = Path(d)
            work = base / 'project with spaces'
            work.mkdir()
            state = base / 'guard/state'
            state.mkdir(parents=True)
            (state / 'opencode-auth.json').write_text('{}')
            with patch.object(guard, 'ROOT', state.parent), \
                 patch.object(guard.os, 'getcwd', return_value=str(work)), \
                 patch.dict(os.environ, {'PWD': str(Path.home())}), \
                 patch.object(guard, 'verify_opencode_binary', return_value='test'), \
                 patch.object(guard, 'load_opencode_profile', return_value={'domains': []}), \
                 patch.object(guard, 'run_confined', return_value=0) as execute:
                result = guard.main(['safecode', '--', 'run', '--model', 'provider/model', 'prompt with spaces'])
            self.assertEqual(result, 0)
            args = execute.call_args.args
            self.assertEqual(args[1], work)
            self.assertEqual(args[2], [str(guard.OPENCODE), 'run', '--model', 'provider/model', 'prompt with spaces'])

    def test_home_directory_is_still_rejected(self):
        with patch.object(guard.os, 'getcwd', return_value=str(Path.home())), \
             patch.object(guard, 'run_confined') as execute:
            with self.assertRaises(guard.GuardError):
                guard.main(['safecode', '--'])
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
