"""Private GUI/backend routes never select the original vendor application."""
import json
import os
from pathlib import Path
import tempfile
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import agentbelt as g


class PrivateZcodeRoutesTests(unittest.TestCase):
    def test_isolated_cli_loads_its_own_private_adapter_before_refusing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / 'agentbelt.py'
            shutil.copyfile(g.__file__, script)
            (root / 'adapters').mkdir()
            (root / 'adapters/zcode_privacy.py').write_text(
                'def verify(*args, **kwargs):\n    raise RuntimeError("synthetic invalid manifest")\n'
                'launch_plan = verify\n')
            for arguments in [['check-zcode-private'], ['zcode-private-backend', '--generation', 'a' * 32, 'app-server', '--stdio']]:
                result = subprocess.run(['/usr/bin/python3', '-I', str(script), *arguments],
                                        capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'})
                self.assertEqual(result.returncode, 2)
                self.assertIn('snapshot-blocked Zcode copy is missing or changed', result.stderr)
                self.assertNotIn('Local setup failed', result.stderr)

    def test_invalid_generation_never_falls_back_to_original_backend(self):
        with patch.object(g, 'verified_private_zcode', side_effect=g.GuardError('invalid generation')), \
             patch.object(g, 'verify_zcode_binary') as original, patch.object(g, 'run_confined') as launch:
            with self.assertRaisesRegex(g.GuardError, 'invalid generation'):
                g.main(['zcode-private-backend', '--generation', 'a' * 32, 'app-server', '--stdio'])
        original.assert_not_called()
        launch.assert_not_called()

    def test_private_backend_uses_only_the_verified_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'guard'
            work = Path(temporary) / 'work'
            work.mkdir()
            (root / 'state').mkdir(parents=True)
            (root / 'state/zcode-agent-config.json').write_text('{}')
            app = root / 'state/zcode-private/ZCode.app'
            manifest = {'generation': 'a' * 32, 'app_path': str(app)}
            with patch.object(g, 'ROOT', root), \
                 patch.object(g, 'verified_private_zcode', return_value=manifest) as verify, \
                 patch.object(g, 'verify_zcode_binary') as original, \
                 patch.object(g, 'workspace_path', return_value=work), \
                 patch.object(g, 'development_options', return_value={'packageDomains': [], 'devPorts': []}), \
                 patch.object(g, 'riskgate_policy', return_value=root / 'state/policy.yaml'), \
                 patch.object(g, 'packet_relay_settings', return_value=None), \
                 patch.object(g, 'run_confined', return_value=0) as launch:
                status = g.main(['zcode-private-backend', '--generation', 'a' * 32, 'app-server', '--stdio'])
            self.assertEqual(status, 0)
            verify.assert_called_once_with('a' * 32)
            original.assert_not_called()
            self.assertEqual(launch.call_args.args[2][1], str(app / 'Contents/Resources/glm/zcode.cjs'))
            self.assertIn(app, launch.call_args.kwargs['extra_reads'])
            self.assertNotIn('/Applications/ZCode.app', launch.call_args.kwargs['extra_reads'])
            self.assertEqual(launch.call_args.kwargs['blocked_workspace_paths'], g.ZCODE_WORKSPACE_CONFIG_PATHS)

    def test_process_classification_uses_executable_path_and_user(self):
        root = Path('/synthetic/guard')
        uid = os.getuid()
        rows = f'10 {uid}\n11 {uid}\n12 {uid}\n13 {uid + 1}\n'
        paths = {10: '/Applications/ZCode.app/Contents/MacOS/ZCode',
                 11: str(root / 'state/zcode-private/ZCode.app/Contents/MacOS/ZCode'),
                 12: '/synthetic/renamed-unrelated-program'}
        with patch.object(g, 'ROOT', root), \
             patch.object(g.subprocess, 'run', return_value=SimpleNamespace(stdout=rows)), \
             patch.object(g, 'executable_path', side_effect=lambda pid: paths[pid]):
            self.assertEqual(g.zcode_gui_processes(), {'original': [10], 'private': [11]})

    def test_original_process_cannot_receive_a_private_receipt(self):
        with patch.object(g, 'verified_private_zcode', return_value={'generation': 'a' * 32}), \
             patch.object(g, 'executable_path', return_value='/Applications/ZCode.app/Contents/MacOS/ZCode'), \
             patch.object(g, 'runtime_status') as record:
            with self.assertRaisesRegex(g.GuardError, 'not the verified private'):
                g.record_private_zcode_launch(123, 'a' * 32)
        record.assert_not_called()

    def test_matching_process_receipt_contains_only_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / 'state/zcode-private/ZCode.app/Contents/MacOS/ZCode'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'SYNTHETIC')
            with patch.object(g, 'ROOT', root), \
                 patch.object(g, 'verified_private_zcode', return_value={'generation': 'a' * 32, 'bundle_digest': 'b' * 64}), \
                 patch.object(g, 'executable_path', return_value=str(executable)), \
                 patch.object(g, 'process_started_at', return_value='synthetic-start'), \
                 patch.object(g.subprocess, 'run', return_value=SimpleNamespace(stdout=str(os.getuid()))), \
                 patch.object(g, 'runtime_status') as record:
                g.record_private_zcode_launch(123, 'a' * 32)
            data = record.call_args.args[1]
            self.assertEqual(data['generation'], 'a' * 32)
            self.assertEqual(data['executable_inode'], executable.stat().st_ino)
            self.assertNotIn('url', data)
            self.assertNotIn('environment', data)

    def test_private_cli_launch_refuses_before_exec_if_plan_fails(self):
        with patch.object(g, 'private_zcode_launch_plan', side_effect=g.GuardError('not verified')), \
             patch.object(g.os, 'execve') as execute, patch.object(g, 'runtime_status') as record:
            with self.assertRaisesRegex(g.GuardError, 'not verified'):
                g.main(['zcode-private-app'])
        execute.assert_not_called()
        record.assert_not_called()

    def test_private_launch_refuses_original_gui_even_with_valid_bundle(self):
        from adapters import zcode_privacy
        with patch.object(zcode_privacy, 'launch_plan', return_value={'generation': 'a' * 32}), \
             patch.object(g, 'zcode_gui_processes', return_value={'original': [123], 'private': []}):
            with self.assertRaisesRegex(g.GuardError, 'quit the original'):
                g.private_zcode_launch_plan()

    def test_private_process_title_and_stale_receipt_do_not_confuse_status(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / 'state/zcode-private/ZCode.app/Contents/MacOS/ZCode'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'SYNTHETIC')
            (root / 'state/zcode-private/manifest.json').write_text('{}')
            receipt = root / 'state/runtime/zcode-private-gui.json'
            receipt.parent.mkdir()
            info = executable.stat()
            record = {'pid': 101, 'uid': os.getuid(), 'started': 'synthetic-start',
                      'generation': 'a' * 32, 'bundle_digest': 'b' * 64,
                      'executable_device': info.st_dev, 'executable_inode': info.st_ino}
            receipt.write_text(json.dumps(record))
            def process(args, **kwargs):
                if '-axo' in args:
                    return SimpleNamespace(stdout='101 1 ZCode Snapshot Blocked\n102 101 Python\n')
                return SimpleNamespace(stdout=str(root / 'agentbelt.py') + ' zcode-private-backend --generation ' + 'a' * 32)
            with patch.object(g, 'ROOT', root), \
                 patch.object(g, 'zcode_gui_processes', return_value={'original': [], 'private': [101]}), \
                 patch.object(g, 'verified_private_zcode', return_value={'generation': 'a' * 32, 'bundle_digest': 'b' * 64}), \
                 patch.object(g, 'process_started_at', return_value='synthetic-start'), \
                 patch.object(g.subprocess, 'run', side_effect=process), \
                 patch('ctypes.CDLL', return_value=SimpleNamespace(sandbox_check=Mock(return_value=1))):
                status = g.live_zcode_status()
                self.assertEqual(status['backend_count'], 1)
                self.assertTrue(status['private_launch_recorded'])
                self.assertFalse(status['safe_launch'])
                self.assertFalse(status['gui_egress_confined'])
                receipt.write_text(json.dumps({**record, 'executable_inode': -1}))
                self.assertFalse(g.live_zcode_status()['private_launch_recorded'])


if __name__ == '__main__':
    unittest.main()
