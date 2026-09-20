"""A backend sandbox must never be presented as a GUI egress boundary."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import agentbelt as g


class GuiPrivacyTests(unittest.TestCase):
    def test_gui_launch_refuses_before_any_host_process_or_exec(self):
        with patch.object(g, 'verify_zcode_binary'), \
             patch.object(g.subprocess, 'run') as process, patch.object(g.os, 'execve') as execute:
            with self.assertRaisesRegex(g.GuardError, 'GUI.*upload'):
                g.launch_zcode_app()
            process.assert_not_called()
            execute.assert_not_called()

    def test_gui_preflight_and_receipt_cannot_claim_safe_launch(self):
        for args in (['check-zcode'], ['check-zcode-gui'], ['record-zcode-launch', '123']):
            with self.subTest(args=args), patch.object(g.subprocess, 'run') as process:
                with self.assertRaisesRegex(g.GuardError, 'GUI.*upload'):
                    g.main(args)
                process.assert_not_called()

    def test_backend_check_remains_available(self):
        with patch.object(g, 'verify_zcode_binary') as verify, patch.object(g, 'riskgate_policy'):
            self.assertEqual(g.main(['check-zcode-backend']), 0)
        verify.assert_called_once()

    def test_old_matching_launch_receipt_is_only_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / 'state/runtime'
            state.mkdir(parents=True)
            (state / 'zcode-gui.json').write_text(json.dumps({'pid': 123, 'started': 'synthetic-start'}))
            def process(command, **kwargs):
                output = '123 1 ZCode\n' if '-axo' in command else 'synthetic-start\n'
                return SimpleNamespace(stdout=output, returncode=0)
            with patch.object(g, 'ROOT', root), patch.object(g.subprocess, 'run', side_effect=process):
                status = g.live_zcode_status()
        self.assertTrue(status['gui_running'])
        self.assertFalse(status['safe_launch'])
        self.assertFalse(status['gui_egress_confined'])
        self.assertFalse(status['gui_launch_allowed'])
        self.assertTrue(status['backend_launch_recorded'])


if __name__ == '__main__':
    unittest.main()
