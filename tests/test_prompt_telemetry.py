"""Regressions for recording only the commands that actually prompt."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g
import riskgate_bridge as bridge

POLICY = ('version: 1\ndefaults: prompt\n'
          'risk_matrix:\n  dangerous: prompt\n  safe: allow\n'
          'rules:\n'
          '  - id: allow-echo\n    match: {tool: Bash, cmd_regex: "^echo "}\n    risk: safe\n'
          '  - id: deny-secret\n    match: {tool: Bash, cmd_regex: "^cat /etc/master.passwd"}\n    risk: deny\n')


class PromptTelemetryTests(unittest.TestCase):
    def decide(self, command, telemetry):
        """Run the real bridge against a synthetic policy and private home."""
        with tempfile.TemporaryDirectory(prefix='telemetry-', dir=Path.home()) as tmp:
            home = Path(tmp)
            policy = home / 'policy.yaml'
            policy.write_text(POLICY)
            environment = {'AGENT_GUARD_PROMPT_TELEMETRY': '1'} if telemetry else {}
            with patch.object(bridge, 'riskgate_policy', return_value=policy), \
                 patch.object(bridge.Path, 'home', return_value=home), \
                 patch.dict(os.environ, environment, clear=False):
                if not telemetry:
                    os.environ.pop('AGENT_GUARD_PROMPT_TELEMETRY', None)
                verdict = bridge.riskgate_decision(
                    {'tool_input': {'command': command}, 'cwd': str(home)})
            entries = [json.loads(line) for line in
                       (home / 'riskgate-decisions.jsonl').read_text().splitlines() if line.strip()]
        return verdict, entries[-1]

    def test_a_prompted_command_is_recorded_only_when_enabled(self):
        verdict, record = self.decide('rsync -a src/ dst/', telemetry=True)
        self.assertEqual(verdict, 'ask')
        self.assertEqual(record['command'], 'rsync -a src/ dst/')
        self.assertIn('rule', record)
        verdict, record = self.decide('rsync -a src/ dst/', telemetry=False)
        self.assertEqual(verdict, 'ask')
        self.assertNotIn('command', record)

    def test_allowed_and_denied_calls_never_record_the_command(self):
        for command, expected in [('echo safe', 'allow'), ('cat /etc/master.passwd', 'deny')]:
            with self.subTest(command=command):
                verdict, record = self.decide(command, telemetry=True)
                self.assertEqual(verdict, expected)
                self.assertNotIn('command', record)
                self.assertEqual(record['decision'], expected)

    def test_a_huge_command_is_truncated(self):
        _, record = self.decide('rsync ' + 'a' * 9000, telemetry=True)
        self.assertEqual(len(record['command']), 4096)

    def test_the_capped_substitution_verdict_is_visible_in_the_record(self):
        # The engine caps allow to prompt for command substitution while the
        # risk level stays "safe"; a rule written from risk alone would undo it.
        verdict, record = self.decide('echo safe "$(id)"', telemetry=True)
        self.assertEqual(verdict, 'ask')
        self.assertEqual(record['risk'], 'safe')

    def test_the_opt_in_is_off_without_a_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            with patch.object(g, 'ROOT', root):
                self.assertFalse(g.prompt_telemetry_enabled())
                (root / 'state/telemetry.json').write_text(json.dumps({'promptedCommands': False}))
                self.assertFalse(g.prompt_telemetry_enabled())
                (root / 'state/telemetry.json').write_text(json.dumps({'promptedCommands': True}))
                self.assertTrue(g.prompt_telemetry_enabled())


if __name__ == '__main__': unittest.main()
