"""Synthetic audit-file safety regressions for the riskgate bridge."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import riskgate_bridge as bridge
from agentbelt import GuardError


POLICY = "version: 1\ndefaults: allow\nrules: []\n"
PAYLOAD = {'tool_input': {'command': 'echo synthetic'}, 'cwd': 'synthetic-cwd'}


class RiskgateAuditTests(unittest.TestCase):
    def make_home(self):
        tmp = tempfile.TemporaryDirectory(prefix='riskgate-audit-')
        home = Path(tmp.name)
        (home / 'policy.yaml').write_text(POLICY)
        return tmp, home

    def decide(self, home):
        with patch.object(bridge, 'riskgate_policy', return_value=home / 'policy.yaml'), \
             patch.object(bridge.Path, 'home', return_value=home), \
             patch.dict(os.environ, {'AGENTBELT_PROMPT_TELEMETRY': '0'}):
            return bridge.riskgate_decision(PAYLOAD)

    def assert_guarded(self, home):
        with self.assertRaises(GuardError):
            self.decide(home)

    def test_normal_verdict_creates_private_single_link_audit(self):
        tmp, home = self.make_home()
        try:
            self.assertEqual(self.decide(home), 'allow')
            audit = home / 'riskgate-decisions.jsonl'
            info = audit.stat()
            self.assertTrue(audit.is_file())
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(info.st_mode & 0o077, 0)
            self.assertEqual(json.loads(audit.read_text()), {'tool': 'Bash', 'decision': 'allow'})
        finally:
            tmp.cleanup()

    def test_alternate_audit_types_fail_closed(self):
        for kind in ('directory', 'socket', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                tmp, home = self.make_home()
                sock = None
                try:
                    audit = home / 'riskgate-decisions.jsonl'
                    if kind == 'directory':
                        audit.mkdir()
                    elif kind == 'socket':
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.bind(str(audit))
                    elif kind == 'symlink':
                        target = home / 'audit-target.jsonl'
                        target.write_text('synthetic\n')
                        audit.symlink_to(target)
                    else:
                        target = home / 'audit-target.jsonl'
                        target.write_text('synthetic\n')
                        os.link(target, audit)
                    self.assert_guarded(home)
                finally:
                    if sock is not None:
                        sock.close()
                    tmp.cleanup()

    def test_fifo_without_reader_fails_promptly_in_synthetic_child(self):
        tmp, home = self.make_home()
        try:
            audit = home / 'riskgate-decisions.jsonl'
            os.mkfifo(audit, 0o600)
            child = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import riskgate_bridge as bridge
from agentbelt import GuardError
home = Path(sys.argv[2])
bridge.riskgate_policy = lambda: home / 'policy.yaml'
try:
    bridge.riskgate_decision({'tool_input': {'command': 'echo synthetic'}, 'cwd': str(home)})
except GuardError:
    print('GUARD_ERROR')
else:
    raise SystemExit('unexpected allow')
"""
            started = time.monotonic()
            result = subprocess.run(
                [sys.executable, '-I', '-c', child, str(ROOT), str(home)],
                cwd=str(home),
                env={'HOME': str(home), 'PATH': '/usr/bin:/bin'},
                capture_output=True,
                text=True,
                timeout=2,
            )
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'GUARD_ERROR')
        finally:
            tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
