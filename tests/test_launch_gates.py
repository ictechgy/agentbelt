"""Regression for broker listener lookup (netstat) and the AutoClaw launch-stage receipts.

lsof scans the fds of every process, so it can take tens of seconds when a large process such as a JVM is present. netstat reads
the kernel table directly. The hard-link check of a large workspace (900,000 files) takes 25 seconds, so the installer raises the
AutoClaw-side handshake limit to 3 minutes.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g


class ListenerLookupTests(unittest.TestCase):
    def test_netstat_lines_are_parsed_for_the_port_on_any_address(self):
        sample = ('Proto Recv-Q Send-Q  Local Address  Foreign Address (state) rxbytes txbytes rhiwat shiwat process:pid state\n'
                  'tcp4       0      0  127.0.0.1.43210        *.*   LISTEN   0 0 131072 131072   node:4242  00000\n'
                  'tcp6       0      0  ::1.43210              *.*   LISTEN   0 0 131072 131072   other:5151 00000\n'
                  'tcp4       0      0  *.432100               *.*   LISTEN   0 0 131072 131072   decoy:6161 00000\n'
                  'tcp4       0      0  127.0.0.1.43210        127.0.0.1.5000 ESTABLISHED 0 0 0 0 node:4242 00000\n')
        self.assertEqual(g.listener_pids_from_netstat(sample, 43210), [4242, 5151])

    def test_lookup_fails_closed_on_timeout(self):
        with patch.object(g.subprocess, 'run', side_effect=subprocess.TimeoutExpired('netstat', 5)):
            self.assertEqual(g.listener_executables(43210), [''])
        with self.assertRaises(g.GuardError):
            with patch.object(g.subprocess, 'run', side_effect=subprocess.TimeoutExpired('netstat', 5)):
                g.verify_broker_owner(43210)


if __name__ == '__main__':
    unittest.main()
