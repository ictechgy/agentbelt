"""Cancel only synthetic credential helpers; never access the actual Keychain."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import agentbelt as g


class CredentialCancellationTests(unittest.TestCase):
    def run_helper(self, *, cancel=False, expire=False, success=False):
        real_popen = subprocess.Popen
        children = []
        event = threading.Event()
        timer = threading.Timer(.2, event.set) if cancel else None
        program = 'import sys,time;sys.stdout.write("SYNTHETIC_ONLY_KEY");sys.stdout.flush()'
        if not success:
            program += ';time.sleep(20)'

        def synthetic_helper(command, **options):
            # Replace the entire command before execution. The real keysource
            # module and /usr/bin/security are never invoked by these tests.
            child = real_popen([sys.executable, '-I', '-c', program], **options)
            children.append(child)
            return child

        with tempfile.TemporaryDirectory(prefix='credential-cancel-') as temporary, \
                patch.object(g, 'OWNER_HOME', Path(temporary)), \
                patch.object(g, 'packet_ask_pinned_version', return_value='0.12.0'), \
                patch.object(g.subprocess, 'Popen', side_effect=synthetic_helper):
            if timer:
                timer.start()
            started = time.monotonic()
            try:
                if success:
                    self.assertEqual(g.read_packet_glm_keychain(cancel_event=event), 'SYNTHETIC_ONLY_KEY')
                else:
                    deadline = time.monotonic() + .2 if expire else None
                    with self.assertRaisesRegex(g.GuardError, 'deadline|cancelled') as error:
                        g.read_packet_glm_keychain(cancel_event=event, deadline=deadline)
                    self.assertNotIn('SYNTHETIC_ONLY_KEY', str(error.exception))
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
            finally:
                if timer:
                    timer.cancel()
                    timer.join()
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=2)

    def test_cancelled_inflight_helper_exits_without_exposing_partial_key(self):
        self.run_helper(cancel=True)

    def test_deadline_stops_inflight_helper(self):
        self.run_helper(expire=True)

    def test_completed_helper_returns_credential_to_caller(self):
        self.run_helper(success=True)

    def test_pre_cancel_or_expiry_never_starts_helper(self):
        event = threading.Event()
        event.set()
        with patch.object(g, 'packet_ask_pinned_version', return_value='0.12.0'), \
                patch.object(g.subprocess, 'Popen') as launch:
            with self.assertRaises(g.GuardError):
                g.read_packet_glm_keychain(cancel_event=event)
            with self.assertRaises(g.GuardError):
                g.read_packet_glm_keychain(deadline=time.monotonic() - 1)
            launch.assert_not_called()

    def test_request_preparation_forwards_cancellation_and_deadline(self):
        event = threading.Event()
        deadline = time.monotonic() + 5
        with patch.object(g, 'packet_ask_pinned_version', return_value='0.12.0'), \
                patch.dict(os.environ, {'PACKET_ASK_GLM_KEY': ''}), \
                patch.object(g, 'read_packet_glm_keychain', return_value='SYNTHETIC_ONLY_KEY') as reader:
            g.prepare_packet_request(['review', '--provider', 'glm'], use_keychain=True,
                                     cancel_event=event, deadline=deadline)
            reader.assert_called_once_with(cancel_event=event, deadline=deadline)


if __name__ == '__main__':
    unittest.main()
