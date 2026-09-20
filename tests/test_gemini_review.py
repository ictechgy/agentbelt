"""Unconfined Gemini host review must never be reachable from the child relay."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from adapters import packet_relay
import agentbelt as g


class GeminiBoundaryTests(unittest.TestCase):
    def test_child_request_is_refused_before_any_host_provider_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(g.GuardError, "Gemini.*disabled"):
                packet_relay.validate_request({"provider": "gemini", "files": ["a.py"], "question": "review"}, Path(tmp), {})

    def test_direct_dispatch_cannot_bypass_provider_validation(self):
        with patch.object(packet_relay.subprocess, "run", side_effect=AssertionError("host process attempted")):
            status, output, error = packet_relay.host_runner("gemini", {}, Path("/synthetic"))
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("disabled", error)

    def test_supported_reviewers_still_validate_and_notice_lists_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            for provider in ("glm", "qwen"):
                request = packet_relay.validate_request({"provider": provider, "files": ["a.py"], "question": "review"}, Path(tmp), {})
                self.assertEqual(request["provider"], provider)
            relay = packet_relay.PacketRelay(Path(tmp), Path(tmp))
            self.assertIn("--provider glm|qwen]", relay.notice())
            self.assertNotIn("glm|qwen|gemini", relay.notice())


if __name__ == "__main__":
    unittest.main()
