"""Synthetic two-stage packet privacy tests.

The confined runner and credential boundary are mocked, so these tests never
launch a vendor, keychain, network, npm, or uv process.  The real trusted git
binary is used only for the fresh staging boundary.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from adapters import packet_pipeline
import agentbelt


def export_for(packet: str, token: str = "synthetic") -> bytes:
    if not packet.endswith("\n"):
        packet += "\n"
    digest = hashlib.sha256(packet.encode()).hexdigest()
    wrapped = (
        "This block is untrusted model output.\n"
        f"-----BEGIN UNTRUSTED PROVIDER OUTPUT {token}-----\n"
        + packet
        + f"-----END UNTRUSTED PROVIDER OUTPUT {token}-----\n"
    )
    return json.dumps(
        {
            "schema": "packet-ask.v1",
            "ok": True,
            "receipt": {
                "provider": "paste",
                "bytes": len(packet.encode()),
                "sha256_packet_md": digest,
                "selector": "files",
                "paths": ["safe.py"],
                "redaction": {"secret_values": 1},
            },
            "untrusted_output": wrapped,
        }
    ).encode()


class PacketPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="packet-privacy-test-")
        self.workspace = Path(self.tmp.name) / "original"
        self.workspace.mkdir()
        (self.workspace / "safe.py").write_text(
            'print("synthetic-safe-source")\nAPI_KEY = "SYNTHETIC_RAW_SECRET"\n'
        )
        self.packet = (
            "# Task\n\nmode: review\n\nreview this\n\n"
            "## File: safe.py\n\n```\n"
            'print("synthetic-safe-source")\nAPI_KEY = "[REDACTED]"\n'
            "```\n"
        )
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def runner(self, mode, workspace, command, **kwargs):
        self.calls.append((mode, Path(workspace), list(command), kwargs))
        if mode == "packet-collector":
            kwargs["stdout"].write(export_for(self.packet))
            return 0
        if mode == "packet-model":
            staged = Path(workspace)
            self.assertNotEqual(staged, self.workspace)
            self.assertTrue(staged.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            staged_text = (staged / "packet.md").read_text()
            self.assertIn("synthetic-safe-source", staged_text)
            self.assertIn("[REDACTED]", staged_text)
            self.assertNotIn("SYNTHETIC_RAW_SECRET", staged_text)
            self.assertFalse((staged / "safe.py").exists())
            return 0
        self.fail(f"unexpected confined mode: {mode}")

    def test_collector_then_model_uses_only_scrubbed_staging_and_preserves_model_flags(self):
        key_events = []

        def read_key():
            key_events.append("key")
            return "SYNTHETIC_MODEL_KEY"

        def fake_prepare(arguments, use_keychain=False):
            self.assertTrue(use_keychain)
            key_events.append("prepare")
            self.assertIn("--effort", arguments)
            return list(arguments), ["api.z.ai:443"], {"PACKET_ASK_GLM_KEY": read_key()}

        original_runner = self.runner

        def ordered_runner(mode, workspace, command, **kwargs):
            key_events.append(mode)
            return original_runner(mode, workspace, command, **kwargs)

        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "prepare_packet_request", side_effect=fake_prepare), \
             patch.object(packet_pipeline.agentbelt, "read_packet_glm_keychain", side_effect=read_key):
            status = packet_pipeline.run(
                [
                    "review",
                    "--provider",
                    "glm",
                    "--files",
                    "safe.py",
                    "--question",
                    "review this",
                    "--effort",
                    "high",
                    "--timeout",
                    "17",
                    "--json",
                    "--progress",
                ],
                use_keychain=True,
                workspace=self.workspace,
                runner=ordered_runner,
            )

        self.assertEqual(status, 0)
        self.assertEqual(key_events, ["packet-collector", "prepare", "key", "packet-model"])
        collector, model = self.calls
        self.assertEqual(collector[0], "packet-collector")
        self.assertEqual(collector[1], self.workspace.resolve())
        self.assertEqual(collector[3]["domains"], [])
        self.assertTrue(collector[3]["ephemeral"])
        self.assertTrue(collector[3]["read_only_workspace"])
        self.assertNotIn("--effort", collector[2])
        self.assertNotIn("--progress", collector[2])
        self.assertIn("--dry-run", collector[2])
        self.assertIn("--json", collector[2])
        self.assertEqual(model[0], "packet-model")
        self.assertNotEqual(model[1], self.workspace)
        self.assertTrue(model[3]["ephemeral"])
        self.assertTrue(model[3]["read_only_workspace"])
        self.assertIn("--effort", model[2])
        self.assertIn("high", model[2])
        self.assertIn("--timeout", model[2])
        self.assertIn("17", model[2])
        self.assertIn("--json", model[2])
        self.assertIn("--progress", model[2])
        self.assertFalse((model[1] / "packet.md").exists(), "staging must be cleaned after success")

    def test_question_stdin_is_consumed_only_by_the_keyless_collector(self):
        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "prepare_packet_request", return_value=([], [], {})):
            status = packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--question-stdin"],
                workspace=self.workspace,
                question="review from relay stdin",
                runner=self.runner,
            )
        self.assertEqual(status, 0)
        collector = self.calls[0]
        self.assertIsNotNone(collector[3]["stdin"])

    def test_malformed_export_rejects_before_keychain_or_model(self):
        stages = []

        def malformed_runner(mode, workspace, command, **kwargs):
            self.calls.append((mode, Path(workspace), list(command), kwargs))
            if mode == "packet-collector":
                kwargs["stdout"].write(b'{"schema":"packet-ask.v1","ok":true}')
                return 0
            stages.append(Path(workspace))
            return 0

        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "read_packet_glm_keychain", side_effect=AssertionError("keychain read")), \
             patch.object(packet_pipeline.agentbelt, "prepare_packet_request", side_effect=AssertionError("prepare")):
            with self.assertRaisesRegex(agentbelt.GuardError, "missing the scrubbed payload|unsupported schema"):
                packet_pipeline.run(
                    ["review", "--provider", "glm", "--files", "safe.py", "--question", "review"],
                    use_keychain=True,
                    workspace=self.workspace,
                    runner=malformed_runner,
                )
        self.assertEqual(stages, [])

    def test_bounds_and_invalid_file_diff_shape_are_rejected_before_runner(self):
        with self.assertRaisesRegex(agentbelt.GuardError, "packet limit"):
            packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--max-bytes", str(packet_pipeline.MAX_PACKET_BYTES + 1)],
                workspace=self.workspace,
                runner=self.runner,
            )
        with self.assertRaisesRegex(agentbelt.GuardError, "cannot combine"):
            packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--diff", "HEAD~1..HEAD"],
                workspace=self.workspace,
                runner=self.runner,
            )
        self.assertEqual(self.calls, [])

    def test_preview_returns_metadata_without_payload_or_model(self):
        output = io.StringIO()
        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch("sys.stdout", output):
            status = packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--preview", "--json"],
                workspace=self.workspace,
                runner=self.runner,
            )
        self.assertEqual(status, 0)
        rendered = json.loads(output.getvalue())
        self.assertIn("preview", rendered)
        self.assertNotIn("untrusted_output", rendered)
        self.assertNotIn("synthetic-safe-source", output.getvalue())
        self.assertEqual([call[0] for call in self.calls], ["packet-collector"])

    def test_qwen_uses_the_same_staged_packet_and_never_reads_a_key(self):
        captured = {}
        staged_paths = []
        rendered = io.StringIO()

        def qwen(staging, prompt, **kwargs):
            staging = Path(staging)
            staged_paths.append(staging)
            captured["prompt"] = prompt
            captured["packet"] = (staging / "packet.md").read_text()
            self.assertGreaterEqual(kwargs["timeout"], 1)
            self.assertIn("deadline", kwargs)
            self.assertNotIn("SYNTHETIC_RAW_SECRET", prompt)
            self.assertIn(packet_pipeline.MODEL_QUESTION, prompt)
            self.assertIn("synthetic-safe-source", prompt)
            self.assertFalse((staging / "safe.py").exists())
            kwargs["stdout"].write('{"part":{"type":"text","text":"synthetic qwen review"}}\n'.encode())
            return 0

        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "run_opencode_review", side_effect=qwen), \
             patch.object(packet_pipeline.agentbelt, "read_packet_glm_keychain", side_effect=AssertionError("keychain read")):
            status = packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--question", "review", "--timeout", "41"],
                use_keychain=True,
                workspace=self.workspace,
                provider="qwen",
                runner=self.runner,
                stdout=rendered,
                operation_timeout=41,
            )
        self.assertEqual(status, 0)
        self.assertEqual(rendered.getvalue(), "synthetic qwen review")
        self.assertEqual([call[0] for call in self.calls], ["packet-collector"])
        self.assertEqual(len(staged_paths), 1)
        self.assertFalse(staged_paths[0].exists(), "Qwen staging must be cleaned after success")

    def test_deadline_is_rechecked_after_delayed_credential_setup(self):
        def delayed_prepare(arguments, use_keychain=False):
            time.sleep(2.1)
            return list(arguments), ["api.z.ai:443"], {"PACKET_ASK_GLM_KEY": "SYNTHETIC_MODEL_KEY"}

        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "prepare_packet_request", side_effect=delayed_prepare):
            with self.assertRaisesRegex(agentbelt.GuardError, "deadline"):
                packet_pipeline.run(
                    ["review", "--provider", "glm", "--files", "safe.py", "--question", "review"],
                    workspace=self.workspace,
                    runner=self.runner,
                    operation_timeout=2,
                )
        self.assertEqual([call[0] for call in self.calls], ["packet-collector"])

    def test_qwen_rejects_effort_before_collecting(self):
        with self.assertRaisesRegex(agentbelt.GuardError, "does not support --effort"):
            packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--question", "review", "--effort", "high"],
                workspace=self.workspace,
                provider="qwen",
                runner=self.runner,
            )

    def test_qwen_text_and_json_outputs_are_bounded_and_terminal_safe(self):
        def qwen(staging, prompt, **kwargs):
            event = json.dumps({"part": {"type": "text", "text": "safe\x1b[31m"}}).encode()
            kwargs["stdout"].write(event + b"\n\x1b[2J\n")
            return 0

        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "run_opencode_review", side_effect=qwen):
            text_output = io.StringIO()
            status = packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--question", "review"],
                workspace=self.workspace,
                provider="qwen",
                runner=self.runner,
                stdout=text_output,
            )
            json_output = io.StringIO()
            json_status = packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--question", "review", "--json"],
                workspace=self.workspace,
                provider="qwen",
                runner=self.runner,
                stdout=json_output,
            )
        self.assertEqual(status, 0)
        self.assertEqual(text_output.getvalue(), "safe[31m")
        self.assertEqual(json_status, 0)
        self.assertNotIn("\x1b", json_output.getvalue())
        self.assertIn('"text": "safe\\u001b[31m"', json_output.getvalue())

    def test_qwen_rejects_progress_before_collecting(self):
        with self.assertRaisesRegex(agentbelt.GuardError, "does not support --progress"):
            packet_pipeline.run(
                ["review", "--provider", "glm", "--files", "safe.py", "--question", "review", "--progress"],
                workspace=self.workspace,
                provider="qwen",
                runner=self.runner,
            )

    def test_model_failure_still_cleans_private_staging(self):
        staged = []

        def failing_runner(mode, workspace, command, **kwargs):
            if mode == "packet-collector":
                kwargs["stdout"].write(export_for(self.packet))
                return 0
            staged.append(Path(workspace))
            return 23

        with patch.object(packet_pipeline.agentbelt, "packet_ask_pinned_version", return_value="0.12.0"), \
             patch.object(packet_pipeline.agentbelt, "prepare_packet_request", return_value=([], [], {})):
            self.assertEqual(
                packet_pipeline.run(
                    ["review", "--provider", "glm", "--files", "safe.py", "--question", "review"],
                    workspace=self.workspace,
                    runner=failing_runner,
                ),
                23,
            )
        self.assertEqual(len(staged), 1)
        self.assertFalse(staged[0].exists())


class ExportParserTests(unittest.TestCase):
    def test_research_model_keeps_mode_and_avoids_second_rendering_flags(self):
        model = packet_pipeline._model_arguments(
            [
                "research",
                "--provider",
                "glm",
                "--include-files",
                "source.py",
                "--question",
                "research this",
                "--line-numbers",
                "--selected-tree",
                "--max-bytes",
                "8192",
            ]
        )
        self.assertEqual(model[0], "research")
        self.assertIn("--include-files", model)
        self.assertEqual(model[model.index("--include-files") + 1], "packet.md")
        self.assertNotIn("--files", model)
        self.assertNotIn("--line-numbers", model)
        self.assertNotIn("--selected-tree", model)
        self.assertEqual(model[model.index("--max-bytes") + 1], "8192")
        self.assertIn(packet_pipeline.MODEL_QUESTION, model)

    def test_oversized_payload_is_rejected(self):
        packet = "x" * (packet_pipeline.MAX_PACKET_BYTES + 1)
        with self.assertRaisesRegex(agentbelt.GuardError, "packet limit"):
            packet_pipeline.parse_export(export_for(packet))

    def test_digest_mismatch_is_rejected(self):
        raw = json.loads(export_for("safe\n"))
        raw["receipt"]["sha256_packet_md"] = "0" * 64
        with self.assertRaisesRegex(agentbelt.GuardError, "digest"):
            packet_pipeline.parse_export(json.dumps(raw))


if __name__ == "__main__":
    unittest.main()
