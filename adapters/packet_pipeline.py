"""Two-stage, scrubbed packet execution.

The packet boundary is deliberately split into two confined processes.  The
collector can read the selected files from the caller's worktree, but has no
network and no credential.  It uses the public packet-ask command in dry-run
mode and exports only the scrubbed ``packet.md`` payload.  The model process
gets a new private worktree containing that payload and cannot read the
caller's worktree.

This module only uses packet-ask's public executable entry point.  It does not
import or patch packet-ask internals.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import agentbelt  # noqa: E402
from adapters import packet_transaction  # noqa: E402


# These are independent bounds.  The envelope includes receipts and framing;
# the payload bound is the only content bound exposed to the model phase.
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
MAX_PACKET_BYTES = 1 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
COLLECTOR_TIMEOUT_MARGIN_SECONDS = 10
MODEL_QUESTION = "Answer the top-level task in the supplied scrubbed packet using only that packet."
SUPPORTED_PROVIDERS = frozenset({"glm", "qwen"})
REDACTION_FIELDS = (
    "private_key_blocks",
    "secret_lines",
    "secret_values",
    "home_paths",
    "emails",
    "phones",
)

_BEGIN_RE = re.compile(r"^-----BEGIN UNTRUSTED PROVIDER OUTPUT ([A-Za-z0-9_-]+)-----$")
_END_RE = re.compile(r"^-----END UNTRUSTED PROVIDER OUTPUT ([A-Za-z0-9_-]+)-----$")
_VALUE_OPTIONS = frozenset(
    {
        "--provider",
        "--question",
        "--files",
        "--include-files",
        "--diff",
        "--timeout",
        "--max-files",
        "--max-bytes",
        "--preflight-timeout",
        "--credential-source",
        "--effort",
    }
)


class PacketPipelineError(agentbelt.GuardError):
    """A malformed export or unsafe staged invocation."""


def _error(message: str) -> PacketPipelineError:
    # Error strings are intentionally independent of captured packet content.
    return PacketPipelineError(message)


def _as_arguments(arguments: Sequence[str]) -> list[str]:
    if isinstance(arguments, (str, bytes)):
        raise _error("packet arguments must be a sequence, not a string")
    try:
        values = list(arguments)
    except TypeError:
        raise _error("packet arguments must be a sequence") from None
    if not all(isinstance(value, str) and "\x00" not in value for value in values):
        raise _error("packet arguments must be non-NUL strings")
    if not values:
        raise _error("packet review/research arguments are required")
    return values


def _split_option(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        name, value = token.split("=", 1)
        return name, value
    return token, None


def _option_values(tokens: Sequence[str], name: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(tokens):
        option, inline = _split_option(tokens[index])
        if option != name:
            index += 1
            continue
        if inline is not None:
            values.append(inline)
            index += 1
            continue
        if index + 1 >= len(tokens):
            raise _error(name + " requires a value")
        values.append(tokens[index + 1])
        index += 2
    return values


def _has_flag(tokens: Sequence[str], name: str) -> bool:
    return any(token == name for token in tokens)


def _remove_flag(tokens: Iterable[str], name: str) -> list[str]:
    return [token for token in tokens if token != name]


def _remove_value_option(tokens: Sequence[str], name: str) -> list[str]:
    """Remove one or more ``name value``/``name=value`` options safely."""
    result: list[str] = []
    index = 0
    while index < len(tokens):
        option, inline = _split_option(tokens[index])
        if option != name:
            result.append(tokens[index])
            index += 1
            continue
        if inline is None:
            if index + 1 >= len(tokens):
                raise _error(name + " requires a value")
            index += 2
        else:
            index += 1
    return result


def _replace_provider(tokens: Sequence[str], provider: str) -> list[str]:
    result: list[str] = []
    found = False
    index = 0
    while index < len(tokens):
        option, inline = _split_option(tokens[index])
        if option != "--provider":
            result.append(tokens[index])
            index += 1
            continue
        if found:
            raise _error("--provider may be supplied only once")
        found = True
        if inline is None:
            if index + 1 >= len(tokens):
                raise _error("--provider requires a value")
            index += 2
        else:
            index += 1
        result.extend(("--provider", provider))
    if not found:
        # The first token is the subcommand, so placing the selector directly
        # after it avoids it being consumed by --files/--include-files.
        result[1:1] = ["--provider", provider]
    return result


def _strip_effort(tokens: Sequence[str]) -> list[str]:
    return _remove_value_option(tokens, "--effort")


def _validate_shape(tokens: Sequence[str], provider: str) -> tuple[str, bool, bool]:
    if not tokens or tokens[0] not in {"review", "research"}:
        raise _error("two-stage packet mode supports review or research only")
    if provider not in SUPPORTED_PROVIDERS:
        raise _error("provider must be one of glm, qwen")
    embedded = _option_values(tokens, "--provider")
    if len(embedded) > 1:
        raise _error("--provider may be supplied only once")
    if embedded and embedded[0] not in SUPPORTED_PROVIDERS:
        raise _error("provider must be one of glm, qwen")
    # Qwen is a host-side model phase, so its collector is intentionally still
    # the keyless GLM/paste invocation.  A caller may therefore carry
    # ``--provider glm`` while selecting ``provider='qwen'`` for the second
    # phase.
    if embedded and embedded[0] != provider and not (provider == "qwen" and embedded[0] == "glm"):
        raise _error("provider argument does not match the selected provider")

    has_files = any(_split_option(token)[0] in {"--files", "--include-files"} for token in tokens)
    has_diff = any(_split_option(token)[0] in {"--diff", "--staged", "--unstaged"} for token in tokens)
    if has_files and has_diff:
        raise _error("file selectors cannot combine with --diff/--staged/--unstaged")
    max_bytes = _option_values(tokens, "--max-bytes")
    for raw in max_bytes:
        try:
            value = int(raw)
        except ValueError:
            raise _error("--max-bytes must be a positive integer") from None
        if value < 1:
            raise _error("--max-bytes must be a positive integer")
        if value > MAX_PACKET_BYTES:
            raise _error("--max-bytes exceeds the two-stage packet limit")
    for name in ("--timeout", "--max-files", "--preflight-timeout"):
        for raw in _option_values(tokens, name):
            try:
                value = int(raw)
            except ValueError:
                raise _error(name + " must be a positive integer") from None
            if value < 1:
                raise _error(name + " must be a positive integer")
    if _has_flag(tokens, "--preview") and _has_flag(tokens, "--dry-run"):
        raise _error("--preview and --dry-run cannot be combined")
    if provider == "qwen" and _option_values(tokens, "--effort"):
        raise _error("qwen does not support --effort")
    if provider == "qwen" and _has_flag(tokens, "--progress"):
        raise _error("qwen does not support --progress")
    return tokens[0], has_files, has_diff


def _collector_arguments(tokens: Sequence[str]) -> list[str]:
    """Build the keyless, no-network packet-ask invocation."""
    result = _replace_provider(tokens, "glm")
    result = _strip_effort(result)
    # Explicit credential-source selection belongs to the live model phase;
    # dry-run must not even inspect a keychain-backed source.
    result = _remove_value_option(result, "--credential-source")
    # A caller's preview is rendered from the parsed scrubbed receipt below;
    # keeping it here would omit the payload that must be validated for a live
    # two-stage invocation.
    result = _remove_flag(result, "--preview")
    result = _remove_flag(result, "--progress")
    if not _has_flag(result, "--dry-run"):
        result.append("--dry-run")
    if not _has_flag(result, "--json"):
        result.append("--json")
    return result


def _skip_selector_values(tokens: Sequence[str], index: int, option: str) -> int:
    """Return the index after a nargs='*' selector and its values."""
    option_name, inline = _split_option(tokens[index])
    if option_name != option:
        return index + 1
    if inline is not None:
        return index + 1
    index += 1
    while index < len(tokens) and not tokens[index].startswith("--"):
        index += 1
    return index


def _model_arguments(tokens: Sequence[str]) -> list[str]:
    """Make a fresh request whose only selected file is packet.md."""
    mode = tokens[0]
    kept: list[str] = [mode]
    requested_max_bytes = _option_values(tokens, "--max-bytes")
    index = 1
    while index < len(tokens):
        option, inline = _split_option(tokens[index])
        if option in {"--files", "--include-files"}:
            index = _skip_selector_values(tokens, index, option)
            continue
        if option in {"--diff", "--staged", "--unstaged"}:
            if option in {"--diff"} and inline is None:
                if index + 1 >= len(tokens):
                    raise _error(option + " requires a value")
                index += 2
            else:
                index += 1
            continue
        if option in {"--question", "--provider"}:
            if inline is None:
                if index + 1 >= len(tokens):
                    raise _error(option + " requires a value")
                index += 2
            else:
                index += 1
            continue
        if option in {"--question-stdin", "--dry-run", "--preview"}:
            index += 1
            continue
        if option == "--max-bytes":
            if inline is None:
                if index + 1 >= len(tokens):
                    raise _error(option + " requires a value")
                index += 2
            else:
                index += 1
            continue
        if option in {"--line-numbers", "--selected-tree"}:
            index += 1
            continue
        kept.append(tokens[index])
        if inline is None and option in _VALUE_OPTIONS - {
            "--files",
            "--include-files",
            "--diff",
            "--question",
            "--provider",
            "--max-bytes",
        }:
            if index + 1 >= len(tokens):
                raise _error(option + " requires a value")
            kept.append(tokens[index + 1])
            index += 2
        else:
            index += 1
    kept = _replace_provider(kept, "glm")
    # The model packet has additional framing around packet.md.  Keep an
    # explicit caller budget as the strict final budget; otherwise use the
    # global final-packet cap.  This may reject a packet whose collector body
    # fits but whose second rendering adds too much framing, which is safer
    # than silently increasing the requested limit.
    final_max_bytes = requested_max_bytes[-1] if requested_max_bytes else str(MAX_PACKET_BYTES)
    selector = "--include-files" if mode == "research" else "--files"
    kept.extend(("--max-bytes", final_max_bytes, selector, "packet.md", "--question", MODEL_QUESTION))
    return kept


def _read_capture(stream: Any, cap: int) -> bytes:
    try:
        stream.seek(0)
        data = stream.read(cap + 1)
    except (OSError, ValueError, AttributeError):
        raise _error("packet-ask output could not be read") from None
    if not isinstance(data, bytes):
        data = str(data).encode("utf-8", errors="replace")
    if len(data) > cap:
        raise _error("packet-ask export exceeds the envelope limit")
    return data


def _bounded_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise _error("packet-ask export is not UTF-8") from None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _extract_payload(untrusted_output: str) -> str:
    lines = untrusted_output.splitlines(keepends=True)
    begins: list[tuple[int, str]] = []
    ends: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        bare = line.rstrip("\r\n")
        begin = _BEGIN_RE.fullmatch(bare)
        end = _END_RE.fullmatch(bare)
        if begin:
            begins.append((index, begin.group(1)))
        if end:
            ends.append((index, end.group(1)))
    if len(begins) != 1 or len(ends) != 1:
        raise _error("packet-ask did not return exactly one scrubbed packet")
    begin_index, token = begins[0]
    end_index, end_token = ends[0]
    if end_index <= begin_index or token != end_token:
        raise _error("packet-ask returned an invalid scrubbed packet envelope")
    payload = "".join(lines[begin_index + 1 : end_index])
    if not payload:
        raise _error("packet-ask returned an empty scrubbed packet")
    if len(payload.encode("utf-8")) > MAX_PACKET_BYTES:
        raise _error("scrubbed packet exceeds the two-stage packet limit")
    return payload


def parse_export(raw: bytes | str) -> tuple[str, dict[str, Any]]:
    """Validate a packet-ask JSON dry-run export and return ``(packet, receipt)``.

    The function validates the public envelope and digest before any model
    credential is requested.  It never returns the raw JSON envelope to callers.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    elif isinstance(raw, bytes):
        raw_bytes = raw
    else:
        raise _error("packet-ask export must be text or bytes")
    if len(raw_bytes) > MAX_ENVELOPE_BYTES:
        raise _error("packet-ask export exceeds the envelope limit")
    try:
        envelope = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _error("packet-ask export is not valid JSON") from None
    if not isinstance(envelope, dict) or envelope.get("schema") != "packet-ask.v1" or envelope.get("ok") is not True:
        raise _error("packet-ask export has an unsupported schema")
    receipt = envelope.get("receipt")
    wrapped = envelope.get("untrusted_output")
    if not isinstance(receipt, dict) or not isinstance(wrapped, str):
        raise _error("packet-ask export is missing the scrubbed payload")
    if receipt.get("provider") != "paste":
        raise _error("collector did not run in paste mode")
    paths = receipt.get("paths")
    redaction = receipt.get("redaction")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise _error("packet-ask export has invalid path metadata")
    if not isinstance(redaction, dict):
        raise _error("packet-ask export has invalid redaction metadata")
    if set(redaction) - set(REDACTION_FIELDS) or any(
        type(value) is not int or value < 0 for value in redaction.values()
    ):
        raise _error("packet-ask export has invalid redaction metadata")
    packet = _extract_payload(wrapped)
    if "\x00" in packet:
        raise _error("scrubbed packet contains a NUL byte")
    packet_bytes = packet.encode("utf-8")
    if type(receipt.get("bytes")) is not int or receipt["bytes"] != len(packet_bytes):
        raise _error("scrubbed packet byte count does not match its receipt")
    digest = receipt.get("sha256_packet_md")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != hashlib.sha256(packet_bytes).hexdigest():
        raise _error("scrubbed packet digest does not match its receipt")
    return packet, receipt


def _private_write(path: Path, content: bytes) -> None:
    if path.is_symlink() or path.exists():
        raise _error("staging packet path already exists")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _trusted_git_init(staging: Path) -> None:
    """Create the only VCS boundary, in the fresh staging directory."""
    environment = {
        "HOME": str(staging),
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "DEVELOPER_DIR": "/Library/Developer/CommandLineTools",
    }
    try:
        result = subprocess.run(
            ["/usr/bin/git", "init", "--quiet"],
            cwd=str(staging),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise _error("could not create the staging git boundary") from None
    if result.returncode != 0:
        raise _error("could not create the staging git boundary")


@contextmanager
def _staging_workspace(packet: str):
    temporary = tempfile.TemporaryDirectory(prefix="agentbelt-packet-stage-")
    staging = Path(temporary.name).resolve()
    try:
        if staging.is_symlink() or not staging.is_dir():
            raise _error("staging workspace is not a private directory")
        staging.chmod(stat.S_IRWXU)
        _private_write(staging / "packet.md", packet.encode("utf-8"))
        _trusted_git_init(staging)
        yield temporary, staging
    finally:
        temporary.cleanup()


def _run_confined_call(
    runner: Callable[..., int],
    mode: str,
    workspace: Path,
    command: list[str],
    **kwargs: Any,
) -> int:
    return int(runner(mode, workspace, command, **kwargs))


def _remaining_seconds(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    return remaining if remaining > 0 else None


def _check_cancelled(cancel_event: Any) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise packet_transaction.TransactionCancelled("packet review was cancelled")


def _collector(
    arguments: list[str],
    workspace: Path,
    *,
    question: str | None,
    runner: Callable[..., int],
    operation_timeout: int | None = None,
    deadline: float | None = None,
    cancel_event: Any = None,
) -> tuple[int, bytes, bytes]:
    output = tempfile.TemporaryFile(mode="w+b")
    errors = tempfile.TemporaryFile(mode="w+b")
    question_stream = None
    try:
        if question is not None:
            if not _has_flag(arguments, "--question-stdin"):
                raise _error("relay question text requires --question-stdin")
            question_stream = tempfile.TemporaryFile(mode="w+b")
            question_stream.write(question.encode("utf-8"))
            question_stream.seek(0)
        environment = {
            "AGENTBELT_PACKET_ASK_VERSION": agentbelt.packet_ask_pinned_version(),
        }
        preflight = _option_values(arguments, "--preflight-timeout")
        collector_timeout = (int(preflight[-1]) if preflight else 30) + COLLECTOR_TIMEOUT_MARGIN_SECONDS
        if operation_timeout is not None:
            collector_timeout = min(collector_timeout, operation_timeout)
        remaining = _remaining_seconds(deadline)
        if deadline is not None and remaining is None:
            raise _error("packet-review exceeded its time limit")
        if remaining is not None:
            collector_timeout = min(collector_timeout, remaining)
        command = [str(agentbelt.PACKET_PYTHON), "-I", str(ROOT / "packet_entry.py"), *arguments]
        options = {
            "domains": [],
            "extra_env": environment,
            "ephemeral": True,
            "read_only_workspace": True,
            "blocked_workspace_paths": (),
            "stdout": output,
            "stderr": errors,
            "stdin": question_stream,
            "timeout": collector_timeout,
        }
        if cancel_event is not None:
            options["cancel_event"] = cancel_event
        status = _run_confined_call(
            runner, "packet-collector", workspace, command, **options)
        return status, _read_capture(output, MAX_ENVELOPE_BYTES), _read_capture(errors, MAX_DIAGNOSTIC_BYTES)
    finally:
        output.close()
        errors.close()
        if question_stream is not None:
            question_stream.close()


def _write_stderr(data: bytes) -> None:
    if not data:
        return
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return
    sys.stderr.write(text)
    sys.stderr.flush()


def _extract_qwen_text(json_lines: str) -> str:
    texts: list[str] = []
    for line in json_lines.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        part = event.get("part") if isinstance(event, dict) else None
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
    return "\n".join(texts)


def _sanitize_terminal_text(text: str) -> str:
    """Drop terminal control bytes while preserving Unicode, LF, and tab."""
    return "".join(
        char
        for char in text
        if char in {"\n", "\t"}
        or not (ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F)
    )


def _write_model_text(text: str, target: Any = None) -> None:
    stream = target if target is not None else sys.stdout
    try:
        stream.write(text)
    except TypeError:
        stream.write(text.encode("utf-8"))
    stream.flush()


def _write_model_error(message: str, target: Any = None) -> None:
    stream = target if target is not None else sys.stderr
    try:
        stream.write(message + "\n")
    except TypeError:
        stream.write((message + "\n").encode("utf-8"))
    stream.flush()


def _preview(receipt: dict[str, Any], provider: str) -> dict[str, Any]:
    # Only allowlisted metadata crosses the preview boundary.  In particular,
    # never copy untrusted_output or arbitrary receipt keys to the caller.
    fields = (
        "selector",
        "paths",
        "bytes",
        "redaction",
        "sha256_packet_md",
        "timeout_seconds",
        "timeout_source",
        "timeout_applies",
        "surface",
        "effort",
        "effort_source",
        "secret_name_exempt_used",
        "supervision",
        "guarantees",
    )
    value = {name: receipt[name] for name in fields if name in receipt}
    value["redaction"] = {
        name: int(receipt["redaction"][name])
        for name in REDACTION_FIELDS
        if name in receipt.get("redaction", {})
    }
    value.update({"provider": provider, "launch": "not-started"})
    return value


def _emit_preview(
    receipt: dict[str, Any],
    provider: str,
    as_json: bool,
    tokens: Sequence[str],
) -> None:
    value = _preview(receipt, provider)
    efforts = _option_values(tokens, "--effort")
    if efforts:
        value["effort"] = efforts[-1]
        value["effort_source"] = "explicit"
    if as_json:
        sys.stdout.write(json.dumps({"schema": "packet-ask.v1", "ok": True, "preview": value}, ensure_ascii=False, indent=2) + "\n")
    else:
        paths = json.dumps(value.get("paths", []), ensure_ascii=False)
        print(
            "packet-ask preview provider=" + provider +
            " selector=" + str(value.get("selector", "none")) +
            " paths=" + paths +
            " bytes=" + str(value.get("bytes", 0)) +
            " launch=not-started"
        )


def _model_glm(
    tokens: Sequence[str],
    staging: Path,
    *,
    use_keychain: bool,
    runner: Callable[..., int],
    stdout: Any = None,
    stderr: Any = None,
    deadline: float | None = None,
    cancel_event: Any = None,
) -> int:
    model_args = _model_arguments(tokens)
    _check_cancelled(cancel_event)
    prepare_options: dict[str, Any] = {}
    if deadline is not None:
        prepare_options["deadline"] = deadline
    if cancel_event is not None:
        prepare_options["cancel_event"] = cancel_event
    prepared, domains, environment = agentbelt.prepare_packet_request(
        model_args, use_keychain, **prepare_options)
    _check_cancelled(cancel_event)
    process_timeout = _remaining_seconds(deadline)
    if deadline is not None and process_timeout is None:
        raise _error("packet-review deadline expired before model start")
    command = [str(agentbelt.PACKET_PYTHON), "-I", str(ROOT / "packet_entry.py"), *prepared]
    options = {
        "domains": domains,
        "extra_env": environment,
        "ephemeral": True,
        "read_only_workspace": True,
        "blocked_workspace_paths": (),
        "stdout": stdout,
        "stderr": stderr,
        "timeout": process_timeout,
    }
    if cancel_event is not None:
        options["cancel_event"] = cancel_event
    return _run_confined_call(
        runner, "packet-model", staging, command, **options)


def _model_qwen(
    packet: str,
    staging: Path,
    tokens: Sequence[str],
    *,
    stdout: Any = None,
    stderr: Any = None,
    operation_timeout: float | None = None,
    deadline: float | None = None,
    cancel_event: Any = None,
) -> int:
    _check_cancelled(cancel_event)
    prompt = MODEL_QUESTION + "\n\nScrubbed packet:\n" + packet
    options: dict[str, Any] = {}
    if stderr is not None:
        options["stderr"] = stderr
    timeout = _option_values(tokens, "--timeout")
    if timeout:
        requested = int(timeout[-1])
        options["timeout"] = min(requested, operation_timeout) if operation_timeout is not None else requested
    elif operation_timeout is not None:
        options["timeout"] = operation_timeout
    if deadline is not None:
        if _remaining_seconds(deadline) is None:
            raise _error("packet-review deadline expired before model start")
        options["deadline"] = deadline
    if cancel_event is not None:
        options["cancel_event"] = cancel_event
    capture = tempfile.TemporaryFile(mode="w+b")
    options["stdout"] = capture
    try:
        status = int(agentbelt.run_opencode_review(staging, prompt, **options))
        if status != 0:
            return status
        try:
            raw = _read_capture(capture, MAX_ENVELOPE_BYTES)
            rendered = _bounded_text(raw)
        except PacketPipelineError:
            _write_model_error("reviewer output was invalid or exceeded the output limit", stderr)
            return 1
        text_content = _extract_qwen_text(rendered)
        if not text_content.strip():
            _write_model_error("reviewer produced no text", stderr)
            return 1
        if _has_flag(tokens, "--json"):
            rendered = _sanitize_terminal_text(rendered)
        else:
            rendered = _sanitize_terminal_text(text_content)
        if not rendered.strip():
            _write_model_error("reviewer produced no text", stderr)
            return 1
        _write_model_text(rendered, stdout)
        return 0
    finally:
        capture.close()


def run(
    arguments: Sequence[str],
    use_keychain: bool = False,
    workspace: str | os.PathLike[str] | None = None,
    provider: str = "glm",
    *,
    question: str | None = None,
    runner: Callable[..., int] | None = None,
    stdout: Any = None,
    stderr: Any = None,
    operation_timeout: int | None = None,
    deadline: float | None = None,
    cancel_event: Any = None,
    transaction_state_file: str | os.PathLike[str] | None = None,
) -> int:
    """Run a two-stage packet operation and return the model process status.

    ``arguments`` has the same shape as packet-ask's ``review``/``research``
    arguments after agentbelt's top-level ``--use-keychain`` flag.  The
    optional ``question`` is used only by the relay when it has already read a
    ``--question-stdin`` request; normal CLI calls inherit their stdin.
    """
    tokens = _as_arguments(arguments)
    if "--use-keychain" in tokens:
        tokens = [token for token in tokens if token != "--use-keychain"]
    _validate_shape(tokens, provider)
    if operation_timeout is not None and (type(operation_timeout) is not int or operation_timeout < 1):
        raise _error("operation timeout must be a positive integer")
    if operation_timeout is None:
        requested_timeout = _option_values(tokens, "--timeout")
        operation_timeout = int(requested_timeout[-1]) if requested_timeout else None
    if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float))):
        raise _error("operation deadline must be monotonic time")
    started = time.monotonic()
    operation_deadline = started + operation_timeout if operation_timeout is not None else None
    if deadline is None:
        deadline = operation_deadline
    elif operation_deadline is not None:
        deadline = min(deadline, operation_deadline)
    root = Path(workspace or os.getcwd()).resolve()
    if not root.is_dir() or root.is_symlink():
        raise _error("workspace must be a directory")
    confined = runner or agentbelt.run_confined
    collector_args = _collector_arguments(tokens)
    state_file = (Path(transaction_state_file) if transaction_state_file is not None
                  else Path(agentbelt.ROOT) / "state/packet-ask-version.json")
    with packet_transaction.consumer(state_file, deadline=deadline, cancel_event=cancel_event):
        _check_cancelled(cancel_event)
        status, raw, errors = _collector(
            collector_args,
            root,
            question=question,
            runner=confined,
            operation_timeout=operation_timeout,
            deadline=deadline,
            cancel_event=cancel_event,
        )
        if status != 0:
            _write_stderr(errors)
            return status
        packet, receipt = parse_export(raw)

        # Explicit dry-run remains a collector-only operation.  The packet body is
        # intentionally returned only because the caller requested dry-run; preview
        # always emits metadata and never exposes the body.
        if _has_flag(tokens, "--dry-run"):
            _write_stderr(errors)
            sys.stdout.write(_bounded_text(raw))
            return 0
        if _has_flag(tokens, "--preview"):
            _emit_preview(receipt, provider, _has_flag(tokens, "--json"), tokens)
            _write_stderr(errors)
            return 0

        with _staging_workspace(packet) as (_temporary, staging):
            if provider == "qwen":
                return _model_qwen(
                    packet,
                    staging,
                    tokens,
                    stdout=stdout,
                    stderr=stderr,
                    operation_timeout=_remaining_seconds(deadline),
                    deadline=deadline,
                    cancel_event=cancel_event,
                )
            return _model_glm(
                tokens,
                staging,
                use_keychain=use_keychain,
                runner=confined,
                stdout=stdout,
                stderr=stderr,
                deadline=deadline,
                cancel_event=cancel_event,
            )


__all__ = [
    "MAX_ENVELOPE_BYTES",
    "MAX_PACKET_BYTES",
    "MODEL_QUESTION",
    "PacketPipelineError",
    "parse_export",
    "run",
]
