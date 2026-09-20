"""File relay that lets the safecode supervisor run packet-ask on behalf of the sandbox.

Why this is needed. Inside the sandbox the kernel refuses nested `sandbox-exec`, so packet-ask
cannot be run there. Previously the agent had to prepare the packet and a human had to run it in
a host terminal and paste the result back. This module makes the supervisor that is already
running on the host (the agentbelt process that launched safecode) do that work instead.

The channel is a file. The child writes `$TMPDIR/packet-requests/<id>.json`, and the supervisor
thread reads it, runs the two-stage packet pipeline (a keyless scrubber in the
original read-only worktree followed by the selected model in a fresh staging
workspace) and then returns `<id>.result.md` or `<id>.error.txt`. There is no
new port, socket or daemon, and the channel disappears when the session ends.
The key never enters the collector sandbox.
"""
import json
from contextlib import contextmanager
import os
import secrets
import signal
import stat
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agentbelt  # noqa: E402
from adapters import packet_transaction  # noqa: E402

# The request directory lives under the child's $TMPDIR (the isolated home's tmp). It has to be a place the child can write.
REQUEST_DIRECTORY = 'tmp/packet-requests'
# Helpers planted by the supervisor. They are read-only, so the child cannot swap them out.
HELPER_PATH = 'bin/packet-review'
PROMOTE_HELPER_PATH = 'bin/packet-promote'
PROMOTE_HELPER_SCRIPT = r'''#!/bin/bash
# agentbelt packet-promote: ask the supervisor to promote packet-ask. On the host it checks provenance, adapter
# identity and the guard tests, and installs and pins only when they pass. Usage: packet-promote <x.y.z>
set -u
[ $# -eq 1 ] || { echo "usage: packet-promote <x.y.z>" >&2; exit 64; }
dir="$TMPDIR/packet-requests"; mkdir -p "$dir"; id="promote-$(date +%s)-$$"
printf '{"promote": "%s"}' "$1" > "$dir/$id.json.tmp" && mv "$dir/$id.json.tmp" "$dir/$id.json"
echo "packet-promote: request $id submitted; the supervisor installs, diffs the adapter and runs the guard suite (up to 15 min)" >&2
waited=0
while [ "$waited" -lt 1200 ]; do
  if [ -f "$dir/$id.result.md" ]; then cat "$dir/$id.result.md"; exit 0; fi
  if [ -f "$dir/$id.error.txt" ]; then echo "packet-promote: refused" >&2; cat "$dir/$id.error.txt" >&2; exit 1; fi
  sleep 2; waited=$((waited + 2))
done
echo "packet-promote: timed out" >&2; exit 124
'''
# timeoutSeconds: 30 minutes, matching the measurement where the qwen reviewer took more than 9 minutes on a large repository .
DEFAULT_SETTINGS = {'maxPerHour': 6, 'maxQuestionBytes': 16384, 'maxFiles': 40, 'pollSeconds': 1.0, 'timeoutSeconds': 1800}
EFFORTS = {'low', 'medium', 'high', 'xhigh', 'max'}
# glm: packet-ask (a scrubbed packet). qwen: the same staged packet is handed to a read-only reviewer.
PROVIDERS = {'glm', 'qwen'}
GEMINI_DISABLED = ('Gemini relay is disabled because host agy has no enforced isolation. '
                   'Use --provider glm or --provider qwen.')
PROGRESS_DISABLED = ('--progress is unavailable through the packet-review file relay; '
                     'use packet-ask-safe directly for live progress.')
# packet-ask --diff only takes a git reference range. Shell metacharacters and path characters are rejected.
DIFF_CHARACTERS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/~^@{}')

# The helper script the child uses. It turns its arguments into a JSON request and waits for the result file.
HELPER_SCRIPT = r'''#!/bin/bash
# agentbelt packet-review: ask the supervisor for a GLM review. packet-ask does not run directly
# inside the sandbox, so this script is the only path. Usage:
#   packet-review [--provider glm|qwen] --files a.py b.py [--diff origin/main...HEAD] [--effort high] (--question "..." | --question-stdin)
# glm (default): packet-ask sends a scrubbed packet to GLM. qwen: the same scrubbed packet is reviewed in private staging.
set -u
files=(); question=""; from_stdin=0; effort=""; diff=""; provider=""; timeout=1800; json_output=0
while [ $# -gt 0 ]; do
  case "$1" in
    --files) shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do files+=("$1"); shift; done ;;
    --question) question="$2"; shift 2 ;;
    --question-stdin) from_stdin=1; shift ;;
    --effort) effort="$2"; shift 2 ;;
    --diff) diff="$2"; shift 2 ;;
    --provider) provider="$2"; shift 2 ;;
    --timeout) timeout="$2"; shift 2 ;;
    --json) json_output=1; shift ;;
    --progress) echo "packet-review: --progress is unavailable through the file relay; use packet-ask-safe directly for live progress." >&2; exit 64 ;;
    *) echo "packet-review: unknown argument $1" >&2; exit 64 ;;
  esac
done
if [ "$from_stdin" = 1 ]; then question="$(cat)"; fi
if [ -z "$question" ]; then echo "packet-review: a question is required (--question or --question-stdin)" >&2; exit 64; fi
dir="$TMPDIR/packet-requests"; mkdir -p "$dir"
id="$(date +%s)-$$"
export PR_ID="$id" PR_Q="$question" PR_EFFORT="$effort" PR_DIFF="$diff" PR_PROVIDER="$provider" PR_TIMEOUT="$timeout" PR_JSON="$json_output"
# The /usr/bin/python3 shim tries to use the xcrun cache and prints an error inside the sandbox, so use the CLT interpreter directly.
/Library/Developer/CommandLineTools/usr/bin/python3 -I - "${files[@]}" > "$dir/$id.json.tmp" <<'PY'
import json, os, sys
payload = {'files': sys.argv[1:], 'question': os.environ['PR_Q']}
if os.environ.get('PR_EFFORT'): payload['effort'] = os.environ['PR_EFFORT']
if os.environ.get('PR_DIFF'): payload['diff'] = os.environ['PR_DIFF']
if os.environ.get('PR_PROVIDER'): payload['provider'] = os.environ['PR_PROVIDER']
if os.environ.get('PR_TIMEOUT'): payload['timeout'] = os.environ['PR_TIMEOUT']
if os.environ.get('PR_JSON') == '1': payload['json'] = True
json.dump(payload, sys.stdout)
PY
mv "$dir/$id.json.tmp" "$dir/$id.json"
echo "packet-review: request $id submitted; waiting for the supervisor (up to ${timeout}s)" >&2
waited=0
while [ "$waited" -lt "$timeout" ]; do
  if [ -f "$dir/$id.result.md" ]; then cat "$dir/$id.result.md"; exit 0; fi
  if [ -f "$dir/$id.error.txt" ]; then echo "packet-review: failed" >&2; cat "$dir/$id.error.txt" >&2; exit 1; fi
  sleep 1; waited=$((waited + 1))
done
echo "packet-review: timed out waiting for $id" >&2; exit 124
'''


def validate_request(payload, workspace, settings):
    """Validate the request written by the child and turn it into packet-ask arguments. Paths outside the workspace are rejected."""
    limits = dict(DEFAULT_SETTINGS, **settings)
    if not isinstance(payload, dict):
        raise agentbelt.GuardError('request must be a JSON object')
    if 'promote' in payload:
        from adapters import packet_promote
        packet_promote.parse_version(payload['promote'])  # Format check. The host runner checks existence and publisher.
        return {'provider': 'promote', 'version': str(payload['promote'])}
    files = payload.get('files', [])
    if not isinstance(files, list) or len(files) > limits['maxFiles']:
        raise agentbelt.GuardError('files must be a list within the maxFiles limit')
    diff = payload.get('diff')
    if files and diff is not None:
        raise agentbelt.GuardError('review cannot combine --files with --diff; choose one selector')
    if not files and diff is None:
        raise agentbelt.GuardError('supply either a non-empty files list or a diff selector')
    root = Path(workspace).resolve()
    for name in files:
        if not isinstance(name, str) or not name or '\x00' in name or any(ord(char) < 32 for char in name):
            raise agentbelt.GuardError('file names must be non-empty strings')
        if name.startswith('-'):
            # It goes into the packet-ask argv as is, so a name that looks like a flag is rejected.
            raise agentbelt.GuardError('file name ' + name + ' looks like a flag; rename it or use a ./ prefix')
        candidate = (root / name).resolve()
        if candidate == root or root not in candidate.parents:
            raise agentbelt.GuardError('file ' + name + ' is outside the workspace')
    question = payload.get('question')
    if not isinstance(question, str) or not question.strip():
        raise agentbelt.GuardError('question must be a non-empty string')
    try:
        question_bytes = question.encode('utf-8')
    except UnicodeEncodeError:
        raise agentbelt.GuardError('question must be valid UTF-8') from None
    if len(question_bytes) > limits['maxQuestionBytes']:
        raise agentbelt.GuardError('question exceeds maxQuestionBytes')
    arguments = ['--use-keychain', 'review', '--provider', 'glm']
    if files:
        arguments += ['--files', *files]
    else:
        # packet-ask's review mode accepts a git range as its sole scope.
        arguments += ['--diff', diff]
    arguments += ['--question-stdin']
    effort = payload.get('effort')
    if effort is not None:
        if effort not in EFFORTS:
            raise agentbelt.GuardError('effort must be one of ' + ', '.join(sorted(EFFORTS)))
    if diff is not None:
        if not isinstance(diff, str) or not diff or len(diff) > 200 or not set(diff) <= DIFF_CHARACTERS or diff.startswith('-'):
            raise agentbelt.GuardError('diff must be a plain git reference range')
    provider = payload.get('provider', 'glm')
    if provider == 'gemini':
        raise agentbelt.GuardError(GEMINI_DISABLED)
    if provider not in PROVIDERS:
        raise agentbelt.GuardError('provider must be one of ' + ', '.join(sorted(PROVIDERS)))
    if effort is not None:
        if provider == 'qwen':
            raise agentbelt.GuardError('qwen does not support --effort')
        arguments += ['--effort', effort]
    timeout = payload.get('timeout')
    if timeout is not None:
        if isinstance(timeout, bool) or (not isinstance(timeout, (int, str))):
            raise agentbelt.GuardError('timeout must be a positive integer within timeoutSeconds')
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise agentbelt.GuardError('timeout must be a positive integer within timeoutSeconds') from None
        if timeout < 1 or timeout > limits['timeoutSeconds']:
            raise agentbelt.GuardError('timeout must be a positive integer within timeoutSeconds')
        arguments += ['--timeout', str(timeout)]
    if payload.get('json') is True:
        arguments.append('--json')
    if payload.get('progress') is True:
        raise agentbelt.GuardError(PROGRESS_DISABLED)
    if provider == 'qwen':
        return {'provider': 'qwen', 'arguments': arguments, 'question': question,
                'prompt': review_prompt(files, diff, question)}
    return {'provider': 'glm', 'arguments': arguments, 'question': question}


def review_prompt(files, diff, question):
    """Legacy metadata prompt retained without carrying raw-workspace input.

    The actual Qwen call is made by :mod:`packet_pipeline` after staging.  A
    generic value here keeps old request records structurally compatible while
    ensuring no relay path can accidentally hand raw paths or questions to a
    reviewer.
    """
    return 'Review the scrubbed packet in the private staging workspace and report concrete findings.'


def extract_review_text(json_lines):
    """Concatenate only the text parts out of the `opencode run --format json` event stream."""
    texts = []
    for line in json_lines.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        part = event.get('part') if isinstance(event, dict) else None
        if isinstance(part, dict) and part.get('type') == 'text' and isinstance(part.get('text'), str):
            texts.append(part['text'])
    return '\n'.join(texts)


def host_runner(provider, prepared, workspace):
    """Run the two-stage protected path for the selected provider.

    Both providers collect through the keyless packet-ask dry-run first.  The
    model phase receives a fresh staged workspace; no provider gets the relay's
    original worktree.
    """
    if provider == 'promote':
        from adapters import packet_promote
        try:
            return 0, packet_promote.promote(prepared['version']), ''
        except agentbelt.GuardError as problem:
            return 1, '', str(problem)
    if provider == 'gemini':
        return 2, '', GEMINI_DISABLED
    if provider not in PROVIDERS:
        return 2, '', 'Unsupported review provider.'
    from adapters import packet_pipeline
    from tempfile import TemporaryFile

    timeout = _relay_timeout(prepared.get('arguments', []))
    if timeout is None:
        return 1, '', 'packet-review timeout is invalid or exceeds the 1800-second limit'

    output = TemporaryFile(mode='w+b')
    errors = TemporaryFile(mode='w+b')
    try:
        try:
            with packet_transaction.consumer(ROOT / 'state/packet-ask-version.json'):
                status = packet_pipeline.run(
                    prepared['arguments'],
                    use_keychain=True,
                    workspace=workspace,
                    provider=provider,
                    question=prepared['question'],
                    stdout=output,
                    stderr=errors,
                    operation_timeout=timeout,
                )
        except agentbelt.GuardError as problem:
            return 1, '', str(problem)
        output.seek(0)
        errors.seek(0)
        text_bytes = output.read(packet_pipeline.MAX_ENVELOPE_BYTES + 1)
        error_text = errors.read(16 * 1024).decode('utf-8', errors='replace')
        if len(text_bytes) > packet_pipeline.MAX_ENVELOPE_BYTES:
            return 1, '', 'model output exceeded the relay limit'
        text = text_bytes.decode('utf-8', errors='replace')
        return status, text, error_text
    finally:
        output.close()
        errors.close()


def _relay_timeout(arguments):
    """Return the requested provider timeout, bounded by the relay lifetime."""
    value = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == '--timeout':
            if index + 1 >= len(arguments):
                return None
            raw = arguments[index + 1]
            index += 2
        elif token.startswith('--timeout='):
            raw = token.partition('=')[2]
            index += 1
        else:
            index += 1
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        if value < 1 or value > DEFAULT_SETTINGS['timeoutSeconds']:
            return None
    return value if value is not None else DEFAULT_SETTINGS['timeoutSeconds']


class PacketRelay:
    """Supervisor thread that watches the request directory during a safecode session and runs packet-ask on the child's behalf."""

    def __init__(self, workspace, home, runner=host_runner, settings=None):
        self.workspace = Path(workspace)
        self.home = Path(home)
        self.runner = runner
        self.settings = dict(DEFAULT_SETTINGS, **(settings or {}))
        self.requests = self.home / REQUEST_DIRECTORY
        self.write_root = self.home
        self.started = []  # Recent run timestamps. Used for the hourly limit.
        self.stop = threading.Event()
        # A live promotion is part of the supervisor lifetime.  A non-daemon
        # watcher cannot silently release its transaction lock at interpreter
        # shutdown while an installer it started keeps mutating the uv tool.
        self.thread = threading.Thread(target=self._watch, daemon=False)
        self._scan = None
        self._scan_path = None
        self._previous_sigterm = None
        self._termination_started = False

    def prepare(self, home, env):
        """The prepare_home hook of run_confined. It plants the helpers, creates the request directory and puts them first on PATH.

        The home passed in by run_confined is the home the child actually sees, so the paths are
        rebound here. The watcher thread reads self.requests on every pass, so it takes effect immediately.
        """
        self.home = Path(home)
        # The helper writes to `$TMPDIR/packet-requests`, so if the child's TMPDIR is not the isolated home's tmp, look there.
        # The result files are also written link-safely relative to that same root (a supervisor-owned directory).
        self.write_root = Path(env['TMPDIR']) if env.get('TMPDIR') else self.home
        self.requests = self.write_root / 'packet-requests' if env.get('TMPDIR') else self.home / REQUEST_DIRECTORY
        helper = self.home / HELPER_PATH
        # Link-safe write: a link planted by an earlier session is not followed; the link itself is removed.
        agentbelt.write_private_file(self.home, HELPER_PATH, HELPER_SCRIPT, mode=0o500)
        agentbelt.write_private_file(self.home, PROMOTE_HELPER_PATH, PROMOTE_HELPER_SCRIPT, mode=0o500)
        agentbelt.private_dir(self.requests)
        env['PATH'] = str(helper.parent) + ':' + env.get('PATH', '')
        # The marker that makes the notice point at packet-review instead of "hand it to the user".
        env['AGENTBELT_PACKET_REVIEW'] = '1'

    def read_only_home_paths(self):
        """Isolated-home-relative paths to put in denyWrite so the child cannot swap out the helpers."""
        return [HELPER_PATH, PROMOTE_HELPER_PATH]

    def notice(self):
        """Usage text to append to the environment notice."""
        return ('## External model review (packet-review)\n\n'
                'You cannot run `packet-ask` directly in this session, but the supervisor runs it for you. '
                'Request it with `packet-review [--provider glm|qwen] --files <workspace-relative paths...> '
                '[--diff <git range>] [--effort high] [--timeout seconds] [--json] --question-stdin` '
                'and the resulting Markdown comes back on standard output. '
                'glm (the default) sends a scrubbed packet to GLM; with qwen the same scrubbed packet is reviewed in a fresh read-only staging workspace. '
                'diff is not a file but a git range (`origin/main...HEAD`). Do not ask the user to run this on the host; '
                'use this command. Limited to ' + str(self.settings['maxPerHour']) + ' per hour.\n'
                'To bring a new version of packet-ask onto the host, use `packet-promote <x.y.z>`. The supervisor checks the PyPI provenance '
                'publisher, the byte identity of the adapter files and the guard tests, and installs and pins it only when they pass. If it is refused, the reason comes back.\n')

    def __enter__(self):
        if threading.current_thread() is threading.main_thread():
            self._previous_sigterm = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGTERM, self._handle_sigterm)
        try:
            self.thread.start()
        except BaseException:
            self._restore_sigterm()
            raise
        return self

    def __exit__(self, *details):
        self.stop.set()
        # _watch runs each request synchronously.  Waiting without an arbitrary
        # timeout keeps the supervisor and promotion rollback authority alive
        # until the active request has reached a durable result.
        try:
            self.thread.join()
        finally:
            self._restore_sigterm()

    def _handle_sigterm(self, signum, frame):
        """Turn normal termination into stack unwinding through ``__exit__``."""
        if self._termination_started:
            return
        self._termination_started = True
        self.stop.set()
        raise SystemExit(128 + signum)

    def _restore_sigterm(self):
        if self._previous_sigterm is not None and threading.current_thread() is threading.main_thread():
            previous, self._previous_sigterm = self._previous_sigterm, None
            signal.signal(signal.SIGTERM, previous)

    def _watch(self):
        try:
            while not self.stop.is_set():
                try:
                    self._poll()
                except FileNotFoundError:
                    self._close_scan()  # prepare() may not have created the channel yet.
                except Exception as error:
                    self._close_scan()
                    print('packet-relay: watcher error: ' + type(error).__name__, file=sys.stderr)
                self.stop.wait(self.settings['pollSeconds'])
        finally:
            self._close_scan()

    @contextmanager
    def _queue_directory(self):
        """Keep every queue read, rename and unlink beneath held no-follow dirfds."""
        relative = self.requests.relative_to(self.write_root)
        if any(part in ('.', '..') for part in relative.parts):
            raise agentbelt.GuardError('Invalid request directory.')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(str(self.write_root), flags)
        try:
            for part in relative.parts:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            if os.fstat(descriptor).st_uid != os.getuid():
                raise agentbelt.GuardError('Request directory is not owned by you.')
            yield descriptor
        finally:
            os.close(descriptor)

    def _close_scan(self):
        if self._scan is not None:
            self._scan.close()
            self._scan = None
        self._scan_path = None

    def _poll(self):
        # Keep the directory cursor between polls instead of sorting all retained
        # files each second. Even a child-created backlog costs at most 128 entries.
        if self._scan_path != self.requests:
            self._close_scan()
        if self._scan is None:
            with self._queue_directory() as descriptor:
                self._scan = os.scandir(descriptor)
            self._scan_path = self.requests
        count = 0
        for _ in range(128):
            if self.stop.is_set():
                break
            try:
                entry = next(self._scan)
            except StopIteration:
                self._close_scan()
                break
            count += 1
            if entry.name.endswith('.json'):
                try:
                    self._handle(self.requests / entry.name)
                except FileNotFoundError:
                    pass  # The child may have withdrawn this request.
            elif entry.name.endswith(('.result.md', '.error.txt')):
                with self._queue_directory() as descriptor:
                    try:
                        info = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                        if info.st_mtime < time.time() - 86400:
                            os.unlink(entry.name, dir_fd=descriptor)
                    except FileNotFoundError:
                        pass
        return count

    def _handle(self, request):
        if request.parent != self.requests:
            raise agentbelt.GuardError('Request is outside its channel.')
        self._process_request(request)
        # The response has been published (or already existed). Keep it for the
        # waiting helper, but remove the request so it cannot be replayed next run.
        with self._queue_directory() as descriptor:
            try:
                os.unlink(request.name, dir_fd=descriptor)
            except FileNotFoundError:
                pass

    def _process_request(self, request):
        stem = request.name[:-len('.json')]
        result, error = request.with_name(stem + '.result.md'), request.with_name(stem + '.error.txt')
        if result.exists() or error.exists():
            return
        now = time.monotonic()
        self.started = [t for t in self.started if now - t < 3600]
        if len(self.started) >= self.settings['maxPerHour']:
            self._write(error, 'hourly packet-review limit reached (' + str(self.settings['maxPerHour']) + ')')
            return
        # Invalid input still spends a request attempt; it cannot bypass accounting.
        self.started.append(now)
        try:
            payload = json.loads(self._read_request(request))
        except agentbelt.GuardError as problem:
            self._write(error, str(problem))
            return
        except ValueError:
            self._write(error, 'request is not valid JSON')
            return
        try:
            prepared = validate_request(payload, self.workspace, self.settings)
        except agentbelt.GuardError as problem:
            self._write(error, str(problem))
            return
        self._record(stem, payload)
        try:
            status, out, err = self.runner(prepared['provider'], prepared, self.workspace)
        except Exception as problem:
            self._write(error, 'packet-ask could not be started: ' + type(problem).__name__)
            return
        if status != 0:
            note = ''
            if status == 125:
                # 125 is the supervisor's sandbox-init failure exit: the child never ran, so the
                # attempt never reached the provider and must not spend the hourly budget.
                self.started.remove(now)
                note = ' (not counted toward the hourly limit)'
            self._write(error, 'packet-ask exited ' + str(status) + note + '\n' + err[-4000:])
        else:
            self._write(result, out)

    def _record(self, stem, payload):
        """A content-free audit record. It keeps only what was sent and when."""
        log = agentbelt.private_dir(ROOT / 'state/packet-relay') / 'requests.jsonl'
        entry = {'time': time.strftime('%Y-%m-%dT%H:%M:%S'), 'id': stem, 'workspace': str(self.workspace),
                 'provider': 'promote' if 'promote' in payload else payload.get('provider', 'glm'),
                 'promote': payload.get('promote'),
                 'files': payload.get('files'), 'diff': payload.get('diff'), 'effort': payload.get('effort'),
                 'questionBytes': len(str(payload.get('question', '')).encode())}
        descriptor = os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, 'a') as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + '\n')

    # The cap on the request file written by the child. It is the question cap (16 KB) plus room for the JSON wrapper.
    MAX_REQUEST_BYTES = 64 * 1024

    def _read_request(self, request):
        """Read the request the child created. Regular files only, links are not followed, and only up to the cap.

        A FIFO or a device file would stall the watcher thread forever, a huge file would exhaust
        memory, and a link would make it read a host file (review HIGH). All three are filtered out here.
        """
        with self._queue_directory() as parent:
            try:
                descriptor = os.open(request.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                raise
            except OSError:
                raise agentbelt.GuardError('request must be a readable regular file') from None
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise agentbelt.GuardError('request must be a regular file')
            raw = stream.read(self.MAX_REQUEST_BYTES + 1)
            if len(raw) > self.MAX_REQUEST_BYTES:
                raise agentbelt.GuardError('request too large (limit ' + str(self.MAX_REQUEST_BYTES) + ' bytes)')
            return raw.decode('utf-8', errors='replace')

    def _write(self, path, text):
        """Write the result or error file link-safely, then expose it atomically with a rename."""
        if path.parent != self.requests:
            raise agentbelt.GuardError('Response is outside its channel.')
        with self._queue_directory() as parent:
            temporary = '.response-' + secrets.token_hex(12)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                with os.fdopen(descriptor, 'w') as stream:
                    stream.write(text)
                os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
