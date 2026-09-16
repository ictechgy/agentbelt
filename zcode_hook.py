#!/usr/bin/python3
"""PreToolUse guardrails. Errors deny; original inputs are never logged."""
import base64
import fnmatch
import json
from pathlib import Path
import re
import os
import shlex
import stat
import sys


def decision(value, reason=None, updated=None):
    body = {'hookEventName': 'PreToolUse', 'permissionDecision': value}
    if reason:
        body['permissionDecisionReason'] = reason
    if updated is not None:
        body['updatedInput'] = updated
    return {'hookSpecificOutput': body}


def emit(result):
    print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))


sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    # Loading the policy modules is a precondition for evaluating anything. A
    # failure here leaves no basis for a decision, so honour the deny contract
    # instead of exiting on an uncaught import error. The exception text carries
    # installation paths, so only a fixed message is emitted.
    from agentbelt import GuardError, ROOT, SECRET_NAMES, inside_zcode_sandbox, workspace_path
    from riskgate_bridge import riskgate_decision
except Exception:
    emit(decision('deny', 'The request was blocked because the protection policy modules could not be loaded.'))
    raise SystemExit(2)


# A token naming the shared temp directory, which the sandbox never grants.
SHARED_TEMP = re.compile(r'(?:^|[\s"\'=<>(|;&])/(?:private/)?tmp(?:/|\b)')


def agent_state_root():
    """The agent's own persistent area inside the isolated home.

    Memory lives here, not in the project, so a workspace-only rule refuses the
    agent's own notes. HOME is the isolated home while confined.
    """
    return Path(os.environ.get('HOME', '/nonexistent')) / '.zcode'


def safe_path(raw, workspace, allow_directory=False, agent_state=False):
    if not isinstance(raw, str) or not raw or '\x00' in raw:
        raise GuardError('The file path is missing or invalid.')
    value = Path(raw).expanduser()
    if not value.is_absolute():
        value = workspace / value
    resolved = value.resolve(strict=False)
    inside_workspace = resolved == workspace or workspace in resolved.parents
    state = agent_state_root()
    inside_state = agent_state and (resolved == state or state in resolved.parents)
    if not inside_workspace and not inside_state:
        raise GuardError('File access outside the project is blocked.')
    if inside_state:
        return resolved
    parts = value.relative_to(workspace).parts if value.is_relative_to(workspace) else ()
    for part in (*parts, *resolved.relative_to(workspace).parts):
        if part.lower() == '.git' or any(fnmatch.fnmatchcase(part.lower(), p.lower()) for p in SECRET_NAMES):
            raise GuardError('Sensitive files and credential or Git internal paths cannot be accessed directly.')
    try:
        info = resolved.stat()
    except FileNotFoundError:
        return resolved
    if stat.S_ISDIR(info.st_mode):
        if not allow_directory:
            raise GuardError('This tool accepts regular file paths only.')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
        raise GuardError('Special files and hard links cannot be accessed.')
    return resolved


def evaluate(payload):
    if not isinstance(payload, dict) or payload.get('hook_event_name', payload.get('hookEventName')) != 'PreToolUse':
        raise GuardError('This hook request is not supported.')
    tool = payload.get('tool_name', payload.get('toolName'))
    inputs = payload.get('tool_input', payload.get('toolInput'))
    if not isinstance(tool, str) or not isinstance(inputs, dict):
        raise GuardError('The tool request format is invalid.')
    workspace = workspace_path(payload.get('cwd', ''), scan_hardlinks=False)
    confined = inside_zcode_sandbox()
    if tool in {'TodoRead', 'TodoWrite', 'AskUserQuestion', 'EnterPlanMode', 'ExitPlanMode'}:
        return decision('allow')
    if tool in {'Read', 'Edit', 'Write'}:
        path = safe_path(inputs.get('file_path'), workspace, agent_state=confined)
        updated = dict(inputs, file_path=str(path))
        return decision('allow' if tool == 'Read' else 'ask', updated=updated)
    if tool in {'Grep', 'Glob'}:
        if not confined:
            raise GuardError('Run a full search through the protected Zcode launcher or through Bash.')
        path = safe_path(inputs.get('path', '.'), workspace, allow_directory=True)
        return decision('allow', updated=dict(inputs, path=str(path)))
    if tool == 'Bash':
        if inputs.get('dangerouslyDisableSandbox'):
            raise GuardError('A request to disable the sandbox is not allowed.')
        command = inputs.get('command')
        if not isinstance(command, str) or not command.strip() or '\x00' in command:
            raise GuardError('The shell command is invalid.')
        verdict = riskgate_decision(dict(payload, tool_input=inputs, cwd=str(workspace)))
        if verdict == 'deny':
            return decision('deny', 'The riskgate policy blocked this command.')
        if SHARED_TEMP.search(command):
            # The kernel denies the shared temp directory, and its EPERM tells the
            # agent nothing, so it escalates to the operator. TMPDIR already points
            # at a private directory inside the isolated home; name it instead.
            return decision('deny', 'The sandbox does not allow the shared /tmp. Use $TMPDIR instead. It is a '
                                    'private temporary directory inside the isolated home, so it can be read and written without approval.')
        updated = dict(inputs, dangerouslyDisableSandbox=False)
        if not confined:
            # Host tools still require confirmation after policy evaluation.
            verdict = 'ask'
            encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
            # Invoke the supervisor by its own path rather than through a wrapper: the wrapper directory is an
            # installer choice (AGENTBELT_BIN) that the hook, running inside the sandbox, cannot look up.
            updated['command'] = shlex.join(['/usr/bin/python3', '-I', str(ROOT / 'agentbelt.py'),
                                             'zcode-shell', str(workspace), encoded])
        return decision(verdict, 'The riskgate and project-scope sandbox policies are applied.', updated)
    if tool in {'Agent', 'Task'} and confined:
        return decision('ask')
    raise GuardError('This tool is not allowed by the current protection policy. Use the file or shell tools.')


def main():
    try:
        raw = sys.stdin.buffer.readline(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise GuardError('The hook request size exceeds the limit.')
        result = evaluate(json.loads(raw))
        status = 0
    except Exception as error:
        reason = str(error) if isinstance(error, GuardError) else 'The request was blocked because the protection policy check failed.'
        result = decision('deny', reason)
        status = 2
    emit(result)
    return status


if __name__ == '__main__':
    sys.exit(main())
