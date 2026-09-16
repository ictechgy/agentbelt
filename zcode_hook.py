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
    from agent_guard import GuardError, ROOT, SECRET_NAMES, inside_zcode_sandbox, workspace_path
    from riskgate_bridge import riskgate_decision
except Exception:
    emit(decision('deny', '보호 정책 모듈을 불러오지 못해 요청을 차단했습니다.'))
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
        raise GuardError('파일 경로가 없거나 올바르지 않습니다.')
    value = Path(raw).expanduser()
    if not value.is_absolute():
        value = workspace / value
    resolved = value.resolve(strict=False)
    inside_workspace = resolved == workspace or workspace in resolved.parents
    state = agent_state_root()
    inside_state = agent_state and (resolved == state or state in resolved.parents)
    if not inside_workspace and not inside_state:
        raise GuardError('프로젝트 밖의 파일 접근은 차단됩니다.')
    if inside_state:
        return resolved
    parts = value.relative_to(workspace).parts if value.is_relative_to(workspace) else ()
    for part in (*parts, *resolved.relative_to(workspace).parts):
        if part.lower() == '.git' or any(fnmatch.fnmatchcase(part.lower(), p.lower()) for p in SECRET_NAMES):
            raise GuardError('민감 파일과 인증·Git 내부 경로는 직접 접근할 수 없습니다.')
    try:
        info = resolved.stat()
    except FileNotFoundError:
        return resolved
    if stat.S_ISDIR(info.st_mode):
        if not allow_directory:
            raise GuardError('이 도구에서는 일반 파일 경로만 사용할 수 있습니다.')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
        raise GuardError('특수 파일과 하드링크는 접근할 수 없습니다.')
    return resolved


def evaluate(payload):
    if not isinstance(payload, dict) or payload.get('hook_event_name', payload.get('hookEventName')) != 'PreToolUse':
        raise GuardError('지원하지 않는 훅 요청입니다.')
    tool = payload.get('tool_name', payload.get('toolName'))
    inputs = payload.get('tool_input', payload.get('toolInput'))
    if not isinstance(tool, str) or not isinstance(inputs, dict):
        raise GuardError('도구 요청 형식이 올바르지 않습니다.')
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
            raise GuardError('전체 검색은 보호된 Zcode 실행기 또는 Bash를 통해 수행하세요.')
        path = safe_path(inputs.get('path', '.'), workspace, allow_directory=True)
        return decision('allow', updated=dict(inputs, path=str(path)))
    if tool == 'Bash':
        if inputs.get('dangerouslyDisableSandbox'):
            raise GuardError('샌드박스 해제 요청은 허용하지 않습니다.')
        command = inputs.get('command')
        if not isinstance(command, str) or not command.strip() or '\x00' in command:
            raise GuardError('셸 명령이 올바르지 않습니다.')
        verdict = riskgate_decision(dict(payload, tool_input=inputs, cwd=str(workspace)))
        if verdict == 'deny':
            return decision('deny', 'riskgate 정책이 이 명령을 차단했습니다.')
        if SHARED_TEMP.search(command):
            # The kernel denies the shared temp directory, and its EPERM tells the
            # agent nothing, so it escalates to the operator. TMPDIR already points
            # at a private directory inside the isolated home; name it instead.
            return decision('deny', '샌드박스는 공용 /tmp 를 허용하지 않습니다. 대신 $TMPDIR 을 '
                                    '사용하세요. 격리 홈 안의 전용 임시 디렉터리라 승인 없이 읽고 쓸 수 있습니다.')
        updated = dict(inputs, dangerouslyDisableSandbox=False)
        if not confined:
            # Host tools still require confirmation after policy evaluation.
            verdict = 'ask'
            encoded = base64.b64encode(command.encode('utf-8')).decode('ascii')
            updated['command'] = shlex.join([str(ROOT.parent.parent / 'bin/agent-guard'),
                                             'zcode-shell', str(workspace), encoded])
        return decision(verdict, 'riskgate와 프로젝트 범위 샌드박스 정책을 적용합니다.', updated)
    if tool in {'Agent', 'Task'} and confined:
        return decision('ask')
    raise GuardError('이 도구는 현재 보호 정책에서 허용되지 않습니다. 파일·셸 도구를 사용하세요.')


def main():
    try:
        raw = sys.stdin.buffer.readline(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise GuardError('훅 요청 크기가 제한을 초과했습니다.')
        result = evaluate(json.loads(raw))
        status = 0
    except Exception as error:
        reason = str(error) if isinstance(error, GuardError) else '보호 정책 검사에 실패하여 요청을 차단했습니다.'
        result = decision('deny', reason)
        status = 2
    emit(result)
    return status


if __name__ == '__main__':
    sys.exit(main())
