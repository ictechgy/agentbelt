#!/usr/bin/python3
"""AutoClaw 세션에 코딩 워크스페이스를 바인딩한다(호스트 전용).

AutoClaw 의 zcode-runtime 플러그인은 모든 `zcode_run` 에 세션별 바인딩을 요구한다(`requireBoundWorkspace`). 앱 UI 는
앱 안의 대화 세션에만 워크스페이스를 고를 수 있어 Discord 채널 세션은 기본 숨김 폴더에 묶인 채 남고, 우리 가드는
그 경로를 거부한다. 이 도구는 플러그인(session-workspace-binding.js)이 검증하는 형식 그대로 바인딩 파일을 쓴다:
`<state>/autoclaw/coding-workspaces/v1/<sha256("local\\0"+sessionKey)>.json`, 0600, 키 집합 고정, workspaceId =
sha256("workspace\\0"+realPath), pathIdentity = {dev, ino}. 워크스페이스는 가드의 `workspace_path` 검사를 통과해야
한다(숨김 폴더·홈 전체 등은 애초에 격리 실행이 거부되므로 바인딩하지 않는다).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import agent_guard

OPENCLAW_STATE = agent_guard.OWNER_HOME / '.openclaw-autoclaw'
SCHEMA_VERSION = 1
AGENT_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
SNOWFLAKE = re.compile(r'^[0-9]{17,20}$')


def session_key_hash(session_key):
    """플러그인과 같은 해시: sha256("local\\0" + sessionKey)."""
    key = (session_key or '').strip()
    if not key or len(key) > 1024:
        raise RuntimeError('A non-empty session key is required.')
    return hashlib.sha256(b'local\0' + key.encode()).hexdigest()


def workspace_id(real_path):
    """플러그인과 같은 워크스페이스 ID: sha256("workspace\\0" + realPath)."""
    return hashlib.sha256(b'workspace\0' + real_path.encode()).hexdigest()


def discord_channel_session_key(agent_id, channel_id):
    """OpenClaw 가 Discord 서버 채널에 쓰는 세션 키. 실측: agent:auto-coder:discord:channel:<채널 ID>."""
    if not AGENT_ID.match(agent_id or ''):
        raise RuntimeError('Agent id must be a short identifier.')
    if not SNOWFLAKE.match(str(channel_id or '')):
        raise RuntimeError('Discord channel id must be a numeric snowflake.')
    return 'agent:' + agent_id + ':discord:channel:' + str(channel_id)


def binding_path(session_key):
    """세션 키에 대응하는 바인딩 파일 경로."""
    return OPENCLAW_STATE / 'autoclaw/coding-workspaces' / ('v' + str(SCHEMA_VERSION)) / (session_key_hash(session_key) + '.json')


def existing_binding(path):
    """기존 바인딩(있으면). 링크나 이상한 파일이면 덮어쓰지 않고 거부한다."""
    if path.is_symlink():
        raise RuntimeError('Refusing a symlinked binding file: ' + str(path))
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError('Binding path is not a regular file: ' + str(path))
    try:
        return json.loads(path.read_text())
    except ValueError:
        return None


def build_binding(session_key, workspace, previous=None):
    """검증된 워크스페이스로 바인딩 문서를 만든다. 재바인딩이면 revision 을 올리고 boundAt 은 유지한다."""
    real = str(agent_guard.workspace_path(str(workspace)))
    info = os.stat(real)
    now = int(time.time() * 1000)
    bound_at = previous.get('boundAt') if isinstance(previous, dict) and isinstance(previous.get('boundAt'), int) else now
    revision = previous.get('bindingRevision') + 1 if isinstance(previous, dict) and isinstance(previous.get('bindingRevision'), int) else 1
    return {'schemaVersion': SCHEMA_VERSION, 'sessionKeyHash': session_key_hash(session_key), 'workspaceId': workspace_id(real),
            'realPath': real, 'bindingRevision': revision, 'pathIdentity': {'dev': str(info.st_dev), 'ino': str(info.st_ino)},
            'boundAt': min(bound_at, now), 'updatedAt': now}


def bind(session_key, workspace):
    """바인딩 파일을 0600 으로 원자적으로 쓴다. 돌려주는 값은 파일 경로."""
    path = binding_path(session_key)
    previous = existing_binding(path)
    document = build_binding(session_key, workspace, previous)
    directory = path.parent
    # 앱보다 먼저 만들게 되면 umask 에 기대지 않고 비공개 모드로 만든다.
    for ancestor in [directory.parent.parent, directory.parent, directory]:
        if not ancestor.exists():
            ancestor.mkdir(mode=0o700)
    if directory.stat().st_mode & 0o077:
        directory.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.binding-', dir=str(directory))
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(document, stream)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workspace', help='Project directory to bind (must pass the guard workspace checks).')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--session-key', help='Exact OpenClaw session key, e.g. agent:auto-coder:9931d08f')
    target.add_argument('--discord-channel', metavar='CHANNEL_ID', help='Bind the Discord server-channel session of --agent.')
    parser.add_argument('--agent', default='auto-coder', help='Agent id for --discord-channel (default auto-coder).')
    options = parser.parse_args(argv)
    key = options.session_key or discord_channel_session_key(options.agent, options.discord_channel)
    path = bind(key, options.workspace)
    print('Bound ' + key + ' -> ' + json.loads(path.read_text())['realPath'])
    print('Binding file: ' + str(path))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, agent_guard.GuardError) as error:
        raise SystemExit('bind_autoclaw_workspace: ' + str(error))
