#!/usr/bin/python3
"""AutoClaw 코딩 런타임을 agent-guard 런처로 돌리도록 설치한다.

하는 일: (1) 검토된 AutoClaw 앱·번들 Zcode CLI 를 프로필과 호환 기준선에 기록, (2) `~/.local/bin/autoclaw-zcode-safe`
런처 설치, (3) `~/.openclaw-autoclaw/openclaw.json` 의 zcode-runtime 플러그인 `command` 를 런처로 바꾸고 모델 브로커
주소 두 변수를 envPassthrough 로 넘기게 한다. 그 외 설정(모델·API 키 등)은 읽되 바꾸지 않는다.
다시 실행해도 안전하며 원본은 state/backups 에 한 번만 보관한다. 이미 기록된 기준선과 다른 바이너리는
`--rebaseline` 없이는 축복하지 않는다. `--deny-host-exec` 는 바깥 에이전트의 호스트 exec 를 도구 정책으로 막고,
`--discord-guild`/`--discord-dm` 은 Discord 원격 제어를 본인 ID 로만 연다.
"""
import argparse
import fcntl
import json
import os
import pwd
from pathlib import Path
import re
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import agent_guard
import compatibility_check
from configure_existing import publish_settings

HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # 계정 DB 의 홈(환경변수 아님)
STATE = ROOT / 'state'
OPENCLAW_STATE = HOME / '.openclaw-autoclaw'
BROKER_VARIABLES = ['AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL', 'AUTOCLAW_MODEL_BROKER_ANTHROPIC_BASE_URL']


def launcher_path():
    """AutoClaw 플러그인이 `command` 로 부를 런처 경로."""
    return HOME / '.local/bin/autoclaw-zcode-safe'


def launcher_exec_line():
    """런처의 마지막 줄. 플러그인이 넘기는 인자(version / agent-server)를 그대로 전달한다."""
    return 'exec /usr/bin/python3 -I ' + shlex.quote(str(ROOT / 'agent_guard.py')) + ' autoclaw-backend "$@"\n'


def launcher_text():
    """런처 본문. `agent-server` 호출은 파이썬에 닿기 전에 셸이 먼저 `sh-start` 를 기록한다.

    isthmus 채널 사고에서 게이트웨이가 띄운 런처가 파이썬 첫 줄(`started`)에도 못 닿았고 감독자 쪽 재현은
    전부 정상이었다. 셸 자체가 증거를 남겨야 셸 기동·python3 셔틀·파이썬 기동 중 어디서 멈췄는지 가른다.
    pid 는 exec 로 이어지므로 파이썬 단계의 pid 와 같다. 기록 실패는 실행을 막지 않는다. 로그 자리나 `state/runtime`
    이 링크면 쓰지 않고(파이썬 쪽 O_NOFOLLOW·private_dir 와 같은 뜻), 로그가 일반 파일이 아니면(FIFO 는 `>>` 가
    읽는 쪽을 기다리며 exec 전에 멈춘다) 건너뛴다. 새 파일은 서브셸 umask 로 0600 이 되게 한다(자식 umask 는 그대로).
    version 프로브는 기록하지 않는다 — 남기면 "python-start 없음" 으로 오독된다. 파이썬 쪽 판정
    (`is_autoclaw_agent_server_call`)도 같은 기준(첫 인자만)이다.
    """
    log = shlex.quote(str(ROOT / 'state/runtime/autoclaw-launches.log'))
    return ('#!/bin/sh\n'
            'log=' + log + '\n'
            '[ "$1" = agent-server ] && [ ! -L "${log%/*}" ] && [ ! -L "$log" ] && { [ ! -e "$log" ] || [ -f "$log" ]; } && '
            '( umask 077; printf \'%s pid=%s stage=sh-start cwd=%s\\n\' '
            '"$(/bin/date +%Y-%m-%dT%H:%M:%S)" "$$" "$PWD" >> "$log" ) 2>/dev/null\n'
            + launcher_exec_line())


def previous_launcher_texts():
    """재설치가 알아보고 교체해도 되는 이전 가드 런처 본문. 여기 없는 내용은 낯선 런처로 보고 거부한다.

    본문을 바꿀 때마다 직전 본문을 여기에 추가한다(2026-09-15: 두 줄짜리 원본, sh-start 첫 판).
    """
    log = shlex.quote(str(ROOT / 'state/runtime/autoclaw-launches.log'))
    first_stage_logging = ('#!/bin/sh\n'
                           'log=' + log + '\n'
                           '[ "$1" = agent-server ] && [ ! -L "$log" ] && ( umask 077; printf \'%s pid=%s stage=sh-start cwd=%s\\n\' '
                           '"$(/bin/date +%Y-%m-%dT%H:%M:%S)" "$$" "$PWD" >> "$log" ) 2>/dev/null\n'
                           + launcher_exec_line())
    return ['#!/bin/sh\n' + launcher_exec_line(), first_stage_logging]


def read_bundle():
    """설치된 AutoClaw 앱에서 버전·번들 CLI 해시를 읽는다. 앱이 없으면 설치를 거부한다."""
    bundle = compatibility_check.autoclaw_candidate(agent_guard.AUTOCLAW_APP)
    if bundle is None:
        raise RuntimeError('AutoClaw.app is not installed; nothing to protect.')
    return bundle


def check_launcher_directory(directory):
    """런처 디렉터리는 링크가 아니고 내 소유이며 그룹·타인이 쓸 수 없어야 한다. 아니면 런처가 바꿔치기된다."""
    if directory.is_symlink():
        raise RuntimeError('Refusing a symlinked launcher directory')
    info = directory.stat()
    if not directory.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError('The launcher directory must be a private directory owned by you (no group/other write).')


def install_launcher():
    """런처를 0700 으로 만든다. 같은 내용이면 그대로 두고, 0700 인 이전 가드 런처면 교체하며, 그 밖의 파일은 덮어쓰지 않는다.

    교체는 같은 디렉터리의 임시 파일에 다 쓰고 fsync 한 뒤 rename 으로 한다 — unlink 후 새로 만들면 그 사이에
    게이트웨이가 런처를 띄웠을 때 부재나 빈 스크립트를 실행한다. 이전 실패가 남긴 임시 파일은 치우고 진행한다.
    """
    path = launcher_path()
    check_launcher_directory(path.parent)
    if path.is_symlink():
        raise RuntimeError('Refusing a symlinked launcher path')
    temporary = '.' + path.name + '.tmp'
    directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if path.exists():
            current = path.read_text()
            if current == launcher_text() and path.stat().st_mode & 0o777 == 0o700:
                return
            if current not in previous_launcher_texts() or path.stat().st_mode & 0o777 != 0o700:
                raise RuntimeError('A different autoclaw-zcode-safe launcher already exists; remove it first.')
        if (path.parent / temporary).is_symlink() or (path.parent / temporary).exists():
            os.unlink(temporary, dir_fd=directory)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700, dir_fd=directory)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(launcher_text())
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        os.close(directory)


def load_openclaw_config():
    """AutoClaw 설정 파일을 읽는다. 링크이거나 없으면(앱을 아직 한 번도 안 켰으면) 거부한다."""
    path = OPENCLAW_STATE / 'openclaw.json'
    if path.is_symlink():
        raise RuntimeError('Refusing a symlinked openclaw.json')
    if not path.is_file():
        raise RuntimeError('openclaw.json is missing; launch AutoClaw once and quit it first.')
    return path, json.loads(path.read_text())


def patched_plugin_entry(entry):
    """zcode-runtime 항목에 런처·envPassthrough 를 넣은 사본. 다른 키는 유지한다."""
    entry = dict(entry or {})
    config = dict(entry.get('config') or {})
    config.update({'command': str(launcher_path()), 'args': [], 'envPassthrough': list(BROKER_VARIABLES),
                   'runtimeEnabled': True,
                   # 기본 30초 핸드셰이크는 큰 워크스페이스의 하드링크 검사(파일 90만 개 = 25초)와 첫 기동을 못 기다린다.
                   'requestTimeoutMs': 180000})
    entry.update({'enabled': True, 'config': config})
    return entry


def backup_once(path, data):
    """원본을 state/backups 에 한 번만 보관한다. 이미 보관본이 있으면 새로 만들지 않는다."""
    backups = agent_guard.private_dir(STATE / 'backups')
    if any(backups.glob(path.name + '.*')):
        return
    target = backups / (path.name + '.' + time.strftime('%Y%m%d-%H%M%S'))
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)


def reviewed_baseline(existing, bundle, rebaseline):
    """기록된 기준선이 있고 지금 번들과 다르면 명시적 --rebaseline 없이는 바꾸지 않는다."""
    if existing and existing != bundle and not rebaseline:
        raise RuntimeError('AutoClaw bundle differs from the reviewed baseline (recorded ' + existing.get('zcodeSha256', '?')[:12]
                           + ', installed ' + bundle['zcodeSha256'][:12] + '). Review the update, then rerun with --rebaseline.')
    return bundle


# exec/process: 호스트 셸. gateway: 에이전트가 openclaw.json 을 config.patch/apply 로 고치거나 재시작할 수 있는 도구라
# 이 잠금 자체를 되돌릴 수 있다(2026-09-14 모델이 config.schema.lookup 으로 설정을 뒤지는 것을 실측).
HOST_EXEC_TOOLS = {'exec', 'process', 'gateway'}
# AutoClaw 의 zcode-runtime 은 이 에이전트 ID 에게만 zcode_run 을 노출한다(extensions/zcode-runtime/agent-context.js).
ZCODE_OWNER_AGENT_ID = 'auto-coder'
DISCORD_USER_ID = re.compile(r'^[0-9]{17,20}$')


def deny_host_exec_tools(tools):
    """바깥 OpenClaw 에이전트의 호스트 exec·process·gateway 도구를 막은 tools 사본. 코딩은 zcode 경로로만 가게 된다.

    AutoClaw 의 원격 설정 새로고침이 `exec.security` 를 `full` 로 되돌리므로 실제 잠금은 도구 정책 `deny` 다
    (OpenClaw 문서: "To hard-disable exec, deny it via tool policy"). elevated 도 꺼서 채널의 `/elevated` 가 못 살린다.
    """
    tools = dict(tools or {})
    tools['exec'] = dict(tools.get('exec') or {}, security='deny')
    tools['deny'] = sorted(set(tools.get('deny') or []) | HOST_EXEC_TOOLS)
    tools['elevated'] = dict(tools.get('elevated') or {}, enabled=False)
    return tools


def deny_host_exec_agents(agents):
    """에이전트별 도구 정책에도 같은 deny 를 넣은 agents 사본. 전역 정책이 되돌려져도 에이전트 범위가 남는다."""
    agents = dict(agents or {})
    entries = []
    for agent in agents.get('list') or []:
        agent = dict(agent)
        tools = dict(agent.get('tools') or {})
        tools['deny'] = sorted(set(tools.get('deny') or []) | HOST_EXEC_TOOLS)
        tools['elevated'] = dict(tools.get('elevated') or {}, enabled=False)
        agent['tools'] = tools
        entries.append(agent)
    agents['list'] = entries
    return agents


def discord_accounts(channels):
    """설정된 Discord 계정 사전(사본). 없으면 앱에서 봇을 먼저 연결해야 한다."""
    channels = dict(channels or {})
    discord = dict(channels.get('discord') or {})
    accounts = dict(discord.get('accounts') or {})
    if not accounts:
        raise RuntimeError('No Discord account is configured in AutoClaw; connect the bot in the app first.')
    return channels, discord, accounts


def snowflakes(values, what):
    """Discord ID(17~20자리 숫자)만 받는다. `*`·접근 그룹·이름은 원격 제어 표면을 키우므로 거부한다."""
    if isinstance(values, (str, bytes)):
        raise RuntimeError('Discord ' + what + ' must be a list of IDs, not a single string.')
    values = [str(value) for value in (values or [])]
    if not values or any(not DISCORD_USER_ID.match(value) for value in values):
        raise RuntimeError('Discord ' + what + ' must be numeric Discord IDs (17-20 digits).')
    return values


def discord_dm_allowlist(channels, user_ids):
    """모든 Discord 계정의 DM 을 주어진 사용자 ID 로만 허용한 channels 사본. 서버 정책·토큰은 그대로."""
    users = snowflakes(user_ids, 'user IDs')
    channels, discord, accounts = discord_accounts(channels)
    for name, account in accounts.items():
        accounts[name] = dict(account or {}, dmPolicy='allowlist', allowFrom=users)
    discord['accounts'] = accounts
    channels['discord'] = discord
    return channels


def discord_guild_allowlist(channels, user_ids, guild_id, channel_id=None):
    """비공개 서버 채널로 제어할 때의 channels 사본. DM 은 건드리지 않는다(끈 채로 둔다).

    서버 하나만 허용 목록에 넣고 그 안에서도 `users` 로 보낸 사람을 본인 ID 로 고정한다. 서버에 누가 초대돼도
    그 사람 메시지는 무시된다. 채널 ID 를 주면 그 채널 밖은 거부된다. 서버에 본인뿐이므로 멘션은 요구하지 않는다.
    """
    users = snowflakes(user_ids, 'user IDs')
    guild = snowflakes([guild_id], 'server ID')[0]
    entry = {'requireMention': False, 'users': users}
    if channel_id is not None:
        entry['channels'] = {snowflakes([channel_id], 'channel ID')[0]: {'allow': True}}
    channels, discord, accounts = discord_accounts(channels)
    for name, account in accounts.items():
        accounts[name] = dict(account or {}, groupPolicy='allowlist', guilds={guild: entry})
    discord['accounts'] = accounts
    channels['discord'] = discord
    return channels


AGENT_TOOLS_NOTE = """# TOOLS.md - Local Notes

### 이 환경의 실행 규칙 (agent-guard)

- 이 설치에는 호스트 셸 도구가 **없다**: `exec`, `process`, `gateway` 는 의도적으로 제거됐다. 켜 달라고 요청하지 마라.
- 이 워크스페이스는 코디네이터 메모 폴더일 뿐이다. 프로젝트 저장소는 여기 없다. 저장소의 모든 읽기·수정·명령
  (`git status`, 테스트·빌드, 파일 삭제 포함)은 **`zcode_run`** 으로 보낸다. 세션은 이미 프로젝트에 바인딩돼 있다.
  예: prompt="Run `git status` and `git diff --stat` and report the output verbatim."
- 저장소 작업을 서브에이전트(`sessions_spawn`)에 넘기지 마라. 서브에이전트 세션에는 워크스페이스 바인딩이 없어
  `zcode_run` 이 거부된다. 이 세션에서 직접 부른다.
- `zcode_run` 안의 Zcode 는 macOS 샌드박스에서 돌며 승인창은 뜨지 않는다. 결과를 기다렸다가 그대로 보고한다.
"""


def private_agent_workspace_path(agent_id):
    """에이전트 전용 메모 폴더(AutoClaw 기본 배치와 같은 위치)."""
    if not re.match(r'^[A-Za-z0-9_-]{1,64}$', agent_id or ''):
        raise RuntimeError('Agent id must be a short identifier.')
    return OPENCLAW_STATE / 'agents' / agent_id / 'workspace'


def relocate_agent_workspace(agents, agent_id):
    """해당 에이전트의 workspace 를 전용 폴더로 바꾼 agents 사본. 다른 키·다른 에이전트는 그대로."""
    agents = dict(agents or {})
    entries = []
    found = False
    for agent in agents.get('list') or []:
        agent = dict(agent)
        if agent.get('id') == agent_id:
            agent['workspace'] = str(private_agent_workspace_path(agent_id))
            found = True
        entries.append(agent)
    if not found:
        raise RuntimeError('No agent with id ' + agent_id + ' in openclaw.json.')
    agents['list'] = entries
    return agents


def seed_private_workspace(agent_id):
    """전용 폴더를 0700 으로 만들고 실행 규칙 메모(TOOLS.md)를 심는다. 이미 있으면 메모만 보장한다."""
    directory = private_agent_workspace_path(agent_id)
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    note = directory / 'TOOLS.md'
    if note.is_symlink():
        raise RuntimeError('Refusing a symlinked TOOLS.md')
    if not note.is_file() or '실행 규칙 (agent-guard)' not in note.read_text():
        with open(note, 'a', encoding='utf-8') as stream:
            stream.write(('' if not note.exists() or note.stat().st_size == 0 else '\n') + AGENT_TOOLS_NOTE)


def rebind_discord_agent(config, agent_id):
    """Discord 채널 바인딩의 agentId 를 바꾼 bindings 사본. 다른 채널 바인딩은 그대로.

    AutoClaw 의 zcode-runtime 은 `zcode_run` 을 에이전트 ID `auto-coder` 에게만 노출하므로(agent-context.js 하드코딩)
    다른 에이전트로 Discord 를 묶으면 격리 코딩이 불가능하다.
    """
    if not any(agent.get('id') == agent_id for agent in (config.get('agents') or {}).get('list') or []):
        raise RuntimeError('No agent with id ' + agent_id + ' in openclaw.json.')
    if agent_id != ZCODE_OWNER_AGENT_ID:
        raise RuntimeError('zcode_run is only exposed to agent ' + ZCODE_OWNER_AGENT_ID + '; binding Discord to ' + agent_id + ' disables guarded coding.')
    bindings = []
    changed = False
    for binding in config.get('bindings') or []:
        binding = dict(binding)
        if (binding.get('match') or {}).get('channel') == 'discord':
            binding['agentId'] = agent_id
            changed = True
        bindings.append(binding)
    if not changed:
        raise RuntimeError('No Discord binding found in openclaw.json; connect the bot in the app first.')
    return bindings


def install(rebaseline=False, deny_host_exec=True, discord_users=None, discord_dm=False, discord_guild=None, discord_channel=None,
            private_agent_workspace=None, discord_agent=None):
    """잠금 안에서 실제 설치를 수행한다. 호스트 exec 차단은 기본값이다(페일오픈 설치 금지)."""
    if discord_dm and discord_guild is not None:
        raise RuntimeError('Choose one Discord path: --discord-guild or --discord-dm, not both.')
    if discord_users is not None and not discord_users:
        raise RuntimeError('--discord-users needs at least one numeric Discord user ID.')
    bundle = read_bundle()
    config_path, config = load_openclaw_config()
    plugins = dict(config.get('plugins') or {})
    entries = dict(plugins.get('entries') or {})
    entries['zcode-runtime'] = patched_plugin_entry(entries.get('zcode-runtime'))
    plugins['entries'] = entries
    updated = dict(config, plugins=plugins)
    if deny_host_exec:
        updated['tools'] = deny_host_exec_tools(config.get('tools'))
        updated['agents'] = deny_host_exec_agents(config.get('agents'))
    if private_agent_workspace is not None:
        updated['agents'] = relocate_agent_workspace(updated.get('agents') or config.get('agents'), private_agent_workspace)
        seed_private_workspace(private_agent_workspace)
    if discord_agent is not None:
        updated['bindings'] = rebind_discord_agent(config, discord_agent)
    if discord_users is not None:
        if discord_guild is not None:
            updated['channels'] = discord_guild_allowlist(config.get('channels'), discord_users, discord_guild, discord_channel)
        elif discord_dm:
            updated['channels'] = discord_dm_allowlist(config.get('channels'), discord_users)
        else:
            raise RuntimeError('Choose the Discord path: --discord-guild SERVER_ID (private server channel) or --discord-dm.')
    existing_profile = STATE / 'autoclaw-profile.json'
    profile = json.loads(existing_profile.read_text()) if existing_profile.is_file() else {'domains': []}
    profile.update({'reviewedAppVersion': bundle['version'], 'zcodeCliVersion': bundle['zcodeCliVersion']})
    baseline_path = STATE / 'compatibility.json'
    baseline = json.loads(baseline_path.read_text()) if baseline_path.is_file() else {}
    baseline['autoclaw'] = reviewed_baseline(baseline.get('autoclaw'), bundle, rebaseline)
    install_launcher()
    if updated != config:
        backup_once(config_path, config_path.read_bytes())
    publish_settings({existing_profile: profile, baseline_path: baseline, config_path: updated})
    print('AutoClaw zcode-runtime now launches ' + str(launcher_path()))
    print('Reviewed AutoClaw ' + bundle['version'] + ' with bundled Zcode CLI ' + bundle['zcodeCliVersion'])


def main(rebaseline=False, deny_host_exec=True, discord_users=None, discord_dm=False, discord_guild=None, discord_channel=None,
         private_agent_workspace=None, discord_agent=None):
    """다른 설정 게시자(configure_existing, verify-updates)와 같은 잠금을 잡고 설치한다."""
    state = agent_guard.private_dir(STATE)
    descriptor = os.open(str(state / '.settings-import.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        install(rebaseline, deny_host_exec, discord_users, discord_dm, discord_guild, discord_channel, private_agent_workspace,
                discord_agent)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rebaseline', action='store_true', help='Accept a bundle whose hash differs from the recorded baseline.')
    parser.add_argument('--deny-host-exec', action='store_true', default=True,
                        help='(default) Deny the exec/process/gateway tools (global and per agent) and elevated exec for the outer AutoClaw agent.')
    parser.add_argument('--allow-host-exec', dest='deny_host_exec', action='store_false',
                        help='Leave the outer agent host exec/gateway tools as they are (not recommended).')
    parser.add_argument('--discord-users', metavar='USER_ID[,USER_ID]',
                        help='Numeric Discord user IDs allowed to drive the agent (required with --discord-guild or --discord-dm).')
    parser.add_argument('--discord-guild', metavar='SERVER_ID',
                        help='Private server path: groupPolicy=allowlist for this server only, senders limited to --discord-users; DMs stay as they are.')
    parser.add_argument('--discord-channel', metavar='CHANNEL_ID', help='With --discord-guild: allow only this channel in the server.')
    parser.add_argument('--discord-dm', action='store_true', help='DM path: dmPolicy=allowlist with --discord-users on every account.')
    parser.add_argument('--private-agent-workspace', metavar='AGENT_ID',
                        help='Move this agent\'s workspace off the repository to ~/.openclaw-autoclaw/agents/<id>/workspace and seed TOOLS.md.')
    parser.add_argument('--discord-agent', metavar='AGENT_ID',
                        help='Route the Discord channel binding to this agent (zcode_run is only exposed to auto-coder).')
    options = parser.parse_args()
    users = [part.strip() for part in options.discord_users.split(',') if part.strip()] if options.discord_users is not None else None
    try:
        main(options.rebaseline, options.deny_host_exec, users, options.discord_dm, options.discord_guild, options.discord_channel,
             options.private_agent_workspace, options.discord_agent)
    except RuntimeError as error:
        # 가드가 만든 문구만 보여 준다. 설정 파서 예외에는 자격 증명 조각이 섞일 수 있다.
        raise SystemExit('install_autoclaw: ' + str(error))
    except Exception:
        raise SystemExit('install_autoclaw: failed; no credential values are shown. Inspect the local setup before retrying.')
