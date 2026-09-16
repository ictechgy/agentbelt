"""Token Plan 사용량 CLI(`bl`, bailian-cli)를 격리해서 돌리는 usage 모드.

왜 격리하는가. `bl` 은 `bl config agent` 로 `CLAUDE_CONFIG_DIR`·`CODEX_HOME` 같은 다른
에이전트 설정을 건드릴 수 있고, 콘솔 로그인 토큰을 보관한다. 호스트에 전역 설치하지 않고
가드 소유 격리 홈 안에만 설치해, 사용자 프로젝트·실제 홈·다른 격리 홈·Keychain 은 기존
Seatbelt 정책대로 보이지 않게 한다.

왜 로그인만 호스트에서 하는가. `bl usage token-plan` 은 API 키가 아니라 콘솔 로그인
토큰을 요구하며, 로그인은 무작위 127.0.0.1 포트에 콜백 서버를 열고 브라우저를 띄운다.
둘 다 샌드박스에서 막히므로 로그인 1회는 호스트에서 돌리되, HOME 과 `BAILIAN_CONFIG_DIR`
을 격리 홈으로 고정해 토큰이 격리 홈 밖에 남지 않게 한다. 이후 모든 조회는 샌드박스 안이다.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import agent_guard  # noqa: E402

# usage 모드 정책 파일. 도메인·CLI 버전·콘솔 사이트/리전을 여기서만 바꾼다.
PROFILE_PATH = ROOT / 'state/usage-profile.json'
# 격리 홈 안의 bl 설치 접두사. npm --prefix 로 이 아래 node_modules 에 들어간다.
CLI_PREFIX = 'bl-prefix'


def default_profile():
    """검토된 기본 정책. 국제 사이트 콘솔 게이트웨이와 Token Plan 호스트만 허용한다.

    중국 본토 게이트웨이는 넣지 않는다. 사용자의 Token Plan 엔드포인트가 ap-southeast-1 이다.
    """
    return {
        'cliVersion': '1.21.0',
        'consoleSite': 'international',
        'consoleRegion': 'ap-southeast-1',
        'domains': [
            'bailian-singapore-cs.alibabacloud.com:443',   # ap-southeast-1 국제 콘솔 게이트웨이
            'bailian-cs.console.alibabacloud.com:443',     # cn-beijing 국제 콘솔 게이트웨이
            'modelstudio.console.alibabacloud.com:443',    # 국제 콘솔(로그인 리다이렉트)
            'token-plan.ap-southeast-1.maas.aliyuncs.com:443',
        ],
    }


def load_profile():
    """정책 파일을 읽는다. 없으면 기본값을 0600 으로 만들어 둔다."""
    if not PROFILE_PATH.is_file():
        agent_guard.private_dir(PROFILE_PATH.parent)
        agent_guard.write_private_json(PROFILE_PATH, default_profile())
    profile = json.loads(PROFILE_PATH.read_text())
    if not isinstance(profile.get('domains'), list) or not profile['domains']:
        raise agent_guard.GuardError('state/usage-profile.json needs a non-empty domains list.')
    return profile


def usage_workspace():
    """가드 소유의 빈 워크스페이스. 사용자 프로젝트는 절대 쓰지 않는다."""
    return agent_guard.private_dir(agent_guard.private_dir(ROOT / 'state') / 'usage-workspace')


def usage_home():
    """run_confined 가 mode='usage' 에 쓰는 지속 격리 홈과 같은 경로."""
    identity = hashlib.sha256(str(usage_workspace()).encode()).hexdigest()[:20]
    state = ROOT / 'state'
    return agent_guard.private_dir(agent_guard.private_dir(agent_guard.private_dir(state / 'homes') / 'usage') / identity)


def bl_entry(home):
    """격리 홈 안에 설치된 bl 진입 스크립트."""
    return home / CLI_PREFIX / 'node_modules/bailian-cli/dist/bailian.mjs'


def install_command(profile):
    """고정 버전의 bailian-cli 를 격리 홈 접두사에 설치하는 셸 명령."""
    version = profile['cliVersion']
    if not all(part.isdigit() for part in version.split('.')):
        raise agent_guard.GuardError('usage-profile cliVersion must be a plain semantic version.')
    return ['/bin/bash', '--noprofile', '--norc', '-c',
            'mkdir -p "$HOME/' + CLI_PREFIX + '" && npm install --prefix "$HOME/' + CLI_PREFIX
            + '" --no-audit --no-fund --loglevel=error bailian-cli@' + version]


def query_command(home, profile, extra):
    """샌드박스 안에서 돌릴 bl 명령. 인자가 없으면 Token Plan 요약이다."""
    entry = bl_entry(home)
    if not entry.is_file():
        raise agent_guard.GuardError('bl is not installed in the isolated home yet; run agent-guard usage setup first.')
    if extra:
        return [str(agent_guard.NODE), str(entry), *extra]
    return [str(agent_guard.NODE), str(entry), 'usage', 'token-plan',
            '--console-site', profile['consoleSite'], '--console-region', profile['consoleRegion']]


def host_time_zone():
    """호스트의 시간대 이름. 샌드박스는 zoneinfo 파일을 못 읽어 UTC 로 찍히므로 이름만 넘긴다.

    Node 는 TZ 이름을 내장 ICU 데이터로 해석하므로 파일 접근이 필요 없다.
    """
    try:
        target = os.readlink('/etc/localtime')
    except OSError:
        return 'UTC'
    marker = 'zoneinfo/'
    name = target.split(marker, 1)[1] if marker in target else ''
    return name if name and all(c.isalnum() or c in '/_-+' for c in name) else 'UTC'


def run_sandboxed(command, domains):
    """가드 소유 워크스페이스와 지속 격리 홈으로 bl 을 Seatbelt 안에서 실행한다."""
    # bl 은 실행마다 Node 의 실험 기능 경고(UNDICI-EHPA)를 두 줄 찍어 결과를 가린다.
    status = agent_guard.run_confined('usage', usage_workspace(), command, sorted(set(domains)),
                                      extra_env={'TZ': host_time_zone(), 'NODE_OPTIONS': '--no-warnings'})
    if status == 3:
        # bl 의 종료 코드 3 은 인증 문제다. bl 의 안내(`bl auth login --console`)는 호스트 홈에 저장하므로
        # 격리 홈을 쓰는 우리 명령을 대신 알려 준다.
        print('token-usage: 콘솔 로그인이 없거나 만료됐습니다. `token-usage login` 으로 다시 로그인하세요.', file=sys.stderr)
    return status


def login_on_host(home):
    """콘솔 로그인 1회. 샌드박스 밖이지만 HOME 과 설정 디렉터리를 격리 홈으로 고정한다.

    브라우저가 열리고 로컬 콜백 포트가 필요해서 샌드박스 안에서는 돌 수 없다.
    환경은 최소한만 넘긴다. 다른 에이전트의 설정 디렉터리 변수는 일부러 빼서
    `bl config agent` 류가 실제 설정을 찾지 못하게 한다.
    """
    entry = bl_entry(home)
    if not entry.is_file():
        raise agent_guard.GuardError('bl is not installed in the isolated home yet; run agent-guard usage setup first.')
    profile = load_profile()
    env = {
        'HOME': str(home), 'BAILIAN_CONFIG_DIR': str(home / '.bailian'),
        'PATH': ':'.join([str(agent_guard.NODE.parent), '/usr/bin', '/bin']),
        'TMPDIR': str(agent_guard.private_dir(home / 'tmp')),
        'DO_NOT_TRACK': '1', 'LANG': 'en_US.UTF-8', 'TERM': os.environ.get('TERM', 'xterm-256color'),
    }
    print('Console login opens your browser once; the token is stored only in the isolated home.', file=sys.stderr)
    return subprocess.call([str(agent_guard.NODE), str(entry), 'auth', 'login', '--console',
                            '--console-site', profile['consoleSite']], env=env, cwd=str(home))


def run_usage(arguments):
    """`agent-guard usage [setup|login|-- <bl args>]` 진입점."""
    profile = load_profile()
    home = usage_home()
    if arguments == ['setup']:
        development = agent_guard.development_options()
        status = run_sandboxed(install_command(profile), profile['domains'] + development['packageDomains'])
        if status != 0:
            raise agent_guard.GuardError('bailian-cli install failed inside the isolated home; see npm output above.')
        return login_on_host(home)
    if arguments == ['login']:
        return login_on_host(home)
    return run_sandboxed(query_command(home, profile, arguments), profile['domains'])
