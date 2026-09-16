"""Kimi Code CLI(Moonshot `kimi`)를 격리해서 돌리는 kimi 모드(`safekimi`).

왜 격리하는가. Kimi Code 0.43 은 Node SEA 단일 바이너리로, 네이티브 클립보드 바인딩
(`@mariozechner/clipboard`, NSPasteboard)·`pbcopy`·osascript(JXA) 로 시스템 클립보드를 읽고 쓰며,
텔레메트리(`telemetry-logs.kimi.*`)·자동 갱신(`code.kimi.*`)·플러그인 마켓·WebBridge/Computer-Use
바이너리 다운로드(`cdn.kimi.com`)·launchd 서비스 등록(`ai.kimi.cu.service`) 경로를 갖는다. safecode 와 같은
Seatbelt 경계(워크스페이스 하나 + 프로젝트별 격리 홈 + 도메인 허용 목록)로 감싸고, 클립보드는 페이스트보드
mach 서비스를 커널에서 거부해 어떤 경로(네이티브·pbpaste·JXA)로도 읽지 못하게 한다(`sandbox_runner.mjs`).

왜 로그인이 세션 안에서 되는가. Kimi 의 로그인은 디바이스 코드 흐름(`auth.kimi.*/api/oauth/device_authorization`)
이라 로컬 콜백 포트가 필요 없다. 브라우저 자동 열기(`open`)는 샌드박스에서 실패하지만 URL 이 화면에
찍히므로 사용자가 직접 연다. 토큰은 `<격리홈>/.kimi-code/credentials/` 에 저장되며 임시 파일 + rename 으로
갱신되므로 하드링크 공유가 갈라진다 — 그래서 워크스페이스마다 한 번씩 로그인한다(호스트 `~/.kimi-code` 는
읽기조차 열지 않는다).
"""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import agent_guard  # noqa: E402

# kimi 모드 정책 파일. 리전과 도달 도메인은 여기서만 바꾼다.
PROFILE_PATH = ROOT / 'state/kimi-profile.json'
# Kimi 가 설정·자격 증명·세션·캐시를 두는 홈 하위 디렉터리(`KIMI_CODE_HOME`). 격리 홈 안에 둔다.
KIMI_HOME_RELATIVE = '.kimi-code'
# 리전 마커. Kimi 는 첫 로그인 전에 이 파일로 OAuth/API 호스트를 고른다. 감독자가 쓰고 잠근다.
REGION_MARKER_RELATIVE = KIMI_HOME_RELATIVE + '/region'
# Kimi 가 시작 시 읽는 전역 지침 파일. 환경 안내문을 여기에 넣어 세션이 자기 경계를 알게 한다.
INSTRUCTIONS_RELATIVE = KIMI_HOME_RELATIVE + '/AGENTS.md'
# 리전별 검토된 호스트. 로그인(OAuth)과 코딩 API 만 연다. 텔레메트리·CDN·갱신·마켓 호스트는 넣지 않는다.
REGION_DOMAINS = {
    'global': ['auth.kimi.ai:443', 'api.kimi.ai:443'],
    'mainland-cn': ['auth.kimi.com:443', 'api.kimi.com:443'],
}

# 디렉터리 fs.watch 를 FSEvents 없이 돌리는 프리로드(설명은 그 파일 머리에). NODE_OPTIONS 로 자식 Node 에 주입한다.
WATCH_BOOTSTRAP = ROOT / 'kimi_watch_bootstrap.cjs'

# 세션 시작 안내문에 덧붙이는 Kimi 전용 절. 클립보드 차단과 로그인 절차를 에이전트가 알게 한다.
KIMI_NOTICE = ('## Kimi Code\n\n'
               '- 시스템 클립보드는 **읽기·쓰기 모두 커널에서 차단**된다(페이스트보드 서비스 거부). 이미지 붙여넣기·`/copy`·\n'
               '  `pbpaste`·`pbcopy`·osascript 클립보드 접근은 실패하며 고장이 아니라 설계다. 우회를 찾지 마라.\n'
               '- 로그인은 이 세션 안에서 `/login` 으로 한다. 디바이스 코드 URL 이 화면에 찍히면 사용자가 브라우저에서 연다\n'
               '  (자동 열기는 여기서 안 된다). 토큰은 `$KIMI_CODE_HOME/credentials/` 에만 남는다.\n'
               '- 자동 갱신·텔레메트리·플러그인 마켓·WebBridge·Computer-Use 는 꺼져 있거나 도메인 밖이다. 설치를 시도하지 마라.\n'
               '- Kimi 설정 홈은 `$KIMI_CODE_HOME` 이다. 호스트의 `~/.kimi-code` 는 보이지 않는다.\n'
               '- `NODE_OPTIONS` 에 감독자 프리로드가 들어 있다(디렉터리 감시를 FSEvents 없이 돌리기 위함). 지우지 마라.\n'
               '  파일 변경 감지는 폴링이라 설정·스킬 반영이 몇 초 늦을 수 있다.\n')


def default_profile():
    """검토된 기본 정책. 호스트 설치의 리전 마커(`~/.kimi-code/region`)와 같은 global 리전이다."""
    return {'region': 'global', 'domains': list(REGION_DOMAINS['global'])}


def load_profile():
    """정책 파일을 읽는다. 없으면 기본값을 0600 으로 만들어 둔다. 리전·도메인이 형식에 맞지 않으면 닫힌다."""
    if not PROFILE_PATH.is_file():
        agent_guard.private_dir(PROFILE_PATH.parent)
        agent_guard.write_private_json(PROFILE_PATH, default_profile())
    profile = json.loads(PROFILE_PATH.read_text())
    if profile.get('region') not in REGION_DOMAINS:
        raise agent_guard.GuardError('state/kimi-profile.json region must be "global" or "mainland-cn".')
    domains = profile.get('domains')
    reviewed = {domain for region in REGION_DOMAINS.values() for domain in region}
    # 와일드카드·다른 포트·검토 밖 호스트는 거부한다(리뷰 LOW: `*.kimi.ai:443` 이 텔레메트리·갱신 호스트를 다시 연다).
    if not isinstance(domains, list) or not domains or not all(isinstance(d, str) and d in reviewed for d in domains):
        raise agent_guard.GuardError('state/kimi-profile.json domains must be a non-empty subset of the reviewed Kimi hosts: '
                                     + ', '.join(sorted(reviewed)) + '.')
    return profile


def kimi_environment(home, binary=None):
    """자식 Kimi 프로세스에 넘길 환경. 텔레메트리·자동 갱신을 끄고 설정 홈을 격리 홈 안으로 고정한다.

    binary 는 실제로 실행되는(복제된) Kimi 경로다. 프리로드는 `process.execPath` 가 이 값과 같을 때만 fs.watch 를
    바꾼다 — NODE_OPTIONS 는 에이전트가 띄우는 다른 node 도구에도 상속되므로 그쪽 감시는 건드리지 않는다.
    """
    return {
        'KIMI_CODE_HOME': str(Path(home) / KIMI_HOME_RELATIVE),
        'AGENT_GUARD_KIMI_BINARY': str(binary if binary is not None else agent_guard.KIMI),
        'KIMI_DISABLE_TELEMETRY': '1',
        'KIMI_CODE_NO_AUTO_UPDATE': '1',
        'KIMI_CLI_NO_AUTO_UPDATE': '1',
        'KIMI_SHELL_PATH': '/bin/bash',
        # 디렉터리 감시: FSEvents 는 샌드박스에서 막히고(허용하면 읽기 거부 경로의 파일 이름이 샌다) chokidar 의
        # 내부 FSWatcher 는 error 리스너가 없어 EMFILE 로 프로세스가 죽는다. chokidar 는 stat 폴링으로, 남은
        # 디렉터리 fs.watch 는 프리로드가 조용한 감시자로 바꾼다. 둘 중 하나만 있으면 여전히 죽거나 시끄럽다.
        'CHOKIDAR_USEPOLLING': '1',
        'NODE_OPTIONS': '--require ' + str(WATCH_BOOTSTRAP),
    }


def prepare_kimi_home(region, binary=None):
    """실행 전 격리 홈에 리전 마커를 링크 안전하게 쓰고 Kimi 환경 변수를 넣는 준비 함수를 만든다.

    격리 홈 경로는 run_confined 가 정한 것을 콜백으로 받는다. 여기서 persistent_home 을 미리 부르면 실행 없이도
    (예: 배선 테스트) `state/homes/kimi/` 에 빈 홈이 생긴다. 리전 마커는 run_confined 가 denyWrite 로 잠근다.
    """
    def prepare(home, env):
        agent_guard.write_private_file(home, REGION_MARKER_RELATIVE, region + '\n')
        env.update(kimi_environment(home, binary))
    return prepare


def run_kimi(arguments):
    """`agent-guard kimi -- <kimi 인자>` 진입점. 현재 디렉터리가 워크스페이스다."""
    workspace = agent_guard.workspace_path(os.getcwd())
    agent_guard.verify_kimi_binary()
    profile = load_profile()
    development = agent_guard.development_options()
    publish = agent_guard.pub_publish_grant(workspace)
    publish_credentials = [('dart/pub-credentials.json', agent_guard.PUB_CREDENTIALS)] if publish is not None else []
    publish_notice = ('\n## pub.dev 게시\n\n이 워크스페이스는 `dart pub publish` 가 허용돼 있다. `--dry-run` 은 자유롭게, '
                      '실제 게시는 사용자가 지시했을 때만 한다.\n' if publish is not None else '')
    domains = sorted(set(profile['domains'] + development['packageDomains']
                         + (agent_guard.PUB_PUBLISH_DOMAINS if publish is not None else [])))
    # 검증과 실행 사이의 바꿔치기를 막기 위해 가드 소유 복제본을 검증해 그것만 실행한다. 읽기 허용도 복제본이다.
    staged = agent_guard.stage_kimi_binary()
    try:
        return launch_kimi(workspace, staged, arguments, domains, profile, development, publish_credentials,
                           KIMI_NOTICE + publish_notice)
    finally:
        agent_guard.discard_staged_binary(staged)


def launch_kimi(workspace, binary, arguments, domains, profile, development, publish_credentials, notice):
    """검증된 복제본으로 run_confined 를 부른다. run_kimi 에서 분리해 정리(finally)와 배선을 따로 검사한다."""
    return agent_guard.run_confined(
        'kimi', workspace, [str(binary), *arguments], domains,
        extra_reads=[binary, WATCH_BOOTSTRAP],
        prepare_home=prepare_kimi_home(profile['region'], binary),
        read_only_home_paths=[REGION_MARKER_RELATIVE],
        dev_ports=development['devPorts'],
        instruction_files=[INSTRUCTIONS_RELATIVE],
        notice_extra=notice,
        loopback_port=True,
        config_credentials=publish_credentials,
        loopback_all=agent_guard.loopback_grant(workspace),
        allow_gradle_keystore=agent_guard.gradle_keystore_grant(workspace))
