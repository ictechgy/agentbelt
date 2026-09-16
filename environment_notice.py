"""격리 환경 설명 문서 생성.

에이전트가 세션 시작 시점부터 자신이 격리 환경에 있음을 알아야 한다. 과거 세션에서
"dart 가 없다", "CLT 가 망가졌다", "네트워크가 막혔다" 같은 오진의 뿌리는 에이전트가
자기가 무엇을 못 보는지 모른 채 원인을 지어낸 데 있었다. 이 문서는 감독자가 실제 정책
값으로 만들어 세션마다 다시 쓰며, 자식은 읽을 수만 있다. 토큰 값은 절대 넣지 않는다.
"""
from pathlib import Path

# 격리 홈 안에서 에이전트가 직접 읽을 수 있는 설명 파일 이름.
NOTICE_FILE_NAME = 'AGENT_GUARD_ENVIRONMENT.md'


def _bullet_lines(values):
    """문자열 목록을 Markdown 불릿으로 바꾼다. 비어 있으면 '(없음)' 한 줄을 돌려준다."""
    return '\n'.join('- `' + str(value) + '`' for value in values) if values else '- (없음)'


def _readable_roots(policy, workspace, home):
    """정책의 allowRead 중 워크스페이스·홈·장치 파일을 뺀 도구·시스템 경로만 고른다."""
    skip = {str(workspace), str(home)}
    return [path for path in policy['filesystem']['allowRead']
            if path not in skip and not path.startswith('/dev/') and not path.startswith('/private/')]


def _data_home_line(home, env):
    """자식의 HOME 과 지속 데이터 홈이 다를 때만(OpenCode 보호 모드) 그 위치를 알려 준다."""
    if env.get('HOME', str(home)) == str(home):
        return ''
    return f'- 대화·캐시·상태 같은 프로젝트별 지속 데이터: `{home}` (XDG_DATA_HOME/CACHE_HOME/STATE_HOME)\n'


def _external_review_line(env):
    """외부 모델 리뷰 안내. 중계가 켜진 세션은 packet-review 로, 아니면 사용자에게 넘긴다.

    두 안내가 같이 있으면 에이전트가 앞쪽(사용자에게 넘기기)을 따랐다. 하나만 남긴다.
    """
    if env.get('AGENT_GUARD_PACKET_REVIEW') == '1':
        return ('- 외부 모델 리뷰는 아래 `packet-review` 명령으로 감독자에게 맡긴다. 패킷 파일을 직접 만들거나\n'
                '  사용자에게 호스트 실행을 요청하지 마라. 파일을 `tmp/packet-requests` 에 손으로 넣어도 처리되지 않는다.\n')
    return ('- 외부 모델 리뷰가 필요하면 패킷 파일(diff·질문)을 워크스페이스에 저장하고, 사용자가 호스트\n'
            '  터미널에서 실행할 `packet-ask-safe` 명령을 제시한 뒤 멈춘다. 재시도·우회를 탐색하지 마라.\n')


def _loopback_section(env):
    """세션 전용 루프백 포트가 있으면 그 사용법을, 없으면 무작위 바인드가 막힌다는 사실만 알린다."""
    if env.get('AGENT_GUARD_LOOPBACK_ALL') == '1':
        return ('- 이 워크스페이스는 **루프백 전체가 열려 있다**(JVM 빌드 허가). 임의 로컬 포트 바인드·수신·자기 접속이 된다.\n'
                '  같은 사용자의 다른 로컬 서비스(다른 에이전트 서버, 앱 포트)에도 접속이 가능하지만 프로젝트와 무관하니 접속하지 마라.\n')
    port = env.get('AGENT_GUARD_LOOPBACK_PORT', '')
    if not port:
        return '- 로컬 포트 바인드는 허용 목록 밖이면 EPERM 이다. VM 서비스·디버거를 켜는 옵션은 쓰지 마라.\n'
    return (f'- 무작위 로컬 포트 바인드는 EPERM 이다. 로컬 포트가 꼭 필요하면 이 세션 전용 포트 `{port}`'
            ' (`$AGENT_GUARD_LOOPBACK_PORT`) 하나만 쓸 수 있다. 바인드와 자기 접속 모두 된다.\n'
            '- Dart 커버리지는 VM 서비스 포트가 필요하므로 이렇게 실행한다:\n'
            '  `dart --enable-vm-service=$AGENT_GUARD_LOOPBACK_PORT --no-dds --disable-service-auth-codes test --coverage=coverage`\n'
            '  (`dart test --coverage` 만 치면 무작위 포트를 열다 멈춘다.)\n')


def render_environment_notice(workspace, home, env, policy, extra=''):
    """세션에 주입할 격리 환경 설명 Markdown 을 만든다.

    workspace/home 은 실제 경로, env 는 자식에게 넘길 환경, policy 는 sandbox_policy 결과다.
    GH_TOKEN 은 존재 여부만 기록한다. 값이 문서에 들어가면 로그·모델 입력으로 새어 나간다.
    """
    home = Path(home)
    has_github = bool(env.get('GH_TOKEN') or env.get('GITHUB_TOKEN'))
    github_line = ('`GH_TOKEN`/`GITHUB_TOKEN` 환경 변수와 격리 홈의 `.git-credentials` 로 GitHub 인증이 주입되어 있다. '
                   '`gh` 와 `git push` 는 그대로 쓰면 된다.' if has_github else
                   'GitHub 토큰이 주입되지 않았다. `gh` 인증 실패는 환경 결함이 아니라 미설정이다.')
    return f"""# agent-guard 격리 환경 안내

이 세션은 macOS Seatbelt 샌드박스 안에서 실행 중이다. 아래 사실은 감독자가 실제 정책 값으로
세션 시작 시 생성했다. 환경이 이상해 보이면 추측하기 전에 이 문서를 다시 읽어라:
`cat "$HOME/{NOTICE_FILE_NAME}"`

## 경로

- HOME 은 실제 사용자 홈이 아니라 격리 홈이다: `{env.get('HOME', home)}`
{_data_home_line(home, env)}- 워크스페이스(쓰기 가능): `{workspace}`
- 임시 파일은 반드시 `$TMPDIR` 에 만든다: `{env.get('TMPDIR', '')}`
- `/tmp`, 실제 사용자 홈, 다른 프로젝트 디렉터리는 읽기·쓰기 모두 막혀 있다.
- Dart 패키지 캐시는 `$PUB_CACHE` 다: `{env.get('PUB_CACHE', '')}`. 호스트의 `~/.pub-cache` 는
  의도적으로 차단되며 `~` 는 격리 홈이므로 그 경로를 쓰지 마라. `dart pub get` 은 pub.dev 에서
  이 캐시로 직접 받는다. 의존성을 호스트에서 복사할 필요가 없다.

## 읽을 수 있는 도구·시스템 경로

{_bullet_lines(_readable_roots(policy, workspace, home))}

PATH: `{env.get('PATH', '')}`

위 목록 밖의 실행 파일(예: `~/.local/bin`, 다른 버전 관리자)은 보이지 않는다. 이는 설치 누락이
아니라 경계 밖에 있는 것이다. 호스트에 이미 설치된 `dart`, `gh`, `node`, `npm` 은 위 경로로 쓸 수 있다.

## 네트워크

다음 도메인만 감독자 프록시를 거쳐 도달한다. 목록 밖은 DNS 부터 실패한다.

{_bullet_lines(policy['network']['allowedDomains'])}

## 이 안에서 실행할 수 없는 것

- `sandbox-exec` 중첩은 커널이 거부한다. 따라서 `packet-ask`, `packet-ask-safe`, `agent_guard.py`
  같은 보호 실행기는 이 세션 안에서 돌지 않는다. 고장이 아니라 설계다.
{_external_review_line(env)}
## Swift

- `swift 파일.swift`·`swiftc` 는 그대로 된다. "this SDK is not supported by the compiler" 가 보이면 툴체인 고장이
  아니라 모듈 캐시 문제이며, `CLANG_MODULE_CACHE_PATH` 가 이미 설정돼 있으므로 새 세션에서는 나지 않는다.
- SwiftPM 은 반드시 이렇게 실행한다. 자체 sandbox-exec 는 중첩이 거부되고, 워크스페이스 안 `.build/build.db` 는
  비밀 파일 규칙(`*.db`)에 막히므로 scratch 를 `$TMPDIR` 아래에 둔다:
  `swift build --build-system native --disable-sandbox --scratch-path "$TMPDIR/swiftpm-build" --cache-path "$TMPDIR/swiftpm-cache"`
  (`swift test`·`swift run` 도 같은 플래그.) `--build-system native` 는 필수다: CLT 27 부터 기본인 `swiftbuild` 는
  링커 단계의 swiftc 를 TMPDIR 없이 띄워 닫힌 `/var/folders/…/T` 에 임시 파일을 쓰다 `error: permissionDenied` 로
  실패한다(툴체인 고장 아님). deprecated 경고는 무시한다. 인덱스 스토어가 필요하면 `-Xswiftc -index-store-path -Xswiftc "$TMPDIR/index"`.
- `NSTemporaryDirectory()`(= `/var/folders/…/T/`)는 TMPDIR 과 다르며 기본적으로 막혀 있다. 예외로 열린 하위 폴더:
  `cartograph-index-db`, `cartograph-syntax-cache`(읽기·쓰기), `TemporaryItems`(쓰기만). 다른 도구가 거기에 캐시를
  두려 하면 그 도구가 TMPDIR 을 무시하는 것이니 도구 쪽 옵션을 찾거나 사용자에게 폴더 이름 허용을 요청한다.

## 로컬 포트

{_loopback_section(env)}
## JVM (Gradle·Maven·Kotlin)

- `java` 는 `/usr/bin/java` 스텁이 아니라 Homebrew JDK 를 쓴다. 먼저 `export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`
  (프로젝트가 요구하는 버전에 맞게 `openjdk@21` 등) 뒤 `export PATH="$JAVA_HOME/bin:$PATH"`. `/usr/libexec/java_home` 은 여기서 JDK 를 못 찾는다.
- `user.home`·`java.io.tmpdir`·`GRADLE_USER_HOME` 은 이미 격리 홈으로 잡혀 있다(`JAVA_TOOL_OPTIONS`). 이 값을 지우지 마라.
- Gradle 배포판·Maven Central·Plugin Portal·Google Maven 은 허용 도메인이다. 첫 실행은 다운로드로 수 분 걸린다.
- Gradle 데몬·Kotlin 데몬·테스트 워커는 임의 루프백 포트가 필요하다. 위 "로컬 포트" 절이 "루프백 전체가 열려 있다"고
  하지 않으면 이 워크스페이스에서는 Gradle 을 돌릴 수 없으니 사용자에게 `state/loopback-grants.json` 허가를 요청하고 멈춘다.
- 파일 감시 경고 "Could not start the FSEvents stream" 은 무해하며 이미 `org.gradle.vfs.watch=false` 로 꺼져 있다.

## 인증

- {github_line}
- `~/.config/gh` 는 의도적으로 비어 있다. 여기서 로그인 상태를 판단하지 마라.
- git 작성자 신원은 `$GIT_CONFIG_GLOBAL`(격리 홈, 잠김)에 이미 있다. `git config user.name/email` 은 `.git/config` 가 잠겨 실패한다.
  다른 신원이 꼭 필요하면 `git -c user.name=… -c user.email=…` 또는 `GIT_AUTHOR_*` 환경변수로 한 번만 넘겨라.
- 새 저장소 초기화(`git init`)는 워크스페이스 안에서 되지 않는다(`.git/hooks`·`.git/config` 보호의 조상 경로). 기존 저장소에서 작업한다.
- macOS Keychain 과 실제 홈의 자격 증명은 접근이 차단된다.

## 하지 말 것

- 도구가 없거나 권한 오류가 나면 **샌드박스 경계**를 먼저 의심한다. `sudo`, `rm -rf`,
  Command Line Tools 재설치, 시스템 설정 변경을 권하거나 시도하지 마라. 시스템은 멀쩡하다.
- 경계 밖 접근이 꼭 필요하면 무엇이 왜 필요한지 사용자에게 보고하고 멈춘다.

## 진단 명령

```sh
echo "HOME=$HOME"; echo "TMPDIR=$TMPDIR"; echo "PATH=$PATH"
cat "$HOME/{NOTICE_FILE_NAME}"
```
{extra}"""
