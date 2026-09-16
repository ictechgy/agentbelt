# 이 맥의 에이전트 보호 실행기

리뷰에서 검증된 보호 결함을 수정했다. [수정·검증 기록](REPAIRS.md)에 변경과 검증 범위를 기록했다.
[원래 리뷰 보고서](.codex/artifacts/ultra-review/agentbelt-eaa74cf67b0c430d/report.md)는 수정 전 재현 기록이다.

최근 실제 사용에서 발견한 시작·대화·provider 문제와 Dock 개선은 [복구 기록](RECOVERY.md)에 정리했다.

## 호환성 보완

[호환성 적용 기록](COMPATIBILITY.md)에 riskgate 통합, Git 작업, 업데이트 검사와 남은 승인·실기기 검증을 정리했다.

- 상태 확인: `agentbelt doctor`
- Zcode/OpenCode 업데이트 후: `agentbelt verify-updates`
- Claude Code에서도 `/packet-ask-safe` 사용 가능. 호출 대상은 GLM이며 Claude Code가 MAIN 역할이다.

## 현재 상태

- macOS 계정을 바꾸지 않고 사용할 수 있는 Zcode 백엔드 실행기와 훅을 구현했다.
- `~/Applications/Zcode Safe.app`은 기존 Zcode 화면·프로필을 유지하고 에이전트의
  시작 경로를 `zcode-backend-safe`로 지정한다. 기존 Zcode가 실행 중이면 종료를
  요구하며 세션을 자동으로 닫지 않는다.
- 보호된 Zcode 백엔드의 시작과 실제 `workspace/readState` 프로토콜 응답을 확인했다.
- OpenCode는 실제 바이너리와 로컬 가짜 모델 서버를 연결해 Bash를 통한 프로젝트
  밖 가짜 민감 파일 읽기가 차단되고, 내용이 모델 서버에 전달되지 않는 것을 확인했다.
- 사용자 승인 후 실제 인증 이관과 Zcode 전역 훅 적용을 완료했다.
  OpenCode의 `alibaba-token-plan` API 인증만 이관했고 OpenAI OAuth는 제외했다.
  네트워크를 차단한 검증 환경에서 Qwen·DeepSeek를 포함한 모델 식별자 26개의
  로딩을 확인했다. 이는 실제 API의 응답/구독 권한까지 확인했다는 뜻은 아니다.
- API 허용 대상은 OpenCode의 `token-plan.ap-southeast-1.maas.aliyuncs.com:443`과
  Zcode/GLM의 `api.z.ai:443`이다. 로컬 서비스 직접 접속은 허용하지 않는다.
- 일반 `opencode` 명령과 일반 Zcode 실행 자체에는 OS 격리가 자동 적용되지 않는다.
- 별도 macOS 사용자 계정은 만들지 않았다. 이전 계정 생성 스크립트는 비활성 보관했다.

## 사용할 경로

Dock의 초록색 **Zcode Safe**를 사용한다. 독립된 Safe 관리 앱이 Dock에 남고, 실제 작업 창은 Zcode로 표시된다.
기존 일반 Zcode가 실행 중이면 먼저 저장·종료한 뒤 Safe로 연다.
로그아웃이나 사용자 전환은 필요하지 않다. 새로 시작하는 에이전트 백엔드에 적용된다.

OpenCode는 원하는 프로젝트 디렉터리에서 `safecode`로 실행한다.

```sh
cd /절대/프로젝트/경로
safecode
safecode --model 공급자ID/모델ID

# 경로를 명시하는 기존 보호 실행기도 유지한다.
opencode-safe /절대/프로젝트/경로
opencode-safe /절대/프로젝트/경로 --model 공급자ID/모델ID
```

Kimi Code 는 원하는 프로젝트 디렉터리에서 `safekimi` 로 실행한다. 클립보드(페이스트보드 서비스)는 커널에서
차단되고, 로그인은 세션 안 `/login`(디바이스 코드 URL 을 브라우저에서 직접 연다)으로 워크스페이스마다 한 번 한다.

```sh
cd /절대/프로젝트/경로
safekimi
safekimi -p "한 번만 실행할 프롬프트"
```

`safecode`와 `safekimi`는 실제 현재 디렉터리를 사용하고 나머지 인자를 그대로 전달한다.
조작된 `PWD` 환경변수로 범위를 바꾸지 않는다. 기존 `opencode` 명령은 변경하지 않았다.
OpenCode의 설정용 HOME은 실행마다 새로 만들고 설정 디렉터리 쓰기를 차단한다.
대화·인증 연결·캐시·상태는 기존 프로젝트별 XDG 데이터 경로에 유지한다.
이전에 격리 홈에 만들어진 개인 설정은 다음 실행의 승인 정책에 병합하지 않는다.

packet-ask의 GLM 보호 실행은 프로젝트에서 다음 형식으로 사용한다.

```sh
packet-ask-safe --use-keychain review --provider glm --files src/example.py --question-stdin
```

`--use-keychain`은 필요할 때 기존 `packet-ask-glm` 전용 항목을 읽도록 명시적으로
허용하는 옵션이다. 전용 환경변수 `PACKET_ASK_GLM_KEY`가 있으면 그것을 우선 사용한다.
키체인 조회는 신뢰하는 호스트 실행기가 하고, 제한된 자식에는 GLM용 키만 전달한다.
승인된 전용 GLM 키체인과 가짜 질문만으로 실제 GLM 응답을 확인했다. 키 값과 실제 프로젝트 파일은 출력·전송하지 않았다.
`inspect`, `--preview`, `--dry-run`은 키체인 값을 읽지 않는다.
새 키가 필요한 경우에만 실제 macOS Terminal에서 `packet-ask-safe setup-key`를 실행한다.
이미 등록된 현재 키는 실제 호출 검증을 통과했으므로 다시 입력할 필요가 없다.
Codex용 `packet-ask-safe` 스킬도 `~/.codex/skills/packet-ask-safe`에 설치되어 있다.

현재 파일 권한 정책상 프로젝트는 개인 홈 아래의 개별 폴더여야 한다.
홈 전체, Library, 숨겨진 홈 설정 디렉터리, Desktop 전체 같은 넓은 범위는 거부한다.
프로젝트 내 기존 하드링크가 있으면 독립된 작업 사본을 사용하도록 거부한다.
읽을 수 없는 하위 폴더 등으로 전체 검사를 마칠 수 없어도 실행을 거부한다.

## 보호 범위

- 지정 프로젝트와 에이전트 전용 상태 폴더 외에는 읽기/쓰기를 기본 거부한다.
- 시스템 실행 파일·라이브러리와 명시한 CLI 실행 코드에는 필요한 읽기만 허용한다.
- 프로젝트의 `.env*`, 인증·키 파일, 일부 DB 파일 등 알려진 민감 이름을 추가 차단한다.
- 개인 홈의 SSH·클라우드 인증, 다른 앱 상태, 일반 임시 폴더 및 기존 로컬 서비스에
  접근할 수 없도록 제한한다.
- 부모 프로세스의 임의 환경변수는 전달하지 않는다.
- 키체인 서비스와 Apple Events/Launch Services를 통한 우회 경로를 제한한다.
- 네트워크는 승인해 설정한 API 도메인과 포트만 프록시를 통해 허용한다.
- Zcode의 JS/브라우저/MCP 계열 도구는 전역 훅의 허용 대상에서 제외한다.
- 보호된 백엔드가 아닌 일반 Zcode 세션에서는 검색·하위 에이전트가 더 제한된다.
  Bash 요청은 별도 OS 샌드박스 실행으로 바꾼다.

## 한계

Zcode GUI 전체가 OS 샌드박스에 들어가는 것은 아니다. GUI가 이미 읽어서 전달한
첨부 파일·대화 이력·클립보드나, 사용자가 직접 붙여 넣은 데이터까지 되돌려 막지 않는다.
허용된 소스 본문이나 Git 이력 속에 들어 있는 비밀은 파일 이름만으로 판별할 수 없다.
개발용 자료만 작업 폴더에 두고 개인 브라우저 데이터 가져오기를 사용하지 않아야 한다.

모델 호출에 필요한 선택된 공급자의 인증은 해당 CLI에 제공된다. 다른 공급자의
인증을 함께 복사하지 않는다. 모델용 키까지 도구 프로세스에서 완전히 숨기는 별도의
자격증명 주입 프록시는 구현 범위에 포함되지 않았다.

Zcode 훅만으로는 오류 시 항상 차단되는 보안 경계가 되지 않는다. OS 보호는
`Zcode Safe.app`에서 시작한 백엔드와 `safecode` / `opencode-safe` 실행 경로에 적용된다.

## 적용 기록과 재실행

승인받은 Zcode `~/.zcode/cli/config.json`과 OpenCode 인증 저장소를 검사했고,
`configure_existing.py --authorized-live-settings`로 필요한 항목만 적용했다.
기존 Zcode 훅 1개와 플러그인 설정은 유지하고 보호 훅을 추가했다.
OpenCode의 원본 인증 저장소는 수정하지 않았다.

Zcode는 종료 후 보호 실행기로 다시 열어 새 백엔드를 시작해야 한다.
기존 실행 중인 앱/에이전트에는 소급 적용되지 않는다. GUI와 실제 유료 모델 호출을
포함하는 사용 세션은 사용자가 재실행한 후 확인해야 한다.

기존 Zcode 설정 백업은 `state/backups`에 권한 600으로 저장했다.
되돌릴 때는 백업 전체를 무조건 덮어쓰지 말고, 이후 사용자 변경을 보존하면서
이 도구가 추가한 훅과 거부 규칙만 제거한다.

## 검증

```sh
cd ~/.local/share/agentbelt
/usr/bin/python3 -m unittest discover -s tests -v
```

자동 테스트는 가짜 파일·가짜 키·로컬 모델 서버만 사용한다. 별도의 승인된 GLM 실호출에는 가짜 질문만 보냈으며 실제 프로젝트 파일은 보내지 않았다.
호환성 보완을 포함한 전체 70개 테스트가 통과했다.
추가 복구에서는 승인된 Zcode 세션 DB·오류 로그를 확인하고 프로젝트별 대화를 Safe로 복원했다. 전용 GLM 키체인도 승인 범위에서 사용했으며 인증 값은 출력하지 않았다. 이전 설정 로딩 검증에서도 인증 값은 출력하지 않았다.
`safecode` 대화형 화면의 시작과 종료도 가짜 프로젝트의 전용 PTY에서 확인했다.
터미널 제어는 실제로 상속받은 장치의 필요한 ioctl만 허용하고, 다른 TTY 접근과
TIOCSTI 입력 주입은 차단한다. 일반 `/dev/tty` 별칭에 대한 ioctl은 허용하지 않는다.

SRT 0.0.75를 이 폴더의 `runtime`에 고정 설치했다. 시스템 npm 설정을 사용하거나
설치 스크립트를 실행하지 않았다. Zcode 보호 실행기는 검토한 앱 버전 3.11.2가
바뀌면 재검증을 요구한다.
