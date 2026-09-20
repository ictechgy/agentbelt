# agentbelt (한국어)

영어 README 가 기본 문서입니다: [../../README.md](../../README.md). 이 문서는 같은 내용의 요약이며, 두 문서가 다르면 영어 쪽이 맞습니다.

## 무엇을 하는가

macOS 에서 AI 코딩 에이전트를 **프로젝트 디렉터리 하나에 가둬** 실행합니다. 경계는 커널(Seatbelt)이 강제하고, 실제로 경계를 넘어 보는 테스트로 검증합니다.

agentbelt 는 감독자입니다. 실행마다 정책을 만들어 `sandbox-exec` 안에서 에이전트 CLI 를 띄웁니다. 샌드박스 안에서 에이전트가 보는 것:

| 자원 | 에이전트에게 보이는 것 |
| --- | --- |
| 파일 | 프로젝트 디렉터리, 프로젝트별 격리 `HOME`, 필요한 도구 바이너리. 실제 홈·다른 프로젝트·Keychain·`/opt/homebrew/var` 는 보이지 않음. 프로젝트 안의 비밀 파일(`.env`, 키, keystore, SQLite)은 읽을 수 없음. |
| 네트워크 | 감독자 프록시를 거쳐 허용 목록의 모델 제공자·패키지 레지스트리 호스트만. 텔레메트리·자동 갱신·CDN 은 목록에 없음. |
| 데스크톱 서비스 | 클립보드·Keychain·Apple Events·LaunchServices·FSEvents 는 서비스 이름으로 거부. 복사한 내용을 읽을 수 없고, 프로젝트 밖 파일 이름 변경도 볼 수 없음. |
| 터미널 | 상속된 TTY 만. 입력 주입(`TIOCSTI`) 거부. |
| 자격 증명 | 제공자 키는 에이전트 자체 인증 저장소에서 검토된 제공자만 한 번 가져와 격리 홈에 링크. 저장소 범위 GitHub 토큰은 세션별 주입 가능. |
| 자기 인식 | 세션마다 생성되는 `AGENTBELT_ENVIRONMENT.md` 가 무엇이 닿는지 알려 줘서, 에이전트가 샌드박스를 "고장난 기계" 로 오진하지 않음. |

에이전트 자체의 승인 프롬프트는 그대로 동작하고 agentbelt 는 그 아래에 있습니다. 프롬프트나 훅은 가두려는 프로세스 안에서 돌기 때문에 에이전트가 설정을 고쳐 끌 수 있지만, Seatbelt 정책은 에이전트가 시작하기 전에 적용되고 안에서 넓힐 수 없습니다.

## 지원 에이전트

| 명령 | 에이전트 | 비고 |
| --- | --- | --- |
| `safecode` | [OpenCode](https://opencode.ai) TUI, 현재 디렉터리 | 보호된 설정 디렉터리, 제공자 허용 목록, 감독자 측 리뷰 중계 |
| `opencode-safe <경로>` | OpenCode, 경로 지정 | `safecode` 와 같은 정책 |
| `safekimi` | [Kimi Code](https://www.kimi.com/code) CLI, 현재 디렉터리 | OS·터미널 클립보드 접근 차단, 진단 전송·배너 비활성화, 로컬 웹 바인딩만 허용, 디바이스 코드 로그인 |
| `token-usage` | Alibaba Token Plan 사용량 CLI | 설치·로그인·조회 모두 격리; 출력된 로그인 URL은 브라우저에서 직접 열기 |
| Zcode Safe.app | 원본 데스크톱 실행 차단 | 선택 가능한 검증된 비공개 복제본; 보호된 CLI 백엔드는 유지 |
| `autoclaw-backend` | AutoClaw 번들 Zcode CLI | `adapters/install_autoclaw.py` 로 설치; 바깥 에이전트의 호스트 `exec` 없음 |

모든 통합은 선택 사항입니다. `agentbelt doctor` 가 설치된 것과 해시 일치 여부를 보고합니다.

## 요구 사항

- `/usr/bin/sandbox-exec` 가 있는 macOS. macOS 26 / Apple Silicon 에서 개발·테스트했고, 이전 버전과 Intel Homebrew 배치는 미검증.
- Xcode Command Line Tools (`/usr/bin/python3`, `clang`; `swiftc` 는 Zcode Dock 런처에만 필요).
- 감독자 런타임용 Node 22 이상. 선택된 바이너리는 `config.json` 에 고정되어 `nvm install` 이나 `brew upgrade` 가 몰래 바꾸지 못합니다.
- 위 에이전트 중 하나 이상을 공식 경로로 먼저 설치한 뒤 `agentbelt init` 을 실행합니다.

## 설치

```sh
git clone https://github.com/ictechgy/agentbelt
cd agentbelt
./install.sh        # ~/.local/share/agentbelt 에 복사, node 고정, npm ci, 런처 빌드
agentbelt init      # 이 기기에 없는 상태 파일 생성, 에이전트 해시 기록
agentbelt doctor    # 설치된 에이전트와 해시 일치 여부
```

명령은 `~/.local/bin` 에 놓이니 `PATH` 에 있어야 합니다.

OpenCode 는 쓰는 제공자 키를 가져옵니다. 허용 목록의 제공자만, `{type, key}` 만 복사됩니다:

```sh
/usr/bin/python3 ~/.local/share/agentbelt/adapters/configure_existing.py --authorized-live-settings
cd ~/my-project && safecode
```

Kimi Code 는 가져올 것이 없습니다. `cd ~/my-project && safekimi` 뒤 세션 안에서 `/login`. 디바이스 코드 URL 이 찍히면 브라우저에서 엽니다. 토큰은 그 프로젝트의 격리 홈에만 남습니다.

`token-usage setup`은 격리 홈에 CLI를 설치한 뒤 격리된 콘솔 로그인을 시작합니다. 출력된 URL을 브라우저에서 열면 할당된 루프백 포트 하나로 콜백을 받습니다. 갱신은 `token-usage login`으로 합니다. 사용량 조회·설치·검증 프로브에는 저장소 GitHub 토큰을 주지 않습니다.

`install.sh` 를 다시 실행하면 코드만 제자리에서 갱신됩니다. `state/`(격리 홈·자격 증명·기준선)는 건드리지 않고 기존 `config.json` 도 덮지 않습니다. `init` 은 없는 것만 채우고 있는 파일은 절대 덮지 않습니다.

기존 Zcode Safe 앱은 코드 설치 후 `/usr/bin/python3 ~/.local/share/agentbelt/adapters/install_profiles.py --upgrade-launcher`로 갱신합니다. 원본 Zcode GUI는 실행·재활성화하지 않으며, 비공개 복제본이 설치되면 Safe 관리자가 검증된 복제본을 엽니다. GUI의 자동 저장소 업로드를 백엔드 정책으로 막을 수 없어 기존 GUI 게이트는 차단합니다. 이미 실행 중인 앱은 자동 종료하지 않으므로 설치·갱신 전에 두 Zcode 앱을 모두 닫으세요. 원본 Zcode 앱을 직접 여는 것은 보호 범위 밖입니다. 상태·대화 복원과 보호된 CLI 백엔드는 유지합니다. `installation.json`은 설치가 성공한 뒤에만 갱신됩니다.

### 스냅샷 차단 비공개 Zcode 복제본(선택 기능)

데스크톱 창이 필요한 저장소를 위해 Safe 네이티브 관리자는 별도의 비공개 복제본 경로를
제공합니다. 설치기는 Python API이며 별도 비공개 복제본 CLI는 없습니다. 원본과 비공개
Zcode 앱을 모두 닫은 뒤 다음 API를 사용합니다:

```sh
/usr/bin/python3 -I <<'PY'
import sys
from pathlib import Path
root = Path.home() / '.local/share/agentbelt'
sys.path.insert(0, str(root))
from adapters.zcode_privacy import install
install(root)
PY
```

Safe 앱 갱신 후 번들을 등록하고 `zcode://` 처리 앱으로 선택하세요. 첫 명령의 기존
핸들러는 롤백을 위해 기록해 두세요.

```sh
"$HOME/Applications/Zcode Safe.app/Contents/MacOS/launch" --protocol-status
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$HOME/Applications/Zcode Safe.app"
"$HOME/Applications/Zcode Safe.app/Contents/MacOS/launch" --register-zcode-protocol
```

그 뒤 Zcode Safe.app을 열면 검증된 비공개 복제본을 실행합니다. 기존 원본 GUI 게이트는
계속 차단됩니다. 설치할 때마다 generation이 생성되므로 다른 설치 루트의 매니페스트를
복사해서 사용하지 마세요.

복제본은 `3.12.3`로 버전을 고정하고 bundle ID
`local.agentbelt.zcode.snapshot-blocked`를 사용하며 guard root 아래에 둡니다.
`check-zcode-private`는 매니페스트와 실행 파일 해시를 확인하고 32자리 소문자
`generation`을 반환합니다. 관리자는 일치하는 앱 경로, generation이 묶인 백엔드
argv, 비공개 프로필·세션 경로, 스냅샷 업로드와 자동 업데이트가 차단됐다는 명시적
플래그만 받아들입니다. 업데이터와 복제본 시작 시 프로토콜 등록은 비활성화합니다.

백엔드는 기존 Seatbelt 경로를 계속 사용합니다. 데스크톱 GUI 자체는 OS 샌드박스로
격리되지 않으므로 `safe_launch`는 계속 `false`이며, 백엔드 실행 기록만으로 GUI
격리를 주장하지 않습니다. 비공개 복제본은 `~/.zcode`를 공유하며 비공개 Chromium
user-data·session 디렉터리는 `<install>/state/zcode-private/user-data`와
`<install>/state/zcode-private/session`에 둡니다. 관리자는 `zcode://` 경로를 받아 검증된
비공개 복제본의 명시적 앱 경로로 전달할 수 있고 OAuth 값은 argv·로그·파일에 넣지 않습니다.
수동 업로드와 스냅샷 패치 밖의 텔레메트리는 이 경계에 포함되지 않습니다.
기존 `check-zcode`, `check-zcode-gui`, `record-zcode-launch`, `zcode-app` GUI 게이트는
계속 차단됩니다. 실제 계정·모델·OAuth 실행은 테스트하지 않았습니다. 엄격한 오프라인 GUI
창 시험은 CLI 샌드박스에서 원본과 비공개 복제본이 모두 중단되어 수행할 수 없었으며,
이는 GUI 격리의 증거가 아닙니다.

`packet-ask-safe`와 `packet-review`의 GLM/Qwen 경로는 파일 수집과 모델 실행을 분리합니다. 네트워크·모델 키가 없는 임시 수집 환경이 원본 폴더를 읽기 전용으로 처리하고, 정제된 패킷만 새 임시 폴더에 넘깁니다. 모델 환경은 그 패킷만 읽으며 Qwen에도 선택한 공급자 하나의 키·접속 대상만 허용합니다. 수집·검증 실패 시 모델을 실행하지 않습니다.

일반 `packet-ask`는 별도 서버 없이 텍스트를 정제하는 원본 CLI이며 OS 격리는 제공하지 않습니다. 위 보호 진입점을 사용해야 강화된 경계가 적용됩니다. 선택한 코드 본문과 탐지하지 못한 기밀 문장은 모델 API로 전달될 수 있고, 공급자 서버의 저장·학습 정책은 로컬에서 강제할 수 없습니다. `--preview`·`--dry-run`은 모델을 실행하지 않습니다.

### 최초 설치 신뢰

`init` 은 설치된 에이전트 바이너리의 해시를 기준선으로 기록합니다. 이후 바이너리가 바뀌면 `agentbelt verify-updates` 가 테스트 스위트를 다시 돌려 새 해시를 기록하기 전까지 실행이 거부됩니다. 스스로 갱신하는 에이전트는 클립보드·네트워크·파일 동작도 바뀌었을 수 있기 때문입니다.

packet-ask 승격은 사용 중인 요청과 설치 변경을 잠금으로 분리하고 검증·스킬 설치가 끝난 뒤에만 새 기준선을 공개합니다. 복구를 확인할 수 없거나 강제 종료되면 기준선을 무효화해 실행을 거부합니다.

## 알려진 한계

문서화된 경계이며 놓친 것이 아닙니다.

- **네트워크 허용은 호스트 단위이지 경로 단위가 아닙니다.** `api.example.com` 이 허용되면 그 호스트의 모든 경로에 닿습니다. 경로 단위 브로커는 추후 작업.
- **터미널은 전용 PTY로 중계합니다.** 파이프·파일로 보내는 stdout/stderr도 텍스트 필터를 거칩니다. OSC 52와 미허용 OSC/DCS/APC 및 tmux 전달 문자열을 제거하고 OS pasteboard 차단도 유지합니다. UTF-8·일반 스타일·입력·창 크기·신호는 보존하며, 터미널 이미지/전달 프로토콜은 사용할 수 없습니다. 사용자가 붙여넣은 텍스트는 입력으로 전달됩니다. 바이너리 내보내기는 이 텍스트 출력 대신 작업공간의 파일에 저장해야 합니다.
- **Kimi의 검증된 실행 복사본은 진단 피드백·원격 배너·외부 웹 바인딩을 차단합니다.** `NODE_OPTIONS` 없이 다시 실행해도 제한이 유지됩니다. 원본 바이너리는 보존하며, 모르는 빌드는 개인정보 보호 패치를 검토할 때까지 실행을 거부합니다. 임의 코드에 대한 HTTPS 방화벽은 아니므로 OS 네트워크 제한도 함께 필요합니다.
- **Homebrew는 실행 의존 경로와 정확한 CA/OpenSSL 파일만 읽기 허용합니다.** 일반 `etc`, `var`, `Caskroom` 데이터는 허용 범위 밖입니다.
- **로그인 시점에 설정이 필요한 에이전트(Kimi Code)는 설정이 세션 간 쓰기 가능합니다.** 한 세션이 심은 설정을 같은 프로젝트의 다음 세션이 읽습니다. 영향은 샌드박스 안에 한정.
- **주입된 GitHub 토큰은 세션에 보입니다.** 모델이 직접 보진 않지만 환경 변수를 출력하면 컨텍스트에 실립니다. 에이전트가 push 해야 하는 프로젝트에만 주입하세요.
- **샌드박스 안의 프롬프트는 사람의 증명이 아닙니다.** 진짜 승인이 필요한 일은 실행 전에 호스트에서 정책으로 정합니다.

- **Gemini/agy 자동 중계는 비활성화했습니다.** 호스트 실행의 격리가 보장되지 않아 요청을 거부합니다. `packet-review --provider glm` 또는 `--provider qwen`을 사용하세요.

## 어렵게 배운 것

자세한 내용은 테스트와 [ARCHITECTURE.md](../ARCHITECTURE.md)(영어)에 있습니다.

- `sandbox-exec` 는 중첩되지 않습니다. 자체 샌드박스를 쓰는 도구(SwiftPM, 리뷰 도우미)는 안에서 그것을 끄거나 감독자가 대신 실행합니다.
- Seatbelt 우선순위: `denyWrite` 가 `allowWrite` 를 이기고, 구체 op 를 명시한 규칙이 `file-write*` 와일드카드를 이기며, regex 에 negative lookahead 가 없고, `/tmp` 는 심링크라 실경로로 테스트해야 합니다.
- 기본 거부 프로파일에서 `deny` 줄을 지우는 것은 `allow` 가 아닙니다. Go·Dart 는 macOS 신뢰 평가기를 쓰므로 `com.apple.trustd.agent` 를 명시적으로 허용해야 TLS 가 끝납니다.
- **FSEvents 는 샙니다.** `com.apple.FSEvents` 를 허용한 샌드박스 클라이언트는 읽을 수 없는 경로의 파일 이름 변경 이벤트까지 받습니다. 계속 거부합니다. libuv 는 실패한 스트림을 `EMFILE` 로 보고하는데 서술자 한도와 무관하며, 디렉터리를 감시하는 Node 에이전트에는 조용한 감시자를 돌려주는 프리로드와 stat 폴링을 줍니다.
- 상속된 stdio 서술자가 샌드박스가 `fstat` 할 수 없는 파일을 가리키면 Node 가 기동 시 abort 합니다. 테스트 러너가 stderr 를 샌드박스 밖 로그로 보내면 나고, TTY 나 파이프면 나지 않습니다.
- 에이전트는 보이지 않는 것의 원인을 지어냅니다("툴체인이 고장", "gh 미설치"). 세션 시작 때 샌드박스가 무엇인지 알려 주자 그런 보고가 대부분 사라졌습니다.

## 저장소 구조

영어 README 의 "Repository layout" 절을 참조하세요. 런타임 상태는 `~/.local/share/agentbelt/state/` 에 있고 저장소에 포함되지 않습니다.

## 상태

2026년 9월 한 운영자의 일상 설정에서 추출해 다른 기기용으로 다듬었습니다: 개인 경로 없음, 어떤 에이전트 조합에서도 도는 `init`, 대상을 검증하는 설치기. 독립 Codex 리뷰의 지적을 반영했습니다. CI 는 GitHub macOS 러너에서 자립적인 커널 테스트만 돌리고, 에이전트 바이너리가 필요한 테스트는 운영 기기에서 `agentbelt verify-updates` 로 돕니다.

[`@anthropic-ai/sandbox-runtime`](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) 0.0.75(Apache-2.0)에 의존하며 `runtime/package-lock.json` 으로 고정됩니다.

## 라이선스

MIT. `vendor/riskgate` 도 MIT.
