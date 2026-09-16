# 에이전트 게이트 설계

작성: 2026-09-07 · 상태: **개정 필요 — 구현 보류**

> Codex 보안 리뷰에서 핵심 주장이 방어 불가로 판정됐다(HIGH 11, MEDIUM 3). 가장 결정적인 것은 설치 승인이다. 본 문서가 "게이트는 경계를 넘을지 판단하지 않는다"고 선언해 놓고, 처음 보는 패키지 설치를 LLM이 승인하게 두었다. 그 승인은 세션이 갖지 못한 네트워크 권한을 행사시키므로 선언한 원칙과 정면으로 모순된다. 리뷰 전문은 `../reviews/2026-09-07-agent-gate-codex-review.md`. 이 문서의 설계를 그대로 구현하지 말 것.

## 문제

safecode와 Zcode Safe의 OS 제약이 실사용을 방해한다. 두 가지가 구체적으로 걸린다.

1. **다운로드 불가.** `state/development.json`의 `packageDomains`가 비어 있어 `npm install`, `pip install`, 저장소 clone이 전부 실패한다.
2. **승인 프롬프트 과다.** riskgate 정책이 `defaults: prompt`라 명시 규칙에 걸리지 않는 멀쩡한 명령까지 매번 사용자에게 묻는다.

두 문제는 성격이 다르다. 다운로드는 **경계** 문제라 판단으로 풀리지 않는다. LLM이 허용해도 커널이 막는다. 프롬프트 과다는 **판단** 문제이므로 게이트가 직접 해결한다.

## 목표와 비목표

**목표**

- 회색지대 명령의 사용자 확인 횟수를 줄인다.
- 세션 샌드박스의 네트워크를 열지 않고 패키지 설치를 가능하게 한다.
- 반복되는 판단을 결정론적 규칙으로 승격시켜 시간이 갈수록 LLM 의존을 줄인다.

**비목표**

- OS 경계를 LLM 판단으로 대체하지 않는다.
- 게이트가 꺼졌을 때의 동작을 바꾸지 않는다. 옵트인이며 끄면 현재 동작 그대로다.
- 프로젝트 밖 파일 접근 완화는 이번 범위가 아니다.

## 보안 모델

게이트가 심사하는 대상은 신뢰할 수 없는 텍스트(웹 문서, 저장소 파일, 의존성 코드)를 읽는 LLM 에이전트다. 그 에이전트가 게이트가 읽는 근거를 만들 수 있으면 프롬프트 인젝션으로 판단이 뒤집힌다. 커널 경계는 문장에 속지 않지만 LLM은 속는다.

따라서 이 설계의 중심 원리는 하나다.

> **게이트는 경계 안의 소음을 줄일 뿐, 경계를 넘을지 판단하지 않는다.**

### 불변식

1. riskgate는 현재 위치(샌드박스 안 `zcode_hook.py` 경로)에 그대로 둔다. 이 판정이 `deny`와 `dangerous`의 최종 방어선이며, 게이트 서비스는 이를 대체하지 않는다. 서비스도 riskgate를 한 번 더 돌리지만(불변식 5) 그것은 downgrade 요청을 검증하기 위한 독립 확인이지 클라이언트 판정을 대신하는 것이 아니다.
2. `deny`는 `deny`로 남는다. 게이트가 뒤집을 수 없다.
3. `dangerous` 판정은 무조건 사용자에게 간다. 이 경로에서 **LLM을 호출하지 않는다**.
4. `safe` 판정은 그대로 `allow`다. 이 경로에서도 LLM을 호출하지 않는다.
5. 게이트 서비스는 클라이언트가 보낸 판정을 믿지 않는다. **riskgate를 호스트에서 독립적으로 다시 실행**하고, 호스트 판정이 회색지대가 아니면 downgrade를 거부한다.
6. LLM이 보는 입력은 도구명, 명령 문자열, 워크스페이스 상대 cwd, riskgate 판정, 매칭된 규칙 ID뿐이다. 에이전트의 자연어 설명, 파일 내용, 대화 내역은 넘기지 않는다.
7. LLM 출력은 `{"decision": "allow"|"ask", "reason": string}`으로 고정한다. 형식 위반, 파싱 실패, 타임아웃, 모델 오류는 전부 `ask`다.
8. 규칙 승격은 정책 파일을 자동으로 쓰지 않는다. 후보를 제시하고 사용자가 승인해야 반영된다.

### 실패 시 동작

모든 실패는 fail-closed다. 게이트 서비스에 도달하지 못하면 클라이언트는 로컬 riskgate 판정을 그대로 쓴다. 즉 **서비스가 죽으면 현재 동작과 완전히 동일**하다. 게이트는 기능을 더할 뿐 기존 방어를 대체하지 않는다.

## 아키텍처

샌드박스 안의 클라이언트는 판단하지 않는다. 물어보고 받은 답을 쓴다. 판단, 캐시, LLM 호출, 감사 로그는 감독자 쪽에 한 벌만 둔다.

```
[샌드박스]                        [감독자]
 zcode_hook.py ─┐
                ├─→ 브로커 포트 1개 ─→ supervisor_service
 permission.ask ┘                        ├ gate_policy: riskgate 재평가 + 세션 캐시
 (OpenCode 플러그인)                      ├ gate_judge: 도구 없는 LLM (자체 샌드박스)
                                          └ 결정 로그 + 규칙 승격 후보
```

기존 `orca_broker.py`가 이미 이 형태다. 포트를 새로 열지 않고 경로만 추가한다. Seatbelt의 아웃바운드 허용 규칙은 한 줄 그대로 유지된다.

### 구성요소

| 파일 | 역할 | 실행 위치 |
| --- | --- | --- |
| `supervisor_service.py` | `orca_broker.py`를 라우터로 확장. `/hook/opencode`, `/gate/decide`, `/gate/install` | 감독자 |
| `gate_policy.py` | riskgate 재평가, 회색지대 분류, 세션 캐시, 결정 로그 | 감독자 |
| `gate_judge.py` | 도구 없는 단발 LLM 호출. Claude 주, Codex 폴백 | 감독자가 띄우는 별도 샌드박스 |
| `plugin/guard-permission-gate.js` | OpenCode `permission.ask`와 `tool.execute.before` 훅 | 샌드박스 안 |
| `zcode_hook.py` (수정) | 회색지대일 때만 브로커에 질의 | 샌드박스 안 |
| `agent_guard.py` (수정) | 서비스 기동, 브로커 포트 전달, 플러그인 시딩 | 감독자 |

`orca_broker.StatusBroker`는 경로별 핸들러를 받는 `SupervisorService`로 리팩터한다. 기존 Orca 상태 중계는 `/hook/opencode` 핸들러로 그대로 옮기고 동작과 회귀 테스트를 유지한다.

### 연결점

두 에이전트 모두 결정 지점이 존재하며 실물로 확인했다.

- **Zcode**: `zcode_hook.py`의 PreToolUse 훅이 `allow`/`ask`/`deny`를 반환한다.
- **OpenCode**: 플러그인 API에 `"permission.ask"?: (input: Permission, output: { status: "ask" | "deny" | "allow" }) => Promise<void>`가 있다. 플러그인이 permission 결정을 직접 쓴다.

플러그인은 감독자가 Seatbelt 진입 전에 보호 config 디렉터리의 `plugin/`에 심는다. 디렉터리는 읽기 전용이라 자식이 플러그인을 추가하거나 교체할 수 없다. 이 시딩 경로는 Orca 연동에서 이미 구현·검증됐다(`run_confined`의 `opencode_plugins`).

## 결정 흐름

```
클라이언트: 로컬 riskgate 판정
  ├ deny      → deny        (질의 없음)
  ├ dangerous → ask         (질의 없음)
  ├ safe      → allow       (질의 없음)
  └ 회색지대  → 브로커에 질의
                 └ 서비스: riskgate 호스트 재평가
                      ├ 호스트 판정 deny  → deny
                      ├ 그 외 회색 아님   → downgrade 거부 → ask
                      └ 회색 확인 → 세션 캐시 hit? → 캐시값
                                     miss → gate_judge → allow | ask
```

클라이언트가 판정을 위조해 `dangerous` 명령을 회색이라고 주장해도, 서비스의 독립 재평가가 이를 걸러낸다. 호스트 재평가가 `deny`면 서비스는 `deny`를 반환한다. 클라이언트의 위조가 판정을 약화시키는 방향으로 작동하지 않는다.

### 캐시

키는 `(도구명, 정규화된 명령 서명, 워크스페이스 상대 cwd)`다. 정규화는 연속 공백 축약과 앞뒤 공백 제거까지만 한다. 인자 값을 지우는 등의 공격적 정규화는 서로 다른 위험도의 명령을 같은 키로 묶을 수 있으므로 하지 않는다.

캐시는 세션 범위이며 서비스 프로세스와 함께 사라진다. 디스크에 남기지 않는다.

### 규칙 승격

서비스는 회색지대에서 `allow`로 내린 결정을 `state/gate-decisions.jsonl`에 기록한다. 명령 텍스트는 남기되 파일 내용이나 인자 값 중 비밀로 보이는 것은 남기지 않는다.

`agent-guard gate-review`는 반복 승인된 서명을 횟수와 함께 보여주고 riskgate 규칙 초안을 제시한다. 사용자가 승인한 항목만 `~/.config/riskgate/riskgate.yaml`에 추가된다. 서비스는 정책 파일에 절대 쓰지 않는다.

## 설치 경로

핵심은 **명령 단위 임시 네트워크**다. 세션 샌드박스의 네트워크는 계속 비어 있고, 승인된 설치만 별도 일회용 샌드박스에서 실행한다.

### 결정론적 방어선

LLM보다 앞에 둔다.

- 패키지 매니저는 `npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`만 허용한다.
- 패키지명은 안전 문자셋만 허용하고, 설치 대상 경로는 워크스페이스로 고정한다.
- **기본값은 `--ignore-scripts`다.** postinstall 스크립트가 필요한 설치는 `dangerous`로 분류해 무조건 사용자에게 묻는다.
- lockfile에 이미 있는 패키지는 `allow`다. LLM을 호출하지 않는다.

LLM은 처음 보는 패키지명 같은 회색지대만 판단한다. 타이포스쿼팅 의심이 이 자리에 해당한다.

### 실행

승인된 설치는 감독자가 `run_confined(ephemeral=True, domains=<검토된 패키지 도메인>)`으로 실행한다. 쓰기는 워크스페이스로 제한된다. 설치 프로세스 자체가 격리되므로 postinstall이 허용된 경우에도 호스트에서 실행되지 않는다.

검토된 패키지 도메인은 `agent_guard.development_options()`가 이미 상수로 갖고 있다. `registry.npmjs.org:443`, `pypi.org:443`, `files.pythonhosted.org:443`, `github.com:443`, `codeload.github.com:443`.

### 에이전트별 경로

- **Zcode**: 통로가 이미 있다. `zcode_hook.py`가 Bash를 `agent-guard zcode-shell`로 재작성하고, 그 경로가 `run_confined(ephemeral=True, domains=development['packageDomains'])`로 실행한다. 현재 그 목록은 비어 있으므로 `zcode-shell`에 승인 토큰 인자를 추가한다. 게이트가 설치를 승인하면 감독자가 해당 명령 서명에 대해 일회용 토큰을 발급하고, `zcode-shell`은 토큰이 유효할 때만 그 실행에 한해 검토된 패키지 도메인을 적용한다. 토큰은 한 번 쓰면 소멸하며 `development.json`은 비어 있는 채로 둔다.
- **OpenCode**: `permission.ask`는 상태만 반환하므로 재작성이 불가능하다. 대신 `"tool.execute.before"` 훅을 쓴다. 이 훅은 `output.args`를 수정할 수 있다. 설치 패턴을 감지해 `/gate/install`에 위임하고, 감독자가 완료하면 args의 명령을 감독자가 돌려준 종료 코드와 요약을 그대로 출력하는 `printf` 한 줄로 교체한다. 교체된 명령은 네트워크도 쓰기도 하지 않는다. 설치 산출물은 워크스페이스에 떨어지므로 세션 샌드박스에서 그대로 보인다.

## 인터페이스

### `POST /gate/decide`

요청.

```json
{"tool": "Bash", "command": "<원문>", "cwd": "<워크스페이스 상대 경로>", "clientVerdict": "prompt"}
```

응답.

```json
{"status": "allow" | "ask" | "deny", "source": "riskgate" | "cache" | "judge" | "refused"}
```

`reason`은 응답에 포함하지 않는다. 샌드박스가 게이트의 판단 근거를 읽을 수 있으면 그 자체가 인젝션 학습 신호가 된다. 근거는 감사 로그에만 남긴다.

### `POST /gate/install`

요청.

```json
{"manager": "npm", "packages": ["name"], "allowScripts": false, "cwd": "<워크스페이스 상대 경로>"}
```

응답.

```json
{"status": "installed" | "ask" | "refused", "exitCode": 0}
```

### 판정기 계약

`gate_judge`에 넘기는 입력은 다음 필드만 갖는다.

```json
{"tool": "Bash", "command": "<원문>", "cwd": "<상대 경로>",
 "riskgate": {"verdict": "prompt", "matchedRules": ["id", ...]}}
```

출력은 `{"decision": "allow"|"ask", "reason": "<한 문장>"}`이다. 다른 어떤 형태도 `ask`로 처리한다.

## 설정

게이트는 옵트인이다. `state/gate.json`이 없거나 `enabled`가 true가 아니면 서비스가 뜨지 않고 클라이언트는 로컬 판정만 쓴다.

```json
{
  "enabled": true,
  "judge": {"primary": "claude", "fallback": "codex", "timeoutSeconds": 5},
  "install": {"enabled": true, "allowScriptsRequiresApproval": true}
}
```

Orca 연동(`state/orca-integration.json`)과 동일한 패턴이라 끄고 켜기가 일관된다.

## 성능

- `deny`, `dangerous`, `safe` 경로는 LLM을 호출하지 않는다. 현재와 동일한 지연이다.
- 회색지대 첫 호출만 LLM 왕복이 든다. 타임아웃은 5초이며 초과하면 `ask`다.
- 캐시 히트는 로컬 HTTP 왕복 수준이다.
- 반복되는 빌드·테스트 명령은 첫 판정 후 캐시되고, 승격 후에는 결정론적 경로로 빠진다.

## 테스트

기존 스위트의 원칙대로 **외부 모델 API를 호출하지 않는다.** 가짜 판정기를 주입해 검증한다.

불변식별 회귀.

- `dangerous` 명령에서 판정기가 한 번도 호출되지 않음을 단언한다.
- `deny`는 게이트를 거쳐도 `deny`로 남는다.
- 클라이언트가 `clientVerdict`를 위조해도 호스트 재평가가 downgrade를 거부한다.
- 판정기 출력 형식 위반, 타임아웃, 서비스 도달 불가는 전부 `ask`로 떨어진다.
- 서비스가 없을 때 클라이언트 동작이 현재 동작과 동일하다.
- 판정기 입력에 구조화 필드만 들어가고 에이전트 프로즈가 들어가지 않는다.
- 인젝션 문자열이 섞인 회색 명령에서도 `dangerous` 경계가 유지된다.
- 같은 서명은 한 번만 판정되고 이후 캐시에서 나온다.
- `gate-review`는 후보를 제시할 뿐 정책 파일을 수정하지 않는다.

설치 경로.

- 기본 실행에 `--ignore-scripts`가 붙는다.
- 스크립트를 요구하는 설치는 사용자 승인 경로로 간다.
- 설치는 일회용 샌드박스에서 실행되고, 같은 시점 세션 샌드박스의 `allowedDomains`는 여전히 패키지 도메인을 포함하지 않는다.
- 허용되지 않은 매니저나 문자셋 위반 패키지명은 거부된다.

## 구현 단계

한 번에 전부 만들기에는 크다. 각 단계는 독립적으로 쓸모가 있고, 앞 단계가 실패하면 뒤를 만들 이유가 없다.

1. **판정기 인증 스파이크.** 아래 미해결 항목의 첫 번째를 먼저 해결한다. 여기서 막히면 게이트 전체가 성립하지 않으므로 다른 코드를 쓰기 전에 확인한다.
2. **`/gate/decide` + Zcode 클라이언트.** `orca_broker.py`를 `SupervisorService`로 리팩터하고 회색지대 downgrade를 붙인다. 이 단계만으로 Zcode의 프롬프트 피로가 줄어든다.
3. **OpenCode `permission.ask` 클라이언트.** 같은 서비스에 safecode를 연결한다.
4. **설치 경로.** `tool.execute.before` 프로브를 먼저 하고, `zcode-shell` 승인 토큰과 `/gate/install`을 만든다.
5. **`gate-review` 규칙 승격.**

각 단계는 자체 회귀 테스트를 갖고 끝난다.

## 미해결 항목

**판정기의 인증 경로.** Claude Code CLI와 Codex는 자격증명을 Keychain 또는 홈 디렉터리에 둔다. 가드는 Keychain 접근과 홈 읽기를 차단하므로, 판정기를 `run_confined`로 감쌌을 때 인증이 통과하는지 확인되지 않았다. 구현 첫 단계에서 이것부터 검증한다. 통과하지 못하면 선택지는 두 가지다.

1. 판정기 샌드박스에 해당 자격증명 경로만 읽기 허용한다. 판정기는 도구가 없고 입력이 구조화돼 있으므로 노출 범위가 좁다.
2. 감독자가 키를 읽어 모델 API를 직접 호출한다. CLI를 거치지 않으므로 표면이 더 작지만 공급자별 호출 코드를 직접 들고 있어야 한다.

이 결정 전까지는 게이트를 켤 수 없다.

**판정기 샌드박스의 허용 도메인.** Claude는 Anthropic API, Codex는 OpenAI API를 쓴다. 두 도메인을 `state/gate.json`에 명시하고 검토된 목록으로 관리한다. 세션 샌드박스의 도메인 목록과 섞지 않는다.

**`tool.execute.before`의 실제 동작.** `output.args` 수정으로 명령을 교체할 수 있다는 것은 타입 시그니처로 확인했으나 실물로 검증하지 않았다. 설치 경로 구현 전에 프로브가 필요하다.

## 범위 밖

- 프로젝트 밖 파일 접근 완화
- 세션 샌드박스에 패키지 도메인을 상시 허용하는 방식
- 게이트의 판단 근거를 샌드박스에 노출하는 것
- riskgate 정책의 자동 수정
