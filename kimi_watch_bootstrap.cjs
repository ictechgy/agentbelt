// Kimi Code 전용 NODE_OPTIONS 프리로드. 격리 안에서 디렉터리 감시가 프로세스를 죽이는 것을 막는다.
//
// 왜 필요한가. libuv 는 macOS 에서 디렉터리 fs.watch 를 전부 FSEvents 로 구현하고, FSEvents 는
// mach 서비스 `com.apple.FSEvents` 를 요구한다. Seatbelt 가 이를 거부하면 스트림 시작이 실패하며
// libuv 는 그 실패를 비동기 EMFILE 로 보고한다(파일 서술자 고갈이 아니다). Kimi 가 쓰는 chokidar 의
// 내부 FSWatcher 에는 error 리스너가 없어 그 EMFILE 이 처리되지 않은 'error' 이벤트로 프로세스를 죽인다.
//
// 왜 FSEvents 를 허용하지 않는가. 실측(2026-09-16)으로 샌드박스 클라이언트가 FSEvents 를 쓰면 읽기 거부된
// 경로(Chrome 캐시, 다른 앱 임시 파일 등)의 파일 이름 변경 이벤트까지 받는다. fseventsd 는 클라이언트의
// 샌드박스 경계로 걸러 주지 않으므로 사용자 활동의 메타데이터가 샌다. 대신 chokidar 는 stat 폴링
// (`CHOKIDAR_USEPOLLING=1`, 감독자가 설정)으로 실제 변경을 감지하고, 여기서는 디렉터리 fs.watch 만
// 조용한 감시자로 바꾼다. 파일 단위 fs.watch 는 kqueue 라 샌드박스에서도 동작하므로 원본을 그대로 쓴다.
//
// 범위. NODE_OPTIONS 는 감독자 node 와 에이전트가 띄우는 다른 node 도구에도 상속된다. 그쪽 감시를 조용히
// 무력화하면 오진을 낳으므로(리뷰 MEDIUM), `process.execPath` 가 감독자가 넘긴 Kimi 복제본 경로
// (`AGENT_GUARD_KIMI_BINARY`)와 같을 때만 바꾼다. 다른 프로세스에서는 아무것도 하지 않는다.
// 여기에 부수 효과(파일·네트워크·출력)를 넣지 말 것.
'use strict';
const fs = require('node:fs');
const { EventEmitter } = require('node:events');

if (process.env.AGENT_GUARD_KIMI_BINARY && process.execPath === process.env.AGENT_GUARD_KIMI_BINARY) {
  const originalWatch = fs.watch;

  /** 이벤트를 내지 않는 감시자. close 는 한 번만 'close' 를 내고, AbortSignal 은 close 로 이어진다. */
  class InertWatcher extends EventEmitter {
    constructor(signal) {
      super();
      this.closed = false;
      if (signal && typeof signal.addEventListener === 'function') {
        if (signal.aborted) {
          queueMicrotask(() => this.close());
        } else {
          signal.addEventListener('abort', () => this.close(), { once: true });
        }
      }
    }
    close() {
      if (this.closed) return;
      this.closed = true;
      this.emit('close');
    }
    ref() { return this; }
    unref() { return this; }
  }

  /** 감시 대상이 디렉터리인지. 확인할 수 없으면 원본 fs.watch 에 맡긴다(그쪽이 오류를 낸다). */
  function isDirectory(target) {
    try {
      return fs.statSync(target).isDirectory();
    } catch {
      return false;
    }
  }

  fs.watch = function watchWithoutFSEvents(target, options, listener) {
    if (isDirectory(target)) {
      return new InertWatcher(options && typeof options === 'object' ? options.signal : undefined);
    }
    return originalWatch.apply(this, arguments);
  };
}
