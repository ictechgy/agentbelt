// NODE_OPTIONS preload for Kimi Code only. Stops directory watching from killing the process inside the confinement.
//
// Why it is needed. On macOS libuv implements every directory fs.watch with FSEvents, and FSEvents requires
// the mach service `com.apple.FSEvents`. When Seatbelt denies it, starting the stream fails and libuv reports
// that failure as an asynchronous EMFILE (it is not file descriptor exhaustion). The internal FSWatcher of the
// chokidar that Kimi uses has no error listener, so that EMFILE kills the process as an unhandled 'error' event.
//
// Why FSEvents is not allowed. Measured (2026-09-16): when a sandboxed client uses FSEvents it also receives file
// name change events for read-denied paths (the Chrome cache, temporary files of other apps, and so on). fseventsd
// does not filter by the sandbox boundary of the client, so metadata about user activity leaks. Instead chokidar
// detects the real changes through stat polling (`CHOKIDAR_USEPOLLING=1`, set by the supervisor), and here only the
// directory fs.watch is turned into an inert watcher. Per-file fs.watch uses kqueue and works in the sandbox, so the
// original is kept for it.
//
// Scope. NODE_OPTIONS is also inherited by the supervisor node and by other node tools the agent launches. Quietly
// disabling their watching would cause misdiagnoses (review MEDIUM), so it is replaced only when `process.execPath`
// equals the Kimi copy path handed over by the supervisor (`AGENT_GUARD_KIMI_BINARY`). In any other process it does
// nothing. Do not add side effects (file, network, output) here.
'use strict';
const fs = require('node:fs');
const { EventEmitter } = require('node:events');

if (process.env.AGENT_GUARD_KIMI_BINARY && process.execPath === process.env.AGENT_GUARD_KIMI_BINARY) {
  const originalWatch = fs.watch;

  /** A watcher that emits no events. close emits 'close' only once, and an AbortSignal leads to close. */
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

  /** Whether the watch target is a directory. When it cannot be determined, leave it to the original fs.watch (that one raises the error). */
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
