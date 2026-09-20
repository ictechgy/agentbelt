"""Trusted terminal boundary for confined commands; never logs terminal contents."""
import codecs
import errno
import fcntl
import json
import os
import select
import signal
import subprocess
import termios
import threading
import time
import tty


class TerminalError(RuntimeError):
    pass


CANCELLED_STATUS = 130


class TerminalFilter:
    """Preserve text/CSI and reviewed OSCs; discard clipboard and passthrough strings.

    Decode incrementally so UTF-8 continuation bytes are not mistaken for C1
    controls. surrogateescape also recognizes literal 8-bit terminal controls.
    Incomplete/oversized strings stay closed until a real terminator arrives.
    """
    OSC_ALLOWED = frozenset({'0', '1', '2', '7', '8', '10', '11', '12', '133'})
    MAX_STRING = 16384

    def __init__(self, escape_c1=False):
        self.decoder = codecs.getincrementaldecoder('utf-8')('surrogateescape')
        self.escape_c1 = escape_c1
        self.state = 'text'
        self.prefix = ''
        self.payload = ''
        self.dropped = False

    @staticmethod
    def control(char):
        value = ord(char)
        return value - 0xdc00 if 0xdc80 <= value <= 0xdcff else value

    def feed(self, data, final=False):
        output = []
        for char in self.decoder.decode(data, final=final):
            value = self.control(char)
            if self.state == 'text' and self.escape_c1 and 0x80 <= value <= 0x9f:
                # JSON encoders may emit literal C1 Unicode characters. Escaping
                # them keeps structured pipe output valid without giving a
                # downstream terminal an 8-bit control introducer.
                output.append('\\u%04x' % value)
                continue
            if self.state in {'osc', 'osc_escape', 'string', 'string_escape'}:
                osc = self.state.startswith('osc')
                escaped = self.state.endswith('_escape')
                if value in {0x18, 0x1a}:
                    self.state, self.payload = 'text', ''
                    continue
                if value == 0x9c or (osc and value == 7) or (escaped and char == '\\'):
                    if osc and not self.dropped and self.payload.split(';', 1)[0] in self.OSC_ALLOWED:
                        terminator = '\x1b\\' if escaped and char == '\\' else char
                        output.append(self.prefix + self.payload + terminator)
                    self.state, self.payload = 'text', ''
                    continue
                if escaped:
                    # An embedded escape could cancel an allowed OSC and start
                    # another operation in a terminal. Never forward that string.
                    self.dropped = True
                if value == 27:
                    self.state = 'osc_escape' if osc else 'string_escape'
                    continue
                self.state = 'osc' if osc else 'string'
                if value < 32 or 0x7f <= value <= 0x9f:
                    self.dropped = True
                if osc and not self.dropped:
                    if len(self.payload) >= self.MAX_STRING:
                        self.payload, self.dropped = '', True
                    else:
                        self.payload += char
                continue
            if self.state == 'escape':
                if value in {0x18, 0x1a}:
                    self.state = 'text'
                    continue
                if value < 32:
                    # C0 characters do not finish an escape in terminal parsers.
                    continue
                self.state = 'text'
                if char == ']':
                    self.state, self.prefix, self.payload, self.dropped = 'osc', '\x1b]', '', False
                elif char in 'PX^_':
                    self.state = 'string'
                elif char in '[=>78DEHMNOc':
                    output.append('\x1b' + char)
                elif 0x20 <= value <= 0x2f:
                    self.state, self.prefix = 'escape_intermediate', '\x1b' + char
                # Unknown escape forms are discarded, never emitted partially.
                continue
            if self.state == 'escape_intermediate':
                if value == 27:
                    self.state = 'escape'
                elif value in {0x18, 0x1a}:
                    self.state = 'text'
                elif value < 32:
                    continue
                elif 0x20 <= value <= 0x2f and len(self.prefix) < 16:
                    self.prefix += char
                else:
                    # Do not forward encoding/C1-mode switches (ESC % / space).
                    # The UTF-8 parser must remain in sync with the terminal.
                    if self.prefix in {'\x1b(', '\x1b)'} and char in {'B', '0'}:
                        output.append(self.prefix + char)
                    self.state = 'text'
                continue
            if value == 27:
                self.state = 'escape'
            elif value == 0x9d:
                self.state, self.prefix, self.payload, self.dropped = 'osc', char, '', False
            elif value in {0x90, 0x98, 0x9e, 0x9f}:
                self.state = 'string'
            elif value != 0x9c:
                output.append(char)
        if final:
            self.state, self.payload = 'text', ''
        return ''.join(output).encode('utf-8', 'surrogateescape')


def _descriptor(value, default, stdout):
    if value is None:
        return default
    if value == subprocess.STDOUT:
        return _descriptor(stdout, 1, None)
    if isinstance(value, int):
        return value if value >= 0 else None
    return value.fileno()


def _stop(process, drain=None):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 2
    while process.poll() is None and time.monotonic() < deadline:
        if drain is None:
            time.sleep(.02)
        else:
            try:
                drain()
            except OSError:
                time.sleep(.02)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    # Deliver the client's final cleanup output through the same filter.
    if drain is not None:
        for _ in range(5):
            try:
                if not drain():
                    break
            except OSError:
                break


def _pump_output(sources, ready, writable):
    for item in sources:
        if item['fd'] in ready:
            try:
                data = os.read(item['fd'], 16384)
            except OSError as error:
                if error.errno not in {errno.EIO, errno.EAGAIN}:
                    raise
                data = b'' if error.errno == errno.EIO else None
            if data == b'':
                item['open'] = False
                item['pending'].extend(item['filter'].feed(b'', final=True))
            elif data:
                item['pending'].extend(item['filter'].feed(data))
        if item['destination'] in writable and item['pending']:
            try:
                count = os.write(item['destination'], item['pending'][:select.PIPE_BUF])
                del item['pending'][:count]
            except BlockingIOError:
                pass


def _drain_output(sources):
    readers = [item['fd'] for item in sources if item['open'] and len(item['pending']) < 65536]
    writers = [item['destination'] for item in sources if item['pending']]
    if not readers and not writers:
        return False
    ready, writable, _ = select.select(readers, writers, [], .05)
    _pump_output(sources, ready, writable)
    return True


def _signals(process, resize=None, cancelled=None):
    previous = {}
    if threading.current_thread() is not threading.main_thread():
        return previous
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH):
        previous[number] = signal.getsignal(number)
        if number == signal.SIGWINCH:
            handler = lambda signum, frame: resize() if resize else None
        else:
            def handler(signum, frame):
                if cancelled is not None and signum in {signal.SIGTERM, signal.SIGHUP}:
                    cancelled['signal'] = signum
                try:
                    os.killpg(process.pid, signum)
                except ProcessLookupError:
                    pass
        signal.signal(number, handler)
    return previous


def run(command, *, timeout=None, cancel_event=None, **options):
    """Relay all externally delivered text output, including pipes and files.

    Every terminal fd is replaced with a private PTY. Other output channels use
    separate pipes so a downstream `cat` cannot bypass the terminal filter.
    """
    if cancel_event is not None and cancel_event.is_set():
        return CANCELLED_STATUS
    import stat
    from pathlib import Path
    descriptors = [_descriptor(options.get(name), fd, options.get('stdout'))
                   for fd, name in enumerate(('stdin', 'stdout', 'stderr'))]
    terminals = {fd: source for fd, source in enumerate(descriptors)
                 if source is not None and os.isatty(source)}
    devices = {os.fstat(source).st_rdev for source in terminals.values()}
    if len(devices) > 1:
        raise TerminalError('Confined commands require one shared terminal device.')
    env = dict(options.get('env') or os.environ)
    options = dict(options, env=env, close_fds=True)
    env['AGENTBELT_TTY_PATHS'] = '[]'
    master = slave = sink = real = None
    process = original = None
    previous = {}
    sources = []
    try:
        if terminals:
            real = terminals.get(0, next(iter(terminals.values())))
            sink_source = terminals.get(1, terminals.get(2, real))
            master, slave = os.openpty()
            attributes = termios.tcgetattr(real)
            slave_attributes = list(attributes)
            if 0 not in terminals:
                slave_attributes[1] &= ~termios.OPOST
            termios.tcsetattr(slave, termios.TCSANOW, slave_attributes)
            env['AGENTBELT_TTY_PATHS'] = json.dumps([os.ttyname(slave)])
            for fd in terminals:
                options[('stdin', 'stdout', 'stderr')[fd]] = slave
            sink = os.open(os.ttyname(sink_source), os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
            if os.fstat(sink).st_rdev != os.fstat(sink_source).st_rdev:
                raise TerminalError('The output terminal changed before launch.')
            if 0 in terminals:
                original = attributes
                tty.setraw(real, termios.TCSANOW)

        def resize():
            if master is None:
                return
            try:
                size = fcntl.ioctl(real, termios.TIOCGWINSZ, b'\0' * 8)
                fcntl.ioctl(master, termios.TIOCSWINSZ, size)
            except OSError:
                pass
        resize()
        for fd, name in ((1, 'stdout'), (2, 'stderr')):
            if fd not in terminals:
                options[name] = subprocess.PIPE if descriptors[fd] is not None else subprocess.DEVNULL
        # Preserve a single combined pipe when the caller used 2>&1. Regular
        # files with independently opened offsets stay independent.
        combined = options.get('stderr') == subprocess.PIPE and options.get('stdout') == subprocess.PIPE
        if combined:
            a, b = (os.fstat(descriptors[fd]) for fd in (1, 2))
            combined = (descriptors[1] == descriptors[2] or
                        (stat.S_ISFIFO(a.st_mode) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)))
        if combined:
            options['stderr'] = subprocess.STDOUT
        controlling_fd = next(iter(terminals), -1)
        # No Python preexec_fn runs after a multi-threaded parent forks. The
        # fresh single-threaded helper acquires the PTY before execing Node.
        invocation = ['/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                      '--child', str(controlling_fd), '--', *map(str, command)]
        process = subprocess.Popen(invocation, start_new_session=True, **options)
        if slave is not None:
            os.close(slave)
            slave = None
        cancelled = {}
        previous = _signals(process, resize, cancelled)
        def add_source(fd, destination):
            os.set_blocking(fd, False)
            sources.append({'fd': fd, 'destination': destination, 'filter': TerminalFilter(escape_c1=fd != master),
                            'pending': bytearray(), 'open': True})
        if master is not None:
            add_source(master, sink)
        if process.stdout is not None:
            add_source(process.stdout.fileno(), descriptors[1])
        if process.stderr is not None:
            add_source(process.stderr.fileno(), descriptors[2])
        incoming = bytearray()
        input_open = 0 in terminals
        user_suspend = False
        deadline = None if timeout is None else time.monotonic() + timeout
        exited_at = None
        while process.returncode is None or any(item['open'] or item['pending'] for item in sources):
            if cancel_event is not None and cancel_event.is_set():
                _stop(process, lambda: _drain_output(sources))
                return CANCELLED_STATUS
            if cancelled:
                _stop(process, lambda: _drain_output(sources))
                return 128 + cancelled['signal']
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise subprocess.TimeoutExpired(command, timeout)
            if process.poll() is None:
                done, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
                if done and os.WIFSTOPPED(status):
                    if user_suspend:
                        if original is not None:
                            termios.tcsetattr(real, termios.TCSANOW, original)
                        os.kill(os.getpid(), signal.SIGSTOP)
                        if original is not None:
                            tty.setraw(real, termios.TCSANOW)
                        resize()
                        user_suspend = False
                    os.killpg(process.pid, signal.SIGCONT)
                elif done:
                    process.returncode = os.waitstatus_to_exitcode(status)
            if process.returncode is not None:
                exited_at = exited_at or now
            master_open = master is not None and any(item['fd'] == master and item['open'] for item in sources)
            readers = [item['fd'] for item in sources if item['open'] and len(item['pending']) < 65536]
            if input_open and master_open and len(incoming) < 65536:
                readers.append(real)
            writers = [item['destination'] for item in sources if item['pending']]
            if incoming and master_open:
                writers.append(master)
            ready, writable, _ = select.select(readers, writers, [], .05)
            if input_open and real in ready:
                data = os.read(real, 4096)
                if data:
                    mode = termios.tcgetattr(master)
                    suspend = mode[6][termios.VSUSP]
                    if isinstance(suspend, int):
                        suspend = bytes([suspend])
                    if mode[3] & termios.ISIG and suspend != b'\0' and suspend in data:
                        user_suspend = True
                        data = data.replace(suspend, b'')
                        os.killpg(process.pid, signal.SIGSTOP)
                    incoming.extend(data)
                else:
                    input_open = False
            _pump_output(sources, ready, writable)
            if exited_at is not None and time.monotonic() - exited_at >= .25:
                for item in sources:
                    # A full pending buffer means destination backpressure kept
                    # us from reading the child's pipe. Preserve those bytes and
                    # resume reading as the destination drains. Once capacity is
                    # available, a source that stays unreadable belongs only to
                    # an orphan descendant and may be closed after the grace.
                    if (item['open'] and item['fd'] in readers and item['fd'] not in ready
                            and len(item['pending']) < 65536):
                        item['pending'].extend(item['filter'].feed(b'', final=True))
                        item['open'] = False
            if master in writable and incoming:
                try:
                    count = os.write(master, incoming[:16384])
                    del incoming[:count]
                except BlockingIOError:
                    pass
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    incoming.clear()
        return process.returncode
    except BaseException:
        if process is not None:
            _stop(process, lambda: _drain_output(sources))
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        try:
            if original is not None:
                termios.tcsetattr(real, termios.TCSANOW, original)
        finally:
            for fd in (slave, master, sink):
                if fd is not None:
                    os.close(fd)
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()


def _child_main():
    import sys
    try:
        if len(sys.argv) < 5 or sys.argv[1] != '--child' or sys.argv[3] != '--':
            raise TerminalError('Invalid terminal child invocation.')
        descriptor = int(sys.argv[2])
        if descriptor not in {-1, 0, 1, 2} or os.getsid(0) != os.getpid():
            raise TerminalError('Terminal child does not own its session.')
        if descriptor >= 0:
            if not os.isatty(descriptor):
                raise TerminalError('Private terminal descriptor is unavailable.')
            fcntl.ioctl(descriptor, termios.TIOCSCTTY, 0)
        os.execvpe(sys.argv[4], sys.argv[4:], os.environ)
    except (OSError, ValueError, TerminalError):
        os.write(2, b'agentbelt: private terminal setup failed; no fallback.\n')
        return 125


if __name__ == '__main__':
    raise SystemExit(_child_main())
