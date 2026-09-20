"""Synthetic terminal data only: no live clipboard or user terminal is queried."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from terminal_proxy import TerminalFilter


class TerminalFilterTests(unittest.TestCase):
    def filtered(self, chunks):
        parser = TerminalFilter()
        return b''.join(parser.feed(chunk) for chunk in chunks) + parser.feed(b'', final=True)

    def test_clipboard_and_nested_passthrough_are_removed_at_every_split(self):
        cases = [b'\x1b]52;c;U1lOVEhFVElD\x07', b'\x1b]52;p;?\x1b\\',
                 b'\x9d52;c;U1lOVEhFVElD\x9c', '\x9d52;c;test\x9c'.encode(),
                 b'\x1bPtmux;\x1b\x1b]52;c;U1lOVEhFVElD\x07\x1b\\',
                 b'\x1b]8;;safe\x1b]52;c;bad\x07', b'\x1b\x00]52;c;bad\x07',
                 b'\x1b]00052;c;bad\x07', b'\x1b_opaque\x1b\\']
        for sequence in cases:
            data = b'left' + sequence + b'right'
            for split in range(len(data) + 1):
                with self.subTest(sequence=repr(sequence), split=split):
                    self.assertEqual(self.filtered([data[:split], data[split:]]), b'leftright')

    def test_utf8_styles_color_queries_links_and_charset_survive_fragmentation(self):
        data = ('한글 🙂 झ 日本語 é\n\x1b[31mcolor\x1b[0m\x1b(B'
                '\x1b]11;?\x07\x1b]8;;https://example.invalid\x1b\\link\x1b]8;;\x1b\\').encode()
        self.assertEqual(self.filtered([bytes([value]) for value in data]), data)

    def test_oversized_and_unterminated_controls_fail_closed(self):
        parser = TerminalFilter()
        self.assertEqual(parser.feed(b'\x1b]8;;' + b'x' * 50000), b'')
        self.assertLessEqual(len(parser.payload), TerminalFilter.MAX_STRING)
        self.assertEqual(parser.feed(b'\x07visible'), b'visible')
        self.assertEqual(self.filtered([b'left\x1b]52;c;unfinished']), b'left')
        self.assertEqual(self.filtered([b'left\x1b']), b'left')

    def test_control_cancel_recovers_without_forwarding_payload(self):
        self.assertEqual(self.filtered([b'\x1bPdiscard\x18text']), b'text')
        self.assertEqual(self.filtered([b'\x1b]52;c;discard\x1atext']), b'text')

    def test_encoding_switches_cannot_turn_utf8_continuations_into_controls(self):
        unicode_text = '\u049d52;c;harmless'.encode()
        self.assertEqual(self.filtered([b'\x1b%@' + unicode_text]), unicode_text)
        self.assertEqual(self.filtered([b'\x1b Gtext']), b'text')

    def test_structured_pipe_output_keeps_c1_content_as_json_escapes(self):
        value = {'text': '\x9d52;c;?\x9c', 'unicode': '한글'}
        encoded = json.dumps(value, ensure_ascii=False).encode()
        parser = TerminalFilter(escape_c1=True)
        safe = parser.feed(encoded) + parser.feed(b'', final=True)
        self.assertEqual(json.loads(safe), value)
        self.assertNotIn('\x9d'.encode(), safe)


class TerminalRelayTests(unittest.TestCase):
    def run_pty(self, driver, child='', action=None, simulate_clipboard=False):
        pid, master = pty.fork()
        if pid == 0:
            os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', '-c',
                     'import sys;sys.path.insert(0,sys.argv[1]);' + driver, str(ROOT), child])
        output = bytearray()
        status = None
        acted = False
        replied = False
        deadline = time.monotonic() + 12
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], .05)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output.extend(data)
                    if simulate_clipboard and not replied and b'\x1b]52;c;?\x07' in output:
                        os.write(master, b'\x1b]52;c;U1lOVEhFVElDX1JFUExZ\x07')
                        replied = True
                    if action and not acted and b'READY' in output:
                        action(master, pid)
                        acted = True
                done, value = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = value
                    # Drain bytes already queued when the relay exited.
                    while select.select([master], [], [], .05)[0]:
                        try:
                            data = os.read(master, 65536)
                        except OSError:
                            break
                        if not data:
                            break
                        output.extend(data)
                    break
            if status is None:
                # The PTY may report EOF just before the driver is reaped.
                grace = time.monotonic() + .5
                while time.monotonic() < grace:
                    done, value = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = value
                        break
                    time.sleep(.01)
                if status is None:
                    os.kill(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
        finally:
            os.close(master)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, repr(bytes(output)))
        return bytes(output)

    def test_all_terminal_descriptors_and_controlling_tty_are_filtered(self):
        child = """import os,json
sequence=b'\\x1b]52;c;U1lOVEhFVElD\\x07'
for fd in [0,1,2]:os.write(fd,sequence)
fd=os.open('/dev/tty',os.O_WRONLY);os.write(fd,sequence);os.close(fd)
print('SAFE='+json.dumps({'tty':all(os.isatty(fd) for fd in [0,1,2]),'private':os.ttyname(0) in os.environ['AGENTBELT_TTY_PATHS']}),flush=True)
"""
        # Darwin adds the kernel-managed PENDIN bit when returning to canonical
        # mode. Compare the actual configurable flags and all control characters.
        driver = "import terminal_proxy as t,termios,json;before=termios.tcgetattr(0);code=t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],timeout=5);after=termios.tcgetattr(0);before[3]&=~termios.PENDIN;after[3]&=~termios.PENDIN;print('RESTORED='+str(before==after),flush=True);sys.exit(code)"
        output = self.run_pty(driver, child)
        self.assertNotIn(b']52;', output)
        self.assertNotIn(b'U1lOVEhFVElD', output)
        self.assertIn(b'"tty": true', output)
        self.assertIn(b'"private": true', output)
        self.assertIn(b'RESTORED=True', output)

    def test_nonterminal_stdout_stays_separate_from_terminal_stderr(self):
        driver = "import terminal_proxy as t,tempfile;f=tempfile.TemporaryFile();code=t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],stdout=f,timeout=5);f.seek(0);print('FILE='+repr(f.read()),flush=True);sys.exit(code)"
        output = self.run_pty(driver, "import os;os.write(1,b'PIPE_ONLY\\x1b]52;c;bad\\x07');os.write(2,b'TERMINAL_ONLY\\n')")
        self.assertIn(b'TERMINAL_ONLY', output)
        self.assertIn(b"FILE=b'PIPE_ONLY'", output)
        self.assertEqual(output.count(b'PIPE_ONLY'), 1)

    def test_pipe_forwarder_cannot_restore_clipboard_query_or_write(self):
        child = "import os,tty,select;tty.setraw(0);print('READY',flush=True);os.write(1,b'\\x1b]52;c;?\\x07');os.write(2,b'\\x1b]52;c;bad\\x07');print('INPUT_EMPTY='+str(not select.select([0],[],[],.35)[0]),flush=True)"
        driver = """import terminal_proxy as t,subprocess,os
r,w=os.pipe()
forwarder=subprocess.Popen(['/bin/cat'],stdin=r)
os.close(r)
code=t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],stdout=w,stderr=w,timeout=5)
os.close(w);forwarder.wait(timeout=3);sys.exit(code)
"""
        output = self.run_pty(driver, child, simulate_clipboard=True)
        self.assertNotIn(b']52;', output)
        self.assertIn(b'INPUT_EMPTY=True', output)

    def test_interactive_launch_with_a_live_background_thread(self):
        driver = """import terminal_proxy as t,threading
stop=threading.Event();ready=threading.Event();lock=threading.Lock()
def worker():
 with lock:ready.set();stop.wait(6)
thread=threading.Thread(target=worker);thread.start();ready.wait()
try:code=t.run(['/usr/bin/printf','THREAD_OK'],timeout=3)
finally:stop.set();thread.join(3)
sys.exit(code)
"""
        self.assertIn(b'THREAD_OK', self.run_pty(driver))

    def test_redirected_stdio_detaches_the_inherited_controlling_terminal(self):
        child = "import os\ntry:os.open('/dev/tty',os.O_RDWR);print('OPEN')\nexcept OSError:print('DETACHED')"
        driver = "import terminal_proxy as t,tempfile,subprocess;f=tempfile.TemporaryFile();code=t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,timeout=5);f.seek(0);print(f.read().decode(),flush=True);sys.exit(code)"
        output = self.run_pty(driver, child)
        self.assertIn(b'DETACHED', output)
        self.assertNotIn(b'OPEN', output)

    def test_eof_and_input_are_delivered_by_the_private_terminal(self):
        child = "import sys;print('READY',flush=True);print('EOF='+str(sys.stdin.readline()==''),flush=True)"
        driver = "import terminal_proxy as t;sys.exit(t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],timeout=5))"
        self.assertIn(b'EOF=True', self.run_pty(driver, child, lambda fd, pid: os.write(fd, b'\x04')))

    def test_ctrl_c_and_resize_reach_the_child(self):
        child = "import signal,time,fcntl,termios,struct,sys\ndef done(s,f):print('INT',flush=True);sys.exit(0)\ndef size(s,f):print('SIZE='+str(struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))[:2]),flush=True)\nsignal.signal(signal.SIGINT,done);signal.signal(signal.SIGWINCH,size);print('READY',flush=True);time.sleep(5)"
        driver = "import terminal_proxy as t;sys.exit(t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],timeout=7))"
        def act(fd, pid):
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 41, 113, 0, 0))
            time.sleep(.2)
            os.write(fd, b'\x03')
        output = self.run_pty(driver, child, act)
        self.assertIn(b'SIZE=(41, 113)', output)
        self.assertIn(b'INT', output)

    def test_user_job_suspension_and_resume_preserve_control(self):
        child = "import signal,time,sys;signal.signal(signal.SIGINT,lambda s,f:sys.exit(0));signal.signal(signal.SIGCONT,lambda s,f:print('CONTINUED',flush=True));print('READY',flush=True);time.sleep(8)"
        driver = "import terminal_proxy as t;sys.exit(t.run(['/usr/bin/python3','-I','-c',sys.argv[2]],timeout=10))"
        def act(fd, pid):
            os.write(fd, b'\x1a')
            stopped = False
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                done, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
                if done:
                    stopped = os.WIFSTOPPED(status)
                    break
                time.sleep(.02)
            self.assertTrue(stopped)
            os.kill(pid, signal.SIGCONT)
            time.sleep(.2)
            os.write(fd, b'\x03')
        self.assertIn(b'CONTINUED', self.run_pty(driver, child, act))

    def test_timeout_restores_terminal_mode(self):
        driver = """import terminal_proxy as t,termios,subprocess
before=termios.tcgetattr(0)
try:t.run(['/bin/sleep','10'],timeout=.1)
except subprocess.TimeoutExpired:print('TIMEOUT',flush=True)
after=termios.tcgetattr(0)
before[3]&=~termios.PENDIN;after[3]&=~termios.PENDIN
print('RESTORED='+str(before==after),flush=True)
"""
        output = self.run_pty(driver)
        self.assertIn(b'TIMEOUT', output)
        self.assertIn(b'RESTORED=True', output)


if __name__ == '__main__':
    unittest.main()
