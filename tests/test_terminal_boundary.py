"""Exercise a private PTY, never the user's actual interactive terminal."""
import json
import os
from pathlib import Path
import pty
import select
import signal
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TerminalBoundaryTests(unittest.TestCase):
    def test_raw_mode_works_but_input_injection_and_other_tty_access_do_not(self):
        code = '''import os,json,termios,tty,fcntl,sys
result={}
try:
 old=termios.tcgetattr(0);tty.setraw(0);termios.tcsetattr(0,termios.TCSANOW,old);result['raw_mode']=True
except (OSError,termios.error):result['raw_mode']=False
for name,fd in [('stdin',0),('controlling',None)]:
 opened=None
 try:
  if fd is None:opened=os.open('/dev/tty',os.O_RDWR);fd=opened
  fcntl.ioctl(fd,termios.TIOCSTI,b'X');result[name+'_injection']='ALLOWED'
 except PermissionError:result[name+'_injection']='DENIED'
 except OSError:result[name+'_injection']='UNAVAILABLE'
 finally:
  if opened is not None:os.close(opened)
try:
 other=os.open(sys.argv[1],os.O_RDWR);os.close(other);result['other_tty']='ALLOWED'
except PermissionError:result['other_tty']='DENIED'
print('GUARD_TTY_RESULT='+json.dumps(result),flush=True)
'''
        with tempfile.TemporaryDirectory(prefix='guard-tty-test-', dir=Path.home()) as work:
            other_master, other_slave = pty.openpty()
            other_path = os.ttyname(other_slave)
            pid, master = pty.fork()
            if pid == 0:
                os.close(other_master)
                os.close(other_slave)
                os.chdir(work)
                os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', str(ROOT / 'agentbelt.py'),
                         'exec', work, '--', '/usr/bin/python3', '-I', '-c', code, other_path])
            output = bytearray()
            status = None
            deadline = time.monotonic() + 15
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output.extend(chunk)
                    done, value = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = value
                        break
                if status is None:
                    done, value = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = value
                    else:
                        os.killpg(pid, signal.SIGKILL)
                        _, status = os.waitpid(pid, 0)
            finally:
                os.close(master)
                os.close(other_master)
                os.close(other_slave)
            raw = output.decode(errors='replace')
            self.assertIn('GUARD_TTY_RESULT=', raw, 'PTY child did not emit a result')
            record = raw.split('GUARD_TTY_RESULT=', 1)[1].splitlines()[0]
            result = json.loads(record)
            self.assertTrue(result['raw_mode'])
            self.assertEqual(result['stdin_injection'], 'DENIED')
            self.assertEqual(result['controlling_injection'], 'DENIED')
            self.assertEqual(result['other_tty'], 'DENIED')


if __name__ == '__main__':
    unittest.main()
