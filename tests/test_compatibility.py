import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
g = load('compat_guard', 'agent_guard.py')
hook = load('compat_hook', 'zcode_hook.py')

class CompatibilityTests(unittest.TestCase):
    def test_git_commit_works_but_hook_and_config_writes_are_blocked(self):
        with tempfile.TemporaryDirectory(prefix='guard-git-', dir=Path.home()) as tmp:
            p=Path(tmp); env=dict(os.environ, DEVELOPER_DIR='/Library/Developer/CommandLineTools', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null')
            subprocess.run(['/usr/bin/git','init','--quiet',str(p)],env=env,check=True,capture_output=True)
            (p/'file.txt').write_text('synthetic content')
            command='git add file.txt && git -c user.name=Guard -c user.email=guard@example.invalid commit -qm synthetic'
            r=subprocess.run(['/usr/bin/python3',str(ROOT/'agent_guard.py'),'exec',str(p),'--','/bin/bash','-c',command],capture_output=True,text=True,timeout=30)
            self.assertEqual(r.returncode,0,r.stderr)
            for target in ['.git/config','.git/hooks/pre-commit']:
                r=subprocess.run(['/usr/bin/python3',str(ROOT/'agent_guard.py'),'exec',str(p),'--','/bin/sh','-c','echo unsafe >> "$1"','sh',target],capture_output=True,text=True,timeout=30)
                self.assertNotEqual(r.returncode,0,target)

    def test_opencode_rejects_changed_binary_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); binary=p/'opencode'; binary.write_bytes(b'original')
            state=p/'state'; state.mkdir()
            import hashlib
            (state/'compatibility.json').write_text(json.dumps({'opencode':{'version':'test','sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}}))
            with patch.object(g,'ROOT',p),patch.object(g,'OPENCODE',binary):
                g.verify_opencode_binary()
                binary.write_bytes(b'updated')
                with self.assertRaises(g.GuardError):g.verify_opencode_binary()

    def test_running_guard_alone_does_not_certify_an_ordinary_gui_launch(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def process(args, **kwargs):
                if '-axo' in args:
                    return SimpleNamespace(stdout='101 1 ZCode\n102 101 ZCode Helper\n103 102 Python\n')
                if 'command=' in args:
                    return SimpleNamespace(stdout=str(root/'agent_guard.py')+' zcode-backend app-server --stdio')
                return SimpleNamespace(stdout='current-start')
            with patch.object(g,'ROOT',root),patch.object(g.subprocess,'run',side_effect=process), \
                 patch('ctypes.CDLL',return_value=SimpleNamespace(sandbox_check=Mock(return_value=1))):
                result=g.live_zcode_status()
                self.assertEqual(result['backend_count'],1)
                self.assertFalse(result['safe_launch'])
                receipt=root/'state/runtime/zcode-gui.json';receipt.parent.mkdir(parents=True)
                receipt.write_text(json.dumps({'pid':101,'started':'current-start'}))
                self.assertTrue(g.live_zcode_status()['safe_launch'])
                receipt.write_text(json.dumps({'pid':101,'started':'old-start'}))
                self.assertFalse(g.live_zcode_status()['safe_launch'])

    def test_zcode_backend_also_rejects_an_unverified_desktop_version(self):
        import plistlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir()
            (state/'zcode-profile.json').write_text(json.dumps({'reviewedDesktopVersion':'old'}))
            with patch.object(g,'ROOT',root),patch.object(g.plistlib,'load',return_value={'CFBundleShortVersionString':'new'}):
                with self.assertRaises(g.GuardError):g.verify_zcode_binary()

    def test_confined_riskgate_verdict_is_applied_to_original_command(self):
        with tempfile.TemporaryDirectory(prefix='guard-riskgate-',dir=Path.home()) as tmp:
            payload={'hook_event_name':'PreToolUse','cwd':tmp,'tool_name':'Bash','tool_input':{'command':'git status'}}
            for verdict in ['allow','ask','deny']:
                with patch.object(hook,'inside_zcode_sandbox',return_value=True),patch.object(hook,'riskgate_decision',return_value=verdict) as judge:
                    result=hook.evaluate(payload)['hookSpecificOutput']
                self.assertEqual(result['permissionDecision'],verdict)
                self.assertEqual(judge.call_args.args[0]['tool_input']['command'],'git status')
                if verdict!='deny': self.assertEqual(result['updatedInput']['command'],'git status')

    def test_development_port_accepts_browser_but_other_loopback_remains_denied(self):
        import socket
        import threading
        import time
        with tempfile.TemporaryDirectory(prefix='guard-devport-',dir=Path.home()) as tmp:
            p=Path(tmp)
            with socket.socket() as endpoint:
                endpoint.bind(('127.0.0.1',0)); port=endpoint.getsockname()[1]
            with socket.socket() as private:
                private.bind(('127.0.0.1',0)); private.listen(); other=private.getsockname()[1]
                code='''import socket,sys
s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.listen();print('BOUND',flush=True)
try: socket.create_connection(('127.0.0.1',int(sys.argv[2])),timeout=1)
except PermissionError: print('PRIVATE_DENIED',flush=True)
else: sys.exit(5)
s.settimeout(10);conn,_=s.accept();conn.sendall(b'GUARD_DEV_TEST');conn.close()
'''
                runner="import sys;sys.path.insert(0,sys.argv[1]);import agent_guard as g;from pathlib import Path;sys.exit(g.run_confined('dev-test',Path(sys.argv[2]),['/usr/bin/python3','-I','-c',sys.argv[3],sys.argv[4],sys.argv[5]],ephemeral=True,dev_ports=[int(sys.argv[4])]))"
                received=[]
                def browser():
                    for _ in range(200):
                        try:
                            with socket.create_connection(('127.0.0.1',port),timeout=0.2) as client:
                                received.append(client.recv(100));return
                        except OSError:time.sleep(0.05)
                thread=threading.Thread(target=browser);thread.start()
                try:
                    r=subprocess.run(['/usr/bin/python3','-I','-c',runner,str(ROOT),str(p),code,str(port),str(other)],capture_output=True,text=True,timeout=30)
                finally:thread.join(timeout=15)
                self.assertEqual(received,[b'GUARD_DEV_TEST'])
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertIn('BOUND',r.stdout);self.assertIn('PRIVATE_DENIED',r.stdout)

if __name__=='__main__':unittest.main()
