"""Actual protected backend protocol, without GUI sessions or model API calls."""
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ZcodeIntegrationTests(unittest.TestCase):
    def test_actual_backend_loads_workspace_with_protected_settings(self):
        with tempfile.TemporaryDirectory(prefix='zcode-protocol-',dir=Path.home()) as tmp:
            runner="""import sys
sys.path.insert(0,sys.argv[1])
import agentbelt as g
from pathlib import Path
work=Path(sys.argv[2])
def prepare(home,env):
    g.private_dir(g.private_dir(home/'.zcode')/'cli')
    env.update({'ZCODE_HOME':str(home/'.zcode'),'AGENTBELT_BACKEND':'zcode-v1','AGENTBELT_BOOTSTRAP':'zcode'})
reads=['/Applications/ZCode.app',g.ROOT/'agentbelt.py',g.ROOT/'zcode_hook.py',g.ROOT/'riskgate_bridge.py',g.ROOT/'vendor',g.ROOT/'state/zcode-agent-config.json']
sys.exit(g.run_confined('zcode-protocol-test',work,[str(g.NODE),'/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs','app-server','--stdio','--surface','desktop'],extra_reads=reads,prepare_home=prepare,private_sockets=True,read_only_home_paths=['.zcode/cli/config.json'],ephemeral=True))
"""
            process=subprocess.Popen(['/usr/bin/python3','-I','-c',runner,str(ROOT),tmp],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,start_new_session=True)
            messages=queue.Queue()
            def read():
                for line in process.stdout:
                    try: messages.put(json.loads(line))
                    except ValueError: pass
            thread=threading.Thread(target=read,daemon=True);thread.start()
            try:
                request={'id':1,'method':'workspace/readState','params':{'workspace':{'workspacePath':tmp,'workspaceKey':tmp}}}
                process.stdin.write(json.dumps(request)+'\n');process.stdin.flush()
                import time
                deadline=time.monotonic()+20
                reply=None
                while time.monotonic()<deadline:
                    item=messages.get(timeout=max(0.1,deadline-time.monotonic()))
                    if item.get('id')==1:reply=item;break
                self.assertIsNotNone(reply)
                self.assertNotIn('error',reply)
                self.assertIn('result',reply)
                self.assertEqual(reply['result']['settings']['permission']['mode'],'build')
            finally:
                process.stdin.close()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:os.killpg(process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    process.wait(timeout=5)
                process.stdout.close();thread.join(timeout=1)

    def test_kernel_confined_hook_uses_real_engine_and_preserves_denials(self):
        with tempfile.TemporaryDirectory(prefix='zcode-engine-',dir=Path.home()) as tmp:
            policy=Path(tmp)/'policy.yaml'
            policy.write_text('version: 1\ndefaults: prompt\nrules:\n  - id: read\n    match: {tool: Bash, cmd_regex: "^git status$"}\n    risk: allow\n  - id: block\n    match: {tool: Bash, cmd_regex: "^forbidden$"}\n    risk: deny\n')
            runner="""import sys
sys.path.insert(0,sys.argv[1]);import agentbelt as g
from pathlib import Path
inner="import sys;sys.path.insert(0,sys.argv[1]);import riskgate_bridge as b;from pathlib import Path;b.riskgate_policy=lambda:Path(sys.argv[2]);import zcode_hook;sys.exit(zcode_hook.main())"
reads=[g.ROOT/'agentbelt.py',g.ROOT/'zcode_hook.py',g.ROOT/'riskgate_bridge.py',g.ROOT/'vendor']
sys.exit(g.run_confined('riskgate-engine-test',Path(sys.argv[2]),['/Library/Developer/CommandLineTools/usr/bin/python3','-I','-c',inner,str(g.ROOT),sys.argv[3]],extra_reads=reads,extra_env={'AGENTBELT_BACKEND':'zcode-v1'},ephemeral=True))
"""
            for command,verdict in [('git status','allow'),('git commit','ask'),('forbidden','deny')]:
                payload={'hook_event_name':'PreToolUse','tool_name':'Bash','cwd':tmp,'tool_input':{'command':command}}
                r=subprocess.run(['/usr/bin/python3','-I','-c',runner,str(ROOT),tmp,str(policy)],input=json.dumps(payload)+'\n',capture_output=True,text=True,timeout=20)
                self.assertIn(r.returncode,(0,2) if verdict=='deny' else (0,),r.stderr)
                self.assertEqual(json.loads(r.stdout)['hookSpecificOutput']['permissionDecision'],verdict)

if __name__=='__main__':unittest.main()
