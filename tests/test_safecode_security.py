"""Actual kernel and OpenCode regressions; all state and secrets are synthetic."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as guard


class SafecodeSecurityTests(unittest.TestCase):
    def test_unreadable_hardlink_subtree_blocks_launch_without_changing_outside(self):
        with tempfile.TemporaryDirectory(prefix='safecode-hardlink-', dir=Path.home()) as tmp:
            base = Path(tmp); work = base / 'work'; hidden = work / 'hidden'
            hidden.mkdir(parents=True)
            outside = base / 'outside.txt'; outside.write_text('SYNTHETIC_ORIGINAL')
            os.link(outside, hidden / 'alias.txt'); hidden.chmod(0)
            try:
                code = "from pathlib import Path;p=Path('hidden');p.chmod(0o700);(p/'alias.txt').write_text('CHANGED')"
                result = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / 'agentbelt.py'), 'exec', str(work), '--', '/usr/bin/python3', '-I', '-c', code], capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outside.read_text(), 'SYNTHETIC_ORIGINAL')
                self.assertNotIn('Traceback', result.stderr)
            finally:
                hidden.chmod(0o700)

    def test_unexpected_auth_file_is_rejected_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); store = home / '.local/share/opencode'
            store.mkdir(parents=True)
            for path in [home / '.local', home / '.local/share', store]: path.chmod(0o700)
            auth = store / 'auth.json'; auth.write_text('SYNTHETIC_EXISTING')
            with self.assertRaises(guard.GuardError):
                guard.link_opencode_auth(home, home / 'selected-source')
            self.assertEqual(auth.read_text(), 'SYNTHETIC_EXISTING')

    def test_child_cannot_override_policy_and_old_home_config_is_not_loaded(self):
        with tempfile.TemporaryDirectory(prefix='safecode-policy-', dir=Path.home()) as tmp:
            base = Path(tmp); work = base / 'work'; work.mkdir()
            root = base / 'guard'; state = root / 'state'; state.mkdir(parents=True, mode=0o700)
            (root / 'runtime').symlink_to(ROOT / 'runtime', target_is_directory=True)
            (root / 'sandbox_runner.mjs').symlink_to(ROOT / 'sandbox_runner.mjs')
            (state / 'opencode-config.json').write_text(json.dumps({'permission': {'*': 'ask'}}))
            (state / 'opencode-auth.json').write_text('{}')
            identity = hashlib.sha256(str(work).encode()).hexdigest()[:20]
            old_home = state / 'homes/opencode' / identity
            for directory in [state / 'homes', state / 'homes/opencode', old_home]: directory.mkdir(mode=0o700, exist_ok=True)
            for path in [old_home / '.config/opencode/opencode.json', old_home / '.opencode/opencode.json']:
                path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps({'permission': {'*': 'allow'}}))
            history = old_home / '.local/share/opencode/history-canary'; history.parent.mkdir(parents=True)
            for path in [old_home / '.local', old_home / '.local/share', history.parent]: path.chmod(0o700)
            history.write_text('KEEP_SYNTHETIC_HISTORY')
            child = r'''import os,json,subprocess,sys
from pathlib import Path
home=Path.home();config=Path(os.environ['OPENCODE_CONFIG_DIR']);results=[]
for path in [config/'opencode.json',config/'opencode.jsonc',config/'agents/injected.md',home/'.opencode/opencode.json']:
 try:
  path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{"permission":{"*":"allow"}}');results.append('ALLOWED')
 except PermissionError:results.append('DENIED')
# Replacing the config directory must also be forbidden.
try:config.rename(config.with_name('replaced'));results.append('ALLOWED')
except PermissionError:results.append('DENIED')
r=subprocess.run([sys.argv[1],'debug','config'],capture_output=True,text=True)
print(json.dumps({'writes':results,'exit':r.returncode,'permission':json.loads(r.stdout).get('permission') if r.returncode==0 else None,'diagnostic':r.stderr[-2000:],'home':str(home),'history':(Path(os.environ['XDG_DATA_HOME'])/'opencode/history-canary').read_text()}))
'''
            runner = r'''import sys,os
from pathlib import Path
sys.path.insert(0,sys.argv[1]);import agentbelt as g
g.ROOT=Path(sys.argv[2]);g.verify_opencode_binary=lambda:None;g.stage_opencode_binary=lambda:g.OPENCODE;g.load_opencode_profile=lambda:{'domains':[]}
original=g.run_confined
# Substitute only the untrusted child to attempt a configuration attack.
def run(mode,workspace,command,*args,**kwargs):
 return original(mode,workspace,['/usr/bin/python3','-I','-c',sys.argv[4],str(g.OPENCODE)],*args,**kwargs)
g.run_confined=run;os.chdir(sys.argv[3]);sys.exit(g.main(['safecode','--','debug','config']))
'''
            homes = []
            for _ in range(2):
                r = subprocess.run(['/usr/bin/python3', '-I', '-c', runner, str(ROOT), str(root), str(work), child], capture_output=True, text=True, timeout=25)
                self.assertEqual(r.returncode, 0, r.stderr[-2000:])
                result = json.loads(r.stdout)
                self.assertEqual(result['writes'], ['DENIED'] * 5)
                self.assertEqual(result['exit'], 0, result.get('diagnostic'))
                self.assertEqual(result['permission'], {'*': 'ask'})
                self.assertEqual(result['history'], 'KEEP_SYNTHETIC_HISTORY')
                homes.append(result['home'])
            self.assertNotEqual(homes[0], homes[1])
            self.assertEqual(history.read_text(), 'KEEP_SYNTHETIC_HISTORY')
            self.assertEqual(list(state.glob('control-*')), [])


if __name__ == '__main__': unittest.main()
