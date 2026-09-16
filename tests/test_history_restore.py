import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('restore_history',ROOT/'adapters/restore_history.py')
restore=importlib.util.module_from_spec(spec);spec.loader.exec_module(restore)
SCHEMA='''
CREATE TABLE session(id TEXT PRIMARY KEY,directory TEXT,permission TEXT,parent_id TEXT);
CREATE TABLE message(id TEXT PRIMARY KEY,session_id TEXT REFERENCES session(id),data TEXT);
CREATE TABLE session_target(session_id TEXT PRIMARY KEY REFERENCES session(id),status TEXT,active_input_id TEXT);
CREATE TABLE session_input(id TEXT PRIMARY KEY,session_id TEXT REFERENCES session(id),status TEXT,payload TEXT);
CREATE TABLE local_setting(key TEXT,value TEXT);
'''
class HistoryRestoreTests(unittest.TestCase):
    def test_workspace_only_copy_is_idempotent_and_does_not_replay_prompts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'source.db';dest=base/'dest.db';work=base/'work'
            for path in [source,dest]:
                c=sqlite3.connect(path);c.executescript(SCHEMA);c.close()
            c=sqlite3.connect(source)
            c.executemany('INSERT INTO session VALUES(?,?,?,?)',[('one',str(work),'old-grant',None),('other',str(base/'elsewhere'),None,None)])
            c.executemany('INSERT INTO message VALUES(?,?,?)',[('m1','one','SYNTHETIC_SELECTED'),('m2','other','SYNTHETIC_UNRELATED')])
            c.execute("INSERT INTO session_target VALUES('one','active','pending')")
            c.execute("INSERT INTO session_input VALUES('pending','one','admitted','SYNTHETIC_PENDING')")
            c.execute("INSERT INTO local_setting VALUES('credential','SYNTHETIC_NEVER_COPY')")
            c.commit();c.close();before=source.read_bytes()
            self.assertEqual(restore.apply_snapshot(dest,restore.collect_snapshot(source,work))['session'],1)
            self.assertEqual(restore.apply_snapshot(dest,restore.collect_snapshot(source,work))['session'],0)
            c=sqlite3.connect(dest)
            self.assertEqual(c.execute('SELECT id,permission FROM session').fetchall(),[('one',None)])
            self.assertEqual(c.execute('SELECT data FROM message').fetchall(),[('SYNTHETIC_SELECTED',)])
            self.assertEqual(c.execute('SELECT status,active_input_id FROM session_target').fetchall(),[('paused',None)])
            self.assertEqual(c.execute('SELECT count(*) FROM session_input').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM local_setting').fetchone()[0],0)
            c.close();self.assertEqual(source.read_bytes(),before)

    def test_production_writer_cannot_follow_a_link_outside_its_sandbox(self):
        import json
        import subprocess
        with tempfile.TemporaryDirectory(prefix='history-boundary-',dir=Path.home()) as tmp:
            base=Path(tmp);work=base/'work';work.mkdir();source=base/'source.store';outside=base/'outside.store'
            for path in [source,outside]:
                c=sqlite3.connect(path);c.executescript(SCHEMA);c.close()
            c=sqlite3.connect(source);c.execute('INSERT INTO session VALUES(?,?,NULL,NULL)',('one',str(work)));c.commit();c.close()
            target=work/'connection.store';target.symlink_to(outside)
            before=outside.read_bytes();snapshot=restore.collect_snapshot(source,work)
            runner="import sys;sys.path.insert(0,sys.argv[1]);import agent_guard as g;from pathlib import Path;sys.exit(g.run_confined('history-boundary',Path(sys.argv[2]),['/Library/Developer/CommandLineTools/usr/bin/python3','-I',str(g.ROOT/'adapters/restore_history.py'),'--apply-snapshot',sys.argv[3]],extra_reads=[g.ROOT/'adapters/restore_history.py'],ephemeral=True))"
            result=subprocess.run(['/usr/bin/python3','-I','-c',runner,str(ROOT),str(work),str(target)],input=json.dumps(snapshot),capture_output=True,text=True,timeout=20)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(outside.read_bytes(),before)

    def test_schema_failure_rolls_back_the_complete_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);source=base/'source.db';dest=base/'dest.db';work=base/'work'
            for path in [source,dest]:
                c=sqlite3.connect(path);c.executescript(SCHEMA);c.close()
            c=sqlite3.connect(source);c.execute('INSERT INTO session VALUES(?,?,NULL,NULL)',('one',str(work)));c.execute('ALTER TABLE message ADD COLUMN extra TEXT');c.commit();c.close()
            with self.assertRaises(ValueError):restore.apply_snapshot(dest,restore.collect_snapshot(source,work))
            c=sqlite3.connect(dest);self.assertEqual(c.execute('SELECT count(*) FROM session').fetchone()[0],0);c.close()

if __name__=='__main__':unittest.main()
