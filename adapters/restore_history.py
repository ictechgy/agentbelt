"""Read selected history on the host; apply it inside the destination sandbox."""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
TABLES = ('session', 'message', 'part', 'todo', 'session_entry', 'input_history',
          'session_target', 'model_usage', 'turn_usage', 'tool_usage', 'session_input')


def columns(connection, table):
    return [row[1] for row in connection.execute('PRAGMA table_info("' + table + '")')]


def collect_snapshot(source, workspace):
    original = sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True)
    original.row_factory = sqlite3.Row
    try:
        original.execute('PRAGMA query_only=ON')
        original.execute('BEGIN')
        sessions = [dict(row) for row in original.execute('SELECT * FROM session WHERE directory IN (?, ?)',
                                                         (str(workspace), str(workspace.resolve())))]
        ids = [row['id'] for row in sessions]
        snapshot = {'columns': {}, 'rows': {'session': sessions}}
        for table in TABLES:
            snapshot['columns'][table] = columns(original, table)
            if table == 'session': continue
            data = []
            if snapshot['columns'][table]:
                for offset in range(0, len(ids), 200):
                    batch = ids[offset:offset + 200]
                    statement = 'SELECT * FROM "' + table + '" WHERE session_id IN (' + ','.join('?' for _ in batch) + ')'
                    data.extend(dict(row) for row in original.execute(statement, batch))
            snapshot['rows'][table] = data
        return snapshot
    finally:
        original.rollback(); original.close()


def apply_snapshot(destination, snapshot):
    """The production caller runs this writer under Seatbelt, including WAL I/O."""
    target = sqlite3.connect(destination, timeout=15)
    copied = {}
    try:
        target.execute('PRAGMA trusted_schema=OFF')
        target.execute('PRAGMA foreign_keys=ON')
        target.execute('BEGIN IMMEDIATE')
        existing = {row[0] for row in target.execute('SELECT id FROM session')}
        selected = [dict(row) for row in snapshot['rows']['session'] if row['id'] not in existing]
        ids = {row['id'] for row in selected}
        for table in TABLES:
            source_columns = snapshot['columns'].get(table, [])
            target_columns = columns(target, table)
            if not source_columns and not target_columns: continue
            if set(source_columns) != set(target_columns):
                raise ValueError('Database schema differs; verify the installed version before importing history.')
            rows = selected if table == 'session' else [dict(row) for row in snapshot['rows'].get(table, []) if row['session_id'] in ids]
            quoted = ','.join('"' + name.replace('"', '""') + '"' for name in target_columns)
            statement = 'INSERT INTO "' + table + '" (' + quoted + ') VALUES (' + ','.join('?' for _ in target_columns) + ')'
            count = 0
            for row in rows:
                if table == 'session':
                    if 'permission' in row: row['permission'] = None
                    if row.get('parent_id') not in ids | existing: row['parent_id'] = None
                if table == 'session_input' and row.get('status') == 'admitted': continue
                if table == 'session_target' and row.get('status') == 'active':
                    row['status'] = 'paused'
                    for key in ('active_input_id', 'active_run_started_at', 'active_run_last_seen_at'):
                        if key in row: row[key] = None
                target.execute(statement, [row.get(name) for name in target_columns]); count += 1
            copied[table] = count
        target.commit()
        return copied
    except BaseException:
        target.rollback(); raise
    finally:
        target.close()


def registered_workspaces():
    source = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.zcode/cli/db/db.sqlite'
    with sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True) as connection:
        paths = [Path(row[0]).resolve() for row in connection.execute('SELECT DISTINCT directory FROM session')]
    for workspace in paths:
        identity = hashlib.sha256(str(workspace).encode()).hexdigest()[:20]
        destination = ROOT / 'state/homes/zcode' / identity / '.zcode/cli/db/db.sqlite'
        if destination.is_file(): yield workspace


def restore_registered_workspace(workspace):
    from agentbelt import run_confined
    identity = hashlib.sha256(str(workspace.resolve()).encode()).hexdigest()[:20]
    source = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.zcode/cli/db/db.sqlite'
    destination = ROOT / 'state/homes/zcode' / identity / '.zcode/cli/db/db.sqlite'
    if not destination.is_file():
        raise ValueError('Open this workspace once in Zcode Safe before importing history.')
    snapshot = collect_snapshot(source, workspace)
    with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as outgoing:
        incoming.write(json.dumps(snapshot, ensure_ascii=False).encode()); incoming.seek(0)
        status = run_confined('zcode', workspace,
            ['/Library/Developer/CommandLineTools/usr/bin/python3', '-I', str(ROOT / 'adapters/restore_history.py'), '--apply-snapshot', str(destination)],
            extra_reads=[ROOT / 'adapters/restore_history.py'], read_only_home_paths=['.zcode/cli/config.json'],
            stdin=incoming, stdout=outgoing)
        if status: raise ValueError('History writer failed inside the sandbox; original store unchanged.')
        outgoing.seek(0)
        return json.loads(outgoing.read(1024 * 1024))


def main():
    if sys.argv[1:2] == ['--apply-snapshot']:
        import ctypes, os
        library = ctypes.CDLL('/usr/lib/libsandbox.1.dylib')
        if library.sandbox_check(os.getpid(), None, 0) != 1:
            raise ValueError('History writes require the OS sandbox.')
        raw = sys.stdin.buffer.read(128 * 1024 * 1024 + 1)
        if len(raw) > 128 * 1024 * 1024: raise ValueError('History snapshot is too large.')
        print(json.dumps(apply_snapshot(Path(sys.argv[2]), json.loads(raw))))
        return
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('workspace')
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    from agentbelt import workspace_path
    print(json.dumps(restore_registered_workspace(workspace_path(args.workspace))))


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('History import failed; original store unchanged.')
