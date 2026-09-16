#!/usr/bin/python3
"""Bind a coding workspace to an AutoClaw session (host only).

AutoClaw's zcode-runtime plugin requires a per-session binding for every `zcode_run` (`requireBoundWorkspace`). The app UI
can only pick a workspace for conversation sessions inside the app, so a Discord channel session stays bound to the default
hidden folder, and our guard refuses that path. This tool writes the binding file in exactly the format the plugin
(session-workspace-binding.js) validates: `<state>/autoclaw/coding-workspaces/v1/<sha256("local\\0"+sessionKey)>.json`,
0600, a fixed key set, workspaceId = sha256("workspace\\0"+realPath), pathIdentity = {dev, ino}. The workspace must pass
the guard's `workspace_path` check (a hidden folder, the whole home and the like are not bound at all, because confined
execution refuses them in the first place).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agent_guard

OPENCLAW_STATE = agent_guard.OWNER_HOME / '.openclaw-autoclaw'
SCHEMA_VERSION = 1
AGENT_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
SNOWFLAKE = re.compile(r'^[0-9]{17,20}$')


def session_key_hash(session_key):
    """The same hash as the plugin: sha256("local\\0" + sessionKey)."""
    key = (session_key or '').strip()
    if not key or len(key) > 1024:
        raise RuntimeError('A non-empty session key is required.')
    return hashlib.sha256(b'local\0' + key.encode()).hexdigest()


def workspace_id(real_path):
    """The same workspace id as the plugin: sha256("workspace\\0" + realPath)."""
    return hashlib.sha256(b'workspace\0' + real_path.encode()).hexdigest()


def discord_channel_session_key(agent_id, channel_id):
    """The session key OpenClaw uses for a Discord server channel. Measured: agent:auto-coder:discord:channel:<channel ID>."""
    if not AGENT_ID.match(agent_id or ''):
        raise RuntimeError('Agent id must be a short identifier.')
    if not SNOWFLAKE.match(str(channel_id or '')):
        raise RuntimeError('Discord channel id must be a numeric snowflake.')
    return 'agent:' + agent_id + ':discord:channel:' + str(channel_id)


def binding_path(session_key):
    """The path of the binding file that corresponds to the session key."""
    return OPENCLAW_STATE / 'autoclaw/coding-workspaces' / ('v' + str(SCHEMA_VERSION)) / (session_key_hash(session_key) + '.json')


def existing_binding(path):
    """The existing binding, if there is one. If it is a link or an odd file, refuse instead of overwriting it."""
    if path.is_symlink():
        raise RuntimeError('Refusing a symlinked binding file: ' + str(path))
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError('Binding path is not a regular file: ' + str(path))
    try:
        return json.loads(path.read_text())
    except ValueError:
        return None


def build_binding(session_key, workspace, previous=None):
    """Build the binding document from the validated workspace. On a rebind, raise revision and keep boundAt."""
    real = str(agent_guard.workspace_path(str(workspace)))
    info = os.stat(real)
    now = int(time.time() * 1000)
    bound_at = previous.get('boundAt') if isinstance(previous, dict) and isinstance(previous.get('boundAt'), int) else now
    revision = previous.get('bindingRevision') + 1 if isinstance(previous, dict) and isinstance(previous.get('bindingRevision'), int) else 1
    return {'schemaVersion': SCHEMA_VERSION, 'sessionKeyHash': session_key_hash(session_key), 'workspaceId': workspace_id(real),
            'realPath': real, 'bindingRevision': revision, 'pathIdentity': {'dev': str(info.st_dev), 'ino': str(info.st_ino)},
            'boundAt': min(bound_at, now), 'updatedAt': now}


def bind(session_key, workspace):
    """Write the binding file atomically with mode 0600. The return value is the file path."""
    path = binding_path(session_key)
    previous = existing_binding(path)
    document = build_binding(session_key, workspace, previous)
    directory = path.parent
    # If we end up creating it before the app does, create it in private mode rather than relying on umask.
    for ancestor in [directory.parent.parent, directory.parent, directory]:
        if not ancestor.exists():
            ancestor.mkdir(mode=0o700)
    if directory.stat().st_mode & 0o077:
        directory.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.binding-', dir=str(directory))
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(document, stream)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workspace', help='Project directory to bind (must pass the guard workspace checks).')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--session-key', help='Exact OpenClaw session key, e.g. agent:auto-coder:9931d08f')
    target.add_argument('--discord-channel', metavar='CHANNEL_ID', help='Bind the Discord server-channel session of --agent.')
    parser.add_argument('--agent', default='auto-coder', help='Agent id for --discord-channel (default auto-coder).')
    options = parser.parse_args(argv)
    key = options.session_key or discord_channel_session_key(options.agent, options.discord_channel)
    path = bind(key, options.workspace)
    print('Bound ' + key + ' -> ' + json.loads(path.read_text())['realPath'])
    print('Binding file: ' + str(path))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, agent_guard.GuardError) as error:
        raise SystemExit('bind_autoclaw_workspace: ' + str(error))
