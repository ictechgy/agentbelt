"""Host-side audit of git repositories a confined session left in the workspace.

git_lock.mjs keeps new `.git` entries out of every write root except the package managers'
own checkout trees (SwiftPM, dart pub, cargo). A repository made there could still be moved
into the workspace or registered in the workspace index as a gitlink, and host git would
then obey its configuration. This audit compares the workspace before and after the
session and reports new nested repositories outside those trees and new gitlinks.

Host-only: run_confined imports it lazily (agentbelt.py is also imported inside the sandbox).
"""
import os
from pathlib import Path
import subprocess

GIT = '/usr/bin/git'
# The workspace repository's own configuration is locked, so these overrides only make sure
# this read-only listing never starts a monitor or hook even if that changes.
SAFE_GIT = [GIT, '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '--no-optional-locks']
SAFE_ENV = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0'}


def nested_repositories(workspace):
    """Relative paths of every `.git` entry below the workspace except its own, links not followed."""
    root = Path(workspace)
    found = set()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in [*names, *files]:
            if name.casefold() == '.git' and Path(directory, name) != root / '.git':
                found.add(str(Path(directory, name).relative_to(root)))
        # Never descend into a gitdir: its contents are git's own.
        names[:] = [name for name in names if name.casefold() != '.git']
    return found


def gitlinks(workspace):
    """Index paths recorded as gitlinks (mode 160000); empty when the workspace is not a repository."""
    if not (Path(workspace) / '.git').is_dir():
        return set()
    result = subprocess.run([*SAFE_GIT, '-C', str(workspace), 'ls-files', '--stage', '-z'], env=SAFE_ENV,
                            capture_output=True, timeout=60)
    if result.returncode != 0:
        # An unreadable index is itself worth reporting; the caller shows it with the other findings.
        return {'<index unreadable: ' + result.stderr.decode(errors='replace').strip()[:200] + '>'}
    entries = result.stdout.decode(errors='surrogateescape').split('\0')
    return {entry.split('\t', 1)[1] for entry in entries if entry.startswith('160000 ') and '\t' in entry}


def snapshot(workspace):
    return {'repositories': nested_repositories(workspace), 'gitlinks': gitlinks(workspace)}


def findings(before, after, workspace, tool_caches):
    """Human-readable warnings for repositories and gitlinks the session added."""
    root = Path(workspace).resolve()
    caches = [Path(cache) for cache in tool_caches]

    def inside_cache(relative):
        path = root / relative
        return any(path == cache or cache in path.parents for cache in caches)
    added = sorted(path for path in after['repositories'] - before['repositories'] if not inside_cache(path))
    linked = sorted(after['gitlinks'] - before['gitlinks'])
    return ([f'new nested git repository outside the package caches: {path}' for path in added]
            + [f'new gitlink in the workspace index: {path}' for path in linked])


def warning_text(messages):
    """The notice printed after the session. Host git would obey these repositories' configuration."""
    lines = ['agentbelt: the session left git repositories the host git would follow.',
             *('  - ' + message for message in messages),
             '  Inspect them before running git in this workspace (for example, check their .git/config),',
             '  or remove them if they are not yours.']
    return '\n'.join(lines)
