"""git_lock.mjs under real Seatbelt: host git must not obey state the child planted.

Measured 2026-09-24 (git 2.54): with only .git/{hooks,config,config.worktree,info/attributes}
locked, a child could plant a config that an unsandboxed `git status` then obeyed through
.git/commondir, .git/modules/*/config, a nested repository registered as a gitlink, or a
`.git` replaced by a link or a `gitdir:` file. These tests load the same rules the runner
appends and apply them with sandbox-exec to a throwaway repository in the system temp
directory. Git runs with no global or system configuration.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g

GIT = '/usr/bin/git'


def node_binary():
    return str(g.NODE) if g.NODE.is_file() else shutil.which('node')


def git_lock_rules(root):
    script = ("import {gitLockRules} from " + repr((ROOT / 'git_lock.mjs').as_uri()) + ";"
              "process.stdout.write(gitLockRules(process.argv[1]));")
    result = subprocess.run([node_binary(), '--input-type=module', '-e', script, root],
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip())
    return result.stdout


def git_tool_rules(paths):
    script = ("import {gitToolRules} from " + repr((ROOT / 'git_lock.mjs').as_uri()) + ";"
              "process.stdout.write(gitToolRules(JSON.parse(process.argv[1])));")
    result = subprocess.run([node_binary(), '--input-type=module', '-e', script, json.dumps(paths)],
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip())
    return result.stdout


@unittest.skipUnless(sys.platform == 'darwin' and Path('/usr/bin/sandbox-exec').exists() and Path(GIT).exists()
                     and node_binary(), 'needs macOS Seatbelt, git and node')
class GitLockTests(unittest.TestCase):
    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix='git-lock-')).resolve()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.workspace = base / 'ws'
        self.workspace.mkdir()
        # A second write root, like the isolated home: a repository made there could be moved in.
        self.home = base / 'home'
        self.home.mkdir()
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home), 'GIT_CONFIG_GLOBAL': '/dev/null',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 'a', 'GIT_AUTHOR_EMAIL': 'a@example.invalid',
                    'GIT_COMMITTER_NAME': 'a', 'GIT_COMMITTER_EMAIL': 'a@example.invalid'}
        self.host('init', '-q', '.')
        self.host('commit', '-q', '--allow-empty', '-m', 'initial')
        self.profile = base / 'profile.sb'
        # SRT re-allows create/unlink for write roots as concrete operations, which beat a
        # wildcard deny; the same line here keeps that precedence in the synthetic profile.
        # The runner locks every write root, then re-opens the package managers' checkout trees.
        self.profile.write_text('(version 1)\n(allow default)\n'
                                f'(allow file-write-create file-write-unlink (subpath "{self.workspace}") '
                                f'(subpath "{self.home}"))\n'
                                # Like sandbox_policy's secret-name denyWrite, emitted by SRT before our appends.
                                f'(deny file-write* file-write-create file-write-unlink '
                                f'(regex #"^{self.workspace}/(.*/)?\\.env[^/]*$"))\n'
                                + git_lock_rules(str(self.workspace)) + git_lock_rules(str(self.home))
                                + git_tool_rules([str(self.workspace / '.build/checkouts'),
                                                  str(self.home / '.pub-cache/git')]))

    def host(self, *arguments):
        subprocess.run([GIT, *arguments], cwd=self.workspace, env=self.env, check=True, capture_output=True, timeout=60)

    def confined(self, script):
        """True when the shell script succeeds inside the git lock."""
        result = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(self.profile), '/bin/sh', '-c', script],
                                cwd=self.workspace, env=self.env, capture_output=True, timeout=60)
        return result.returncode == 0

    def test_ordinary_git_work_still_succeeds(self):
        for script in ['echo hi > f && git add f && git commit -q -m change',
                       'git switch -q -c topic && git switch -q -',
                       'echo more >> f && git stash -q && git stash pop -q',
                       'git gc -q']:
            with self.subTest(script=script):
                self.assertTrue(self.confined(script))

    def test_planted_git_state_is_denied(self):
        (self.workspace / 'evil').mkdir()
        for script in ['echo ../evil > .git/commondir', 'echo x > .git/COMMONDIR',
                       'mkdir -p .git/modules/sub', 'mkdir -p .git/Modules/sub', 'mkdir -p .git/worktrees/w',
                       'echo x >> .git/config', 'echo x >> .GIT/Config', 'echo x > .git/hooks/pre-commit',
                       'echo x > .git/info/attributes', 'mv .git moved', 'rm -rf .git',
                       'mkdir sub && ln -s ../evil sub/.git', 'mkdir sub && ln -s ../evil sub/.GIT',
                       'mkdir sub && echo "gitdir: ../evil" > sub/.Git', 'mkdir sub && mv evil sub/.git',
                       'mkdir sub && cd sub && git init -q .', 'git clone -q . nested']:
            with self.subTest(script=script):
                self.assertFalse(self.confined(script))
        # The entry, its config and hooks survive; no other gitdir entry appeared. (`rm -rf .git`
        # can still empty objects and refs: data loss like any workspace file, not a redirection.)
        git = self.workspace / '.git'
        self.assertTrue(git.is_dir() and not git.is_symlink())
        self.assertTrue((git / 'config').is_file() and (git / 'hooks').is_dir())
        self.assertFalse(any(path.name.casefold() == '.git' for path in self.workspace.rglob('*') if path.parent != self.workspace))
        for name in ['commondir', 'modules', 'worktrees']:
            self.assertFalse((git / name).exists())

    def test_other_write_roots_are_locked(self):
        for script in ['mkdir -p "$HOME/r" && cd "$HOME/r" && git init -q .', 'git clone -q . "$HOME/copy"',
                       'mkdir -p "$HOME/x" && ln -s ../y "$HOME/x/.git"']:
            with self.subTest(script=script):
                self.assertFalse(self.confined(script))

    def test_package_caches_may_hold_repositories(self):
        for script in ['git clone -q . .build/checkouts/dep && git -C .build/checkouts/dep config x.y z',
                       'git clone -q . "$HOME/.pub-cache/git/dep"']:
            with self.subTest(script=script):
                self.assertTrue(self.confined(script))
        # The trees are exact: a sibling of the cache is still locked.
        self.assertFalse(self.confined('git clone -q . .build/other'))
        # Only the git lock is undone there; other write denials (secret names) still apply.
        self.assertTrue(self.confined('git clone -q . .build/checkouts/second'))
        self.assertFalse(self.confined('echo x > .build/checkouts/second/.env'))
        self.assertFalse(self.confined('echo x > src.env.local && mv src.env.local .env'))

    def test_missing_roots_resolve_through_their_nearest_ancestor(self):
        script = ("import fs from 'node:fs'; import {resolveRoot} from " + repr((ROOT / 'git_lock.mjs').as_uri()) + ";"
                  "console.log(JSON.stringify([resolveRoot('/var/folders/agentbelt-missing-x/TemporaryItems', fs),"
                  " resolveRoot('/tmp', fs), resolveRoot(process.argv[1], fs)]));")
        result = subprocess.run([node_binary(), '--input-type=module', '-e', script, str(self.workspace)],
                                capture_output=True, text=True, timeout=30, check=True)
        self.assertEqual(json.loads(result.stdout), ['/private/var/folders/agentbelt-missing-x/TemporaryItems',
                                                     '/private/tmp', str(self.workspace)])

    def test_rules_refuse_unusable_roots(self):
        for root in ['relative', '/a"b', '/a\nb']:
            with self.subTest(root=root), self.assertRaises(ValueError):
                git_lock_rules(root)
        for paths in [['relative'], ['/a/../b'], ['/a"b'], '/not-a-list']:
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                git_tool_rules(paths)
        self.assertEqual(git_tool_rules([]), '')


PLANTING = ['echo ../evil > .git/commondir', 'mkdir -p .git/modules/sub', 'mkdir -p .git/worktrees/w',
            'echo x >> .git/config', 'echo x > .git/hooks/pre-commit', 'mv .git moved',
            'mkdir sub && ln -s ../evil sub/.git', 'mkdir sub2 && cd sub2 && git init -q .',
            'mkdir -p "$HOME/r" && cd "$HOME/r" && git init -q .']


class RunnerSignalTests(unittest.TestCase):
    def test_run_confined_always_names_the_git_lock_root(self):
        if not (ROOT / 'runtime/node_modules/@anthropic-ai/sandbox-runtime/package.json').is_file():
            self.skipTest('pinned sandbox runtime is not installed in this checkout')
        captured = {}

        def fake_call(argv, **kwargs):
            captured['env'] = kwargs.get('env', {})
            return 0
        with tempfile.TemporaryDirectory(prefix='git-lock-', dir=Path.home()) as tmp, patch('terminal_proxy.run', fake_call):
            g.run_confined('exec', Path(tmp), ['/bin/true'], ephemeral=True)
            self.assertEqual(captured['env'].get('AGENTBELT_GIT_LOCK_ROOT'), str(Path(tmp).resolve()))

    def test_real_confined_session_applies_the_lock(self):
        """The whole chain (SRT profile + runner append) under real Seatbelt, not a synthetic profile."""
        if not (ROOT / 'runtime/node_modules/@anthropic-ai/sandbox-runtime/package.json').is_file():
            self.skipTest('pinned sandbox runtime is not installed in this checkout')
        work = Path(tempfile.mkdtemp(prefix='git-lock-real-', dir=Path.home())).resolve()
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
        subprocess.run([GIT, 'init', '-q', '.'], cwd=work, env=env, check=True)
        identity = ['-c', 'user.name=a', '-c', 'user.email=a@example.invalid']
        subprocess.run([GIT, *identity, 'commit', '-q', '--allow-empty', '-m', 'initial'], cwd=work, env=env, check=True)
        lines = ['cd ' + shlex.quote(str(work)),
                 'try() { if sh -c "$1" >/dev/null 2>&1; then echo "ALLOWED:$1"; else echo "DENIED:$1"; fi; }',
                 'try ' + shlex.quote('echo hi > f && git add f && git -c user.name=a -c user.email=a@example.invalid '
                                      'commit -q -m change')]
        lines += ['try ' + shlex.quote(script) for script in PLANTING]
        # A package manager's checkout is allowed; registering it as a gitlink is reported afterwards.
        tool = 'git clone -q . .build/checkouts/dep && git add -f .build/checkouts/dep'
        lines.append('try ' + shlex.quote(tool))
        report = io.StringIO()
        with tempfile.TemporaryFile() as out, contextlib.redirect_stderr(report):
            status = g.run_confined('exec', work, ['/bin/sh', '-c', '\n'.join(lines)], ephemeral=True, stdout=out)
            out.seek(0)
            text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('ALLOWED:echo hi > f', text)
        self.assertIn('ALLOWED:' + tool, text)
        self.assertIn('new gitlink in the workspace index: .build/checkouts/dep', report.getvalue())
        for script in PLANTING:
            with self.subTest(script=script):
                self.assertIn('DENIED:' + script, text)
        for name in ['commondir', 'modules', 'worktrees']:
            self.assertFalse((work / '.git' / name).exists())


if __name__ == '__main__':
    unittest.main()
