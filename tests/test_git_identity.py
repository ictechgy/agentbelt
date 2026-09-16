"""Regression for planting the git author identity (name and email only) in the isolated home.

The isolated home has no global gitconfig, so the commit author is derived as `user@hostname`, and an agent trying to fix it
with `git config user.name` is blocked by the locked `.git/config` (measured in an AutoClaw session on 2026-09-15). We hand over
a file copying only user.name/email from the host `~/.gitconfig` via GIT_CONFIG_GLOBAL, and lock that file so the child cannot change it.
"""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g


class IdentityTests(unittest.TestCase):
    def test_seeds_only_name_and_email_from_the_host(self):
        with tempfile.TemporaryDirectory(prefix='gitid-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'; home.mkdir(mode=0o700)
            with patch.object(g, 'host_git_identity', lambda: ('Test Name', 'test@example.com')):
                env = g.clean_environment(home, None)
            config = home / '.gitconfig'
            self.assertEqual(env['GIT_CONFIG_GLOBAL'], str(config))
            self.assertEqual(config.read_text(), '[user]\n\tname = Test Name\n\temail = test@example.com\n')
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(env['GIT_CONFIG_SYSTEM'], '/dev/null')

    def test_without_a_host_identity_git_config_stays_off(self):
        with tempfile.TemporaryDirectory(prefix='gitid-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'; home.mkdir(mode=0o700)
            with patch.object(g, 'host_git_identity', lambda: None):
                env = g.clean_environment(home, None)
            self.assertEqual(env['GIT_CONFIG_GLOBAL'], '/dev/null')
            self.assertFalse((home / '.gitconfig').exists())

    def test_host_identity_rejects_odd_values(self):
        with patch.object(g.subprocess, 'run', side_effect=[type('R', (), {'returncode': 0, 'stdout': 'Name\n'})(),
                                                                type('R', (), {'returncode': 0, 'stdout': 'bad\nline\n'})()]):
            self.assertIsNone(g.host_git_identity())
        with patch.object(g.subprocess, 'run', side_effect=[type('R', (), {'returncode': 1, 'stdout': ''})(),
                                                                type('R', (), {'returncode': 0, 'stdout': 'a@b\n'})()]):
            self.assertIsNone(g.host_git_identity())

    def test_child_commits_as_the_seeded_identity_and_cannot_rewrite_it(self):
        # Create the repository on the host (creating .git is an ancestor of the locked hooks/config, so it is blocked in the sandbox, by design).
        script = ('echo x > f && git add f && git commit -q -m init && '
                  'git log -1 --format="AUTHOR=%an <%ae>"; '
                  'git config --global user.name Evil 2>/dev/null && echo GLOBAL_WRITE_OK || echo GLOBAL_WRITE_DENIED; '
                  'git -c user.name=Over commit -q --allow-empty -m over && git log -1 --format="OVERRIDE=%an"')
        import subprocess
        with tempfile.TemporaryDirectory(prefix='gitid-', dir=Path.home()) as tmp, tempfile.TemporaryFile() as out, \
             patch.object(g, 'host_git_identity', lambda: ('Seeded Name', 'seed@example.com')):
            subprocess.run(['/usr/bin/git', 'init', '-q', tmp], check=True)
            status = g.run_confined('exec', Path(tmp), ['/bin/bash', '-c', script], ephemeral=True, stdout=out)
            out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('AUTHOR=Seeded Name <seed@example.com>', text)
        self.assertIn('GLOBAL_WRITE_DENIED', text)
        self.assertIn('OVERRIDE=Over', text)


if __name__ == '__main__':
    unittest.main()
