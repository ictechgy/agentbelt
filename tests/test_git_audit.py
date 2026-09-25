"""git_audit: repositories and gitlinks a session leaves in the workspace are reported.

Throwaway repositories in the system temp directory; git runs without global or system config.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import git_audit

GIT = '/usr/bin/git'
ENV = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'a', 'GIT_AUTHOR_EMAIL': 'a@example.invalid',
       'GIT_COMMITTER_NAME': 'a', 'GIT_COMMITTER_EMAIL': 'a@example.invalid'}


@unittest.skipUnless(Path(GIT).exists(), 'needs git')
class GitAuditTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix='git-audit-')).resolve()
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.git('init', '-q', '.')
        self.git('commit', '-q', '--allow-empty', '-m', 'initial')
        self.caches = [str(self.workspace / '.build/checkouts')]

    def git(self, *arguments, cwd=None):
        subprocess.run([GIT, *arguments], cwd=cwd or self.workspace, env=ENV, check=True, capture_output=True)

    def nested(self, relative):
        path = self.workspace / relative
        path.mkdir(parents=True)
        self.git('init', '-q', '.', cwd=path)
        self.git('commit', '-q', '--allow-empty', '-m', 'nested', cwd=path)
        return path

    def test_clean_session_reports_nothing(self):
        before = git_audit.snapshot(self.workspace)
        (self.workspace / 'file').write_text('x')
        self.assertEqual(git_audit.findings(before, git_audit.snapshot(self.workspace), self.workspace, self.caches), [])

    def test_repositories_in_package_caches_are_expected(self):
        before = git_audit.snapshot(self.workspace)
        self.nested('.build/checkouts/dep')
        self.assertEqual(git_audit.findings(before, git_audit.snapshot(self.workspace), self.workspace, self.caches), [])

    def test_new_nested_repository_and_gitlink_are_reported(self):
        before = git_audit.snapshot(self.workspace)
        self.nested('vendor/dep')
        self.git('add', 'vendor/dep')
        messages = git_audit.findings(before, git_audit.snapshot(self.workspace), self.workspace, self.caches)
        self.assertIn('new nested git repository outside the package caches: vendor/dep/.git', messages)
        self.assertIn('new gitlink in the workspace index: vendor/dep', messages)
        self.assertIn('vendor/dep', git_audit.warning_text(messages))

    def test_gitlink_to_a_package_cache_checkout_is_reported(self):
        before = git_audit.snapshot(self.workspace)
        self.nested('.build/checkouts/dep')
        self.git('add', '-f', '.build/checkouts/dep')
        messages = git_audit.findings(before, git_audit.snapshot(self.workspace), self.workspace, self.caches)
        self.assertEqual(messages, ['new gitlink in the workspace index: .build/checkouts/dep'])

    def test_existing_repositories_are_not_reported_again(self):
        self.nested('tools/existing')
        before = git_audit.snapshot(self.workspace)
        self.assertEqual(git_audit.findings(before, git_audit.snapshot(self.workspace), self.workspace, self.caches), [])

    def test_gitfile_and_links_count_and_links_are_not_followed(self):
        before = git_audit.snapshot(self.workspace)
        (self.workspace / 'sub').mkdir()
        (self.workspace / 'sub/.GIT').write_text('gitdir: elsewhere\n')
        outside = Path(tempfile.mkdtemp(prefix='git-audit-outside-')).resolve()
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        (outside / 'deep').mkdir()
        (self.workspace / 'linked').symlink_to(outside, target_is_directory=True)
        self.nested(outside / 'deep/repo')
        messages = git_audit.findings(before, git_audit.snapshot(self.workspace), self.workspace, self.caches)
        self.assertEqual(messages, ['new nested git repository outside the package caches: sub/.GIT'])

    def test_non_repository_workspace_has_no_gitlinks(self):
        plain = Path(tempfile.mkdtemp(prefix='git-audit-plain-')).resolve()
        self.addCleanup(shutil.rmtree, plain, ignore_errors=True)
        self.assertEqual(git_audit.gitlinks(plain), set())


if __name__ == '__main__':
    unittest.main()
