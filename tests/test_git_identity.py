"""격리 홈에 git 작성자 신원(이름·이메일만)을 심는 회귀.

격리 홈에는 전역 gitconfig 가 없어 커밋 작성자가 `사용자@호스트명` 으로 잡히고, 에이전트가 `git config user.name` 으로
고치려다 잠긴 `.git/config` 에 막힌다(2026-09-15 AutoClaw 세션 실측). 호스트 `~/.gitconfig` 의 user.name/email 만 복사한
파일을 GIT_CONFIG_GLOBAL 로 주고, 그 파일은 자식이 못 바꾸게 잠근다.
"""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g


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
        # 저장소는 호스트에서 만든다(.git 생성은 잠긴 hooks/config 의 조상이라 샌드박스에서 막힌다, 의도).
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
