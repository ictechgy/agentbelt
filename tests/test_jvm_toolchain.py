"""JVM/Gradle 프로젝트(kartograph)가 격리 안에서 빌드·테스트되도록 하는 조건의 회귀.

실측(2026-09-15): JVM 은 `user.home` 을 $HOME 이 아니라 계정 DB 에서, `java.io.tmpdir` 을 $TMPDIR 이 아니라 Darwin
임시 디렉터리에서 얻어 둘 다 닫힌 경로에 쓴다. Gradle 은 데몬·파일 잠금 핸들러·Kotlin 데몬·테스트 워커가 임의 루프백
포트로 통신하므로 워크스페이스별 옵트인으로 루프백을 열어야 한다(Seatbelt 는 포트 범위를 받지 않는다).
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g
import environment_notice as notice


class EnvironmentTests(unittest.TestCase):
    def test_jvm_home_and_tmpdir_follow_the_isolated_home(self):
        with tempfile.TemporaryDirectory(prefix='jvm-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'; home.mkdir(mode=0o700)
            env = g.clean_environment(home, None)
            self.assertEqual(env['GRADLE_USER_HOME'], str(home / '.gradle'))
            self.assertIn('-Duser.home=' + str(home), env['JAVA_TOOL_OPTIONS'])
            self.assertIn('-Djava.io.tmpdir=' + str(home / 'tmp'), env['JAVA_TOOL_OPTIONS'])
            self.assertIn('-Dorg.gradle.vfs.watch=false', env['GRADLE_OPTS'])
            self.assertEqual(env['MAVEN_OPTS'], '-Duser.home=' + str(home) + ' -Djava.io.tmpdir=' + str(home / 'tmp'))

    def test_reviewed_package_domains_include_gradle_and_maven_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'state').mkdir()
            (root / 'state/development.json').write_text(json.dumps({'devPorts': [], 'packageDomains': [
                'services.gradle.org:443', 'repo.maven.apache.org:443', 'repo1.maven.org:443', 'plugins.gradle.org:443',
                'plugins-artifacts.gradle.org:443', 'dl.google.com:443', 'maven.google.com:443']}))
            with patch.object(g, 'ROOT', root):
                self.assertEqual(len(g.development_options()['packageDomains']), 7)
            (root / 'state/development.json').write_text(json.dumps({'devPorts': [], 'packageDomains': ['evil.example:443']}))
            with patch.object(g, 'ROOT', root), self.assertRaises(g.GuardError):
                g.development_options()


class LoopbackGrantTests(unittest.TestCase):
    def test_grant_is_per_workspace_and_off_by_default(self):
        with tempfile.TemporaryDirectory(prefix='lb-', dir=Path.home()) as tmp:
            root = Path(tmp) / 'root'; (root / 'state').mkdir(parents=True)
            project = Path(tmp) / 'proj'; project.mkdir(); other = Path(tmp) / 'other'; other.mkdir()
            with patch.object(g, 'ROOT', root):
                self.assertFalse(g.loopback_grant(project))
                (root / 'state/loopback-grants.json').write_text(json.dumps({'enabled': True, 'workspaces': [str(project)]}))
                self.assertTrue(g.loopback_grant(project))
                self.assertFalse(g.loopback_grant(other))
                (root / 'state/loopback-grants.json').write_text(json.dumps({'enabled': False, 'workspaces': [str(project)]}))
                self.assertFalse(g.loopback_grant(project))

    def test_run_confined_opens_loopback_only_when_asked(self):
        captured = {}
        original = g.sandbox_policy
        def spy(*args, **kwargs):
            captured['policy'] = original(*args, **kwargs); return captured['policy']
        with tempfile.TemporaryDirectory(prefix='lb-', dir=Path.home()) as tmp, patch.object(g, 'sandbox_policy', spy), \
             patch.object(g.subprocess, 'call', return_value=0):
            g.run_confined('exec', Path(tmp), ['/bin/true'], ephemeral=True)
            self.assertFalse(captured['policy']['network']['allowLocalBinding'])
            g.run_confined('exec', Path(tmp), ['/bin/true'], ephemeral=True, loopback_all=True)
            self.assertTrue(captured['policy']['network']['allowLocalBinding'])

    def test_notice_explains_open_loopback(self):
        env = {'HOME': '/tmp/h', 'TMPDIR': '/tmp/h/tmp', 'PUB_CACHE': '/tmp/h/.pub-cache', 'AGENT_GUARD_LOOPBACK_ALL': '1', 'XDG_CONFIG_HOME': '/tmp/h/.config'}
        policy = {'network': {'allowedDomains': [], 'allowLocalBinding': True}, 'filesystem': {'allowRead': [], 'allowWrite': [], 'denyWrite': []}}
        text = notice.render_environment_notice(Path('/tmp/w'), Path('/tmp/h'), env, policy)
        self.assertIn('루프백', text)
        self.assertIn('다른 로컬 서비스', text)
        self.assertIn('JAVA_HOME', text)

    def test_child_can_bind_and_connect_random_loopback_ports_when_granted(self):
        """Gradle 이 하는 일: 임의 포트에 바인드하고 그 포트로 자기 자신에게 접속한다."""
        script = ('import socket\n'
                  's = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); port = s.getsockname()[1]\n'
                  'c = socket.socket(); c.settimeout(5); c.connect(("127.0.0.1", port)); print("LOOPBACK_OK", port > 0)\n'
                  'u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 0)); print("UDP_OK")\n')
        with tempfile.TemporaryDirectory(prefix='lb-', dir=Path.home()) as tmp, tempfile.TemporaryFile() as out:
            status = g.run_confined('exec', Path(tmp), ['/usr/bin/python3', '-c', script], ephemeral=True, stdout=out, loopback_all=True)
            out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('LOOPBACK_OK True', text)
        self.assertIn('UDP_OK', text)

    def test_backends_pass_the_grant_through(self):
        captured = {}
        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured[mode] = kwargs; return 0
        with tempfile.TemporaryDirectory(prefix='lb-', dir=Path.home()) as tmp:
            import os
            previous = os.getcwd(); os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), patch.object(g, 'verify_zcode_binary', lambda: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                     patch.object(g, 'loopback_grant', lambda workspace: True):
                    self.assertEqual(g.main(['zcode-backend', 'app-server', '--stdio']), 0)
                    from riskgate_bridge import riskgate_decision  # noqa: F401  (모듈 존재 확인)
            finally:
                os.chdir(previous)
        self.assertTrue(captured['zcode']['loopback_all'])


class GradleKeystoreGrantTests(unittest.TestCase):
    """Gradle TestKit·configuration-cache 는 무결성 검증용 `gradle.keystore` 를 워크스페이스 안 build 아래에 만든다.

    그 파일명이 SECRET_NAMES 의 `*.keystore` 에 걸려 워크스페이스 안이어도 쓰기가 막혔다(오탐). 워크스페이스별
    옵트인으로 파일명 `gradle.keystore` 만 예외한다. 진짜 서명 키스토어(release.keystore·*.jks·debug.keystore)와
    다른 시크릿(.env 등)은 계속 보호된다.
    """
    def test_grant_is_per_workspace_and_off_by_default(self):
        with tempfile.TemporaryDirectory(prefix='ks-', dir=Path.home()) as tmp:
            root = Path(tmp) / 'root'; (root / 'state').mkdir(parents=True)
            project = Path(tmp) / 'proj'; project.mkdir(); other = Path(tmp) / 'other'; other.mkdir()
            with patch.object(g, 'ROOT', root):
                self.assertFalse(g.gradle_keystore_grant(project))
                (root / 'state/gradle-keystore-grants.json').write_text(json.dumps({'enabled': True, 'workspaces': [str(project)]}))
                self.assertTrue(g.gradle_keystore_grant(project))
                self.assertFalse(g.gradle_keystore_grant(other))
                (root / 'state/gradle-keystore-grants.json').write_text(json.dumps({'enabled': False, 'workspaces': [str(project)]}))
                self.assertFalse(g.gradle_keystore_grant(project))

    def test_run_confined_signals_keystore_root_only_when_granted(self):
        """옵트인 시에만 sandbox_runner 에 워크스페이스 realpath 를 넘긴다(그 안 gradle.keystore 만 re-allow).

        policy 의 denyWrite 는 그대로다(다른 keystore·시크릿 보호). 예외는 SBPL append 로만 하므로 env 신호가 전부다.
        """
        captured = {}
        def fake_call(argv, **kwargs):
            captured['env'] = kwargs.get('env', {}); return 0
        with tempfile.TemporaryDirectory(prefix='ks-', dir=Path.home()) as tmp, patch.object(g.subprocess, 'call', fake_call):
            work = Path(tmp)
            g.run_confined('exec', work, ['/bin/true'], ephemeral=True)
            self.assertNotIn('AGENT_GUARD_GRADLE_KEYSTORE_ROOT', captured['env'])
            g.run_confined('exec', work, ['/bin/true'], ephemeral=True, allow_gradle_keystore=True)
            self.assertEqual(captured['env'].get('AGENT_GUARD_GRADLE_KEYSTORE_ROOT'), str(work.resolve()))

    def test_granted_workspace_writes_gradle_keystore_but_not_other_secrets(self):
        """실 Seatbelt: 더 구체적인 allow 가 `*.keystore` deny 를 이겨 gradle.keystore 만 열린다."""
        work = Path(tempfile.mkdtemp(prefix='ks-real-', dir=Path.home())); self.addCleanup(lambda: __import__('shutil').rmtree(work, ignore_errors=True))
        nested = 'gradle-plugin/build/tmp/test/work/.gradle-test-kit/caches/9.6.1/cc-keystore'
        script = (
            'import os\n'
            f'base = {str(work)!r}\n'
            f'd = os.path.join(base, {nested!r})\n'
            'os.makedirs(d, exist_ok=True)\n'
            'open(os.path.join(d, "gradle.keystore"), "wb").write(b"K"); print("KEYSTORE_OK")\n'
            'print("KEYSTORE_READ", open(os.path.join(d, "gradle.keystore"), "rb").read() == b"K")\n'
            'try:\n'
            '    open(os.path.join(base, "release.keystore"), "wb").write(b"X"); print("RELEASE_WROTE")\n'
            'except OSError: print("RELEASE_DENIED")\n'
            'try:\n'
            '    open(os.path.join(base, ".env"), "wb").write(b"X"); print("ENV_WROTE")\n'
            'except OSError: print("ENV_DENIED")\n')
        with tempfile.TemporaryFile() as out:
            status = g.run_confined('exec', work, ['/usr/bin/python3', '-c', script], ephemeral=True,
                                    allow_gradle_keystore=True, stdout=out)
            out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('KEYSTORE_OK', text)
        self.assertIn('KEYSTORE_READ True', text)
        self.assertIn('RELEASE_DENIED', text)
        self.assertIn('ENV_DENIED', text)

    def test_gradle_keystore_denied_without_grant(self):
        """옵트인 없으면 워크스페이스 안 gradle.keystore 도 여전히 막힌다(현행 보호 유지)."""
        work = Path(tempfile.mkdtemp(prefix='ks-nogrant-', dir=Path.home())); self.addCleanup(lambda: __import__('shutil').rmtree(work, ignore_errors=True))
        script = (
            'import os\n'
            f'base = {str(work)!r}\n'
            'try:\n'
            '    open(os.path.join(base, "gradle.keystore"), "wb").write(b"K"); print("KEYSTORE_WROTE")\n'
            'except OSError: print("KEYSTORE_DENIED")\n')
        with tempfile.TemporaryFile() as out:
            status = g.run_confined('exec', work, ['/usr/bin/python3', '-c', script], ephemeral=True, stdout=out)
            out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('KEYSTORE_DENIED', text)

    def test_coding_backends_pass_the_keystore_grant_through(self):
        captured = {}
        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured[mode] = kwargs; return 0
        with tempfile.TemporaryDirectory(prefix='ks-', dir=Path.home()) as tmp:
            import os
            previous = os.getcwd(); os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), patch.object(g, 'verify_zcode_binary', lambda: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                     patch.object(g, 'gradle_keystore_grant', lambda workspace: True):
                    self.assertEqual(g.main(['zcode-backend', 'app-server', '--stdio']), 0)
            finally:
                os.chdir(previous)
        self.assertTrue(captured['zcode']['allow_gradle_keystore'])


if __name__ == '__main__':
    unittest.main()
