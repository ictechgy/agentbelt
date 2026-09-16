"""AutoClaw(z.ai) 코딩 런타임을 Zcode 백엔드와 같은 격리로 감싸는지 확인하는 회귀.

AutoClaw 는 zcode-runtime 플러그인 설정의 `command` 를 우리 런처로 바꾸면 번들 Zcode CLI 대신
런처를 띄운다(`command version` 프로브 → `command agent-server`, cwd=워크스페이스). 모델 자격 증명은
게이트웨이의 루프백 모델 브로커가 들고 있으므로 자식에게는 브로커 포트 하나만 열어 준다.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g

BROKER_ENV = {'AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL': 'http://127.0.0.1:43210/internal/model-proxy/v1',
              'AUTOCLAW_MODEL_BROKER_ANTHROPIC_BASE_URL': 'http://127.0.0.1:43210/internal/model-proxy/anthropic/v1'}


def synthetic_autoclaw(root, app_version='1.18.5', cli_version='0.15.2', binary=b'synthetic zcode'):
    """가짜 AutoClaw 앱 번들과 그에 맞는 가드 프로필·기준선을 만든다. 실제 앱은 건드리지 않는다."""
    import plistlib
    app = root / 'AutoClaw.app'
    (app / 'Contents/Resources/zcode/darwin-arm64').mkdir(parents=True)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': app_version}))
    executable = app / 'Contents/Resources/zcode/darwin-arm64/zcode'
    executable.write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    (app / 'Contents/Resources/zcode/manifest.json').write_text(json.dumps(
        {'zcodeCliVersion': cli_version, 'artifacts': {'darwin-arm64': {'file': 'darwin-arm64/zcode', 'sha256': digest}}}))
    state = root / 'state'
    state.mkdir(exist_ok=True, mode=0o700)
    state.chmod(0o700)
    (state / 'autoclaw-profile.json').write_text(json.dumps(
        {'domains': [], 'reviewedAppVersion': app_version, 'zcodeCliVersion': cli_version}))
    (state / 'compatibility.json').write_text(json.dumps(
        {'autoclaw': {'version': app_version, 'zcodeCliVersion': cli_version, 'zcodeSha256': digest}}))
    return app


class BrokerPortTests(unittest.TestCase):
    def test_accepts_matching_loopback_broker_urls(self):
        self.assertEqual(g.autoclaw_broker_port(BROKER_ENV), 43210)

    def test_rejects_missing_or_inconsistent_broker_urls(self):
        cases = [
            {},
            dict(BROKER_ENV, AUTOCLAW_MODEL_BROKER_ANTHROPIC_BASE_URL='http://127.0.0.1:43211/internal/model-proxy/anthropic/v1'),
            dict(BROKER_ENV, AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL='http://localhost:43210/internal/model-proxy/v1'),
            dict(BROKER_ENV, AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL='https://127.0.0.1:43210/internal/model-proxy/v1'),
            dict(BROKER_ENV, AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL='http://127.0.0.1:43210/other'),
            dict(BROKER_ENV, AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL='http://127.0.0.1:80/internal/model-proxy/v1'),
        ]
        for env in cases:
            with self.assertRaises(g.GuardError, msg=env):
                g.autoclaw_broker_port(env)


    def test_out_of_range_port_is_a_guard_error(self):
        with self.assertRaises(g.GuardError):
            g.autoclaw_broker_port({'AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL': 'http://127.0.0.1:99999/internal/model-proxy/v1',
                                    'AUTOCLAW_MODEL_BROKER_ANTHROPIC_BASE_URL': 'http://127.0.0.1:99999/internal/model-proxy/anthropic/v1'})

    def test_broker_listener_must_belong_to_autoclaw(self):
        """포트 모양만 맞다고 열지 않는다. 그 포트를 듣는 프로세스가 AutoClaw 앱 안의 실행 파일이어야 한다."""
        import socket
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            port = listener.getsockname()[1]
            with self.assertRaises(g.GuardError):
                g.verify_broker_owner(port)
            with patch.object(g, 'listener_executables', lambda port: ['/Applications/AutoClaw.app/Contents/Resources/node/darwin-arm64/node']):
                g.verify_broker_owner(port)
            with patch.object(g, 'listener_executables', lambda port: []):
                with self.assertRaises(g.GuardError):
                    g.verify_broker_owner(port)
            with patch.object(g, 'listener_executables', lambda port: ['/Applications/AutoClaw.app/../Evil.app/x', '/Applications/AutoClaw.app/Contents/Resources/node/darwin-arm64/node']):
                with self.assertRaises(g.GuardError):
                    g.verify_broker_owner(port)
            # 실행 파일 경로를 못 구한 리스너가 하나라도 있으면 닫힌다(빈 경로를 조용히 버리지 않는다).
            with patch.object(g, 'listener_executables', lambda port: ['/Applications/AutoClaw.app/Contents/Resources/node/darwin-arm64/node', '']):
                with self.assertRaises(g.GuardError):
                    g.verify_broker_owner(port)

    def test_listener_query_covers_every_address_and_keeps_unresolved_pids(self):
        """lsof 는 주소 필터 없이 포트 전체를 보고, proc_pidpath 실패는 빈 문자열로 남겨 게이트가 닫히게 한다."""
        import socket
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            port = listener.getsockname()[1]
            paths = g.listener_executables(port)
            self.assertEqual(len(paths), 1)
            self.assertTrue(paths[0].endswith('/Python') or 'python' in paths[0].lower())
            with patch.object(g, 'executable_path', lambda pid: ''):
                self.assertEqual(g.listener_executables(port), [''])


class BinaryVerificationTests(unittest.TestCase):
    def test_accepts_the_reviewed_bundle_and_rejects_any_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = synthetic_autoclaw(root)
            with patch.object(g, 'ROOT', root), patch.object(g, 'AUTOCLAW_APP', app):
                self.assertEqual(g.verify_autoclaw_binary(), '0.15.2')
                (app / 'Contents/Resources/zcode/darwin-arm64/zcode').write_bytes(b'updated zcode')
                with self.assertRaises(g.GuardError):
                    g.verify_autoclaw_binary()

    def test_rejects_an_unreviewed_app_version_even_with_the_same_binary(self):
        import plistlib
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = synthetic_autoclaw(root)
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': '1.19.0'}))
            with patch.object(g, 'ROOT', root), patch.object(g, 'AUTOCLAW_APP', app):
                with self.assertRaises(g.GuardError):
                    g.verify_autoclaw_binary()

    def test_manifest_cannot_redirect_the_hash_to_another_file(self):
        """매니페스트의 file 항목이 다른 파일을 가리켜도 실행될 바이너리 자체를 대조해야 한다(리뷰 CRITICAL)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = synthetic_autoclaw(root)
            binaries = app / 'Contents/Resources/zcode/darwin-arm64'
            (binaries / 'zcode.bak').write_bytes(b'synthetic zcode')
            (binaries / 'zcode').write_bytes(b'MALICIOUS')
            manifest_path = app / 'Contents/Resources/zcode/manifest.json'
            manifest = json.loads(manifest_path.read_text())
            manifest['artifacts']['darwin-arm64']['file'] = 'darwin-arm64/zcode.bak'
            manifest_path.write_text(json.dumps(manifest))
            with patch.object(g, 'ROOT', root), patch.object(g, 'AUTOCLAW_APP', app), \
                 patch.object(g, 'AUTOCLAW_ZCODE', binaries / 'zcode'):
                with self.assertRaises(g.GuardError):
                    g.verify_autoclaw_binary()

    def test_staged_copy_is_hashed_and_guard_owned(self):
        """실행 파일은 가드 소유 복제본이며 복제 뒤 해시를 다시 대조한다(검증→실행 사이 교체 방지)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = synthetic_autoclaw(root)
            (root / 'state').chmod(0o700)
            source = app / 'Contents/Resources/zcode/darwin-arm64/zcode'
            with patch.object(g, 'ROOT', root), patch.object(g, 'AUTOCLAW_APP', app), patch.object(g, 'AUTOCLAW_ZCODE', source):
                staged = g.stage_autoclaw_binary()
                self.assertEqual(staged.read_bytes(), b'synthetic zcode')
                self.assertTrue(str(staged).startswith(str(root / 'state/autoclaw-runtime/')))
                self.assertEqual(staged.stat().st_mode & 0o777, 0o500)
                # 실행마다 전용 디렉터리라 동시 실행이 서로의 복제본을 지우지 못한다.
                other = g.stage_autoclaw_binary()
                self.assertNotEqual(staged.parent, other.parent)
                self.assertTrue(staged.exists())
                g.discard_staged_binary(other)
                self.assertFalse(other.parent.exists())
                source.write_bytes(b'MALICIOUS')
                with self.assertRaises(g.GuardError):
                    g.stage_autoclaw_binary()
                self.assertEqual(staged.read_bytes(), b'synthetic zcode')
                leftovers = [p for p in (root / 'state/autoclaw-runtime').iterdir() if p != staged.parent]
                self.assertEqual(leftovers, [])
                # 소유자가 죽은(SIGTERM 으로 정리 없이 끝난) 전용 디렉터리는 다음 스테이징이 회수한다.
                dead = root / 'state/autoclaw-runtime/launch-999999999-dead'; dead.mkdir(); (dead / 'zcode').write_bytes(b'old')
                source.write_bytes(b'synthetic zcode')
                fresh = g.stage_autoclaw_binary()
                self.assertFalse(dead.exists())
                self.assertTrue(staged.exists())  # 살아 있는 소유자(현재 프로세스)의 것은 남는다
                g.discard_staged_binary(fresh); g.discard_staged_binary(staged)

    def test_fails_closed_without_a_recorded_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = synthetic_autoclaw(root)
            (root / 'state/compatibility.json').write_text(json.dumps({'opencode': {}}))
            with patch.object(g, 'ROOT', root), patch.object(g, 'AUTOCLAW_APP', app):
                with self.assertRaises(g.GuardError):
                    g.verify_autoclaw_binary()


class LauncherTests(unittest.TestCase):
    def setUp(self):
        # 테스트가 실제 `state/runtime/autoclaw-launches.log`(사고 판독 근거)에 줄을 남기면 안 된다. 헬퍼가 여기로 돌린다.
        self.logged_stages = []

    def run_backend(self, argv, env, captured, broker_owner=lambda port: None):
        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, mode=mode, workspace=workspace, command=command, args=args)
            return 0
        with tempfile.TemporaryDirectory(prefix='autoclaw-', dir=Path.home()) as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'runtime_status', lambda name, value: None), \
                     patch.object(g, 'record_launch_stage', lambda name, cwd: self.logged_stages.append(name)), \
                     patch.object(g, 'verify_autoclaw_binary', lambda: '0.15.2'), \
                     patch.object(g, 'stage_autoclaw_binary', lambda: Path('/synthetic/state/autoclaw-runtime/zcode')), \
                     patch.object(g, 'verify_broker_owner', broker_owner), \
                     patch.object(g, 'autoclaw_profile', lambda: {'domains': [], 'reviewedAppVersion': '1.18.5', 'zcodeCliVersion': '0.15.2'}), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                     patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': ['pub.dev:443']}), \
                     patch.dict(os.environ, env, clear=False):
                    for name in BROKER_ENV:
                        if name not in env:
                            os.environ.pop(name, None)
                    return g.main(['autoclaw-backend', *argv]), Path(tmp)
            finally:
                os.chdir(previous)

    def test_version_probe_answers_with_the_verified_cli_version_without_running_the_binary(self):
        import io
        captured = {}
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            status, _ = self.run_backend(['version'], {}, captured)
        self.assertEqual(status, 0)
        self.assertEqual(out.getvalue().split()[-1], '0.15.2')
        self.assertNotIn('command', captured)
        # 프로브까지 기록하면 로그가 "python-start 뒤 started 없음" 으로 읽혀 사고 판독을 망친다.
        self.assertEqual(self.logged_stages, [])

    def test_agent_server_call_detection_matches_the_launcher_shell(self):
        """셸 런처(`[ "$1" = agent-server ]`)와 같은 기준이어야 `sh-start` 없는 `python-start` 를 셸 손실로 오독하지 않는다."""
        self.assertTrue(g.is_autoclaw_agent_server_call(['autoclaw-backend', 'agent-server']))
        self.assertTrue(g.is_autoclaw_agent_server_call(['autoclaw-backend', 'agent-server', '--extra']))
        for arguments in [['autoclaw-backend', 'version'], ['autoclaw-backend', '--', 'agent-server'], ['autoclaw-backend'], ['zcode-backend', 'agent-server'], []]:
            self.assertFalse(g.is_autoclaw_agent_server_call(arguments), arguments)

    def test_agent_server_runs_the_bundled_cli_confined_with_only_the_broker_port(self):
        captured = {}
        status, workspace = self.run_backend(['agent-server'], BROKER_ENV, captured)
        self.assertEqual(status, 0)
        self.assertEqual(captured['mode'], 'autoclaw')
        self.assertEqual(captured['workspace'], workspace.resolve())
        self.assertEqual(captured['command'], ['/synthetic/state/autoclaw-runtime/zcode', 'agent-server'])
        self.assertIn('/synthetic/state/autoclaw-runtime/zcode', [str(p) for p in captured['extra_reads']])
        self.assertEqual(sorted(captured['read_only_workspace_paths']), ['.agents/mcp.json', '.zcode', 'zcode.json'])
        self.assertEqual(captured['extra_env']['AGENT_GUARD_BROKER_PORT'], '43210')
        self.assertEqual(captured['args'][0], ['pub.dev:443'])
        # 저장소 범위 GitHub 토큰은 safecode·Zcode Safe 와 같이 주입한다(2026-09-15 사용자 결정). yolo 라 push 도 확인 없이 된다.
        self.assertTrue(captured['github'])
        self.assertIn('push', captured['notice_extra'])
        self.assertNotIn(str(g.AUTOCLAW_APP), [str(p) for p in captured['extra_reads']])
        self.assertIn('.zcode/cli/config.json', captured['read_only_home_paths'])
        self.assertEqual(list(captured['instruction_files']), ['.zcode/AGENTS.md'])
        self.assertTrue(captured['private_sockets'])
        self.assertTrue(captured['loopback_port'])
        self.assertIn('AutoClaw', captured['notice_extra'])
        with tempfile.TemporaryDirectory(prefix='autoclaw-home-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'synthetic-home'
            home.mkdir()
            env = {'PATH': '/usr/bin'}
            captured['prepare_home'](home, env)
            self.assertTrue((home / '.zcode/cli').is_dir())
        self.assertEqual(env['AGENT_GUARD_BOOTSTRAP'], 'zcode')
        self.assertEqual(env['AGENT_GUARD_BACKEND'], 'zcode-v1')
        self.assertEqual(env['ZCODE_HOME'], str(home / '.zcode'))

    def test_agent_server_discards_the_staged_copy_and_writes_a_receipt_on_failure(self):
        """실패해도 복제본을 치우고 exit 영수증을 남긴다(AutoClaw 가 죽은 세션을 살아 있다고 보지 않게)."""
        receipts = {}
        def failing_run_confined(*args, **kwargs):
            raise g.GuardError('synthetic launch failure')
        with tempfile.TemporaryDirectory(prefix='autoclaw-fail-', dir=Path.home()) as tmp:
            staged_dir = Path(tempfile.mkdtemp(prefix='launch-test-', dir=str(g.private_dir(ROOT / 'state/autoclaw-runtime'))))
            staged = staged_dir / 'zcode'; staged.write_bytes(b'x')
            previous = os.getcwd(); os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', failing_run_confined), patch.object(g, 'verify_autoclaw_binary', lambda: '0.15.2'), \
                     patch.object(g, 'autoclaw_profile', lambda: {'domains': []}), \
                     patch.object(g, 'runtime_status', lambda name, value: receipts.__setitem__(name, value)), \
                     patch.object(g, 'record_launch_stage', lambda name, cwd: None), \
                     patch.object(g, 'stage_autoclaw_binary', lambda: staged), patch.object(g, 'verify_broker_owner', lambda port: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), patch.dict(os.environ, BROKER_ENV):
                    with self.assertRaises(g.GuardError):
                        g.main(['autoclaw-backend', 'agent-server'])
            finally:
                os.chdir(previous)
            self.assertEqual(receipts['autoclaw-exit.json']['exit_code'], 'error')
            self.assertFalse(staged_dir.exists())

    def test_agent_server_refuses_a_broker_port_owned_by_another_process(self):
        captured = {}
        def refuse(port):
            raise g.GuardError('not autoclaw')
        with self.assertRaises(g.GuardError):
            self.run_backend(['agent-server'], BROKER_ENV, captured, broker_owner=refuse)
        self.assertNotIn('command', captured)

    def test_agent_server_records_each_stage_before_the_sandbox_starts(self):
        """핸드셰이크 한도 안에 못 뜨면 어느 단계에서 멈췄는지 알 수 있어야 한다(isthmus 30초 침묵 사고).
        `python-start` 는 argparse 이전에 남겨 런처 셸 `sh-start` 와 `started` 사이(셔틀·인터프리터 기동)를 가른다."""
        import argparse
        stages = []
        logged = []
        def record(name, value):
            if name == 'autoclaw-stage.json': stages.append(value['stage'])
        captured = {}
        original_parse = argparse.ArgumentParser.parse_args
        def parse_args(parser, *args, **kwargs):
            stages.append('argparse'); return original_parse(parser, *args, **kwargs)
        with patch.object(g, 'runtime_status', record), patch.object(g, 'record_launch_stage', lambda name, cwd: logged.append(name)), \
             patch.object(argparse.ArgumentParser, 'parse_args', parse_args):
            def fake_run_confined(mode, workspace, command, *args, **kwargs):
                captured['ok'] = True; return 0
            with tempfile.TemporaryDirectory(prefix='autoclaw-stage-', dir=Path.home()) as tmp:
                previous = os.getcwd(); os.chdir(tmp)
                try:
                    with patch.object(g, 'run_confined', fake_run_confined), patch.object(g, 'verify_autoclaw_binary', lambda: '0.15.2'), \
                         patch.object(g, 'autoclaw_profile', lambda: {'domains': []}), patch.object(g, 'stage_autoclaw_binary', lambda: Path('/synthetic/zcode')), \
                         patch.object(g, 'verify_broker_owner', lambda port: None), patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                         patch.object(g, 'packet_relay_settings', lambda: None), patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                         patch.dict(os.environ, BROKER_ENV):
                        self.assertEqual(g.main(['autoclaw-backend', 'agent-server']), 0)
                finally:
                    os.chdir(previous)
        self.assertEqual(stages, ['python-start', 'argparse', 'started', 'verified', 'broker-checked', 'workspace-checked', 'staged', 'launching'])
        self.assertEqual(logged, [stage for stage in stages if stage != 'argparse'])

    def test_launch_log_keeps_one_line_per_stage_across_attempts(self):
        """마지막 시도가 덮어쓰는 영수증과 달리, 시도별 기록이 남아야 실패 지점을 나중에 볼 수 있다."""
        with tempfile.TemporaryDirectory(prefix='launchlog-', dir=Path.home()) as tmp:
            root = Path(tmp); (root / 'state').mkdir(mode=0o700)
            with patch.object(g, 'ROOT', root):
                g.record_launch_stage('started', '/w/one'); g.record_launch_stage('verified', '/w/one'); g.record_launch_stage('started', '/w/two')
                lines = (root / 'state/runtime/autoclaw-launches.log').read_text().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn('started', lines[0]); self.assertIn(str(os.getpid()), lines[0]); self.assertIn('/w/two', lines[2])
            self.assertEqual((root / 'state/runtime/autoclaw-launches.log').stat().st_mode & 0o777, 0o600)

    def test_launch_log_rotation_keeps_the_recent_tail(self):
        """200 KB 절단이 같은 기동의 `sh-start` 까지 지우면 "python-start 는 있는데 sh-start 없음" 으로 오독된다. 꼬리를 남긴다."""
        with tempfile.TemporaryDirectory(prefix='launchlog-', dir=Path.home()) as tmp:
            root = Path(tmp); (root / 'state/runtime').mkdir(parents=True, mode=0o700)
            log = root / 'state/runtime/autoclaw-launches.log'
            filler = ''.join('2026-01-01T00:00:00 pid=1 stage=launching cwd=/w/old-%06d\n' % i for i in range(4000))
            log.write_text(filler + '2026-09-15T12:00:00 pid=7 stage=sh-start cwd=/w/current\n')
            self.assertGreater(log.stat().st_size, 200 * 1024)
            with patch.object(g, 'ROOT', root):
                g.record_launch_stage('python-start', '/w/current')
            lines = log.read_text().splitlines()
            self.assertLess(log.stat().st_size, 32 * 1024)
            self.assertIn('stage=sh-start cwd=/w/current', lines[-2])
            self.assertIn('stage=python-start cwd=/w/current', lines[-1])
            self.assertTrue(all(line.startswith('2026-') for line in lines), lines[:2])
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_launch_log_escapes_control_characters_in_cwd(self):
        """cwd 의 개행이 레코드를 두 줄로 쪼개면 판독 도구가 가짜 단계를 본다. `python-start` 는 workspace_path 검사 이전에 기록된다."""
        with tempfile.TemporaryDirectory(prefix='launchlog-', dir=Path.home()) as tmp:
            root = Path(tmp); (root / 'state').mkdir(mode=0o700)
            with patch.object(g, 'ROOT', root):
                g.record_launch_stage('python-start', '/w/a\nb\x1b[0m')
            lines = (root / 'state/runtime/autoclaw-launches.log').read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].endswith(' cwd=/w/a\\nb\\x1b[0m'), lines[0])

    def test_agent_server_refuses_to_start_without_the_broker(self):
        captured = {}
        with self.assertRaises(g.GuardError):
            self.run_backend(['agent-server'], {}, captured)
        self.assertNotIn('command', captured)

    def test_other_arguments_are_refused(self):
        captured = {}
        for argv in [[], ['agent-server', '--extra'], ['shell'], ['version', 'x']]:
            with self.assertRaises(g.GuardError, msg=argv):
                self.run_backend(argv, BROKER_ENV, captured)
        self.assertNotIn('command', captured)


class WorkspaceConfigLockTests(unittest.TestCase):
    def test_child_cannot_plant_workspace_zcode_config(self):
        """워크스페이스 `.zcode/config.json`·`zcode.json` 은 훅을 끄거나 MCP 를 붙일 수 있어 자식이 만들지 못해야 한다."""
        with tempfile.TemporaryDirectory(prefix='wscfg-', dir=Path.home()) as tmp:
            script = ('mkdir -p .zcode && echo PLANT_DIR_OK || echo PLANT_DIR_DENIED; '
                      'echo x > zcode.json && echo PLANT_FILE_OK || echo PLANT_FILE_DENIED; '
                      'mkdir -p staging && echo x > staging/config.json && mv staging .zcode && echo RENAME_OK || echo RENAME_DENIED; '
                      'echo ok > allowed.txt && echo ALLOWED_OK')
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', Path(tmp), ['/bin/bash', '-c', script], ephemeral=True, stdout=out,
                                        read_only_workspace_paths=['.zcode', 'zcode.json', '.agents/mcp.json'])
                out.seek(0); text = out.read().decode(errors='replace')
            self.assertEqual(status, 0, text)
            for marker in ['PLANT_DIR_DENIED', 'PLANT_FILE_DENIED', 'RENAME_DENIED', 'ALLOWED_OK']:
                self.assertIn(marker, text)
            self.assertFalse((Path(tmp) / '.zcode').exists())
            self.assertFalse((Path(tmp) / 'zcode.json').exists())

    def test_zcode_backend_locks_the_same_workspace_paths(self):
        captured = {}
        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs); return 0
        with tempfile.TemporaryDirectory(prefix='zcode-wscfg-', dir=Path.home()) as tmp:
            previous = os.getcwd(); os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), patch.object(g, 'verify_zcode_binary', lambda: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                     patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}):
                    self.assertEqual(g.main(['zcode-backend', 'app-server', '--stdio']), 0)
            finally:
                os.chdir(previous)
        self.assertEqual(sorted(captured['read_only_workspace_paths']), ['.agents/mcp.json', '.zcode', 'zcode.json'])


class LoopbackBoundaryTests(unittest.TestCase):
    def test_child_reaches_only_the_broker_port(self):
        """브로커 포트는 직접 연결되고, 같은 루프백의 다른 리스너에는 연결이 거부된다(정책이 포트 하나로 묶였는지 실측)."""
        import socket, threading
        broker = socket.socket(); broker.bind(('127.0.0.1', 0)); broker.listen(5)
        other = socket.socket(); other.bind(('127.0.0.1', 0)); other.listen(5)
        accepted = []
        def serve(listener, tag):
            listener.settimeout(20)
            try:
                conn, _ = listener.accept(); accepted.append(tag); conn.close()
            except OSError:
                pass
        threads = [threading.Thread(target=serve, args=(broker, 'broker'), daemon=True), threading.Thread(target=serve, args=(other, 'other'), daemon=True)]
        for t in threads: t.start()
        script = ('import socket, os\n'
                  'def probe(port):\n'
                  '    s = socket.socket(); s.settimeout(5)\n'
                  '    try:\n        s.connect(("127.0.0.1", port)); return "OPEN"\n'
                  '    except OSError as e:\n        return "DENIED" if e.errno in (1, 13) else "ERR" + str(e.errno)\n'
                  '    finally:\n        s.close()\n'
                  'print("BROKER=" + probe(int(os.environ["AGENT_GUARD_BROKER_PORT"])))\n'
                  'print("OTHER=" + probe(int(os.environ["OTHER_PORT"])))\n')
        try:
            with tempfile.TemporaryDirectory(prefix='loopback-', dir=Path.home()) as tmp, tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', Path(tmp), ['/usr/bin/python3', '-c', script], ephemeral=True, stdout=out,
                                        extra_env={'AGENT_GUARD_BROKER_PORT': str(broker.getsockname()[1]), 'OTHER_PORT': str(other.getsockname()[1])})
                out.seek(0); text = out.read().decode(errors='replace')
        finally:
            broker.close(); other.close()
        self.assertEqual(status, 0, text)
        self.assertIn('BROKER=OPEN', text)
        self.assertIn('OTHER=DENIED', text)
        self.assertEqual(accepted, ['broker'])


class ShortTempDirTests(unittest.TestCase):
    def test_child_can_bind_a_unix_socket_under_a_short_tmpdir(self):
        """번들 CLI 는 `$TMPDIR/znr-<uuid>.sock` 을 바인드한다. 격리 홈 tmp(88자)로는 sun_path 한도(104)를 넘어 EINVAL 로 죽었다."""
        script = ('import os, socket, uuid; p = os.path.join(os.environ["TMPDIR"], "znr-" + str(uuid.uuid4()) + ".sock"); '
                  'print("TMPDIR_LEN", len(os.environ["TMPDIR"])); s = socket.socket(socket.AF_UNIX); s.bind(p); print("BIND_OK"); '
                  'open(os.path.join(os.environ["TMPDIR"], "note.txt"), "w").write("x"); print("WRITE_OK")')
        with tempfile.TemporaryDirectory(prefix='shorttmp-', dir=Path.home()) as tmp:
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('autoclaw-test', Path(tmp), ['/usr/bin/python3', '-c', script], ephemeral=True,
                                        private_sockets=True, short_tmpdir=True, stdout=out)
                out.seek(0); text = out.read().decode(errors='replace')
            self.assertEqual(status, 0, text)
            self.assertIn('BIND_OK', text)
            self.assertIn('WRITE_OK', text)
            length = int(text.split('TMPDIR_LEN ')[1].split()[0])
            self.assertLessEqual(length, 57)
            self.assertFalse((ROOT / 'state/t' / hashlib.sha256(('autoclaw-test\0' + str(Path(tmp).resolve())).encode()).hexdigest()[:7]).exists())

    def test_relay_follows_the_short_tmpdir(self):
        from packet_relay import PacketRelay
        with tempfile.TemporaryDirectory(prefix='relaytmp-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'; home.mkdir()
            short = Path(tmp) / 't'; short.mkdir()
            relay = PacketRelay(Path(tmp), home)
            env = {'PATH': '/usr/bin', 'TMPDIR': str(short)}
            relay.prepare(home, env)
            self.assertEqual(relay.requests, short / 'packet-requests')
            self.assertTrue((short / 'packet-requests').is_dir())
            # 결과·오류 파일도 그 디렉터리에 써져야 한다(격리 홈 기준 상대 경로를 요구하면 ValueError 로 중계가 죽는다).
            relay._write(relay.requests / 'r1.result.md', 'answer')
            self.assertEqual((short / 'packet-requests/r1.result.md').read_text(), 'answer')
            self.assertEqual(sorted(p.name for p in (short / 'packet-requests').iterdir()), ['r1.result.md'])

    def test_autoclaw_backend_requests_the_short_tmpdir(self):
        captured = {}
        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs); return 0
        with tempfile.TemporaryDirectory(prefix='autoclaw-tmp-', dir=Path.home()) as tmp:
            previous = os.getcwd(); os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), patch.object(g, 'verify_autoclaw_binary', lambda: '0.15.2'), \
                     patch.object(g, 'autoclaw_profile', lambda: {'domains': []}), patch.object(g, 'runtime_status', lambda n, v: None), \
                     patch.object(g, 'record_launch_stage', lambda name, cwd: None), \
                     patch.object(g, 'stage_autoclaw_binary', lambda: Path('/synthetic/zcode')), patch.object(g, 'verify_broker_owner', lambda port: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), patch.dict(os.environ, BROKER_ENV):
                    self.assertEqual(g.main(['autoclaw-backend', 'agent-server']), 0)
            finally:
                os.chdir(previous)
        self.assertTrue(captured['short_tmpdir'])


class GithubOptOutTests(unittest.TestCase):
    def test_run_confined_can_withhold_the_github_token(self):
        seen = {}
        def fake_clean(home, github=None):
            seen['github'] = github
            return {'HOME': str(home), 'PATH': '/usr/bin:/bin'}
        with tempfile.TemporaryDirectory(prefix='gh-', dir=Path.home()) as tmp, \
             patch.object(g, 'github_token', lambda: 'synthetic-token'), \
             patch.object(g, 'clean_environment', fake_clean), \
             patch.object(g.subprocess, 'call', return_value=0):
            g.run_confined('exec', Path(tmp), ['/bin/true'], ephemeral=True, github=False)
            self.assertIsNone(seen['github'])
            g.run_confined('exec', Path(tmp), ['/bin/true'], ephemeral=True)
            self.assertEqual(seen['github'], 'synthetic-token')


class StaleCredentialTests(unittest.TestCase):
    def test_withholding_github_removes_credentials_left_by_an_earlier_launch(self):
        with tempfile.TemporaryDirectory(prefix='cred-', dir=Path.home()) as tmp:
            home = Path(tmp) / 'home'; home.mkdir(mode=0o700)
            env = g.clean_environment(home, 'synthetic-token')
            self.assertTrue((home / '.git-credentials').is_file())
            self.assertEqual(env['GH_TOKEN'], 'synthetic-token')
            env = g.clean_environment(home, None)
            self.assertFalse((home / '.git-credentials').exists())
            self.assertNotIn('GH_TOKEN', env)


class RunnerBrokerProxyTests(unittest.TestCase):
    def test_zcode_config_bypasses_the_proxy_for_loopback_when_a_broker_port_is_granted(self):
        with tempfile.TemporaryDirectory(prefix='broker-noproxy-', dir=Path.home()) as tmp:
            def prepare(home, env):
                g.private_dir(g.private_dir(home / '.zcode') / 'cli')
                env.update({'AGENT_GUARD_BOOTSTRAP': 'zcode', 'AGENT_GUARD_BROKER_PORT': '43210'})
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', Path(tmp), ['/bin/sh', '-c', 'cat "$HOME/.zcode/cli/config.json"'], ephemeral=True,
                                        prepare_home=prepare, extra_reads=[ROOT / 'state/zcode-agent-config.json'],
                                        stdout=out, extra_env={'AGENT_GUARD_BROKER_PORT': '43210'})
                out.seek(0)
                text = out.read().decode(errors='replace')
            self.assertEqual(status, 0, text)
            config = json.loads(text[text.index('{'):])
            self.assertEqual(config['network']['noProxy'], '127.0.0.1,localhost')

    def test_zcode_config_keeps_loopback_proxied_without_a_broker(self):
        with tempfile.TemporaryDirectory(prefix='nobroker-', dir=Path.home()) as tmp:
            def prepare(home, env):
                g.private_dir(g.private_dir(home / '.zcode') / 'cli')
                env.update({'AGENT_GUARD_BOOTSTRAP': 'zcode'})
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', Path(tmp), ['/bin/sh', '-c', 'cat "$HOME/.zcode/cli/config.json"'], ephemeral=True,
                                        prepare_home=prepare, extra_reads=[ROOT / 'state/zcode-agent-config.json'], stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
            self.assertEqual(status, 0, text)
            config = json.loads(text[text.index('{'):])
            self.assertEqual(config['network']['noProxy'], '')


class InstallerTests(unittest.TestCase):
    def test_installer_points_the_plugin_at_the_launcher_and_keeps_everything_else(self):
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            root = home / 'guard'
            (root / 'state').mkdir(parents=True, mode=0o700)
            app = synthetic_autoclaw(root)
            (root / 'state/compatibility.json').write_text(json.dumps({'opencode': {'version': 'x'}}))
            state_dir = home / '.openclaw-autoclaw'
            state_dir.mkdir()
            original = {'meta': {'x': 1}, 'models': {'providers': {'zai': {'apiKey': 'SYNTHETIC'}}},
                        'plugins': {'entries': {'other': {'enabled': True},
                                                'zcode-runtime': {'enabled': True, 'config': {'runtimeEnabled': True}}}}}
            (state_dir / 'openclaw.json').write_text(json.dumps(original))
            (home / '.local/bin').mkdir(parents=True)
            with patch.object(installer, 'HOME', home), patch.object(installer, 'ROOT', root), \
                 patch.object(installer, 'STATE', root / 'state'), patch.object(installer, 'OPENCLAW_STATE', state_dir), \
                 patch.object(installer.agent_guard, 'ROOT', root), patch.object(installer.agent_guard, 'AUTOCLAW_APP', app):
                installer.main()
                updated = json.loads((state_dir / 'openclaw.json').read_text())
                plugin = updated['plugins']['entries']['zcode-runtime']
                self.assertEqual(plugin['config']['command'], str(home / '.local/bin/autoclaw-zcode-safe'))
                self.assertEqual(plugin['config']['args'], [])
                self.assertEqual(sorted(plugin['config']['envPassthrough']), sorted(BROKER_ENV))
                # 큰 워크스페이스의 하드링크 검사(25초)와 첫 기동이 기본 30초 핸드셰이크를 넘기므로 3분으로 올린다.
                self.assertEqual(plugin['config']['requestTimeoutMs'], 180000)
                self.assertTrue(plugin['config']['runtimeEnabled'])
                self.assertTrue(plugin['enabled'])
                self.assertEqual(updated['models'], original['models'])
                self.assertEqual(updated['meta'], original['meta'])
                self.assertEqual(updated['plugins']['entries']['other'], {'enabled': True})
                launcher = home / '.local/bin/autoclaw-zcode-safe'
                self.assertEqual(launcher.stat().st_mode & 0o777, 0o700)
                self.assertIn(str(root / 'agent_guard.py'), launcher.read_text())
                self.assertIn('autoclaw-backend', launcher.read_text())
                baseline = json.loads((root / 'state/compatibility.json').read_text())
                self.assertEqual(baseline['opencode'], {'version': 'x'})
                self.assertEqual(baseline['autoclaw']['zcodeSha256'], hashlib.sha256(b'synthetic zcode').hexdigest())
                profile = json.loads((root / 'state/autoclaw-profile.json').read_text())
                self.assertEqual(profile['reviewedAppVersion'], '1.18.5')
                backups = list((root / 'state/backups').glob('openclaw.json.*'))
                self.assertEqual(len(backups), 1)
                self.assertEqual(json.loads(backups[0].read_text()), original)
                self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
                self.assertEqual((root / 'state/backups').stat().st_mode & 0o777, 0o700)
                self.assertEqual([p.name for p in state_dir.iterdir()], ['openclaw.json'])
                # 다시 실행해도 같은 결과이고 백업이 늘지 않는다.
                installer.main()
                self.assertEqual(json.loads((state_dir / 'openclaw.json').read_text()), updated)
                self.assertEqual(len(list((root / 'state/backups').glob('openclaw.json.*'))), 1)

    def test_installer_refuses_a_symlinked_or_missing_config(self):
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            root = home / 'guard'
            (root / 'state').mkdir(parents=True, mode=0o700)
            app = synthetic_autoclaw(root)
            state_dir = home / '.openclaw-autoclaw'
            state_dir.mkdir()
            (home / '.local/bin').mkdir(parents=True)
            with patch.object(installer, 'HOME', home), patch.object(installer, 'ROOT', root), \
                 patch.object(installer, 'STATE', root / 'state'), patch.object(installer, 'OPENCLAW_STATE', state_dir), \
                 patch.object(installer.agent_guard, 'ROOT', root), patch.object(installer.agent_guard, 'AUTOCLAW_APP', app):
                with self.assertRaises(RuntimeError):
                    installer.main()
                victim = home / 'victim.json'
                victim.write_text('{}')
                os.symlink(str(victim), str(state_dir / 'openclaw.json'))
                with self.assertRaises(RuntimeError):
                    installer.main()
                self.assertEqual(victim.read_text(), '{}')


    def installer_context(self, installer, home, root, app, state_dir):
        from contextlib import ExitStack
        stack = ExitStack()
        for target, name, value in [(installer, 'HOME', home), (installer, 'ROOT', root), (installer, 'STATE', root / 'state'),
                                    (installer, 'OPENCLAW_STATE', state_dir), (installer.agent_guard, 'ROOT', root),
                                    (installer.agent_guard, 'AUTOCLAW_APP', app),
                                    (installer.agent_guard, 'AUTOCLAW_ZCODE', app / 'Contents/Resources/zcode/darwin-arm64/zcode')]:
            stack.enter_context(patch.object(target, name, value))
        return stack

    def prepared_home(self, tmp):
        home = Path(tmp); root = home / 'guard'; (root / 'state').mkdir(parents=True, mode=0o700)
        app = synthetic_autoclaw(root)
        state_dir = home / '.openclaw-autoclaw'; state_dir.mkdir()
        (state_dir / 'openclaw.json').write_text(json.dumps({'plugins': {'entries': {}}}))
        (home / '.local/bin').mkdir(parents=True)
        return home, root, app, state_dir

    def test_installer_refuses_a_foreign_or_linked_launcher(self):
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            launcher = home / '.local/bin/autoclaw-zcode-safe'
            with self.installer_context(installer, home, root, app, state_dir):
                launcher.write_text('#!/bin/sh\necho foreign\n')
                with self.assertRaises(RuntimeError):
                    installer.main()
                self.assertEqual(launcher.read_text(), '#!/bin/sh\necho foreign\n')
                # 권한이 0700 이어도 본문이 이전 가드 런처가 아니면 교체하지 않는다(이전 런처 교체 경로의 경계).
                launcher.chmod(0o700)
                with self.assertRaises(RuntimeError):
                    installer.main()
                self.assertEqual(launcher.read_text(), '#!/bin/sh\necho foreign\n')
                launcher.unlink()
                victim = home / 'victim'; victim.write_text('keep')
                os.symlink(str(victim), str(launcher))
                with self.assertRaises(RuntimeError):
                    installer.main()
                self.assertEqual(victim.read_text(), 'keep')

    def test_launcher_logs_a_shell_stage_before_handing_over_to_python(self):
        """isthmus 30초 침묵: 게이트웨이가 띄운 런처가 파이썬 첫 줄에도 못 닿았다. 셸 자체가 첫 증거를 남겨야
        셸 기동·python3 셔틀·파이썬 기동 중 어디서 멈췄는지 가를 수 있다. pid 는 exec 로 이어지므로 파이썬 pid 와 같다."""
        import subprocess
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory(prefix='launcher-', dir=Path.home()) as tmp:
            home = Path(tmp); root = home / 'guard'; (root / 'state').mkdir(parents=True, mode=0o700)
            (root / 'agent_guard.py').write_text('import os, sys\nprint(os.getpid(), sys.argv[1:])\n')
            workspace = home / 'ws'; workspace.mkdir()
            launcher = home / 'autoclaw-zcode-safe'
            with patch.object(installer, 'ROOT', root):
                launcher.write_text(installer.launcher_text())
            log = root / 'state/runtime/autoclaw-launches.log'
            (root / 'state/runtime').mkdir(mode=0o700)
            result = subprocess.run(['/bin/sh', str(launcher), 'agent-server'], cwd=str(workspace), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            python_pid, arguments = result.stdout.split(' ', 1)
            self.assertEqual(arguments.strip(), "['autoclaw-backend', 'agent-server']")
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertRegex(lines[0], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d pid=' + python_pid + ' stage=sh-start cwd=' + str(workspace) + '$')
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            # version 프로브는 한 턴에 여러 번 올 수 있어 기록하면 "python-start 없음" 으로 오독된다.
            subprocess.run(['/bin/sh', str(launcher), 'version'], cwd=str(workspace), capture_output=True, check=True)
            self.assertEqual(len(log.read_text().splitlines()), 1)
            # 로그 자리에 링크가 있으면 쓰지 않고, 실행은 계속된다.
            log.unlink(); victim = home / 'victim'; victim.write_text(''); os.symlink(str(victim), str(log))
            result = subprocess.run(['/bin/sh', str(launcher), 'agent-server'], cwd=str(workspace), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(victim.read_text(), '')
            # FIFO 가 있으면 `>>` 가 읽는 쪽을 기다리며 exec 전에 멈춘다 — 증거를 남기기도 전에 30초 침묵이 된다. 건너뛰어야 한다.
            log.unlink(); os.mkfifo(str(log))
            result = subprocess.run(['/bin/sh', str(launcher), 'agent-server'], cwd=str(workspace), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            # `state/runtime` 자체가 링크면 파이썬(private_dir)은 거부한다. 셸도 따라가 쓰지 않는다.
            log.unlink(); (root / 'state/runtime').rmdir(); outside = home / 'outside'; outside.mkdir()
            os.symlink(str(outside), str(root / 'state/runtime'))
            result = subprocess.run(['/bin/sh', str(launcher), 'agent-server'], cwd=str(workspace), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(outside.iterdir()), [])

    def test_installer_replaces_the_previous_guard_launcher_in_place(self):
        """런처 본문이 바뀌면 재설치가 이전 가드 런처를 알아보고 교체해야 한다. 낯선 런처 거부는 그대로다."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            launcher = home / '.local/bin/autoclaw-zcode-safe'
            with self.installer_context(installer, home, root, app, state_dir):
                import shlex
                previous = '#!/bin/sh\nexec /usr/bin/python3 -I ' + shlex.quote(str(root / 'agent_guard.py')) + ' autoclaw-backend "$@"\n'
                launcher.write_text(previous); launcher.chmod(0o700)
                installer.main()
                self.assertEqual(launcher.read_text(), installer.launcher_text())
                self.assertNotEqual(launcher.read_text(), previous)
                self.assertEqual(launcher.stat().st_mode & 0o777, 0o700)
                self.assertEqual(sorted(p.name for p in launcher.parent.iterdir()), ['autoclaw-zcode-safe'])
                # 게이트웨이가 교체 순간에 런처를 띄워도 빈 파일이나 부재를 보지 않도록 임시 파일 + rename 으로 바꾼다.
                # 이전 실패가 남긴 임시 파일은 치우고 진행한다.
                launcher.write_text(previous); launcher.chmod(0o700)
                stale = launcher.parent / '.autoclaw-zcode-safe.tmp'; stale.write_text('stale')
                seen = []
                original_rename = os.rename
                def rename(src, dst, *args, **kwargs):
                    seen.append((launcher.exists(), launcher.read_text() if launcher.exists() else None)); return original_rename(src, dst, *args, **kwargs)
                with patch.object(os, 'rename', rename):
                    installer.main()
                self.assertEqual(seen, [(True, previous)])
                self.assertEqual(launcher.read_text(), installer.launcher_text())
                self.assertFalse(stale.exists())
                # 같은 본문이라도 권한이 열려 있으면 이전 런처로 인정하지 않는다.
                launcher.write_text(previous); launcher.chmod(0o755)
                with self.assertRaises(RuntimeError):
                    installer.main()
                self.assertEqual(launcher.read_text(), previous)

    def test_installer_refuses_a_world_writable_or_linked_bin_directory(self):
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            with self.installer_context(installer, home, root, app, state_dir):
                (home / '.local/bin').chmod(0o777)
                with self.assertRaises(RuntimeError):
                    installer.main()
                (home / '.local/bin').chmod(0o755)
                (home / '.local/bin').rmdir()
                elsewhere = home / 'elsewhere'; elsewhere.mkdir()
                os.symlink(str(elsewhere), str(home / '.local/bin'))
                with self.assertRaises(RuntimeError):
                    installer.main()
                self.assertEqual(list(elsewhere.iterdir()), [])

    def test_installer_refuses_to_rebless_a_changed_binary_without_the_flag(self):
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main()
                (app / 'Contents/Resources/zcode/darwin-arm64/zcode').write_bytes(b'updated zcode')
                manifest_path = app / 'Contents/Resources/zcode/manifest.json'
                manifest = json.loads(manifest_path.read_text())
                manifest['artifacts']['darwin-arm64']['sha256'] = hashlib.sha256(b'updated zcode').hexdigest()
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaises(RuntimeError):
                    installer.main()
                baseline = json.loads((root / 'state/compatibility.json').read_text())
                self.assertEqual(baseline['autoclaw']['zcodeSha256'], hashlib.sha256(b'synthetic zcode').hexdigest())
                installer.main(rebaseline=True)
                baseline = json.loads((root / 'state/compatibility.json').read_text())
                self.assertEqual(baseline['autoclaw']['zcodeSha256'], hashlib.sha256(b'updated zcode').hexdigest())

    def test_installer_can_deny_host_exec_for_the_outer_agent(self):
        """AutoClaw 의 바깥 에이전트는 호스트 exec 를 승인 없이 돌린다. 옵션으로 이를 막아 코딩이 zcode 경로로만 가게 한다."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            (state_dir / 'openclaw.json').write_text(json.dumps({'plugins': {'entries': {}}, 'tools': {'exec': {'security': 'full', 'ask': 'off'}, 'deny': ['browser']}}))
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main(deny_host_exec=False)
                tools = json.loads((state_dir / 'openclaw.json').read_text())['tools']
                self.assertEqual(tools['exec'], {'security': 'full', 'ask': 'off'})
                installer.main()  # 기본값이 차단이다(페일오픈 설치 금지).
                tools = json.loads((state_dir / 'openclaw.json').read_text())['tools']
                self.assertEqual(tools['exec']['security'], 'deny')
                self.assertEqual(sorted(tools['deny']), ['browser', 'exec', 'gateway', 'process'])

    def test_deny_host_exec_also_denies_per_agent_and_elevated(self):
        """AutoClaw 의 원격 설정 새로고침이 전역 tools.exec.security 를 full 로 되돌린다. 에이전트별 deny 와 elevated 차단까지 넣어야 버틴다."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            (state_dir / 'openclaw.json').write_text(json.dumps({
                'plugins': {'entries': {}},
                'tools': {'exec': {'security': 'full', 'ask': 'off'}},
                'agents': {'list': [{'id': 'main', 'workspace': '~/w'},
                                    {'id': 'auto-coder', 'model': 'zai/x', 'tools': {'deny': ['canvas'], 'allow': ['read']}}]}}))
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main(deny_host_exec=True)
                updated = json.loads((state_dir / 'openclaw.json').read_text())
                self.assertEqual(updated['tools']['elevated'], {'enabled': False})
                agents = {a['id']: a for a in updated['agents']['list']}
                self.assertEqual(agents['main']['tools'], {'deny': ['exec', 'gateway', 'process'], 'elevated': {'enabled': False}})
                self.assertEqual(agents['main']['workspace'], '~/w')
                self.assertEqual(agents['auto-coder']['tools'], {'deny': ['canvas', 'exec', 'gateway', 'process'], 'allow': ['read'], 'elevated': {'enabled': False}})
                self.assertEqual(agents['auto-coder']['model'], 'zai/x')

    def discord_config(self):
        return {'plugins': {'entries': {}},
                'channels': {'discord': {'enabled': True, 'accounts': {'myclaw': {'dmPolicy': 'disabled', 'groupPolicy': 'disabled',
                                                                                 'token': 'SYNTHETIC', 'enabled': True}}}}}

    def test_discord_dm_mode_locks_every_account_to_the_given_users(self):
        """DM 경로를 열 때는 본인 사용자 ID 만 허용 목록에 넣는다. 토큰·서버 정책은 그대로."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            (state_dir / 'openclaw.json').write_text(json.dumps(self.discord_config()))
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main(discord_users=['123456789012345678'], discord_dm=True)
                account = json.loads((state_dir / 'openclaw.json').read_text())['channels']['discord']['accounts']['myclaw']
                self.assertEqual(account['dmPolicy'], 'allowlist')
                self.assertEqual(account['allowFrom'], ['123456789012345678'])
                self.assertEqual(account['groupPolicy'], 'disabled')
                self.assertEqual(account['token'], 'SYNTHETIC')
                for bad in (['abc'], ['*'], ['123'], [], ['123456789012345678', 'accessGroup:x']):
                    with self.assertRaises(RuntimeError, msg=bad):
                        installer.main(discord_users=bad, discord_dm=True)
                (state_dir / 'openclaw.json').write_text(json.dumps({'plugins': {'entries': {}}, 'channels': {}}))
                with self.assertRaises(RuntimeError):
                    installer.main(discord_users=['123456789012345678'], discord_dm=True)

    def test_discord_guild_mode_keeps_dm_disabled_and_locks_the_sender(self):
        """비공개 서버 채널로 제어할 때: DM 은 계속 끄고, 서버 하나·보낸 사람 ID 하나(선택적으로 채널 하나)만 허용한다."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            (state_dir / 'openclaw.json').write_text(json.dumps(self.discord_config()))
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main(discord_users=['123456789012345678'], discord_guild='987654321098765432')
                account = json.loads((state_dir / 'openclaw.json').read_text())['channels']['discord']['accounts']['myclaw']
                self.assertEqual(account['dmPolicy'], 'disabled')
                self.assertNotIn('allowFrom', account)
                self.assertEqual(account['groupPolicy'], 'allowlist')
                self.assertEqual(account['guilds'], {'987654321098765432': {'requireMention': False, 'users': ['123456789012345678']}})
                self.assertEqual(account['token'], 'SYNTHETIC')
                installer.main(discord_users=['123456789012345678'], discord_guild='987654321098765432', discord_channel='111111111111111111')
                account = json.loads((state_dir / 'openclaw.json').read_text())['channels']['discord']['accounts']['myclaw']
                self.assertEqual(account['guilds']['987654321098765432']['channels'], {'111111111111111111': {'allow': True}})
                for bad in ({'discord_guild': 'my-server'}, {'discord_guild': '987654321098765432', 'discord_channel': 'general'},
                            {'discord_guild': '987654321098765432', 'discord_dm': True}):
                    with self.assertRaises(RuntimeError, msg=bad):
                        installer.main(discord_users=['123456789012345678'], **bad)
                with self.assertRaises(RuntimeError):
                    installer.main(discord_users=['123456789012345678'])
                with self.assertRaises(RuntimeError):
                    installer.main(discord_users=[], discord_guild='987654321098765432')
                with self.assertRaises(RuntimeError):
                    installer.main(discord_users='123456789012345678', discord_guild='987654321098765432')

    def test_private_agent_workspace_moves_the_agent_off_the_repository(self):
        """에이전트 워크스페이스가 저장소면 네이티브 read/write 가 호스트에서 저장소를 직접 만진다. 전용 폴더로 옮기고 메모를 심는다."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            repo = home / 'Desktop/repo'; repo.mkdir(parents=True)
            (state_dir / 'openclaw.json').write_text(json.dumps({'plugins': {'entries': {}},
                'agents': {'list': [{'id': 'main', 'workspace': '~/x'}, {'id': 'programmer', 'workspace': str(repo), 'model': 'zai/x'}]}}))
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main(private_agent_workspace='programmer')
                updated = json.loads((state_dir / 'openclaw.json').read_text())
                agents = {a['id']: a for a in updated['agents']['list']}
                expected = str(state_dir / 'agents/programmer/workspace')
                self.assertEqual(agents['programmer']['workspace'], expected)
                self.assertEqual(agents['programmer']['model'], 'zai/x')
                self.assertEqual(agents['main']['workspace'], '~/x')
                self.assertTrue((Path(expected) / 'TOOLS.md').is_file())
                self.assertIn('zcode_run', (Path(expected) / 'TOOLS.md').read_text())
                self.assertEqual(Path(expected).stat().st_mode & 0o777, 0o700)
                # 저장소는 건드리지 않는다.
                self.assertEqual(list(repo.iterdir()), [])
                with self.assertRaises(RuntimeError):
                    installer.main(private_agent_workspace='ghost')
                installer.main(private_agent_workspace='programmer')  # 재실행 안전
                self.assertEqual((Path(expected) / 'TOOLS.md').read_text().count('실행 규칙 (agent-guard)'), 1)
                # 'zcode_run' 이라는 낱말만 있는 메모는 우리 규칙이 아니다: 규칙 절을 붙인다.
                (Path(expected) / 'TOOLS.md').write_text('# notes\nuse zcode_run freely, exec is fine\n')
                installer.main(private_agent_workspace='programmer')
                self.assertEqual((Path(expected) / 'TOOLS.md').read_text().count('실행 규칙 (agent-guard)'), 1)

    def test_discord_agent_rebinds_the_channel_to_the_named_agent(self):
        """zcode_run 은 auto-coder 에게만 노출된다(플러그인 하드코딩). Discord 바인딩을 그 에이전트로 돌린다."""
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            (state_dir / 'openclaw.json').write_text(json.dumps({'plugins': {'entries': {}},
                'agents': {'list': [{'id': 'auto-coder'}, {'id': 'programmer'}]},
                'bindings': [{'agentId': 'programmer', 'match': {'channel': 'discord', 'accountId': 'myclaw'}},
                             {'agentId': 'main', 'match': {'channel': 'telegram'}}]}))
            with self.installer_context(installer, home, root, app, state_dir):
                installer.main(discord_agent='auto-coder')
                updated = json.loads((state_dir / 'openclaw.json').read_text())
                self.assertEqual(updated['bindings'], [{'agentId': 'auto-coder', 'match': {'channel': 'discord', 'accountId': 'myclaw'}},
                                                       {'agentId': 'main', 'match': {'channel': 'telegram'}}])
                with self.assertRaises(RuntimeError):
                    installer.main(discord_agent='ghost')
                # zcode_run 은 auto-coder 에게만 노출되므로 다른 에이전트로 묶는 것은 거부한다(programmer 사고 재발 방지).
                with self.assertRaises(RuntimeError):
                    installer.main(discord_agent='programmer')
                (state_dir / 'openclaw.json').write_text(json.dumps({'plugins': {'entries': {}}, 'agents': {'list': [{'id': 'auto-coder'}]}, 'bindings': []}))
                with self.assertRaises(RuntimeError):
                    installer.main(discord_agent='auto-coder')

    def test_installer_takes_the_settings_lock(self):
        import fcntl
        import install_autoclaw as installer
        with tempfile.TemporaryDirectory() as tmp:
            home, root, app, state_dir = self.prepared_home(tmp)
            with self.installer_context(installer, home, root, app, state_dir):
                seen = {}
                original = fcntl.flock
                def spy(descriptor, operation):
                    seen['locked'] = operation == fcntl.LOCK_EX
                    return original(descriptor, operation)
                with patch.object(installer.fcntl, 'flock', spy):
                    installer.main()
                self.assertTrue(seen.get('locked'))
                self.assertTrue((root / 'state/.settings-import.lock').is_file())


class DoctorTests(unittest.TestCase):
    def test_doctor_fails_when_the_autoclaw_baseline_no_longer_matches(self):
        import io
        current = {'opencode': {'version': '1', 'sha256': 'a'}, 'zcode': {'version': '3', 'asarSha256': 'b', 'agentSha256': 'c'},
                   'mobile': 'm', 'autoclaw': {'version': '1.18.5', 'zcodeCliVersion': '0.15.2', 'zcodeSha256': 'd'}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'state').mkdir()
            saved = dict(current, autoclaw=dict(current['autoclaw'], zcodeSha256='e'))
            (root / 'state/compatibility.json').write_text(json.dumps(saved))
            fake_module = type(sys)('compatibility_check'); fake_module.candidate = lambda: current
            with patch.object(g, 'ROOT', root), patch.dict(sys.modules, {'compatibility_check': fake_module}), \
                 patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                 patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(g.doctor(), 2)
                (root / 'state/compatibility.json').write_text(json.dumps(current))
                self.assertEqual(g.doctor(), 0)


class CompatibilityTests(unittest.TestCase):
    def test_candidate_records_the_autoclaw_bundle_when_installed(self):
        import compatibility_check as check
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = synthetic_autoclaw(root)
            entry = check.autoclaw_candidate(app)
            self.assertEqual(entry, {'version': '1.18.5', 'zcodeCliVersion': '0.15.2',
                                     'zcodeSha256': hashlib.sha256(b'synthetic zcode').hexdigest()})
            self.assertIsNone(check.autoclaw_candidate(root / 'missing.app'))

    def test_verification_keeps_the_autoclaw_baseline_when_the_app_is_unavailable(self):
        """앱이 잠시 없을 때 verify-updates 가 autoclaw 기준선을 지우면 재설치가 공격자 해시를 축복한다."""
        import compatibility_check as check
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'state').mkdir()
            saved = {'opencode': {'version': 'o'}, 'zcode': {'version': 'z'}, 'autoclaw': {'version': '1.18.5', 'zcodeCliVersion': '0.15.2', 'zcodeSha256': 'kept'}}
            (root / 'state/compatibility.json').write_text(json.dumps(saved))
            merged = check.merged_baseline({'opencode': {'version': 'o2'}, 'zcode': {'version': 'z'}}, saved)
            self.assertEqual(merged['autoclaw'], saved['autoclaw'])
            self.assertEqual(merged['opencode'], {'version': 'o2'})
            merged = check.merged_baseline({'opencode': {'version': 'o2'}, 'zcode': {'version': 'z'}, 'autoclaw': {'version': 'new'}}, saved)
            self.assertEqual(merged['autoclaw'], {'version': 'new'})


if __name__ == '__main__':
    unittest.main()
