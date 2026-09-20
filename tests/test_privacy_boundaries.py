"""Offline regressions for workspace configuration, staging, and temporary isolation."""
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import agentbelt as g


class TemporaryIsolationTests(unittest.TestCase):
    def test_same_workspace_and_distinct_workspaces_never_reuse_temp_data(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(g, 'ROOT', Path(root)):
                paths = [g.short_temp_directory('autoclaw', Path(work))
                         for work in ['/synthetic/one', '/synthetic/one', '/synthetic/two']]
            try:
                self.assertEqual(len(set(paths)), 3)
                (paths[0] / 'review.txt').write_text('SYNTHETIC_PRIVATE_REVIEW')
                self.assertFalse((paths[1] / 'review.txt').exists())
                self.assertFalse((paths[2] / 'review.txt').exists())
                for path in paths:
                    self.assertLessEqual(len(str(path).encode()), 57)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            finally:
                for path in paths:
                    for child in path.iterdir():
                        child.unlink()
                    path.rmdir()

    def test_random_identifier_collision_never_adopts_existing_directory(self):
        with tempfile.TemporaryDirectory() as root, patch.object(g, 'ROOT', Path(root)):
            first_name = 'A' * 22
            with patch.object(secrets, 'token_urlsafe', return_value=first_name):
                first = g.short_temp_directory('usage', Path('/synthetic/work'))
            try:
                with patch.object(secrets, 'token_urlsafe', return_value=first_name):
                    with self.assertRaises(g.GuardError):
                        g.short_temp_directory('usage', Path('/synthetic/work'))
            finally:
                first.rmdir()


@unittest.skipUnless((g.ROOT / 'runtime/node_modules/@anthropic-ai/sandbox-runtime/package.json').is_file(),
                     'requires staged macOS sandbox runtime')
class PrivacyKernelTests(unittest.TestCase):
    def test_timeout_allows_client_to_reap_its_detached_vendor_child(self):
        import signal
        program = '''import signal,subprocess,sys,time
child=subprocess.Popen(['/bin/sleep','30'],start_new_session=True)
print(child.pid,flush=True)
def cleanup(*args):
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 child.kill();child.wait(timeout=1)
 print('DETACHED_CHILD_REAPED',flush=True)
 raise SystemExit(0)
signal.signal(signal.SIGTERM,cleanup)
time.sleep(30)
'''
        with tempfile.TemporaryDirectory(prefix='timeout-cleanup-', dir=g.OWNER_HOME) as temporary, \
             tempfile.TemporaryFile() as out:
            try:
                with self.assertRaisesRegex(g.GuardError, 'time limit'):
                    g.run_confined('cleanup-probe', Path(temporary),
                                   ['/Library/Developer/CommandLineTools/usr/bin/python3', '-I', '-c', program],
                                   ephemeral=True, stdout=out, timeout=1)
            finally:
                out.seek(0)
                output = out.read().decode()
                # Only the synthetic 30-second child we just created can still
                # be alive here if the regression returns; never leave it behind.
                if 'DETACHED_CHILD_REAPED' not in output and output.splitlines():
                    try:
                        os.killpg(int(output.splitlines()[0]), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            self.assertIn('DETACHED_CHILD_REAPED', output)

    def test_reviewed_opencode_clone_starts_without_network_or_credentials(self):
        if not g.OPENCODE.is_file():
            self.skipTest('OpenCode is not installed')
        with tempfile.TemporaryDirectory(prefix='opencode-clone-', dir=g.OWNER_HOME) as temporary:
            staged = g.stage_opencode_binary()
            try:
                with tempfile.TemporaryFile() as out:
                    status = g.run_confined('opencode-clone-probe', Path(temporary), [str(staged), '--version'],
                                            extra_reads=[staged], ephemeral=True, read_only_workspace=True,
                                            stdout=out, timeout=15)
                    out.seek(0)
                    version = out.read().decode().strip()
                self.assertEqual(status, 0)
                self.assertRegex(version, r'^\d+\.\d+\.\d+')
            finally:
                g.discard_staged_binary(staged)

    def run_script(self, work, script, **kwargs):
        with tempfile.TemporaryFile() as out, patch.object(g, 'host_git_identity', return_value={}):
            status = g.run_confined('privacy-probe', work, ['/bin/sh', '-c', script],
                                    ephemeral=True, stdout=out, **kwargs)
            out.seek(0)
            return status, out.read().decode()

    def test_preexisting_project_configuration_is_unreadable_but_source_works(self):
        with tempfile.TemporaryDirectory(prefix='privacy-work-', dir=g.OWNER_HOME) as temporary:
            work = Path(temporary)
            for relative in ['.zcode/config.json', 'zcode.json', '.agents/mcp.json']:
                path = work / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('SYNTHETIC_HOSTILE_CONFIG')
            (work / 'source.txt').write_text('NORMAL_SOURCE')
            status, output = self.run_script(work,
                'cat .zcode/config.json zcode.json .agents/mcp.json 2>/dev/null; cat source.txt',
                blocked_workspace_paths=g.ZCODE_WORKSPACE_CONFIG_PATHS)
            self.assertEqual(status, 0)
            self.assertEqual(output, 'NORMAL_SOURCE')

    def test_review_workspace_is_kernel_read_only_and_outside_source_is_denied(self):
        with tempfile.TemporaryDirectory(prefix='privacy-stage-', dir=g.OWNER_HOME) as temporary:
            base = Path(temporary)
            work = base / 'stage'
            work.mkdir()
            (work / 'packet.md').write_text('SCRUBBED_PACKET')
            (base / 'original.py').write_text('UNSELECTED_SOURCE')
            status, output = self.run_script(work,
                'cat packet.md; cat ../original.py 2>/dev/null; '
                'echo change >> packet.md 2>/dev/null; echo x > new.txt 2>/dev/null; exit 0',
                read_only_workspace=True)
            self.assertEqual(status, 0)
            self.assertEqual(output, 'SCRUBBED_PACKET')
            self.assertEqual((work / 'packet.md').read_text(), 'SCRUBBED_PACKET')
            self.assertFalse((work / 'new.txt').exists())

    def test_real_packet_collector_and_synthetic_model_have_separate_kernel_authority(self):
        if not g.PACKET_PYTHON.is_file():
            self.skipTest('requires the installed public packet-ask package')
        from adapters import packet_pipeline
        with tempfile.TemporaryDirectory(prefix='packet-kernel-', dir=g.OWNER_HOME) as temporary:
            work = Path(temporary).resolve()
            (work / 'selected.py').write_text('print("SELECTED_CODE")\napi_key = "SYNTHETIC_ONLY_KEY"\n')
            (work / 'unselected.py').write_text('UNSELECTED_CODE')
            subprocess.run(['/usr/bin/git', '-C', str(work), 'init', '--quiet'], check=True,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={'HOME': str(work), 'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null',
                                'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'})
            original_runner = g.run_confined
            seen = []
            probe = '''import os,sys
from pathlib import Path
body=Path('packet.md').read_text()
assert 'SELECTED_CODE' in body
assert 'SYNTHETIC_ONLY_KEY' not in body and 'UNSELECTED_CODE' not in body
assert not os.environ.get('GH_TOKEN')
assert os.environ['GIT_CONFIG_GLOBAL']=='/dev/null'
for path,mode in [(Path(sys.argv[1])/'unselected.py','r'),(Path('packet.md'),'w')]:
 try:
  with path.open(mode):pass
 except PermissionError:pass
 else:raise AssertionError('forbidden file operation succeeded')
print('MODEL_BOUNDARY_OK')
'''
            def confined(mode, workspace, command, **kwargs):
                seen.append((mode, Path(workspace)))
                if mode == 'packet-model':
                    self.assertNotEqual(Path(workspace), work)
                    # The only live phase is replaced with this fixed synthetic
                    # program and all network is denied, regardless of adapter.
                    command = ['/Library/Developer/CommandLineTools/usr/bin/python3', '-I', '-c', probe, str(work)]
                    kwargs['domains'] = []
                elif mode != 'packet-collector':
                    self.fail('unexpected process mode')
                return original_runner(mode, workspace, command, **kwargs)
            with tempfile.TemporaryFile() as out, patch.dict(os.environ, {'PACKET_ASK_GLM_KEY': 'SYNTHETIC_FIXTURE_KEY'}):
                status = packet_pipeline.run(['review', '--provider', 'glm', '--files', 'selected.py',
                                              '--question', 'Review the selected code'],
                                             workspace=work, runner=confined, stdout=out)
                out.seek(0)
                self.assertEqual(status, 0)
                self.assertEqual(out.read().decode().strip(), 'MODEL_BOUNDARY_OK')
            self.assertEqual([mode for mode, _ in seen], ['packet-collector', 'packet-model'])
            self.assertFalse(seen[-1][1].exists())


if __name__ == '__main__':
    unittest.main()
