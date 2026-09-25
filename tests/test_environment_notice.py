"""Regression checking that the isolated-environment description is delivered to the child at session start."""
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
import agentbelt as g
import environment_notice as notice


def confined(script, **options):
    """Run a shell snippet under the real guard policy and return (exit code, output)."""
    with tempfile.TemporaryDirectory(prefix='notice-', dir=Path.home()) as tmp:
        work = Path(tmp)
        (work / 'p.sh').write_text(script)
        with tempfile.TemporaryFile() as out:
            status = g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')],
                                    domains=['pub.dev:443'], ephemeral=True, stdout=out, **options)
            out.seek(0)
            return status, out.read().decode(errors='replace')


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.home = Path('/tmp/synthetic-home')
        self.workspace = Path('/tmp/synthetic-work')
        self.env = {'HOME': str(self.home), 'TMPDIR': str(self.home / 'tmp'), 'PUB_CACHE': str(self.home / '.pub-cache'),
                    'PATH': '/opt/homebrew/bin:/usr/bin', 'GH_CONFIG_DIR': str(self.home / '.config/gh')}
        self.policy = g.sandbox_policy(self.workspace, self.home, ['pub.dev:443', 'api.z.ai:443'])
        self.text = notice.render_environment_notice(self.workspace, self.home, self.env, self.policy)

    def test_states_isolated_home_temp_and_workspace(self):
        self.assertIn(str(self.home), self.text)
        self.assertIn(str(self.home / 'tmp'), self.text)
        self.assertIn(str(self.workspace), self.text)
        self.assertIn('AGENTBELT_ENVIRONMENT.md', self.text)

    def test_lists_reachable_domains_and_readable_paths(self):
        self.assertIn('pub.dev:443', self.text)
        self.assertIn('api.z.ai:443', self.text)
        self.assertIn('/opt/homebrew', self.text)
        self.assertIn('/Library/Developer/CommandLineTools', self.text)

    def test_describes_github_auth_as_files_not_environment(self):
        self.assertIn('.config/gh', self.text)
        self.assertIn('gh auth token', self.text)
        self.assertIn('Do not export', self.text)
        without = {key: value for key, value in self.env.items() if key != 'GH_CONFIG_DIR'}
        absent = notice.render_environment_notice(self.workspace, self.home, without, self.policy)
        self.assertNotEqual(absent, self.text)
        self.assertIn('No GitHub token', absent)

    def test_explains_dart_cache_location(self):
        """A real session saw the ~/.pub-cache block and misdiagnosed dart verification as impossible."""
        self.assertIn(str(self.home / '.pub-cache'), self.text)
        self.assertIn('PUB_CACHE', self.text)
        self.assertIn('dart pub get', self.text)

    def test_states_that_nested_launchers_cannot_run_inside(self):
        """The kernel rejects nested sandbox-exec, so packet-ask runs only on the host."""
        self.assertIn('packet-ask', self.text)
        self.assertIn('sandbox-exec', self.text)
        self.assertIn('host', self.text)

    def test_explains_the_session_loopback_port_for_dart_coverage(self):
        """A real session reported that dart test --coverage hangs on the VM service port."""
        with_port = notice.render_environment_notice(self.workspace, self.home, dict(self.env, AGENTBELT_LOOPBACK_PORT='47311'), self.policy)
        self.assertIn('47311', with_port)
        self.assertIn('--enable-vm-service=$AGENTBELT_LOOPBACK_PORT', with_port)
        self.assertIn('--no-dds', with_port)
        self.assertIn('EPERM', self.text)

    def test_relay_session_points_at_packet_review_instead_of_the_user(self):
        """A real session followed the 'request host execution and stop' clause and did not use packet-review."""
        relayed = notice.render_environment_notice(self.workspace, self.home, dict(self.env, AGENTBELT_PACKET_REVIEW='1'), self.policy)
        self.assertNotIn('for the user to run on the host terminal', relayed)
        self.assertNotIn('and then stop. Do not explore retries or workarounds.', relayed)
        self.assertIn('`packet-review`', relayed)
        # A session without a relay is still told to hand off to the user.
        self.assertIn('and then stop. Do not explore retries or workarounds.', self.text)

    def test_explains_swiftpm_flags(self):
        """A session misdiagnosed this as a 'broken Swift toolchain'. It was really the module cache, the nested sandbox and the *.db rule."""
        self.assertIn('swift build --build-system native --disable-sandbox --scratch-path "$TMPDIR/swiftpm-build"', self.text)
        self.assertIn('not supported by the compiler', self.text)
        # The granted temp folders are taken from the policy, never hardcoded.
        from unittest.mock import patch
        with patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': [], 'darwinTempDirectories': ['probe-index-db']}):
            policy = g.sandbox_policy(self.workspace, self.home, [])
        self.assertIn('`probe-index-db`', notice.render_environment_notice(self.workspace, self.home, self.env, policy))
        stripped = dict(self.policy, filesystem=dict(self.policy['filesystem'], allowRead=[p for p in self.policy['filesystem']['allowRead'] if '/T/' not in p]))
        self.assertIn('(none granted)', notice.render_environment_notice(self.workspace, self.home, self.env, stripped))

    def test_warns_against_repairing_the_host(self):
        self.assertIn('sudo', self.text)
        self.assertIn('rm -rf', self.text)


class ZcodeWiringTests(unittest.TestCase):
    def test_zcode_backend_requests_global_agents_file(self):
        """Zcode reads $HOME/.zcode/AGENTS.md as global instructions, so the notice must be requested at that path."""
        from unittest.mock import patch
        import os
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs)
            return 0

        with tempfile.TemporaryDirectory(prefix='zcode-notice-', dir=Path.home()) as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'verify_zcode_binary', lambda: None), \
                     patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}):
                    self.assertEqual(g.main(['zcode-backend', 'app-server', '--stdio']), 0)
            finally:
                os.chdir(previous)
        self.assertEqual(list(captured['instruction_files']), ['.zcode/AGENTS.md'])


class DeliveryTests(unittest.TestCase):
    def test_notice_is_readable_but_locked_in_isolated_home(self):
        status, out = confined('cat "$HOME/AGENTBELT_ENVIRONMENT.md" | head -3; '
                               'echo tampered 2>/dev/null >> "$HOME/AGENTBELT_ENVIRONMENT.md" && echo WRITE_OK || echo WRITE_DENIED')
        self.assertEqual(status, 0, out)
        self.assertIn('agentbelt', out)
        self.assertIn('WRITE_DENIED', out)
        self.assertNotIn('WRITE_OK', out)

    def test_instruction_files_receive_the_same_notice(self):
        status, out = confined('cmp -s "$HOME/AGENTBELT_ENVIRONMENT.md" "$HOME/.zcode/AGENTS.md" && echo SAME || echo DIFF; '
                               'echo x 2>/dev/null >> "$HOME/.zcode/AGENTS.md" && echo WRITE_OK || echo WRITE_DENIED',
                               instruction_files=['.zcode/AGENTS.md'])
        self.assertEqual(status, 0, out)
        self.assertIn('SAME', out)
        self.assertIn('WRITE_DENIED', out)

    def test_protected_opencode_config_directory_receives_notice(self):
        status, out = confined('cmp -s "$OPENCODE_CONFIG_DIR/AGENTS.md" "$HOME/AGENTBELT_ENVIRONMENT.md" && echo SAME || echo DIFF; '
                               'grep -c "$HOME" "$OPENCODE_CONFIG_DIR/AGENTS.md"; '
                               'echo x 2>/dev/null >> "$OPENCODE_CONFIG_DIR/AGENTS.md" && echo WRITE_OK || echo WRITE_DENIED',
                               protect_opencode_config=True)
        self.assertEqual(status, 0, out)
        self.assertIn('SAME', out)
        self.assertNotIn('\n0\n', '\n' + out)
        self.assertIn('WRITE_DENIED', out)


if __name__ == '__main__':
    unittest.main()
