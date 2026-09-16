"""Regressions for the toolchain the operator already installed being usable."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g


def confined(script, extra_env=None):
    """Run a shell snippet under the real guard policy and return its output."""
    with tempfile.TemporaryDirectory(prefix='toolchain-', dir=Path.home()) as tmp:
        work = Path(tmp)
        (work / 'p.sh').write_text(script)
        development = g.development_options()
        profile = json.loads((ROOT / 'state/zcode-profile.json').read_text())
        with tempfile.TemporaryFile() as out:
            status = g.run_confined(
                'exec', work, ['/bin/bash', str(work / 'p.sh')],
                domains=sorted(set(profile['domains'] + development['packageDomains'])),
                extra_env=extra_env, ephemeral=True, stdout=out)
            out.seek(0)
            return status, out.read().decode(errors='replace')


class ToolchainVisibilityTests(unittest.TestCase):
    def test_the_operators_installed_tools_resolve(self):
        """Homebrew and the node bin directory carry dart, gh and npm."""
        _, text = confined('for t in dart gh npm node git; do printf "%s=%s\\n" "$t" "$(command -v $t)"; done\n')
        for tool in ['dart', 'gh', 'npm', 'node', 'git']:
            with self.subTest(tool=tool):
                self.assertRegex(text, tool + r'=/\S+', text[:400])

    def test_npm_starts_instead_of_refusing_its_own_config(self):
        # Naming the same file as user and global config makes npm exit before
        # it resolves anything at all.
        _, text = confined('npm --version 2>&1 | head -1\n')
        self.assertRegex(text.strip(), r'^\d+\.\d+\.\d+', text[:300])


class DartCoverageTests(unittest.TestCase):
    def test_dart_coverage_runs_on_the_session_loopback_port(self):
        """Reported by a real session: dart test --coverage hung on the VM service port. It must run on the dedicated port."""
        with tempfile.TemporaryDirectory(prefix='dartcov-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'pubspec.yaml').write_text('name: covtest\nenvironment:\n  sdk: ">=3.0.0 <4.0.0"\ndev_dependencies:\n  test: ^1.25.0\n')
            (work / 'lib').mkdir()
            (work / 'lib/a.dart').write_text('int add(int a, int b) => a + b;\n')
            (work / 'test').mkdir()
            (work / 'test/a_test.dart').write_text("import 'package:test/test.dart';\nimport 'package:covtest/a.dart';\n"
                                                   "void main() { test('add', () { expect(add(1, 2), 3); }); }\n")
            (work / 'p.sh').write_text(
                'dart pub get >/dev/null 2>&1 || { echo PUB_GET_FAILED; exit 1; }\n'
                'dart --enable-vm-service=$AGENT_GUARD_LOOPBACK_PORT --no-dds --disable-service-auth-codes '
                'test --coverage=coverage 2>&1 | tail -2\n'
                'ls coverage/test/*.json >/dev/null 2>&1 && echo COVERAGE_WRITTEN || echo NO_COVERAGE\n')
            development = g.development_options()
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')],
                                        domains=development['packageDomains'], ephemeral=True,
                                        loopback_port=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('All tests passed', text)
        self.assertIn('COVERAGE_WRITTEN', text)


class GithubReleaseAssetTests(unittest.TestCase):
    def test_release_assets_host_is_reviewed_and_reachable(self):
        """OpenCode fetches ripgrep from GitHub releases, and with the asset host blocked, glob and grep all failed."""
        self.assertIn('release-assets.githubusercontent.com:443', g.development_options()['packageDomains'])
        _, text = confined('curl -sSL -m 60 -o "$TMPDIR/rg.tgz" -w "final:%{http_code}\\n" '
                           'https://github.com/BurntSushi/ripgrep/releases/download/15.1.0/ripgrep-15.1.0-aarch64-apple-darwin.tar.gz 2>&1 | tail -1\n'
                           'tar -tzf "$TMPDIR/rg.tgz" 2>/dev/null | grep -c "/rg$"\n')
        self.assertIn('final:200', text)
        self.assertRegex(text, r'\n1\s*$')


class SystemTrustTests(unittest.TestCase):
    def test_a_client_using_the_macos_verifier_completes_tls(self):
        """curl carries its own CA bundle and hid this; Go and Dart do not."""
        _, text = confined('gh api user --jq ".login" 2>&1 | head -1\n')
        self.assertNotIn('OSStatus', text, text[:300])

    def test_trust_evaluation_does_not_open_the_keychain(self):
        _, text = confined(
            'security find-generic-password -s "Claude Code-credentials" >/dev/null 2>&1'
            ' && echo OPEN || echo BLOCKED\n'
            'ls ' + str(Path.home()) + '/.ssh >/dev/null 2>&1 && echo OPEN || echo BLOCKED\n'
            'cat ' + str(Path.home()) + '/.zshrc >/dev/null 2>&1 && echo OPEN || echo BLOCKED\n')
        self.assertNotIn('OPEN', text, text[:300])
        self.assertEqual(text.count('BLOCKED'), 3, text[:300])


if __name__ == '__main__': unittest.main()
