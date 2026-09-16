"""Regression for the problem a safecode session misdiagnosed as a 'broken Swift toolchain'. The real cause was three sandbox policy rules."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g


def confined(work, script, **options):
    (work / 'p.sh').write_text(script)
    development = g.development_options()
    with tempfile.TemporaryFile() as out:
        status = g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')],
                                domains=development['packageDomains'], ephemeral=True, stdout=out, **options)
        out.seek(0)
        return status, out.read().decode(errors='replace')


class PolicyTests(unittest.TestCase):
    def test_environment_points_clang_module_cache_into_the_isolated_home(self):
        """The default module cache (/var/folders) was blocked, so it rebuilt stdlib from the interface and tripped the version check."""
        with tempfile.TemporaryDirectory(prefix='swift-env-', dir=Path.home()) as tmp:
            env = g.clean_environment(Path(tmp))
        self.assertTrue(env['CLANG_MODULE_CACHE_PATH'].startswith(tmp + '/'))

    def test_policy_allows_writing_but_not_reading_foundation_temporary_items(self):
        """Foundation's atomic write only needs write access to TemporaryItems in the Darwin per-user temporary directory."""
        items = g.darwin_temporary_items()
        self.assertTrue(items.endswith('/T/TemporaryItems'), items)
        policy = g.sandbox_policy(Path('/tmp/x'), Path('/tmp/h'), [])
        self.assertIn(items, policy['filesystem']['allowWrite'])
        self.assertNotIn(items, policy['filesystem']['allowRead'])
        self.assertNotIn(os.path.dirname(items), policy['filesystem']['allowWrite'])


class DarwinTempDirectoryTests(unittest.TestCase):
    """Some tools hardcode folders under NSTemporaryDirectory() and ignore TMPDIR."""

    def test_configured_names_get_read_write_and_others_stay_closed(self):
        from unittest.mock import patch
        with patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': [],
                                                              'darwinTempDirectories': ['tool-index-db']}):
            policy = g.sandbox_policy(Path('/tmp/x'), Path('/tmp/h'), [])
        base = os.path.dirname(g.darwin_temporary_items())
        self.assertIn(base + '/tool-index-db', policy['filesystem']['allowRead'])
        self.assertIn(base + '/tool-index-db', policy['filesystem']['allowWrite'])
        self.assertNotIn(base, policy['filesystem']['allowRead'])
        self.assertNotIn(base, policy['filesystem']['allowWrite'])

    def test_names_are_validated(self):
        from unittest.mock import patch
        for bad in ['../T', 'a/b', 'xcrun_db-*', '', '.hidden']:
            with patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': [], 'darwinTempDirectories': [bad]}):
                with self.assertRaises(g.GuardError, msg=bad):
                    g.sandbox_policy(Path('/tmp/x'), Path('/tmp/h'), [])

    def test_sandbox_can_use_granted_temp_directories_but_not_siblings(self):
        """The opt-in folder need not exist on the host: `T/` itself is closed, so the supervisor creates it before execution.

        Uses names unique to this test run and removes only what it created, so the operator's real caches are untouched.
        """
        from unittest.mock import patch
        base = os.path.dirname(g.darwin_temporary_items())
        import shutil
        names = ['agent-guard-test-' + os.urandom(3).hex() + suffix for suffix in ('-index', '-cache')]
        options = dict(g.development_options(), darwinTempDirectories=names)
        try:
            with patch.object(g, 'development_options', lambda: options), \
                 tempfile.TemporaryDirectory(prefix='temp-grant-', dir=Path.home()) as tmp:
                status, text = confined(Path(tmp),
                    'd="' + base + '/' + names[0] + '/probe-$$"; mkdir -p "$d" && echo hi > "$d/f" && cat "$d/f" && rm -r "$d" && echo GRANT_RW_OK\n'
                    'mkdir "' + base + '/agent-guard-sibling-$$" 2>/dev/null && echo SIBLING_OPEN || echo SIBLING_BLOCKED\n'
                    'ls "' + base + '" >/dev/null 2>&1 && echo LIST_OPEN || echo LIST_BLOCKED\n')
        finally:
            for name in names:
                shutil.rmtree(os.path.join(base, name), ignore_errors=True)
        self.assertEqual(status, 0, text)
        self.assertIn('GRANT_RW_OK', text)
        self.assertIn('SIBLING_BLOCKED', text)
        self.assertIn('LIST_BLOCKED', text)


class SandboxTests(unittest.TestCase):
    def test_swift_script_runs_and_foundation_atomic_write_works(self):
        with tempfile.TemporaryDirectory(prefix='swift-sb-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 't.swift').write_text('import Foundation\nprint(1)\n'
                                          'try! Data("{}".utf8).write(to: URL(fileURLWithPath: CommandLine.arguments[1] + "/atomic.json"), options: .atomic)\n'
                                          'print("ATOMIC_OK")\n')
            planted = Path(g.darwin_temporary_items()) / 'agent-guard-planted-canary.txt'
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text('CANARY_TEMP_ITEM')
            try:
                status, text = confined(work, 'swift t.swift "$PWD" 2>&1 | tail -2\n'
                                              'cat "' + str(planted) + '" >/dev/null 2>&1 && echo TEMP_READ_OPEN || echo TEMP_READ_BLOCKED\n')
            finally:
                planted.unlink()
        self.assertEqual(status, 0, text)
        self.assertIn('ATOMIC_OK', text)
        self.assertIn('TEMP_READ_BLOCKED', text)
        self.assertNotIn('not supported by the compiler', text)

    def test_swift_package_builds_with_the_documented_flags(self):
        """swift build needs flags because of its own sandbox-exec (nesting is not possible) and .build/build.db (the *.db secret rule)."""
        with tempfile.TemporaryDirectory(prefix='swift-pkg-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'Sources/hello').mkdir(parents=True)
            (work / 'Package.swift').write_text('// swift-tools-version:5.9\nimport PackageDescription\n'
                                                'let package = Package(name: "hello", targets: [.executableTarget(name: "hello")])\n')
            (work / 'Sources/hello/main.swift').write_text('print("HELLO_PKG")\n')
            # The default swiftbuild of CLT 27 loses TMPDIR at the link stage and dies with permissionDenied. Same flags as the notice.
            status, text = confined(work, 'swift build --build-system native --disable-sandbox --scratch-path "$TMPDIR/swiftpm-build" '
                                          '--cache-path "$TMPDIR/swiftpm-cache" 2>&1 | grep -E "Build complete|error" | tail -1\n'
                                          '"$TMPDIR/swiftpm-build/debug/hello"\n')
        self.assertEqual(status, 0, text)
        self.assertIn('Build complete', text)
        self.assertIn('HELLO_PKG', text)


if __name__ == '__main__':
    unittest.main()
