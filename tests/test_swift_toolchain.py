"""safecode 세션이 'Swift 툴체인 고장'으로 오진한 문제의 회귀. 실제 원인은 샌드박스 정책 셋이었다."""
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
        """기본 모듈 캐시(/var/folders)가 막혀 stdlib 를 인터페이스에서 다시 빌드하다 버전 검사에 걸렸다."""
        with tempfile.TemporaryDirectory(prefix='swift-env-', dir=Path.home()) as tmp:
            env = g.clean_environment(Path(tmp))
        self.assertTrue(env['CLANG_MODULE_CACHE_PATH'].startswith(tmp + '/'))

    def test_policy_allows_writing_but_not_reading_foundation_temporary_items(self):
        """Foundation 의 원자적 쓰기는 Darwin 사용자 임시 디렉터리의 TemporaryItems 에 쓰기만 필요하다."""
        items = g.darwin_temporary_items()
        self.assertTrue(items.endswith('/T/TemporaryItems'), items)
        policy = g.sandbox_policy(Path('/tmp/x'), Path('/tmp/h'), [])
        self.assertIn(items, policy['filesystem']['allowWrite'])
        self.assertNotIn(items, policy['filesystem']['allowRead'])
        self.assertNotIn(os.path.dirname(items), policy['filesystem']['allowWrite'])


class DarwinTempDirectoryTests(unittest.TestCase):
    """cartograph 는 NSTemporaryDirectory() 아래 두 폴더를 하드코딩하고 TMPDIR 을 무시한다."""

    def test_configured_names_get_read_write_and_others_stay_closed(self):
        from unittest.mock import patch
        with patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': [],
                                                              'darwinTempDirectories': ['cartograph-index-db']}):
            policy = g.sandbox_policy(Path('/tmp/x'), Path('/tmp/h'), [])
        base = os.path.dirname(g.darwin_temporary_items())
        self.assertIn(base + '/cartograph-index-db', policy['filesystem']['allowRead'])
        self.assertIn(base + '/cartograph-index-db', policy['filesystem']['allowWrite'])
        self.assertNotIn(base, policy['filesystem']['allowRead'])
        self.assertNotIn(base, policy['filesystem']['allowWrite'])

    def test_names_are_validated(self):
        from unittest.mock import patch
        for bad in ['../T', 'a/b', 'xcrun_db-*', '', '.hidden']:
            with patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': [], 'darwinTempDirectories': [bad]}):
                with self.assertRaises(g.GuardError, msg=bad):
                    g.sandbox_policy(Path('/tmp/x'), Path('/tmp/h'), [])

    def test_state_file_opts_in_the_two_cartograph_directories(self):
        options = g.development_options()
        self.assertEqual(sorted(options.get('darwinTempDirectories', [])), ['cartograph-index-db', 'cartograph-syntax-cache'])

    def test_sandbox_can_use_the_cartograph_directories_but_not_siblings(self):
        """옵트인 폴더가 호스트에 없어도 된다: `T/` 자체는 닫혀 있으므로 감독자가 실행 전에 만들어 둔다."""
        base = os.path.dirname(g.darwin_temporary_items())
        import shutil
        for name in ('cartograph-index-db', 'cartograph-syntax-cache'):
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)
        with tempfile.TemporaryDirectory(prefix='carto-tmp-', dir=Path.home()) as tmp:
            status, text = confined(Path(tmp),
                'd="' + base + '/cartograph-index-db/probe-$$"; mkdir -p "$d" && echo hi > "$d/f" && cat "$d/f" && rm -r "$d" && echo CARTO_RW_OK\n'
                'mkdir "' + base + '/agent-guard-sibling-$$" 2>/dev/null && echo SIBLING_OPEN || echo SIBLING_BLOCKED\n'
                'ls "' + base + '" >/dev/null 2>&1 && echo LIST_OPEN || echo LIST_BLOCKED\n')
        self.assertEqual(status, 0, text)
        self.assertIn('CARTO_RW_OK', text)
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
        """swift build 는 자체 sandbox-exec(중첩 불가)와 .build/build.db(*.db 비밀 규칙) 때문에 플래그가 필요하다."""
        with tempfile.TemporaryDirectory(prefix='swift-pkg-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'Sources/hello').mkdir(parents=True)
            (work / 'Package.swift').write_text('// swift-tools-version:5.9\nimport PackageDescription\n'
                                                'let package = Package(name: "hello", targets: [.executableTarget(name: "hello")])\n')
            (work / 'Sources/hello/main.swift').write_text('print("HELLO_PKG")\n')
            # CLT 27 의 기본 swiftbuild 는 링크 단계에서 TMPDIR 을 잃어 permissionDenied 로 죽는다. 안내문과 같은 플래그.
            status, text = confined(work, 'swift build --build-system native --disable-sandbox --scratch-path "$TMPDIR/swiftpm-build" '
                                          '--cache-path "$TMPDIR/swiftpm-cache" 2>&1 | grep -E "Build complete|error" | tail -1\n'
                                          '"$TMPDIR/swiftpm-build/debug/hello"\n')
        self.assertEqual(status, 0, text)
        self.assertIn('Build complete', text)
        self.assertIn('HELLO_PKG', text)


if __name__ == '__main__':
    unittest.main()
