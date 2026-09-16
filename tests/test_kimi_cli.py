"""Regression for kimi mode (safekimi), which runs the Kimi Code CLI in isolation.

The clipboard is the core concern. Kimi reads and writes the clipboard through native NSPasteboard bindings, pbcopy and
osascript (JXA), so we confirm by kernel measurement that all three paths are blocked inside the real Seatbelt (no guessing,
the HANDOFF principle).
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g
from adapters import kimi_cli

# A probe that reads NSPasteboard directly. On the host it must yield real values, and inside the sandbox 0/0/0.
PASTEBOARD_PROBE = '''#import <AppKit/AppKit.h>
#import <stdio.h>
int main(void) {
  @autoreleasepool {
    NSPasteboard *pb = [NSPasteboard generalPasteboard];
    NSInteger count = [pb changeCount];
    NSArray *types = [pb types];
    NSString *text = [pb stringForType:NSPasteboardTypeString];
    printf("PBPROBE changeCount=%ld types=%lu string_len=%lu\\n", (long)count, (unsigned long)[types count], (unsigned long)[text length]);
  }
  return 0;
}
'''


def confined_with_piped_stderr(work, command, out, **options):
    """Run a Node-family child in isolation. stdout goes to out and stderr is taken through a pipe, returning (status, stderr).

    Why stderr is switched to a pipe: if the test runner's stderr is a file outside the sandbox (a log redirect), Node fstats
    fd 0-2 at startup, receives EPERM and aborts (SIGABRT, exit 134). This is a runner condition that does not arise with the
    TTY or pipe of real use.
    """
    read_end, write_end = os.pipe()
    saved = os.dup(2)
    os.dup2(write_end, 2)
    os.close(write_end)
    try:
        status = g.run_confined('kimi-test', work, command, domains=[], ephemeral=True, stdout=out, **options)
    finally:
        os.dup2(saved, 2)
        os.close(saved)
    chunks = []
    while True:
        chunk = os.read(read_end, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_end)
    return status, b''.join(chunks).decode(errors='replace')


def run_kimi_confined(work, arguments, out):
    """Run the installed Kimi in isolation with the real kimi-mode preparation (region marker, environment variables, read allowances, preload)."""
    return confined_with_piped_stderr(work, [str(g.KIMI), *arguments], out,
                                      extra_reads=[g.KIMI, kimi_cli.WATCH_BOOTSTRAP],
                                      prepare_home=kimi_cli.prepare_kimi_home('global', g.KIMI),
                                      read_only_home_paths=[kimi_cli.REGION_MARKER_RELATIVE])


# A probe that opens an FSEvents stream. Inside the isolation it must be START FAILED (allowing it leaks filenames of read-denied paths).
FSEVENTS_PROBE = '''#import <CoreServices/CoreServices.h>
#import <stdio.h>
static void cb(ConstFSEventStreamRef s, void *info, size_t n, void *paths, const FSEventStreamEventFlags f[], const FSEventStreamEventId ids[]) {}
int main(int argc, char **argv) {
  CFStringRef p = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
  CFArrayRef arr = CFArrayCreate(NULL, (const void **)&p, 1, &kCFTypeArrayCallBacks);
  FSEventStreamRef st = FSEventStreamCreate(NULL, cb, NULL, arr, kFSEventStreamEventIdSinceNow, 0.2, kFSEventStreamCreateFlagFileEvents);
  FSEventStreamScheduleWithRunLoop(st, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
  printf("FSEVENTS START %s\\n", FSEventStreamStart(st) ? "ok" : "FAILED");
  return 0;
}
'''


class WatcherBoundaryTests(unittest.TestCase):
    """Directory watching must work without FSEvents. We measured that allowing FSEvents leaks filenames of read-denied paths."""

    def test_fsevents_cannot_be_started_inside_the_sandbox(self):
        with tempfile.TemporaryDirectory(prefix='kimi-fsev-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'fsev.m').write_text(FSEVENTS_PROBE)
            build = subprocess.run(['/usr/bin/clang', '-framework', 'CoreServices', '-o', str(work / 'fsev'), str(work / 'fsev.m')],
                                   capture_output=True, text=True, timeout=120,
                                   env={'PATH': '/usr/bin:/bin', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'})
            if build.returncode:
                raise unittest.SkipTest('clang could not build the FSEvents probe: ' + build.stderr[-300:])
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('kimi-test', work, [str(work / 'fsev'), str(work)], domains=[], ephemeral=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('FSEVENTS START FAILED', text)

    def test_bootstrap_makes_directory_watches_inert_and_keeps_file_watches(self):
        """Under the preload, directory fs.watch is silent without error, and file fs.watch receives real changes through kqueue."""
        script = '''
const fs = require("node:fs");
const dir = process.argv[2], file = process.argv[3];
const d = fs.watch(dir, {recursive: true});
d.on("error", e => { console.log("DIR_ERROR " + e.code); });
const seen = [];
const f = fs.watch(file, (event) => { seen.push(event); });
f.on("error", e => { console.log("FILE_ERROR " + e.code); });
setTimeout(() => fs.appendFileSync(file, "x"), 200);
let closes = 0; d.on("close", () => closes++);
setTimeout(() => { console.log("DIR_CTOR " + d.constructor.name + " FILE_EVENTS " + seen.length); d.close(); d.close(); f.close();
  setTimeout(() => console.log("DIR_CLOSE_EVENTS " + closes), 50); }, 1500);
'''
        for label, binary, expected in [('scoped to kimi', str(g.NODE), 'InertWatcher'), ('other node', '/usr/bin/false', 'FSWatcher')]:
            with tempfile.TemporaryDirectory(prefix='kimi-watch-', dir=Path.home()) as tmp:
                work = Path(tmp)
                (work / 'probe.js').write_text(script)
                (work / 'target.txt').write_text('start')
                with tempfile.TemporaryFile() as out:
                    status, stderr = confined_with_piped_stderr(
                        work, [str(g.NODE), str(work / 'probe.js'), str(work), str(work / 'target.txt')], out,
                        extra_reads=[kimi_cli.WATCH_BOOTSTRAP],
                        extra_env={'NODE_OPTIONS': '--require ' + str(kimi_cli.WATCH_BOOTSTRAP), 'AGENT_GUARD_KIMI_BINARY': binary})
                    out.seek(0)
                    text = out.read().decode(errors='replace')
            self.assertEqual(status, 0, label + ': ' + text + stderr)
            self.assertIn('DIR_CTOR ' + expected, text, label)
            self.assertNotIn('FILE_ERROR', text, label)
            self.assertRegex(text, r'FILE_EVENTS [1-9]')
            if expected == 'InertWatcher':
                self.assertNotIn('DIR_ERROR', text)
                self.assertIn('DIR_CLOSE_EVENTS 1', text)  # close only once
            else:
                self.assertIn('DIR_ERROR EMFILE', text)  # On an out-of-scope node the original behavior holds (the FSEvents denial is visible as is).

    def test_network_reaches_only_the_profile_hosts(self):
        """Telemetry, update and CDN hosts fail as early as DNS, and only the login and API hosts pass through the proxy."""
        script = ('for h in telemetry-logs.kimi.ai code.kimi.ai cdn.kimi.com; do '
                  'curl -sS -m 8 -o /dev/null -w "$h:%{http_code}\\n" "https://$h/" 2>/dev/null || echo "$h:blocked"; done\n'
                  'curl -sS -m 15 -o /dev/null -w "api:%{http_code}\\n" https://api.kimi.ai/ 2>&1 | tail -1\n')
        with tempfile.TemporaryDirectory(prefix='kimi-net-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'p.sh').write_text(script)
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('kimi-test', work, ['/bin/bash', str(work / 'p.sh')],
                                        domains=kimi_cli.default_profile()['domains'], ephemeral=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        for host in ('telemetry-logs.kimi.ai', 'code.kimi.ai', 'cdn.kimi.com'):
            self.assertRegex(text, host + r':(blocked|000)', text)
        self.assertRegex(text, r'api:[1-5]\d\d', text)


class ProfileTests(unittest.TestCase):
    def test_default_profile_opens_only_login_and_coding_api_hosts(self):
        profile = kimi_cli.default_profile()
        self.assertEqual(profile['region'], 'global')
        self.assertIn('auth.kimi.ai:443', profile['domains'])
        self.assertIn('api.kimi.ai:443', profile['domains'])
        joined = ' '.join(profile['domains'])
        for closed in ['telemetry-logs', 'cdn.kimi', 'code.kimi', 'platform.kimi', 'www.kimi', 'kimi.com']:
            self.assertNotIn(closed, joined)

    def test_profile_rejects_unknown_region_and_malformed_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'kimi-profile.json'
            with patch.object(kimi_cli, 'PROFILE_PATH', path):
                path.write_text(json.dumps({'region': 'mars', 'domains': ['api.kimi.ai:443']}))
                with self.assertRaises(g.GuardError):
                    kimi_cli.load_profile()
                for bad in (['api.kimi.ai'], ['*.kimi.ai:443'], ['api.kimi.ai:80'], ['telemetry-logs.kimi.ai:443'], []):
                    path.write_text(json.dumps({'region': 'global', 'domains': bad}))
                    with self.assertRaises(g.GuardError, msg=str(bad)):
                        kimi_cli.load_profile()
                path.unlink()
                self.assertEqual(kimi_cli.load_profile(), kimi_cli.default_profile())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_environment_disables_telemetry_updates_and_pins_the_kimi_home(self):
        env = kimi_cli.kimi_environment(Path('/tmp/synthetic-home'), Path('/tmp/staged/kimi'))
        self.assertEqual(env['KIMI_CODE_HOME'], '/tmp/synthetic-home/.kimi-code')
        self.assertEqual(env['AGENT_GUARD_KIMI_BINARY'], '/tmp/staged/kimi')
        self.assertEqual(env['KIMI_DISABLE_TELEMETRY'], '1')
        self.assertEqual(env['KIMI_CODE_NO_AUTO_UPDATE'], '1')
        self.assertEqual(env['KIMI_CLI_NO_AUTO_UPDATE'], '1')
        self.assertEqual(env['KIMI_SHELL_PATH'], '/bin/bash')


class BinaryGateTests(unittest.TestCase):
    def test_kimi_rejects_changed_binary_and_missing_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'kimi'
            binary.write_bytes(b'original')
            state = root / 'state'
            state.mkdir()
            with patch.object(g, 'ROOT', root), patch.object(g, 'KIMI', binary):
                with self.assertRaises(g.GuardError):
                    g.verify_kimi_binary()  # no baseline -> closed
                (state / 'compatibility.json').write_text(json.dumps({'opencode': {}}))
                with self.assertRaises(g.GuardError):
                    g.verify_kimi_binary()  # no kimi entry -> closed
                (state / 'compatibility.json').write_text(json.dumps(
                    {'kimi': {'version': 't', 'sha256': hashlib.sha256(b'original').hexdigest()}}))
                self.assertEqual(g.verify_kimi_binary(), 't')
                binary.write_bytes(b'updated')
                with self.assertRaises(g.GuardError):
                    g.verify_kimi_binary()

    def test_staged_copy_is_verified_and_replaced_binary_is_refused(self):
        """Swapping between verification and execution: what runs is the guard-owned clone, and it is rejected when its hash differs from the baseline."""
        with tempfile.TemporaryDirectory(prefix='kimi-stage-', dir=Path.home()) as tmp:
            root = Path(tmp)
            binary = root / 'kimi'
            binary.write_bytes(b'reviewed bytes')
            (root / 'state').mkdir()
            (root / 'state/compatibility.json').write_text(json.dumps(
                {'kimi': {'version': 't', 'sha256': hashlib.sha256(b'reviewed bytes').hexdigest()}}))
            with patch.object(g, 'ROOT', root), patch.object(g, 'KIMI', binary):
                staged = g.stage_kimi_binary()
                self.assertEqual(staged.parent.parent, root / 'state/kimi-runtime')
                self.assertEqual(staged.read_bytes(), b'reviewed bytes')
                self.assertEqual(staged.stat().st_mode & 0o777, 0o500)
                binary.write_bytes(b'swapped after review')
                self.assertEqual(staged.read_bytes(), b'reviewed bytes')  # The clone is unaffected by writes to the original.
                g.discard_staged_binary(staged)
                self.assertFalse(staged.parent.exists())
                with self.assertRaises(g.GuardError):
                    g.stage_kimi_binary()
                self.assertEqual([p for p in (root / 'state/kimi-runtime').iterdir()], [])

    def test_compatibility_candidate_is_optional_and_baseline_is_kept_without_it(self):
        from adapters import compatibility_check as check
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(check.kimi_candidate(Path(tmp) / 'missing'))
        saved = {'opencode': {'version': 'o'}, 'zcode': {'version': 'z'}, 'kimi': {'version': '0.43.1', 'sha256': 'kept'}}
        merged = check.merged_baseline({'opencode': {'version': 'o2'}, 'zcode': {'version': 'z'}}, saved)
        self.assertEqual(merged['kimi'], saved['kimi'])
        merged = check.merged_baseline({'opencode': {'version': 'o2'}, 'zcode': {'version': 'z'}, 'kimi': {'version': 'new'}}, saved)
        self.assertEqual(merged['kimi'], {'version': 'new'})

    def test_doctor_reports_the_kimi_baseline(self):
        current = {'opencode': {'version': '1', 'sha256': 'a'}, 'zcode': {'version': '3', 'asarSha256': 'b', 'agentSha256': 'c'},
                   'mobile': 'm', 'kimi': {'version': '0.43.1', 'sha256': 'd'}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            (root / 'state/compatibility.json').write_text(json.dumps(dict(current, kimi={'version': '0.43.1', 'sha256': 'e'})))
            fake_module = type(sys)('adapters.compatibility_check')
            fake_module.candidate = lambda: current
            with patch.object(g, 'ROOT', root), patch.dict(sys.modules, {'adapters.compatibility_check': fake_module}), \
                 patch.object(g, 'riskgate_policy', lambda: ROOT / 'state/riskgate.json'), \
                 patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': []}), \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(g.doctor(), 2)
                (root / 'state/compatibility.json').write_text(json.dumps(current))
                self.assertEqual(g.doctor(), 0)


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            self.calls.append(dict(kwargs, mode=mode, workspace=workspace, command=command, positional=args))
            return 0
        self.work_dir = tempfile.TemporaryDirectory(prefix='kimi-wiring-', dir=Path.home())
        self.work = Path(self.work_dir.name)
        self.staged = Path('/tmp/synthetic-kimi-runtime/launch-1-x/kimi')
        self.discarded = []
        self.patches = [patch.object(g, 'run_confined', fake_run_confined),
                        patch.object(g, 'verify_kimi_binary', lambda: '0.43.1'),
                        patch.object(g, 'stage_kimi_binary', lambda: self.staged),
                        patch.object(g, 'discard_staged_binary', self.discarded.append),
                        patch.object(g.os, 'getcwd', return_value=str(self.work)),
                        patch.object(kimi_cli, 'load_profile', kimi_cli.default_profile),
                        patch.object(g, 'pub_publish_grant', lambda workspace: None),
                        patch.object(g, 'loopback_grant', lambda workspace: False),
                        patch.object(g, 'gradle_keystore_grant', lambda workspace: False)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.work_dir.cleanup()

    def test_current_directory_becomes_the_workspace_and_arguments_pass_through(self):
        self.assertEqual(g.main(['kimi', '--', '--print', 'prompt with spaces']), 0)
        call = self.calls[0]
        self.assertEqual(call['mode'], 'kimi')
        self.assertEqual(call['workspace'], self.work)
        self.assertEqual(call['command'], [str(self.staged), '--print', 'prompt with spaces'])
        self.assertEqual(self.discarded, [self.staged])

    def test_staged_copy_is_discarded_even_when_the_launch_fails(self):
        with patch.object(g, 'run_confined', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                g.main(['kimi'])
        self.assertEqual(self.discarded, [self.staged])

    def test_domains_are_the_profile_hosts_plus_package_domains_only(self):
        self.assertEqual(g.main(['kimi']), 0)
        call = self.calls[0]
        domains = call['positional'][0] if call['positional'] else call['domains']
        self.assertIn('api.kimi.ai:443', domains)
        self.assertIn('auth.kimi.ai:443', domains)
        self.assertIn('registry.npmjs.org:443', domains)
        self.assertNotIn('telemetry-logs.kimi.ai:443', domains)
        self.assertNotIn('cdn.kimi.com:443', domains)

    def test_binary_is_the_only_extra_read_and_region_marker_is_locked(self):
        self.assertEqual(g.main(['kimi']), 0)
        call = self.calls[0]
        self.assertEqual(list(call['extra_reads']), [self.staged, kimi_cli.WATCH_BOOTSTRAP])
        self.assertEqual(list(call['read_only_home_paths']), ['.kimi-code/region'])
        self.assertEqual(list(call['instruction_files']), ['.kimi-code/AGENTS.md'])
        self.assertTrue(call['loopback_port'])
        self.assertIsNone(call.get('extra_env'))
        # The environment is populated inside prepare_home with the home decided by run_confined (the home is not created in advance).
        self.assertFalse((ROOT / 'state/homes/kimi' / hashlib.sha256(str(self.work).encode()).hexdigest()[:20]).exists())
        with tempfile.TemporaryDirectory(prefix='kimi-env-', dir=Path.home()) as tmp:
            env = {}
            call['prepare_home'](Path(tmp), env)
        self.assertEqual(env['KIMI_CODE_HOME'], tmp + '/.kimi-code')
        self.assertEqual(env['AGENT_GUARD_KIMI_BINARY'], str(self.staged))
        self.assertEqual(env['KIMI_DISABLE_TELEMETRY'], '1')
        self.assertEqual(env['CHOKIDAR_USEPOLLING'], '1')
        self.assertEqual(env['NODE_OPTIONS'], '--require ' + str(kimi_cli.WATCH_BOOTSTRAP))
        self.assertIn('clipboard', call['notice_extra'])
        self.assertIn('/login', call['notice_extra'])

    def test_prepare_home_writes_the_region_marker_link_safely(self):
        self.assertEqual(g.main(['kimi']), 0)
        with tempfile.TemporaryDirectory(prefix='kimi-home-', dir=Path.home()) as tmp:
            home = Path(tmp)
            self.calls[0]['prepare_home'](home, {})
            marker = home / '.kimi-code/region'
            self.assertEqual(marker.read_text(), 'global\n')
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            # Even if a previous session planted a link where the marker goes, the supervisor's write does not leak to the host.
            outside = home / 'outside.txt'
            outside.write_text('host file')
            marker.unlink()
            marker.symlink_to(outside)
            self.calls[0]['prepare_home'](home, {})
            self.assertEqual(outside.read_text(), 'host file')
            self.assertFalse(marker.is_symlink())

    def test_binary_gate_runs_before_launch(self):
        with patch.object(g, 'verify_kimi_binary', side_effect=g.GuardError('changed')):
            with self.assertRaises(g.GuardError):
                g.main(['kimi'])
        self.assertEqual(self.calls, [])

    def test_home_directory_is_rejected_as_a_workspace(self):
        with patch.object(g.os, 'getcwd', return_value=str(Path.home())):
            with self.assertRaises(g.GuardError):
                g.main(['kimi'])
        self.assertEqual(self.calls, [])


class ClipboardBoundaryTests(unittest.TestCase):
    """Measure whether all three clipboard paths (NSPasteboard, pbpaste/pbcopy, osascript JXA) are blocked inside the real Seatbelt."""

    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(prefix='kimi-pbprobe-', dir=Path.home())
        source = Path(cls.build_dir.name) / 'pbprobe.m'
        source.write_text(PASTEBOARD_PROBE)
        cls.probe = Path(cls.build_dir.name) / 'pbprobe'
        build = subprocess.run(['/usr/bin/clang', '-fobjc-arc', '-framework', 'AppKit', '-o', str(cls.probe), str(source)],
                               capture_output=True, text=True, timeout=120,
                               env={'PATH': '/usr/bin:/bin', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'})
        if build.returncode:
            raise unittest.SkipTest('clang could not build the pasteboard probe: ' + build.stderr[-300:])

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def test_host_probe_sees_the_pasteboard(self):
        """Control group. changeCount must be greater than 0 on the host for the sandbox's 0 to mean a block. The contents are not printed."""
        result = subprocess.run([str(self.probe)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r'PBPROBE changeCount=[1-9]\d* ')

    def test_every_clipboard_path_is_closed_inside_the_sandbox(self):
        script = ('./pbprobe\n'
                  'pbpaste >/dev/null 2>&1; echo "pbpaste_exit=$?"\n'
                  'printf x | pbcopy >/dev/null 2>&1; echo "pbcopy_exit=$?"\n'
                  'osascript -l JavaScript -e "ObjC.import(\'AppKit\'); String($.NSPasteboard.generalPasteboard.changeCount)" 2>/dev/null'
                  ' | head -1 | sed "s/^/jxa=/"\n')
        with tempfile.TemporaryDirectory(prefix='kimi-clipboard-', dir=Path.home()) as tmp:
            work = Path(tmp)
            shutil.copy(str(self.probe), str(work / 'pbprobe'))
            (work / 'p.sh').write_text(script)
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('kimi-test', work, ['/bin/bash', str(work / 'p.sh')],
                                        domains=kimi_cli.default_profile()['domains'], ephemeral=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('PBPROBE changeCount=0 types=0 string_len=0', text)
        self.assertIn('pbpaste_exit=1', text)
        self.assertIn('pbcopy_exit=1', text)
        self.assertNotRegex(text, r'jxa=[1-9]')


def require_installed_kimi():
    """Skip only when there is no installed Kimi. Skipping on a baseline mismatch would let verify-updates bless a new candidate without inspection (review HIGH)."""
    if not g.KIMI.is_file():
        raise unittest.SkipTest('Kimi Code is not installed')


class PublicationHardeningTests(unittest.TestCase):
    """Pre-publication review (2026-09-16): defenses that only matter once other people install the guard."""

    def test_workspace_may_not_contain_the_installation_or_trusted_executables(self):
        with tempfile.TemporaryDirectory(prefix='overlap-', dir=Path.home()) as tmp:
            base = Path(tmp)
            (base / 'guard').mkdir(); (base / 'project').mkdir(); (base / 'tools/bin').mkdir(parents=True)
            with patch.object(g, 'ROOT', base / 'guard'):
                with self.assertRaises(g.GuardError):
                    g.workspace_path(base)  # contains the installation
                with self.assertRaises(g.GuardError):
                    g.workspace_path(base / 'guard')  # is the installation
                self.assertEqual(g.workspace_path(base / 'project'), base / 'project')
            with patch.object(g, 'NODE', base / 'tools/bin/node'):
                with self.assertRaises(g.GuardError):
                    g.workspace_path(base / 'tools')  # contains the trusted node binary

    def test_node_discovery_never_raises_on_unreadable_paths(self):
        """The hook imports agent_guard inside the sandbox; a PermissionError at import would deny every tool call."""
        with patch.object(g.Path, 'is_file', side_effect=PermissionError('denied')), \
             patch.object(g.Path, 'glob', side_effect=PermissionError('denied')):
            self.assertTrue(str(g.newest_nvm_node(Path('/nonexistent-home'))).endswith('/bin/node'))

    def test_short_temp_directory_falls_back_when_the_install_path_is_long(self):
        with tempfile.TemporaryDirectory(prefix='very-long-install-root-name-for-agent-guard-', dir=Path.home()) as tmp:
            with patch.object(g, 'ROOT', Path(tmp)):
                directory = g.short_temp_directory('autoclaw', Path('/tmp/w'))
        self.assertLessEqual(len(str(directory).encode()), 57)
        self.assertTrue(str(directory).startswith('/private/tmp/agent-guard-' + str(os.getuid()) + '/'))
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        shutil.rmtree(directory, ignore_errors=True)

    def test_packet_doctor_passes_the_reviewed_version_to_the_entry_point(self):
        seen = {}
        with patch.object(g, 'run_confined', lambda *a, **k: seen.update(k) or 0), \
             patch.object(g, 'packet_ask_pinned_version', lambda: '9.9.9'), \
             patch('sys.stdout', new_callable=io.StringIO):
            g.packet_provider_status(['doctor'])
        self.assertEqual(seen['extra_env']['AGENT_GUARD_PACKET_ASK_VERSION'], '9.9.9')


class HomebrewDataBoundaryTests(unittest.TestCase):
    """Homebrew tools are visible, but service data (`/opt/homebrew/var`) is not readable in any mode (2026-09-16 review HIGH)."""

    def test_homebrew_var_is_closed_while_tools_and_certificates_stay_open(self):
        script = ('ls /opt/homebrew/var >/dev/null 2>&1 && echo VAR_OPEN || echo VAR_BLOCKED\n'
                  'ls /opt/homebrew/var/postgresql@16 >/dev/null 2>&1 && echo PG_OPEN || echo PG_BLOCKED\n'
                  'ls /opt/homebrew/bin >/dev/null 2>&1 && echo BIN_OPEN || echo BIN_BLOCKED\n'
                  'ls /opt/homebrew/etc/ca-certificates >/dev/null 2>&1 && echo CERT_OPEN || echo CERT_BLOCKED\n')
        with tempfile.TemporaryDirectory(prefix='brew-var-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'p.sh').write_text(script)
            with tempfile.TemporaryFile() as out:
                status = g.run_confined('kimi-test', work, ['/bin/bash', str(work / 'p.sh')], domains=[], ephemeral=True, stdout=out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('VAR_BLOCKED', text)
        self.assertIn('PG_BLOCKED', text)
        self.assertIn('BIN_OPEN', text)
        self.assertIn('CERT_OPEN', text)
        self.assertIn('/opt/homebrew/var', g.sandbox_policy(work, work / 'home', [])['filesystem']['denyRead'])


class LaunchSmokeTests(unittest.TestCase):
    def test_installed_kimi_starts_inside_the_sandbox_and_reports_its_version(self):
        """The installed Kimi starts up inside the real policy (SEA loader, read allowances, environment, preload). Skip if absent."""
        require_installed_kimi()
        with tempfile.TemporaryDirectory(prefix='kimi-smoke-', dir=Path.home()) as tmp:
            with tempfile.TemporaryFile() as out:
                status, stderr = run_kimi_confined(Path(tmp), ['--version'], out)
                out.seek(0)
                text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text + stderr)
        self.assertRegex(text.strip(), r'^\d+\.\d+\.\d+')
        self.assertNotIn('Native stack trace', stderr)

    def test_compatibility_probe_runs_the_candidate_inside_the_sandbox(self):
        """Do not run an unreviewed candidate directly on the host. The probe goes through run_confined."""
        from adapters import compatibility_check as check
        require_installed_kimi()
        seen = {}
        real = g.run_confined

        def spy(mode, workspace, command, *args, **kwargs):
            seen.update(mode=mode, command=command, domains=kwargs.get('domains', args[0] if args else None))
            return real(mode, workspace, command, *args, **kwargs)
        with patch.object(g, 'run_confined', spy):
            entry = check.kimi_candidate(g.KIMI)
        self.assertEqual(seen['mode'], 'kimi-probe')
        self.assertEqual(seen['command'][1], '--version')
        self.assertEqual(list(seen['domains'] or []), [])
        self.assertRegex(entry['version'], r'^\d+\.\d+\.\d+')
        self.assertEqual(entry['sha256'], hashlib.sha256(g.KIMI.read_bytes()).hexdigest())

    def test_tui_starts_under_a_private_pty_without_the_fsevents_crash(self):
        """The real TUI comes up inside the isolation as far as the first screen (the folder-trust question). Without the preload it dies with EMFILE."""
        import pty
        import re
        import select
        import signal
        import time
        require_installed_kimi()
        with tempfile.TemporaryDirectory(prefix='kimi-tui-', dir=Path.home()) as tmp:
            work = Path(tmp)
            runner = ('import sys; sys.path.insert(0, sys.argv[1]); import agent_guard as g; from adapters import kimi_cli; from pathlib import Path; '
                      'w = Path(sys.argv[2]); sys.exit(g.run_confined("kimi-test", w, [str(g.KIMI)], domains=[], ephemeral=True, '
                      'extra_reads=[g.KIMI, kimi_cli.WATCH_BOOTSTRAP], prepare_home=kimi_cli.prepare_kimi_home("global", g.KIMI), '
                      'read_only_home_paths=[kimi_cli.REGION_MARKER_RELATIVE]))')
            pid, master = pty.fork()
            if pid == 0:
                os.chdir(str(work))
                os.environ.update({'TERM': 'xterm-256color', 'COLUMNS': '120', 'LINES': '40'})
                os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', '-c', runner, str(ROOT), str(work)])
            buffer = b''
            deadline = time.time() + 25
            try:
                while time.time() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if ready:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        buffer += chunk
                        if b'Trust this folder' in buffer and time.time() + 2 < deadline:
                            deadline = time.time() + 2  # The first screen has been seen, so collect a little longer and finish.
                alive = True
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    alive = False
            finally:
                for _ in range(2):
                    try:
                        os.write(master, b'\x03')
                    except OSError:
                        break
                    time.sleep(0.3)
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                time.sleep(0.5)
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                os.close(master)
        text = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07', '', buffer.decode(errors='replace'))
        self.assertIn('Trust this folder', text, text[-1500:])
        self.assertNotIn('EMFILE', text)
        self.assertNotIn('Native stack trace', text)
        self.assertTrue(alive, 'the TUI exited before the first screen: ' + text[-800:])


if __name__ == '__main__':
    unittest.main()
