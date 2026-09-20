"""Synthetic regressions for the September 18 host/child authority audit."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g
from adapters import compatibility_check, usage_cli


class HostBoundaryTests(unittest.TestCase):
    def setUp(self):
        # Keep SRT's unix socket path below Darwin's sun_path limit.
        self.temp = tempfile.TemporaryDirectory(prefix='g-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'r'
        self.root.mkdir(mode=0o700)
        runtime = ROOT / 'runtime/node_modules'
        if not runtime.is_dir():
            runtime = g.OWNER_HOME / '.local/share/agentbelt/runtime/node_modules'
        if not runtime.is_dir():
            self.skipTest('Install the pinned sandbox runtime before kernel tests.')
        (self.root / 'runtime').mkdir()
        (self.root / 'runtime/node_modules').symlink_to(runtime, target_is_directory=True)
        for suffix in ('*.py', '*.mjs', '*.cjs'):
            for source in ROOT.glob(suffix):
                shutil.copyfile(source, self.root / source.name)
        (self.root / 'state').mkdir(mode=0o700)
        self.patches = [patch.object(g, 'ROOT', self.root),
                        patch.object(g, 'host_git_identity', return_value=None),
                        patch.object(g, 'github_token', return_value='SYNTHETIC_AUDIT_TOKEN'),
                        patch.object(usage_cli, 'ROOT', self.root),
                        patch.object(usage_cli, 'PROFILE_PATH', self.root / 'state/usage-profile.json'),
                        patch.object(compatibility_check, 'ROOT', self.root)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def usage_entry(self, code):
        home = usage_cli.usage_home()
        entry = usage_cli.bl_entry(home)
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text(code)
        return home, entry

    def test_usage_login_cannot_run_a_modified_entry_with_host_authority(self):
        marker = self.base / 'outside-marker'
        code = ('import fs from "node:fs";\n'
                'try { fs.writeFileSync(' + json.dumps(str(marker)) + ', "synthetic"); process.exit(9); }\n'
                'catch (error) { process.exit(["EPERM", "EACCES"].includes(error.code) ? 0 : 2); }\n')
        self.usage_entry(code)
        self.assertEqual(usage_cli.run_usage(['login']), 0)
        self.assertFalse(marker.exists())

    def test_usage_receives_no_repository_token_and_removes_stale_copy(self):
        home = usage_cli.usage_home()
        (home / '.git-credentials').write_text('SYNTHETIC_OLD_TOKEN')
        code = ('import os; from pathlib import Path; '
                'raise SystemExit(9 if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") '
                'or (Path.home()/".git-credentials").exists() else 0)')
        self.assertEqual(usage_cli.run_sandboxed(
            ['/Library/Developer/CommandLineTools/usr/bin/python3', '-I', '-c', code], []), 0)
        self.assertFalse((home / '.git-credentials').exists())

    def test_candidate_probe_cannot_write_outside_its_workspace(self):
        binary = self.base / 'opencode'
        marker = self.base / 'candidate-host-marker'
        import shlex
        binary.write_text('#!/bin/sh\nprintf synthetic > ' + shlex.quote(str(marker)) + '\nprintf 1.2.3\n')
        binary.chmod(0o700)
        with patch.object(g, 'OPENCODE', binary):
            candidate = compatibility_check.opencode_candidate()
        self.assertEqual(candidate['version'], '1.2.3')
        self.assertEqual(candidate['sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
        self.assertFalse(marker.exists())

    def test_candidate_change_during_probe_is_not_recorded_as_reviewed(self):
        binary = self.base / 'opencode'
        original = b'#!/bin/sh\nprintf 1.2.3\n'
        binary.write_bytes(original)
        binary.chmod(0o700)
        seen = []
        real = g.run_confined
        def swap(mode, workspace, command, *args, **kwargs):
            staged = Path(command[0])
            seen.append(staged)
            self.assertNotEqual(staged, binary)
            self.assertEqual(staged.read_bytes(), original)
            binary.write_text('#!/bin/sh\nprintf 9.9.9\n')
            self.assertEqual(staged.read_bytes(), original)
            return real(mode, workspace, command, *args, **kwargs)
        with patch.object(g, 'OPENCODE', binary), patch.object(g, 'run_confined', swap):
            with self.assertRaises(ValueError):
                compatibility_check.opencode_candidate()
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())

    def test_common_launcher_requires_explicit_repository_token_capability(self):
        work = self.base / 'work'
        work.mkdir()
        code = 'import os;raise SystemExit(9 if os.environ.get("GH_TOKEN") else 0)'
        command = ['/Library/Developer/CommandLineTools/usr/bin/python3', '-I', '-c', code]
        self.assertEqual(g.run_confined('probe', work, command, ephemeral=True), 0)
        self.assertEqual(g.run_confined('coding', work, command, ephemeral=True, github=True), 9)

    def test_timed_out_probe_stops_its_child_and_cleans_control_state(self):
        work = self.base / 'timeout-work'
        work.mkdir()
        heartbeat = work / 'heartbeat'
        with self.assertRaisesRegex(g.GuardError, 'time limit'):
            g.run_confined('timeout-probe', work,
                           ['/bin/sh', '-c', 'while :; do printf . >> heartbeat; sleep 0.05; done'],
                           ephemeral=True, timeout=3)
        self.assertTrue(heartbeat.is_file())
        size = heartbeat.stat().st_size
        time.sleep(0.15)
        self.assertEqual(heartbeat.stat().st_size, size)
        self.assertEqual(list((self.root / 'state').glob('control-*')), [])

    def test_login_preload_supports_an_installation_path_with_spaces(self):
        spaced = self.base / 'root with spaces'
        shutil.copytree(self.root, spaced, symlinks=True)
        code = ('import net from "node:net"; const s=net.createServer(); '
                's.listen({port:0,host:"127.0.0.1",exclusive:true},()=>{'
                'if(s.address().port!==Number(process.env.AGENTBELT_LOOPBACK_PORT))process.exit(9);s.close();});')
        with patch.object(g, 'ROOT', spaced), patch.object(usage_cli, 'ROOT', spaced), \
             patch.object(usage_cli, 'PROFILE_PATH', spaced / 'state/usage-profile.json'):
            self.usage_entry(code)
            self.assertEqual(usage_cli.run_usage(['login']), 0)

    def test_login_accepts_its_callback_but_not_another_loopback_service(self):
        port = g.free_loopback_port()
        with socket.socket() as unrelated:
            unrelated.bind(('127.0.0.1', 0))
            unrelated.listen()
            other_port = unrelated.getsockname()[1]
            code = ('import net from "node:net";\n'
                    'const server = net.createServer(socket => { socket.end("CALLBACK_OK"); server.close(); });\n'
                    'server.listen({port:0,host:"127.0.0.1",exclusive:true}, () => {\n'
                    '  const probe = net.connect({port:' + str(other_port) + ',host:"127.0.0.1"});\n'
                    '  probe.on("connect", () => process.exit(8));\n'
                    '  probe.on("error", e => { if (!["EPERM","EACCES"].includes(e.code)) process.exit(7); });\n'
                    '});\nsetTimeout(() => process.exit(6), 8000).unref();\n')
            self.usage_entry(code)
            received = []
            stop = threading.Event()
            def callback():
                while not stop.wait(0.05):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.2) as connection:
                            received.append(connection.recv(100))
                            return
                    except OSError:
                        continue
            thread = threading.Thread(target=callback)
            thread.start()
            try:
                with patch.object(g, 'free_loopback_port', return_value=port):
                    self.assertEqual(usage_cli.run_usage(['login']), 0)
            finally:
                stop.set()
                thread.join(timeout=2)
            self.assertEqual(received, [b'CALLBACK_OK'])

    def test_installed_usage_cli_accepts_a_synthetic_callback_without_network(self):
        # Read only installed package code; never the adjacent console credential store.
        packages = list((g.OWNER_HOME / '.local/share/agentbelt/state/homes/usage').glob(
            '*/bl-prefix/node_modules/bailian-cli/dist/bailian.mjs'))
        if not packages:
            self.skipTest('Optional bailian-cli is not installed.')
        entry = packages[0]
        package_root = entry.parents[2]
        import http.client
        import re
        replies = []
        stop = threading.Event()
        real = g.run_confined
        with tempfile.TemporaryFile() as output:
            def confined(*args, **kwargs):
                kwargs.update(domains=[], stdout=output, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, timeout=20)
                kwargs['extra_reads'] = [*kwargs.get('extra_reads', []), package_root]
                return real(*args, **kwargs)
            def callback():
                while not stop.wait(0.05):
                    output.seek(0)
                    match = re.search(rb'127\.0\.0\.1:(\d+)\?state=([a-f0-9]{32})', output.read())
                    if not match:
                        continue
                    port, state = int(match[1]), match[2].decode()
                    for value in ('wrong-state', state):
                        client = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
                        try:
                            client.request('GET', '/?state=' + value + '&console_site=international')
                            response = client.getresponse()
                            replies.append(response.status)
                            response.read()
                        finally:
                            client.close()
                    return
            thread = threading.Thread(target=callback)
            thread.start()
            try:
                with patch.object(usage_cli, 'bl_entry', return_value=entry), patch.object(g, 'run_confined', confined):
                    self.assertEqual(usage_cli.run_usage(['login']), 0)
            finally:
                stop.set()
                thread.join(timeout=3)
        self.assertEqual(replies, [400, 200])


if __name__ == '__main__':
    unittest.main()
