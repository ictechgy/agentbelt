"""Regression coverage with synthetic homes, policy, commands and Dock preferences."""
import base64
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent_guard as g
import riskgate_bridge as bridge
import zcode_hook as hook


class ReviewFixTests(unittest.TestCase):
    def test_personal_folders_reject_case_aliases_but_accept_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            for name in ['Library', 'Desktop', 'Documents', 'Downloads', 'Pictures', 'Movies', 'Music', 'Public']:
                (home / name / 'project').mkdir(parents=True)
            with patch.object(g, 'OWNER_HOME', home):
                for name in ['Library', 'Desktop', 'Documents', 'Downloads', 'Pictures', 'Movies', 'Music', 'Public']:
                    for alias in [name, name.lower(), name.upper()]:
                        path = home / alias
                        if not path.exists():
                            path.mkdir()
                        with self.subTest(alias=alias), self.assertRaises(g.GuardError):
                            g.workspace_path(path)
                for alias in ['Library', 'library', 'LIBRARY']:
                    (home / alias / 'project').mkdir(exist_ok=True)
                    with self.subTest(alias=alias), self.assertRaises(g.GuardError):
                        g.workspace_path(home / alias / 'project')
                self.assertEqual(g.workspace_path(home / 'Desktop/project'), (home / 'Desktop/project').resolve())

    def test_python_layouts_do_not_break_other_sandbox_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve(); binary = base / 'venv/bin/python'
            binary.parent.mkdir(parents=True)
            real = base / 'runtime/bin/python3'; real.parent.mkdir(parents=True); real.write_text('fixture')
            for layout in ['relative', 'absolute', 'regular', 'missing']:
                with self.subTest(layout=layout):
                    if binary.is_symlink() or binary.exists(): binary.unlink()
                    if layout == 'relative':
                        (binary.parent / 'python3').symlink_to(real)
                        binary.symlink_to('python3')
                    elif layout == 'absolute': binary.symlink_to(real)
                    elif layout == 'regular': binary.write_text('fixture')
                    with patch.object(g, 'PACKET_PYTHON', binary), patch.object(g, 'PACKET_VENV', binary.parents[1]):
                        policy = g.sandbox_policy(base, base, [])
                    self.assertIn(str(base), policy['filesystem']['allowWrite'])
                    if layout in ['relative', 'absolute']:
                        self.assertIn(str(real.parents[1]), policy['filesystem']['allowRead'])

    def test_host_hook_and_direct_shell_enforce_real_policy(self):
        with tempfile.TemporaryDirectory(prefix='guard-review-fix-', dir=Path.home()) as tmp:
            work = Path(tmp); policy = work / 'policy.yaml'; marker = work / 'executed'
            command = 'printf blocked > ' + str(marker)
            policy.write_text('version: 1\ndefaults: prompt\nrules:\n  - id: block\n    match: {tool: Bash, cmd_regex: "^printf blocked"}\n    risk: deny\n  - id: allowed\n    match: {tool: Bash, cmd_regex: "^printf allowed$"}\n    risk: allow\n')
            with patch.object(bridge, 'riskgate_policy', return_value=policy), patch.object(bridge.Path, 'home', return_value=work), patch.object(hook, 'inside_zcode_sandbox', return_value=False):
                payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'cwd': str(work), 'tool_input': {'command': command}}
                self.assertEqual(hook.evaluate(payload)['hookSpecificOutput']['permissionDecision'], 'deny')
                with self.assertRaises(g.GuardError):
                    g.main(['zcode-shell', str(work), base64.b64encode(command.encode()).decode()])
                self.assertFalse(marker.exists())
                payload['tool_input']['command'] = 'printf allowed'
                self.assertEqual(hook.evaluate(payload)['hookSpecificOutput']['permissionDecision'], 'ask')
                policy.unlink()
                with self.assertRaises(g.GuardError): hook.evaluate(payload)
                with self.assertRaises(g.GuardError):
                    g.main(['zcode-shell', str(work), base64.b64encode(b'printf allowed').decode()])

    def test_dock_backup_success_preservation_and_failure_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            # Execute the production Dock function against a private preference domain.
            source = (ROOT / 'ZcodeSafe.swift').read_text().split('final class SafeDelegate:')[0]
            source = source.replace('"com.apple.dock"', '"local.agentguard.test.' + base.name + '"')
            source = source.replace('let dockBackupPath = guardRoot + "/state/backups/dock-before-safe.plist"', 'let dockBackupPath = "' + str(base / 'backups/dock.plist') + '"')
            source += r'''
let domain = "local.agentguard.test.DOMAIN" as CFString
let key = "persistent-apps" as CFString
let fixture: [[String: Any]] = [["tile-type": "fixture"]]
let backup = URL(fileURLWithPath: "BACKUP_PATH")
func resetFixture() { CFPreferencesSetAppValue(key, fixture as CFPropertyList, domain) }
func check(_ condition: Bool) { if !condition { exit(20) } }
defer { CFPreferencesSetAppValue(key, nil, domain); CFPreferencesAppSynchronize(domain) }
resetFixture()
try pinDock()
let saved = try Data(contentsOf: backup)
check((try PropertyListSerialization.propertyList(from: saved, format: nil) as? [[String: String]]) == [["tile-type": "fixture"]])
check((try FileManager.default.attributesOfItem(atPath: backup.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600)
try pinDock()
check(try Data(contentsOf: backup) == saved)
try FileManager.default.removeItem(at: backup)
try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: backup.deletingLastPathComponent().path)
resetFixture()
var writeFailed = false
do { try pinDock() } catch { writeFailed = true }
try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: backup.deletingLastPathComponent().path)
check(writeFailed)
check((CFPreferencesCopyAppValue(key, domain) as? [[String: String]]) == [["tile-type": "fixture"]])
try FileManager.default.removeItem(at: backup.deletingLastPathComponent())
try Data("blocked parent".utf8).write(to: backup.deletingLastPathComponent())
resetFixture()
var failed = false
do { try pinDock() } catch { failed = true }
check(failed)
check((CFPreferencesCopyAppValue(key, domain) as? [[String: String]]) == [["tile-type": "fixture"]])
print("DOCK_BACKUP_OK")
'''.replace('DOMAIN', base.name).replace('BACKUP_PATH', str(base / 'backups/dock.plist'))
            script = base / 'probe.swift'; script.write_text(source)
            result = subprocess.run(['/usr/bin/swift', str(script)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DOCK_BACKUP_OK', result.stdout)


if __name__ == '__main__': unittest.main()


class InternalHardlinkTests(unittest.TestCase):
    """OMC 가 체크포인트 파일과 claim 마커를 같은 폴더 안에서 하드링크로 만든다. 바깥 노출이 없으면 허용한다."""

    def test_hardlinks_wholly_inside_the_workspace_are_accepted(self):
        import os, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='hl-inside-', dir=Path.home()) as tmp:
            work = Path(tmp)
            (work / 'a.json').write_text('{}')
            os.link(str(work / 'a.json'), str(work / '.claim-a'))
            self.assertEqual(g.workspace_path(work), work.resolve())

    def test_hardlink_reaching_outside_the_workspace_is_still_refused(self):
        import os, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='hl-outside-', dir=Path.home()) as tmp:
            outside = Path(tmp) / 'outside.txt'
            outside.write_text('SYNTHETIC')
            work = Path(tmp) / 'work'
            work.mkdir()
            os.link(str(outside), str(work / 'linked.txt'))
            with self.assertRaises(g.GuardError):
                g.workspace_path(work)
