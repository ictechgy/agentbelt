#!/usr/bin/python3
"""Create public guard profiles; importing live credentials is a separate step."""
import json
import os
import pwd
from pathlib import Path
import plistlib
import shlex

ROOT = Path(__file__).resolve().parent
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # 계정 DB 의 홈(환경변수 아님)
STATE = ROOT / 'state'


def hook_declaration():
    return {'matcher': '*', 'hooks': [{'type': 'process', 'command': '/usr/bin/python3',
            'args': ['-I', str(ROOT / 'zcode_hook.py')], 'enabled': True, 'timeoutMs': 10000}]}


def main():
    zcode = {
        'permission': {'mode': 'build', 'autoApproveHighRisk': False,
                       'disallowedTools': ['js', 'js_reset', 'js_add_node_module_dir',
                                           'CronCreate', 'CronUpdate', 'Skill']},
        'features': {'mcp': False, 'skill': False, 'memory': False},
        'hooks': {'enabled': True, 'timeoutMs': 10000, 'maxOutputBytes': 32768,
                  'events': {'PreToolUse': [hook_declaration()]}},
    }
    app = HOME / 'Applications/Zcode Safe.app'
    launcher = '#!/bin/sh\nexec /usr/bin/python3 -I ' + shlex.quote(str(ROOT / 'agent_guard.py'))
    profile = {'domains': [], 'candidateDomains': ['api.z.ai:443'],
               'reviewedDesktopVersion': '3.11.2', 'reviewedAgentVersion': '0.16.5'}
    native = ROOT / 'native/ZcodeSafeLauncher'
    icon = ROOT / 'native/SafeIcon.icns'
    if not native.is_file() or not icon.is_file():
        raise RuntimeError('Build the native Safe launcher before installing the app.')
    plist = {'CFBundleName': 'Zcode Safe', 'CFBundleDisplayName': 'Zcode Safe',
             'CFBundleIdentifier': 'local.agentguard.zcode.safe-launcher', 'CFBundleVersion': '3',
             'CFBundleShortVersionString': '1.2', 'CFBundlePackageType': 'APPL',
             'CFBundleExecutable': 'launch', 'LSUIElement': False, 'CFBundleIconFile': 'SafeIcon.icns'}
    files = {
        STATE / 'zcode-agent-config.json': ((json.dumps(zcode, indent=2) + '\n').encode(), 0o600),
        STATE / 'zcode-profile.json': ((json.dumps(profile, indent=2) + '\n').encode(), 0o600),
        HOME / '.local/bin/zcode-backend-safe': ((launcher + ' zcode-backend "$@"\n').encode(), 0o700),
        app / 'Contents/Info.plist': (plistlib.dumps(plist), 0o600),
        app / 'Contents/MacOS/launch': (native.read_bytes(), 0o700),
        app / 'Contents/Resources/SafeIcon.icns': (icon.read_bytes(), 0o600),
    }
    # Check all conflicts before publishing any file, including dangling links.
    for path in [app, *files]:
        if path.exists() or path.is_symlink():
            raise RuntimeError('Refusing to replace an existing installation artifact')
    created_files, created_dirs = [], []
    def make_parent(path):
        if path.is_symlink():
            raise RuntimeError('Refusing a symlinked installation directory')
        if path.exists():
            if not path.is_dir():
                raise RuntimeError('Installation parent is not a directory')
            return
        make_parent(path.parent)
        path.mkdir(mode=0o700)
        created_dirs.append(path)
    try:
        make_parent(app.parent)
        app.mkdir(mode=0o700)
        created_dirs.append(app)
        for path, (data, mode) in files.items():
            make_parent(path.parent)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created_files.append(path)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        # Only remove artifacts created by this invocation, in reverse order.
        for path in reversed(created_files):
            path.unlink()
        for path in reversed(created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass  # Keep a directory if another process populated it.
        raise
    print('Created Zcode backend profile and Zcode Safe launcher.')


if __name__ == '__main__':
    main()
