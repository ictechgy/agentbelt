#!/usr/bin/python3
"""Create public guard profiles; importing live credentials is a separate step."""
import argparse
import json
import os
import pwd
from pathlib import Path
import plistlib
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # Home from the account database (not the environment variable)
STATE = ROOT / 'state'
BUNDLE_IDENTIFIER = 'local.agentbelt.zcode.safe-launcher'
BUNDLE_URL_TYPES = [{'CFBundleURLName': BUNDLE_IDENTIFIER, 'CFBundleURLSchemes': ['zcode']}]
BUNDLE_ROOT_KEY = 'AgentbeltRoot'
BUNDLE_BIN_KEY = 'AgentbeltBin'


def hook_declaration():
    return {'matcher': '*', 'hooks': [{'type': 'process', 'command': '/usr/bin/python3',
            'args': ['-I', str(ROOT / 'zcode_hook.py')], 'enabled': True, 'timeoutMs': 10000}]}


def absolute_path(value, label):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/' or
            any(ord(character) < 0x20 for character in value)):
        raise RuntimeError(label + ' must be an absolute path')
    path = Path(value)
    if any(part in ('.', '..') for part in path.parts):
        raise RuntimeError(label + ' must not contain dot path components')
    return path


def configured_bin():
    """Use install.sh metadata, then legacy config, while preserving old defaults."""
    metadata = ROOT / 'installation.json'
    config = ROOT / 'config.json'
    source = metadata if metadata.exists() or metadata.is_symlink() else config
    if source.is_symlink():
        raise RuntimeError('Refusing a symlinked ' + source.name)
    if not source.is_file():
        return HOME / '.local/bin'
    try:
        values = json.loads(source.read_text())
        if source == metadata and values.get('root') is not None:
            recorded_root = absolute_path(values['root'], 'installation.json root')
            if recorded_root != ROOT:
                raise RuntimeError('installation.json root does not match this installation')
        value = values.get('bin')
    except (OSError, ValueError, AttributeError):
        raise RuntimeError(source.name + ' is malformed') from None
    return HOME / '.local/bin' if value is None else absolute_path(value, source.name + ' bin')


def bundle_plist(bin_dir):
    return {'CFBundleName': 'Zcode Safe', 'CFBundleDisplayName': 'Zcode Safe',
            'CFBundleIdentifier': BUNDLE_IDENTIFIER, 'CFBundleVersion': '3',
            'CFBundleShortVersionString': '1.2', 'CFBundlePackageType': 'APPL',
            'CFBundleExecutable': 'launch', 'LSUIElement': False, 'CFBundleIconFile': 'SafeIcon.icns',
            'CFBundleURLTypes': BUNDLE_URL_TYPES,
            BUNDLE_ROOT_KEY: str(ROOT), BUNDLE_BIN_KEY: str(bin_dir)}


def _lstat_owned(path, kind):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise RuntimeError('Missing Zcode Safe bundle path: ' + str(path)) from None
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError('Refusing a symlink in the Zcode Safe bundle: ' + str(path))
    if info.st_uid != os.getuid():
        raise RuntimeError('Zcode Safe bundle path is not owned by you: ' + str(path))
    if kind == 'dir' and not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('Zcode Safe bundle path is not a directory: ' + str(path))
    if kind == 'file' and not stat.S_ISREG(info.st_mode):
        raise RuntimeError('Zcode Safe bundle path is not a regular file: ' + str(path))
    return info


def _check_managed_bundle(app):
    """Validate the existing app before an explicit launcher-only upgrade."""
    _lstat_owned(app.parent, 'dir')
    _lstat_owned(app, 'dir')
    contents = app / 'Contents'
    macos = contents / 'MacOS'
    resources = contents / 'Resources'
    info_path = contents / 'Info.plist'
    launch_path = macos / 'launch'
    icon_path = resources / 'SafeIcon.icns'
    for path in [contents, macos, resources, info_path, launch_path, icon_path]:
        _lstat_owned(path, 'dir' if path in (contents, macos, resources) else 'file')
    for directory, directories, files in os.walk(app, followlinks=False):
        _lstat_owned(directory, 'dir')
        for name in directories:
            _lstat_owned(Path(directory) / name, 'dir')
        for name in files:
            _lstat_owned(Path(directory) / name, 'file')
    try:
        with info_path.open('rb') as stream:
            info = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException, ValueError):
        raise RuntimeError('Zcode Safe Info.plist is malformed') from None
    if info.get('CFBundleIdentifier') != BUNDLE_IDENTIFIER:
        raise RuntimeError('Refusing to replace an unrelated Zcode Safe app')
    if info.get('CFBundleExecutable') != 'launch' or info.get('CFBundlePackageType') != 'APPL':
        raise RuntimeError('Zcode Safe bundle shape is not recognized')
    if launch_path.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('Zcode Safe launcher must be private and executable')
    return info, info_path, launch_path


def _stage_file(directory, name, data, mode):
    descriptor, temporary_name = tempfile.mkstemp(prefix='.' + name + '.upgrade-', dir=str(directory))
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _codesign_bundle(app):
    """Reseal and verify the app after replacing its executable or Info.plist."""
    command = ['/usr/bin/codesign', '-s', '-', '-i', BUNDLE_IDENTIFIER, '-f', str(app)]
    signed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    if signed.returncode:
        raise RuntimeError('codesign failed: exit ' + str(signed.returncode))
    verified = subprocess.run(['/usr/bin/codesign', '-v', '--strict', str(app)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    if verified.returncode:
        raise RuntimeError('codesign verification failed: exit ' + str(verified.returncode))


def _upgrade_launcher():
    app = HOME / 'Applications/Zcode Safe.app'
    native = ROOT / 'native/ZcodeSafeLauncher'
    _lstat_owned(native, 'file')
    info, _, _ = _check_managed_bundle(app)
    bin_dir = configured_bin()
    updated = dict(info)
    updated.update({'CFBundleURLTypes': BUNDLE_URL_TYPES,
                    BUNDLE_ROOT_KEY: str(ROOT), BUNDLE_BIN_KEY: str(bin_dir)})
    native_data = native.read_bytes()
    plist_data = plistlib.dumps(updated)
    staging = Path(tempfile.mkdtemp(prefix='.zcode-safe-upgrade-', dir=str(app.parent)))
    keep_staging = False
    try:
        staged_app = staging / app.name
        shutil.copytree(str(app), str(staged_app), copy_function=shutil.copy2)
        staged_launch = staged_app / 'Contents/MacOS/launch'
        staged_info = staged_app / 'Contents/Info.plist'
        try:
            native_temporary = _stage_file(staged_launch.parent, staged_launch.name, native_data, 0o700)
            plist_temporary = _stage_file(staged_info.parent, staged_info.name, plist_data, 0o600)
            os.replace(str(native_temporary), str(staged_launch))
            os.replace(str(plist_temporary), str(staged_info))
            _codesign_bundle(staged_app)
        except BaseException as error:
            raise RuntimeError('launcher upgrade failed: ' + type(error).__name__) from None
        backup_app = staging / (app.name + '.backup')
        os.replace(str(app), str(backup_app))
        try:
            os.replace(str(staged_app), str(app))
        except BaseException as error:
            try:
                os.replace(str(backup_app), str(app))
            except BaseException as restore:
                keep_staging = True
                raise RuntimeError('launcher publication failed and original app restore failed: '
                                   + type(restore).__name__ + '; recovery copy: ' + str(backup_app)) from None
            raise RuntimeError('launcher publication failed: ' + type(error).__name__) from None
        try:
            shutil.rmtree(str(backup_app))
        except BaseException as cleanup:
            keep_staging = True
            raise RuntimeError('launcher publication succeeded but backup cleanup failed: '
                               + type(cleanup).__name__ + '; recovery directory: ' + str(staging)) from None
    except BaseException:
        if keep_staging:
            recovery = backup_app if 'backup_app' in locals() and backup_app.exists() else staging
            print('Safe launcher recovery copy retained at: ' + str(recovery), file=sys.stderr)
        else:
            shutil.rmtree(str(staging), ignore_errors=True)
        raise
    print('Updated and re-signed the Zcode Safe native launcher and bundle metadata.')


def main(upgrade_launcher=False):
    if upgrade_launcher:
        _upgrade_launcher()
        return
    zcode = {
        'permission': {'mode': 'build', 'autoApproveHighRisk': False,
                       'disallowedTools': ['js', 'js_reset', 'js_add_node_module_dir',
                                           'CronCreate', 'CronUpdate', 'Skill']},
        'features': {'mcp': False, 'skill': False, 'memory': False},
        'hooks': {'enabled': True, 'timeoutMs': 10000, 'maxOutputBytes': 32768,
                  'events': {'PreToolUse': [hook_declaration()]}},
    }
    app = HOME / 'Applications/Zcode Safe.app'
    launcher = '#!/bin/sh\nexec /usr/bin/python3 -I ' + shlex.quote(str(ROOT / 'agentbelt.py'))
    profile = {'domains': [], 'candidateDomains': ['api.z.ai:443'],
               'reviewedDesktopVersion': '3.12.3', 'reviewedAgentVersion': '0.16.5'}
    native = ROOT / 'native/ZcodeSafeLauncher'
    icon = ROOT / 'native/SafeIcon.icns'
    if not native.is_file() or not icon.is_file():
        raise RuntimeError('Build the native Safe launcher before installing the app.')
    _lstat_owned(native, 'file')
    _lstat_owned(icon, 'file')
    bin_dir = configured_bin()
    plist = bundle_plist(bin_dir)
    files = {
        STATE / 'zcode-agent-config.json': ((json.dumps(zcode, indent=2) + '\n').encode(), 0o600),
        STATE / 'zcode-profile.json': ((json.dumps(profile, indent=2) + '\n').encode(), 0o600),
        bin_dir / 'zcode-backend-safe': ((launcher + ' zcode-backend "$@"\n').encode(), 0o700),
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
        _codesign_bundle(app)
    except BaseException:
        # Only remove artifacts created by this invocation, in reverse order.
        if app in created_dirs and (app.exists() or app.is_symlink()):
            shutil.rmtree(str(app), ignore_errors=True)
        for path in reversed(created_files):
            if path.exists() or path.is_symlink():
                path.unlink()
        for path in reversed(created_dirs):
            if path == app:
                continue
            try:
                path.rmdir()
            except OSError:
                pass  # Keep a directory if another process populated it.
        raise
    print('Created Zcode backend profile and Zcode Safe launcher.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upgrade-launcher', action='store_true',
                        help='atomically update only the owned Safe native launcher and bundle metadata')
    main(upgrade_launcher=parser.parse_args().upgrade_launcher)
