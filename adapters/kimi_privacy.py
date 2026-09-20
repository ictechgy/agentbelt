"""Host-side hardening for the guard-owned staged Kimi SEA binary.

This module is deliberately independent of the launcher.  The launcher may call
``harden_staged`` after creating an isolated, guard-owned copy and before it
executes that copy.  The original installation is never an accepted target.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess


EXPECTED_ORIGINAL_SHA256 = 'fe351d4872d6b35c27f14ec5e895b21d1e14c2b09d78ea174b4b8ecc288974c6'
_CODESIGN = '/usr/bin/codesign'
_STAGED_NAME = 'kimi'
_LAUNCH_PREFIX = 'launch-'
_RUNTIME_DIR = 'kimi-runtime'
_POLICY_MESSAGE = 'Diagnostic feedback is disabled by local policy.'


class KimiPrivacyError(RuntimeError):
    """Private, sanitized failure for staged Kimi privacy hardening."""


_FUNCTION_ANCHORS = (
    b'async function fetchSubmitFeedback(url, accessToken, body, opts = {})',
    b'async function fetchCreateFeedbackUploadUrl(accessToken, body, opts = {})',
    b'async function fetchCompleteFeedbackUpload(accessToken, body, opts = {})',
    b'async function fetchClientConfig(name, schema, options = {})',
    b'async function uploadArchive(api, archive, feedbackId, options)',
    b'function startServer(opts)',
)
_FEEDBACK_NAMES = (
    b'fetchSubmitFeedback',
    b'fetchCreateFeedbackUploadUrl',
    b'fetchCompleteFeedbackUpload',
    b'uploadArchive',
)
_LISTEN_CONDITION = b'opts.insecureNoTls !== true'
_BIND_CLASS_OVERRIDE = b', { bindClass: opts.bindClass }'
_EXPOSURE_ERROR = b'throw new Error(`Refusing to bind ${host} (${exposureClass}) without TLS; terminate TLS at a reverse proxy or pass --insecure-no-tls.`);'
_LOCAL_EXPOSURE_ERROR = b'throw new Error("Refusing non-loopback Kimi server bind by local policy.");'


def _fail(message):
    raise KimiPrivacyError(message)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _same_length(original, replacement):
    if len(replacement) > len(original):
        _fail('Kimi privacy replacement does not fit the reviewed binary region')
    return replacement + b' ' * (len(original) - len(replacement))


def _find_function_region(data, anchor):
    if data.count(anchor) != 1:
        _fail('Kimi privacy source anchor is not unique')
    start = data.index(anchor)
    close_paren = data.find(b')', start)
    opening = data.find(b'{', close_paren)
    if opening < 0:
        _fail('Kimi privacy function body is malformed')
    depth = 0
    state = 'code'
    escaped = False
    i = opening
    while i < len(data):
        byte = data[i]
        next_byte = data[i + 1] if i + 1 < len(data) else None
        if state == 'code':
            if byte == 0x2f and next_byte == 0x2f:
                state = 'line_comment'
                i += 2
                continue
            if byte == 0x2f and next_byte == 0x2a:
                state = 'block_comment'
                i += 2
                continue
            if byte in (0x27, 0x22, 0x60):
                state = chr(byte)
                escaped = False
            elif byte == 0x7b:
                depth += 1
            elif byte == 0x7d:
                depth -= 1
                if depth == 0:
                    return start, i + 1
        elif state == 'line_comment':
            if byte in (0x0a, 0x0d):
                state = 'code'
        elif state == 'block_comment':
            if byte == 0x2a and next_byte == 0x2f:
                state = 'code'
                i += 2
                continue
        else:
            if escaped:
                escaped = False
            elif byte == 0x5c:
                escaped = True
            elif byte == ord(state):
                state = 'code'
        i += 1
    _fail('Kimi privacy function body is unterminated')


def _stub_for(name):
    if name == b'fetchSubmitFeedback':
        signature = b'async function fetchSubmitFeedback(url, accessToken, body, opts = {})'
    elif name == b'fetchCreateFeedbackUploadUrl':
        signature = b'async function fetchCreateFeedbackUploadUrl(accessToken, body, opts = {})'
    elif name == b'fetchCompleteFeedbackUpload':
        signature = b'async function fetchCompleteFeedbackUpload(accessToken, body, opts = {})'
    elif name == b'uploadArchive':
        signature = b'async function uploadArchive(api, archive, feedbackId, options)'
        return signature + b' { throw new Error("' + _POLICY_MESSAGE.encode() + b'"); }'
    else:
        _fail('Kimi privacy function name is unsupported')
    return signature + b' { return { kind: "error", message: "' + _POLICY_MESSAGE.encode() + b'" }; }'


def _replace_region(data, start, end, replacement):
    return data[:start] + _same_length(data[start:end], replacement) + data[end:]


def _patch_bytes(data):
    """Patch a reviewed binary byte buffer without changing any source offsets."""
    if not isinstance(data, (bytes, bytearray)):
        _fail('Kimi privacy input is not a byte buffer')
    data = bytes(data)
    for anchor in _FUNCTION_ANCHORS:
        if data.count(anchor) != 1:
            _fail('Kimi privacy source anchor is not unique')

    patched = data
    for name in _FEEDBACK_NAMES:
        anchor = b'async function ' + name
        start, end = _find_function_region(patched, anchor)
        patched = _replace_region(patched, start, end, _stub_for(name))

    client_anchor = b'async function fetchClientConfig'
    start, end = _find_function_region(patched, client_anchor)
    original = patched[start:end]
    client_target = b'const fetchFn = options.fetchImpl ?? fetch;'
    if original.count(client_target) != 1:
        _fail('Kimi privacy client config guard anchor is not unique')
    client_guard = b'\n\tif (name === "client_banner") return;'
    client_replacement = original.replace(client_target, client_target + client_guard, 1)
    compacted = bytearray(client_replacement)
    needed = len(client_replacement) - len(original)
    insertion_end = client_replacement.index(client_guard) + len(client_guard)
    line_start = compacted.find(b'\n', insertion_end) + 1
    while line_start > 0 and line_start < len(compacted) and needed > 0:
        while line_start < len(compacted) and compacted[line_start] in (0x09, 0x20) and needed > 0:
            del compacted[line_start]
            needed -= 1
        newline = compacted.find(b'\n', line_start)
        if newline < 0:
            break
        line_start = newline + 1
    if needed != 0:
        _fail('Kimi privacy client config function has insufficient safe indentation')
    patched = patched[:start] + bytes(compacted) + patched[end:]

    condition_count = patched.count(_LISTEN_CONDITION)
    if condition_count != 1:
        _fail('Kimi privacy server exposure condition is not unique')
    patched = patched.replace(_LISTEN_CONDITION, b'true' + b' ' * (len(_LISTEN_CONDITION) - 4), 1)

    if patched.count(_BIND_CLASS_OVERRIDE) != 1:
        _fail('Kimi privacy server classification override is not unique')
    patched = patched.replace(_BIND_CLASS_OVERRIDE, b' ' * len(_BIND_CLASS_OVERRIDE), 1)
    if patched.count(_EXPOSURE_ERROR) != 1:
        _fail('Kimi privacy server refusal message is not unique')
    patched = patched.replace(_EXPOSURE_ERROR, _same_length(_EXPOSURE_ERROR, _LOCAL_EXPOSURE_ERROR), 1)

    if len(patched) != len(data):
        _fail('Kimi privacy patch changed the SEA source length')
    return patched


def _assert_patched(data):
    for anchor in _FUNCTION_ANCHORS:
        if data.count(anchor) != 1:
            _fail('Kimi privacy patched source anchor is missing')
    for name in _FEEDBACK_NAMES:
        anchor = b'async function ' + name
        if data.count(anchor) != 1:
            _fail('Kimi privacy patched function anchor is missing')
        start, end = _find_function_region(data, anchor)
        region = data[start:end]
        if b'Diagnostic feedback is disabled by local policy.' not in region:
            _fail('Kimi privacy patched feedback function is missing its policy stub')
    start, end = _find_function_region(data, b'async function fetchClientConfig')
    if b'const fetchFn = options.fetchImpl ?? fetch;' not in data[start:end] or \
            b'if (name === "client_banner") return;' not in data[start:end]:
        _fail('Kimi privacy client banner guard is missing')
    if data.count(b'true' + b' ' * (len(_LISTEN_CONDITION) - 4)) != 1:
        _fail('Kimi privacy loopback exposure guard is missing')
    if data.count(_LOCAL_EXPOSURE_ERROR) != 1 or _EXPOSURE_ERROR in data or _BIND_CLASS_OVERRIDE in data:
        _fail('Kimi privacy local exposure refusal is missing')


def _check_path(path):
    try:
        raw = Path(path)
    except (TypeError, ValueError):
        _fail('Kimi staged path is malformed')
    if not raw.is_absolute() or any(part in ('.', '..') for part in raw.parts):
        _fail('Kimi staged path is malformed')
    if raw.name != _STAGED_NAME or not raw.parent.name.startswith(_LAUNCH_PREFIX):
        _fail('Kimi staged path is outside the guard-owned runtime')
    if raw.parent.parent.name != _RUNTIME_DIR or raw.parent.parent.parent.name != 'state':
        _fail('Kimi staged path is outside the guard-owned runtime')
    current_uid = os.getuid()
    for parent in (raw.parent.parent.parent, raw.parent.parent, raw.parent):
        try:
            info = parent.lstat()
        except OSError:
            _fail('Kimi staged path is unavailable')
        mode = stat.S_IMODE(info.st_mode)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != current_uid or
                mode & 0o077 or mode & 0o700 != 0o700):
            _fail('Kimi staged runtime ownership is invalid')
    try:
        info = raw.lstat()
    except OSError:
        _fail('Kimi staged binary is unavailable')
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != current_uid:
        _fail('Kimi staged binary identity is invalid')
    if info.st_nlink != 1:
        _fail('Kimi staged binary must be independent')
    if not info.st_mode & 0o111:
        _fail('Kimi staged binary is not executable')
    try:
        candidate = Path(os.path.realpath(os.fspath(raw)))
        canonical_info = candidate.lstat()
    except OSError:
        _fail('Kimi staged canonical path is unavailable')
    if (candidate.name != _STAGED_NAME or not candidate.parent.name.startswith(_LAUNCH_PREFIX) or
            candidate.parent.parent.name != _RUNTIME_DIR or candidate.parent.parent.parent.name != 'state' or
            stat.S_ISLNK(canonical_info.st_mode) or canonical_info.st_dev != info.st_dev or
            canonical_info.st_ino != info.st_ino):
        _fail('Kimi staged canonical path is invalid')
    return candidate


def _codesign_verify(path):
    try:
        result = subprocess.run([_CODESIGN, '--verify', '--strict', str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        _fail('Kimi staged binary signature verification failed')
    if result.returncode != 0:
        _fail('Kimi staged binary signature verification failed')


def _codesign_patch(path):
    try:
        result = subprocess.run([
            _CODESIGN, '--force', '--sign', '-',
            '--preserve-metadata=entitlements,identifier,flags,runtime', str(path)
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        _fail('Kimi staged binary signing failed')
    if result.returncode != 0:
        _fail('Kimi staged binary signing failed')


def _safe_open(path, flags, expected_identity=None):
    no_follow = getattr(os, 'O_NOFOLLOW', 0)
    if no_follow == 0:
        _fail('Kimi staged binary no-follow writes are unavailable')
    try:
        fd = os.open(os.fspath(path), flags | no_follow)
    except OSError:
        _fail('Kimi staged binary could not be opened safely')
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                (expected_identity is not None and (info.st_dev, info.st_ino) != expected_identity)):
            _fail('Kimi staged binary identity changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file_identity(path):
    try:
        info = path.lstat()
    except OSError:
        _fail('Kimi staged binary identity is unavailable')
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        _fail('Kimi staged binary identity is invalid')
    return info.st_dev, info.st_ino


def _chmod_bytes(path, mode, expected_identity):
    fd = _safe_open(path, os.O_RDONLY, expected_identity)
    try:
        os.fchmod(fd, mode)
    except OSError:
        _fail('Kimi staged binary permissions could not be changed')
    finally:
        os.close(fd)


def _write_bytes(path, data, expected_identity):
    fd = _safe_open(path, os.O_RDWR, expected_identity)
    try:
        os.ftruncate(fd, 0)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail('Kimi staged binary write made no progress')
            offset += written
        os.fsync(fd)
    except OSError:
        _fail('Kimi staged binary could not be written')
    finally:
        os.close(fd)


def harden_staged(path):
    """Patch and ad-hoc sign one guard-owned staged Kimi copy.

    The returned metadata contains the pre-patch and post-sign SHA-256 values.
    Any unsupported identity, source drift, malformed region, or signing failure
    raises :class:`KimiPrivacyError` without touching the original installation.
    """
    candidate = _check_path(path)
    try:
        original = candidate.read_bytes()
    except OSError:
        _fail('Kimi staged binary could not be read')
    original_sha = _sha256(original)
    if original_sha != EXPECTED_ORIGINAL_SHA256:
        _fail('Kimi staged binary is not the reviewed Kimi build')
    _codesign_verify(candidate)
    patched = _patch_bytes(original)
    _assert_patched(patched)
    if patched == original or len(patched) != len(original):
        _fail('Kimi privacy patch was empty or changed binary length')
    try:
        original_mode = stat.S_IMODE(candidate.stat().st_mode)
        original_info = candidate.lstat()
    except OSError:
        _fail('Kimi staged binary metadata could not be read')
    identity = (original_info.st_dev, original_info.st_ino)
    try:
        _chmod_bytes(candidate, original_mode | stat.S_IWUSR, identity)
    except KimiPrivacyError:
        _fail('Kimi staged binary could not be made writable')
    try:
        try:
            _write_bytes(candidate, patched, identity)
            _codesign_patch(candidate)
            _codesign_verify(candidate)
            candidate = _check_path(candidate)
            identity = _file_identity(candidate)
            modified = candidate.read_bytes()
            _assert_patched(modified)
        except KimiPrivacyError:
            try:
                candidate = _check_path(candidate)
                identity = _file_identity(candidate)
                _write_bytes(candidate, original, identity)
            except KimiPrivacyError:
                pass
            raise
    except KimiPrivacyError:
        raise
    finally:
        try:
            _chmod_bytes(candidate, original_mode, identity)
        except KimiPrivacyError:
            _fail('Kimi staged binary permissions could not be restored')
    return {
        'path': str(candidate),
        'original_sha256': original_sha,
        'modified_sha256': _sha256(modified),
        'original_size': len(original),
        'patched_size': len(patched),
        'modified_size': len(modified),
    }


__all__ = ['KimiPrivacyError', 'harden_staged']
