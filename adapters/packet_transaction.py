"""Shared/exclusive authority for the live packet-ask installation.

The canonical version file and the installed uv tool form one runtime state.  A
consumer holds a shared lock while it uses that state; a promotion holds the
exclusive lock until it has either published the candidate or restored the old
installation.  Guard tests receive a short-lived capability so they can exercise
the candidate while the promoter still owns the exclusive lock.
"""
from contextlib import contextmanager
import errno
import fcntl
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile


CAPABILITY_ENV = 'AGENTBELT_PACKET_GUARD_TRANSACTION'
LOCK_NAME = '.packet-ask-transaction.lock'
CAPABILITY_NAME = '.packet-ask-guard-transaction.json'


class TransactionError(Exception):
    pass


def _state_path(state_file):
    return Path(state_file).resolve()


def _lock_path(state_file):
    return _state_path(state_file).with_name(LOCK_NAME)


def _open_private(path, flags, mode=0o600):
    descriptor = os.open(str(path), flags | os.O_NOFOLLOW, mode)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(descriptor)
        raise TransactionError('packet transaction authority is not a private regular file')
    return descriptor


def _open_lock(state_file):
    try:
        return _open_private(_lock_path(state_file), os.O_RDWR | os.O_CREAT)
    except OSError as error:
        raise TransactionError('could not open packet transaction authority: ' + type(error).__name__) from None


def _write_capability(path, record):
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + '.tmp-', dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(record, stream)
            stream.write('\n')
        # Pathlib retains the platform's atomic replace primitive without
        # sharing packet_promote.os.replace test instrumentation.
        temporary.replace(path)
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


class PromotionAuthority:
    def __init__(self, state_file, candidate, token):
        self.state_file = _state_path(state_file)
        self.candidate = candidate
        self.token = token

    def guard_environment(self, base_environment):
        """Return an explicit child environment; never changes ``os.environ``."""
        environment = dict(base_environment)
        environment[CAPABILITY_ENV] = self.token
        return environment


def _read_capability(state_file, descriptor, supplied_token):
    if not supplied_token or len(supplied_token) > 256:
        return None
    path = _state_path(state_file).with_name(CAPABILITY_NAME)
    try:
        capability = _open_private(path, os.O_RDONLY)
    except (OSError, TransactionError):
        return None
    try:
        with os.fdopen(capability, 'rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return None
        record = json.loads(raw)
    except (OSError, ValueError, TypeError):
        return None
    lock_info = os.fstat(descriptor)
    expected_state = str(_state_path(state_file))
    if (not isinstance(record, dict)
            or set(record) != {'candidate', 'lockDev', 'lockIno', 'ownerPid', 'state', 'token'}
            or record.get('state') != expected_state
            or record.get('lockDev') != lock_info.st_dev
            or record.get('lockIno') != lock_info.st_ino
            or type(record.get('ownerPid')) is not int
            or not isinstance(record.get('candidate'), str)
            or not isinstance(record.get('token'), str)
            or not hmac.compare_digest(record['token'], supplied_token)):
        return None
    try:
        os.kill(record['ownerPid'], 0)
    except OSError:
        return None
    # A capability file alone is not authority.  Its exact lock must still be
    # held exclusively, otherwise this non-blocking shared acquisition succeeds.
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EAGAIN):
            return None
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return None
    return record


@contextmanager
def promotion(state_file, candidate):
    """Hold exclusive authority and expose a candidate-only guard-test token."""
    descriptor = _open_lock(state_file)
    stream = os.fdopen(descriptor, 'a+b')
    capability_path = _state_path(state_file).with_name(CAPABILITY_NAME)
    token = secrets.token_urlsafe(32)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        info = os.fstat(descriptor)
        record = {'candidate': candidate, 'lockDev': info.st_dev, 'lockIno': info.st_ino,
                  'ownerPid': os.getpid(), 'state': str(_state_path(state_file)), 'token': token}
        _write_capability(capability_path, record)
        yield PromotionAuthority(state_file, candidate, token)
    finally:
        try:
            capability = _open_private(capability_path, os.O_RDONLY)
        except (OSError, TransactionError):
            capability = None
        if capability is not None:
            try:
                with os.fdopen(capability, 'rb') as current:
                    record = json.loads(current.read(4097))
                if isinstance(record, dict) and hmac.compare_digest(str(record.get('token', '')), token):
                    capability_path.unlink()
            except (OSError, ValueError, TypeError):
                pass
        stream.close()


@contextmanager
def consumer(state_file, environment=None):
    """Hold shared authority for one complete packet-ask host operation."""
    descriptor = _open_lock(state_file)
    stream = os.fdopen(descriptor, 'a+b')
    supplied = (os.environ if environment is None else environment).get(CAPABILITY_ENV, '')
    try:
        if _read_capability(state_file, descriptor, supplied) is None:
            fcntl.flock(descriptor, fcntl.LOCK_SH)
        yield
    finally:
        stream.close()


def candidate_version(state_file, environment=None):
    """Return the transaction-scoped candidate visible only to guard tests."""
    descriptor = _open_lock(state_file)
    try:
        supplied = (os.environ if environment is None else environment).get(CAPABILITY_ENV, '')
        record = _read_capability(state_file, descriptor, supplied)
        return record['candidate'] if record is not None else None
    finally:
        os.close(descriptor)
