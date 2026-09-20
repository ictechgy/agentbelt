"""Descriptor-relative primitives for the child-writable screenshot queue.

The confined child owns every pathname below ``shots``.  Host-side callers must
therefore keep the directory descriptor returned by :func:`open_shot_queue`
open for the whole operation and must never turn a child-controlled name back
into an absolute path.

Launcher contract:

* ``open_shot_queue(workspace, create=True)`` returns a new directory fd.  The
  caller owns it and must close it.
* ``read_lock_pid(fd)`` returns a positive pid only for a bounded, regular,
  single-link lock file; missing, malformed, linked, or oversized locks return
  ``None``.
* ``open_queue_log(fd)`` returns a new append-only fd for a regular,
  single-link ``.watcher.log``.  It raises ``OSError`` for links and special
  files.  The caller owns the fd and may pass it to ``subprocess.Popen``.
* ``unlink_name(fd, name)`` removes only the named directory entry and never
  follows it.  It returns ``False`` when the name is absent or is a directory.
"""

import errno
import os
from pathlib import Path
import secrets
import stat


MAX_CONTROL_BYTES = 4096
MAX_OPTIONS_BYTES = 64 * 1024
MAX_PNG_BYTES = 128 * 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class UnsafeQueueEntry(OSError):
    """A queue entry was linked, non-regular, or larger than its contract."""


def _plain_name(name):
    if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\x00' in name:
        raise ValueError('queue entries must be single plain path components')
    return name


def open_directory(path):
    """Open an absolute directory one no-follow component at a time.

    ``Path.resolve`` canonicalizes harmless platform aliases such as macOS's
    ``/var`` symlink.  The subsequent descriptor walk is the operation that
    pins every canonical directory and prevents validation-to-open swaps.
    The caller owns the returned fd.
    """
    canonical = Path(path).resolve(strict=True)
    if not canonical.is_absolute():
        raise OSError(errno.EINVAL, 'directory path must be absolute')
    descriptor = os.open('/', _DIR_FLAGS)
    try:
        for part in canonical.parts[1:]:
            child = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_child_directory(parent_fd, name, create=False, mode=0o755):
    """Open one child directory without following it; caller owns the fd."""
    name = _plain_name(name)
    if create:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
    return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)


def open_shot_queue(workspace, create=False):
    """Return a pinned no-follow fd for ``workspace/shots``; caller closes it."""
    workspace_fd = open_directory(workspace)
    try:
        return open_child_directory(workspace_fd, 'shots', create=create)
    finally:
        os.close(workspace_fd)


def _regular_single_link(descriptor, maximum=None):
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise UnsafeQueueEntry(errno.EPERM, 'queue entry must be a regular single-link file')
    if maximum is not None and info.st_size > maximum:
        raise UnsafeQueueEntry(errno.EFBIG, 'queue entry exceeds its size limit')
    return info


def open_regular(queue_fd, name, maximum=None):
    """Open one existing regular single-link entry without following links."""
    name = _plain_name(name)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=queue_fd)
    try:
        _regular_single_link(descriptor, maximum)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def regular_stat(queue_fd, name, maximum=None):
    """Return a safe entry's stat result, or ``None`` for absent/unsafe input."""
    try:
        descriptor = open_regular(queue_fd, name, maximum)
    except OSError:
        return None
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def read_bytes(queue_fd, name, maximum):
    """Read at most ``maximum`` bytes from a regular single-link queue entry."""
    descriptor = open_regular(queue_fd, name, maximum)
    try:
        chunks = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b''.join(chunks)
        if len(data) > maximum:
            raise UnsafeQueueEntry(errno.EFBIG, 'queue entry exceeds its size limit')
        return data
    finally:
        os.close(descriptor)


def read_lock_pid(queue_fd):
    """Return a positive pid from a safe bounded lock, otherwise ``None``."""
    try:
        raw = read_bytes(queue_fd, '.watcher.lock', MAX_CONTROL_BYTES)
        value = int(raw.decode('ascii').strip())
        return value if value > 0 else None
    except (OSError, UnicodeError, ValueError):
        return None


def acquire_lock(queue_fd, pid):
    """Create the watcher lock exclusively; return ``False`` if it exists."""
    try:
        descriptor = os.open(
            '.watcher.lock',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=queue_fd,
        )
    except FileExistsError:
        return False
    try:
        payload = str(pid).encode('ascii')
        while payload:
            payload = payload[os.write(descriptor, payload):]
        _regular_single_link(descriptor, MAX_CONTROL_BYTES)
        return True
    finally:
        os.close(descriptor)


def open_queue_log(queue_fd):
    """Return a safe append fd for ``.watcher.log``; caller closes it."""
    descriptor = os.open(
        '.watcher.log',
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
        0o600,
        dir_fd=queue_fd,
    )
    try:
        _regular_single_link(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def unlink_name(queue_fd, name):
    """Unlink exactly one non-directory entry without following it."""
    name = _plain_name(name)
    try:
        info = os.stat(name, dir_fd=queue_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            return False
        os.unlink(name, dir_fd=queue_fd)
        return True
    except FileNotFoundError:
        return False


def _temporary_name(label):
    return '.watcher-' + label + '-' + secrets.token_hex(12) + '.tmp'


def _atomic_writer(queue_fd, name, maximum, write):
    name = _plain_name(name)
    temporary = _temporary_name('publish')
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=queue_fd,
    )
    try:
        write(descriptor)
        os.fsync(descriptor)
        _regular_single_link(descriptor, maximum)
        os.replace(temporary, name, src_dir_fd=queue_fd, dst_dir_fd=queue_fd)
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=queue_fd)
        except FileNotFoundError:
            pass


def atomic_write(queue_fd, name, data, maximum=MAX_CONTROL_BYTES):
    """Atomically replace a queue entry with bounded bytes, without following it."""
    if isinstance(data, str):
        data = data.encode('utf-8', 'replace')
    if len(data) > maximum:
        raise UnsafeQueueEntry(errno.EFBIG, 'queue output exceeds its size limit')

    def write(descriptor):
        remaining = data
        while remaining:
            remaining = remaining[os.write(descriptor, remaining):]

    _atomic_writer(queue_fd, name, maximum, write)


def publish_file(queue_fd, name, source, maximum=MAX_PNG_BYTES):
    """Atomically copy one trusted regular single-link file into the queue."""
    source_fd = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _regular_single_link(source_fd, maximum)

        def write(destination):
            total = 0
            while True:
                block = os.read(source_fd, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise UnsafeQueueEntry(errno.EFBIG, 'screenshot exceeds its size limit')
                remaining = block
                while remaining:
                    remaining = remaining[os.write(destination, remaining):]

        _atomic_writer(queue_fd, name, maximum, write)
    finally:
        os.close(source_fd)
