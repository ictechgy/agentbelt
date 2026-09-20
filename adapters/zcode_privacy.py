"""Build and verify the private, snapshot-blocked ZCode application.

This module deliberately treats the ZCode distribution as a version-locked
binary input.  It does not launch the application and it never mutates the
source application.  The installer makes a copy, applies byte-length
preserving patches to the two reviewed JavaScript files inside ``app.asar``,
reseals only the outer application, and publishes it transactionally.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Iterable, Mapping


class ZcodePrivacyError(RuntimeError):
    """Raised when a private bundle cannot be proved safe to use."""


# Public, reviewed ZCode 3.12.3 evidence.  These values are intentionally
# duplicated here so a missing or changed proof file cannot silently widen the
# accepted input set.
VERSION = "3.12.3"
BUILD = "3.12.3.7463"
ORIGINAL_BUNDLE_ID = "dev.zcode.app"
ORIGINAL_APP_NAME = "ZCode"
PRIVATE_BUNDLE_ID = "local.agentbelt.zcode.snapshot-blocked"
PRIVATE_APP_NAME = "ZCode Snapshot Blocked"

ORIGINAL_ASAR_SHA256 = "6d99a52d5c25bcdc9651d0a4aad57d215580cb11fe06c8a9ce3553387013678e"
ORIGINAL_HOST_SHA256 = "c8f7b2e50f2c8f7eeb030a377cfc4779b2a0e2037af2239e065157dc2e3e422e"
ORIGINAL_MAIN_SHA256 = "5105c8659924d8c262bc763302131d6dc1f50b1249d9fc578e2d84cf76f55ae4"
ORIGINAL_SCHEDULER_SHA256 = "61c571c8a8ab926e9b024e3377efdfe32a5caa318418a09a05a65c6baf2004ac"
ORIGINAL_CLI_SHA256 = "da61b0663336a65f7cce3dec223678794ccaa58158e304fc0d97b695434a8f01"
PATCHED_HOST_SHA256 = "fdf8957c843ac7db4d863b72f2eee9c9ea28ad8fa778295913c032148d36f04d"
PATCHED_SCHEDULER_SHA256 = "05dbaaab73bd49d49ceaa9d2fc3296e1999a2de370707bc187d0228065b81425"
HOST_SIZE = 2_588_119
MAIN_SIZE = 708_140
SCHEDULER_SIZE = 2_108_514
HOST_PATH = "out/host/index.js"
MAIN_PATH = "out/main/index.js"
SCHEDULER_PATH = "out/scheduler/index.js"
CLI_PATH = "Contents/Resources/glm/zcode.cjs"
ASAR_PATH = "Contents/Resources/app.asar"
INFO_PATH = "Contents/Info.plist"
CUA_HELPER_PATH = "Contents/Resources/cua-helper/ZCode Computer Use.app"
CUA_TEAM_ID = "8A5X4JJ39T"

DEFAULT_SOURCE_APP = Path("/Applications/ZCode.app")

_HEX64 = frozenset("0123456789abcdef")
_HEX32 = frozenset("0123456789abcdef")

# The host proof uses exact method boundaries from prepare_proof.py.  The
# closing anchors are intentionally included in every spec to prevent a
# broad/ambiguous replacement from modifying unrelated code.
HOST_PATCH_SPECS = (
    (
        "captureBeforePrompt",
        b"async captureBeforePrompt(t){",
        b"}getCaptureQueueDiagnostics()",
        b"return;",
    ),
    (
        "captureBeforePromptUnsafe",
        b"async captureBeforePromptUnsafe(t){",
        b"}};import",
        b"return;",
    ),
    (
        "getUploadCredential",
        b"async getUploadCredential(t,r,o){",
        b"}pruneExpiredUploadCredentials(",
        b"return null;",
    ),
    (
        "getUploadKey",
        b"async getUploadKey(t,r,o,n){",
        b"}async requestUploadTarget(",
        b"return null;",
    ),
    (
        "requestUploadTarget",
        b"async requestUploadTarget(t,r,o,n){",
        b"}consumeUploadCredential(",
        b'return {ok:false,reason:"key_expired",message:"repo snapshots disabled"};',
    ),
    (
        "uploadObject",
        b"async uploadObject(t){",
        b"}};import",
        b'return {ok:false,reason:"object_upload_failed",message:"repo snapshots disabled"};',
    ),
    (
        "flushWorkspace",
        b"async flushWorkspace(t){",
        b"}async flushWorkspaceLoop(",
        b"return;",
    ),
    (
        "flushActiveUpload",
        b"async flushActiveUpload(t){",
        b"}consumePendingCredential(",
        b"return false;",
    ),
)

# Desktop storage preparation runs a fixed bundled Worker with --prepare-storage;
# it does not start the model provider or tools. The normal Agent command remains
# the generation-bound Seatbelt launcher. ZCode 3.12.3 incorrectly asks that custom
# command for a JavaScript Worker entry and rejects it before preparing any DB.
# Resolve only the verified private bundle's CLI relative to the HOST module.
STORAGE_PREPARATION_ORIGINAL = (
    b'let t=WM({workspacePath:e.cwd,workspaceKey:e.cwd,presentationSurface:"desktop"});'
    b'if(!t?.supportsStorageStartup||!t.storagePreparationEntry)throw Ci("unsupported_runtime");'
)
STORAGE_PREPARATION_REPLACEMENT = (
    b'let t={cwd:e.cwd,env:{ELECTRON_RUN_AS_NODE:"1"},'
    b'storagePreparationEntry:new URL("../../../glm/zcode.cjs",import.meta.url)};'
)

# The 3.12.3 scheduler gained a ConversationShareService that uploads prepared
# conversation artifacts through createPreparation + uploadArtifact.  Both
# publish entry points are stubbed so no share payload can leave the private
# copy regardless of which caller reaches the service.
SCHEDULER_PATCH_SPECS = (
    (
        "publishWithAgent",
        b"async publishWithAgent(n,r,i){",
        b"}async publishInternal(",
        b'throw new Le("share_disabled","Conversation sharing is disabled by local policy");',
    ),
    (
        "publishInternal",
        b"async publishInternal(n,r,i=this.zcodeAgentService){",
        b"}getProgressEmitter(",
        b'throw new Le("share_disabled","Conversation sharing is disabled by local policy");',
    ),
)


def _error(message: str) -> ZcodePrivacyError:
    return ZcodePrivacyError(message)


def _as_path(value: os.PathLike[str] | str, label: str) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError):
        raise _error(label + " must be a path") from None
    if not path.is_absolute() or "\x00" in str(path):
        raise _error(label + " must be an absolute path")
    return path


def _validate_generation(generation: str) -> str:
    if (
        not isinstance(generation, str)
        or len(generation) != 32
        or any(character not in _HEX32 for character in generation)
    ):
        raise _error("private generation must be exactly 32 lowercase hex characters")
    return generation


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise _error("cannot read " + str(path) + ": " + type(error).__name__) from None
    return digest.hexdigest()


def _assert_owner(path: Path, kind: str, *, mode: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise _error("missing private " + kind + ": " + str(path)) from None
    if info.st_uid != os.getuid():
        raise _error("private " + kind + " is not owned by the current account")
    if stat.S_ISLNK(info.st_mode):
        raise _error("refusing symlinked private " + kind + ": " + str(path))
    if kind == "directory" and not stat.S_ISDIR(info.st_mode):
        raise _error("private path is not a directory: " + str(path))
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise _error("private path is not a regular file: " + str(path))
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise _error("private " + kind + " has unexpected permissions: " + str(path))
    return info


def _private_directory(path: Path, *, create: bool = False) -> Path:
    if path.exists() or path.is_symlink():
        _assert_owner(path, "directory")
    elif create:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            _assert_owner(path, "directory")
        except OSError as error:
            raise _error("cannot create private directory: " + type(error).__name__) from None
    else:
        raise _error("missing private directory: " + str(path))
    info = _assert_owner(path, "directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise _error("private directory must be owner-only: " + str(path))
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise _error("private directory must be mode 700: " + str(path))
    return path


def private_app(root: os.PathLike[str] | str) -> Path:
    """Return the only application path this adapter may publish or launch."""

    root_path = _as_path(root, "root")
    return root_path / "state" / "zcode-private" / "ZCode.app"


def manifest_path(root: os.PathLike[str] | str) -> Path:
    """Return the private bundle manifest path."""

    root_path = _as_path(root, "root")
    return root_path / "state" / "zcode-private" / "manifest.json"


def _private_root(root: os.PathLike[str] | str, *, create: bool = False) -> Path:
    root_path = _as_path(root, "root")
    state = root_path / "state"
    if create:
        _private_directory(state, create=True)
        return _private_directory(state / "zcode-private", create=True)
    _private_directory(state)
    return _private_directory(state / "zcode-private")


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        raise _error("path escapes bundle root: " + str(path)) from None


def _bundle_owner_allowed(uid: int, *, source: bool) -> bool:
    """Allow system ownership only for the immutable, independently verified source."""

    return uid == os.getuid() or (source and uid == 0)


def _walk_bundle(root: Path, *, source: bool = False) -> Iterable[tuple[Path, os.stat_result]]:
    """Yield bundle entries while rejecting foreign owners, external links and hardlinks."""

    try:
        root_info = root.lstat()
    except OSError:
        raise _error("missing bundle root: " + str(root)) from None
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise _error("bundle root is not a non-symlink directory: " + str(root))
    if not _bundle_owner_allowed(root_info.st_uid, source=source):
        raise _error("bundle root has an untrusted owner: " + str(root))
    root_resolved = root.resolve(strict=True)
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise _error("cannot inspect bundle: " + type(error).__name__) from None
        for path in entries:
            try:
                info = path.lstat()
            except OSError as error:
                raise _error("cannot inspect bundle entry: " + type(error).__name__) from None
            if not _bundle_owner_allowed(info.st_uid, source=source):
                raise _error("bundle entry has an untrusted owner: " + str(path))
            if stat.S_ISLNK(info.st_mode):
                try:
                    target = path.resolve(strict=True)
                except OSError:
                    raise _error("broken bundle symlink: " + str(path)) from None
                try:
                    target.relative_to(root_resolved)
                except ValueError:
                    raise _error("bundle symlink points outside the bundle: " + str(path)) from None
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise _error("bundle contains a hardlinked file: " + str(path))
            elif stat.S_ISDIR(info.st_mode):
                pending.append(path)
            else:
                raise _error("unsupported bundle entry: " + str(path))
            yield path, info


def bundle_digest(app: os.PathLike[str] | str, *, source: bool = False) -> str:
    """Hash the complete public bundle tree, including names, modes and links."""

    root = _as_path(app, "application")
    digest = hashlib.sha256()
    # Include the root marker so a directory cannot be replaced by another
    # entry type while retaining the same child stream.
    digest.update(b"D\0\0\0")
    entries = list(_walk_bundle(root, source=source))
    entries.sort(key=lambda item: _safe_relative(item[0], root))
    for path, info in entries:
        relative = _safe_relative(path, root).encode("utf-8", "surrogateescape")
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            kind = b"D"
            payload = b""
        elif stat.S_ISLNK(info.st_mode):
            kind = b"L"
            try:
                payload = os.readlink(path).encode("utf-8", "surrogateescape")
            except OSError as error:
                raise _error("cannot read bundle symlink: " + type(error).__name__) from None
        else:
            kind = b"F"
            payload_length = info.st_size
            payload = None
        digest.update(kind + b"\0" + len(relative).to_bytes(8, "big") + relative)
        if payload is not None:
            digest.update(mode.to_bytes(4, "big") + len(payload).to_bytes(8, "big") + payload)
            continue
        digest.update(mode.to_bytes(4, "big") + payload_length.to_bytes(8, "big"))
        descriptor = -1
        try:
            descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
            current = os.fstat(descriptor)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_dev != info.st_dev
                or current.st_ino != info.st_ino
                or current.st_size != payload_length
            ):
                raise _error("bundle file changed while hashing: " + str(path))
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                count = 0
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    count += len(chunk)
                if count != payload_length:
                    raise _error("bundle file changed while hashing: " + str(path))
        except ZcodePrivacyError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise _error("cannot read bundle file: " + type(error).__name__) from None
    return digest.hexdigest()


def _same_length(original: bytes, replacement: bytes, label: str) -> bytes:
    if len(replacement) > len(original):
        raise _error(label + " replacement does not fit its reserved byte span")
    # Spaces are safe between minified JavaScript tokens.  Keep existing line
    # breaks, matching the offline proof's exact method-body filler.
    filler = bytes(10 if byte == 10 else 32 for byte in original[len(replacement) :])
    return replacement + filler


def patch_host_payload(payload: bytes, *, require_reviewed: bool = False) -> bytes:
    """Block uploads and retain the bundled storage-only startup Worker."""

    if not isinstance(payload, bytes):
        raise _error("host payload must be bytes")
    if require_reviewed and _sha256_bytes(payload) != ORIGINAL_HOST_SHA256:
        raise _error("host payload does not match the reviewed ZCode 3.12.3 bytes")
    original = payload
    patched = bytearray(payload)
    spans: list[tuple[str, int, int]] = []
    for name, opening, closing, replacement in HOST_PATCH_SPECS:
        if original.count(opening) != 1:
            raise _error("ambiguous host patch anchor: " + name)
        start = original.index(opening) + len(opening)
        end = original.find(closing, start)
        if end < 0 or end <= start:
            raise _error("missing host patch closing anchor: " + name)
        body = _same_length(original[start:end], replacement, "host " + name)
        patched[start:end] = body
        spans.append((name, start, end))
    result = bytes(patched)
    if result.count(STORAGE_PREPARATION_ORIGINAL) != 1:
        raise _error("ambiguous host storage preparation anchor")
    result = result.replace(
        STORAGE_PREPARATION_ORIGINAL,
        _same_length(STORAGE_PREPARATION_ORIGINAL, STORAGE_PREPARATION_REPLACEMENT,
                     "host storage preparation"),
        1,
    )
    if len(result) != len(original):
        raise _error("host patch changed byte length")
    if require_reviewed and _sha256_bytes(result) != PATCHED_HOST_SHA256:
        raise _error("reviewed host patch output does not match the public proof")
    return result


def patch_scheduler_payload(payload: bytes, *, require_reviewed: bool = False) -> bytes:
    """Disable the reviewed conversation-share publish methods in SCHEDULER."""

    if not isinstance(payload, bytes):
        raise _error("scheduler payload must be bytes")
    if require_reviewed and _sha256_bytes(payload) != ORIGINAL_SCHEDULER_SHA256:
        raise _error("scheduler payload does not match the reviewed ZCode 3.12.3 bytes")
    original = payload
    patched = bytearray(payload)
    for name, opening, closing, replacement in SCHEDULER_PATCH_SPECS:
        if original.count(opening) != 1:
            raise _error("ambiguous scheduler patch anchor: " + name)
        start = original.index(opening) + len(opening)
        end = original.find(closing, start)
        if end < 0 or end <= start:
            raise _error("missing scheduler patch closing anchor: " + name)
        patched[start:end] = _same_length(original[start:end], replacement, "scheduler " + name)
    result = bytes(patched)
    if len(result) != len(original):
        raise _error("scheduler patch changed byte length")
    if require_reviewed and _sha256_bytes(result) != PATCHED_SCHEDULER_SHA256:
        raise _error("reviewed scheduler patch output does not match the public proof")
    return result


def _main_replacement_specs() -> tuple[tuple[str, bytes, bytes], ...]:
    return (
        ("production update state", b'enabled:Z==="production"', b"enabled:!1"),
        ("development updater guard", b"jt.isPackaged||Ki()", b"!1"),
        ("initial updater state", b'B={kind:"idle",enabled:!0}', b'B={kind:"idle",enabled:!1}'),
        (
            "force update check",
            b'Z==="production"&&!n?await kv(',
            b"!1?await kv(",
        ),
        ("protocol registration", b"by(g,{iconPath:hH});", b"void 0;"),
    )


def _replace_main_body(original: bytes, opening: bytes, closing: bytes, replacement: bytes, label: str) -> bytes:
    if original.count(opening) != 1:
        raise _error("ambiguous main patch anchor: " + label)
    start = original.index(opening) + len(opening)
    end = original.find(closing, start)
    if end < 0 or end <= start:
        raise _error("missing main patch closing anchor: " + label)
    body = _same_length(original[start:end], replacement, "main " + label)
    output = bytearray(original)
    output[start:end] = body
    return bytes(output)


def _json_js(value: str) -> bytes:
    # JSON string syntax is valid JavaScript string syntax for these values,
    # and ensure_ascii keeps generated bytes independent of locale.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def patch_main_payload(payload: bytes, root: os.PathLike[str] | str, generation: str) -> bytes:
    """Apply the version-locked updater/deep-link/backend routing patches."""

    if not isinstance(payload, bytes):
        raise _error("main payload must be bytes")
    root_path = _as_path(root, "root")
    generation = _validate_generation(generation)
    original = payload
    patched = original
    for label, opening, replacement in _main_replacement_specs():
        if patched.count(opening) != 1:
            raise _error("ambiguous main patch anchor: " + label)
        patched = patched.replace(opening, _same_length(opening, replacement, "main " + label), 1)

    # Disable pending-update hydration while preserving the function's span.
    patched = _replace_main_body(
        patched,
        b"async function vw(e){",
        b"}i(vw,\"hydratePendingPostUpdateReleaseNotes\")",
        b"return;",
        "pending update hydration",
    )

    # The declaration's large existing body is a reserved byte slot.  Keep a
    # declaration so all existing call sites retain their return contract, but
    # execute the backend/profile assignments at module scope before app paths
    # and the single-instance lock are initialized.
    opening = b"async function uo(e=!1){"
    closing = b"i(uo,\"quitAndInstallUpdate\")"
    if patched.count(opening) != 1 or patched.count(closing) != 1:
        raise _error("ambiguous updater install sink anchor")
    start = patched.index(opening)
    end = patched.index(closing, start)
    if end <= start:
        raise _error("invalid updater install sink span")
    profile = root_path / "state" / "zcode-private" / "user-data"
    session = root_path / "state" / "zcode-private" / "session"
    args = [
        "-I",
        str(root_path / "agentbelt.py"),
        "zcode-private-backend",
        "--generation",
        generation,
        "app-server",
        "--stdio",
    ]
    uo_replacement = (
        b"async function uo(e=!1){return;}"
        + b"process.env.ZCODE_AGENT_SERVER_COMMAND=\"/usr/bin/python3\";"
        + b"process.env.ZCODE_AGENT_SERVER_ARGS_JSON=JSON.stringify("
        + json.dumps(args, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        + b");"
        + b"process.env.ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT=\"1\";"
        + b"dr=\"ZCode Snapshot Blocked\";"
        + b"oc=!1;"
        + b"qn=process.env.ZCODE_DESKTOP_USER_DATA_DIR||"
        + _json_js(str(profile))
        + b";"
        + b"ic=process.env.ZCODE_DESKTOP_SESSION_DATA_DIR||"
        + _json_js(str(session))
        + b";"
    )
    replacement = _same_length(patched[start:end], uo_replacement, "updater install sink")
    patched = patched[:start] + replacement + patched[end:]
    if len(patched) != len(original):
        raise _error("main patch changed byte length")
    return patched


def _load_info(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = plistlib.load(stream)
    except (OSError, ValueError, plistlib.InvalidFileException, EOFError):
        raise _error("malformed Info.plist: " + str(path)) from None
    if not isinstance(value, dict):
        raise _error("Info.plist must contain a dictionary")
    return value


def _read_asar(path: Path) -> tuple[bytes, dict[str, Any], int, int]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise _error("cannot read app.asar: " + type(error).__name__) from None
    if len(raw) < 16:
        raise _error("app.asar header is truncated")
    values = [int.from_bytes(raw[offset : offset + 4], "little") for offset in range(0, 16, 4)]
    if values[0] != 4:
        raise _error("unsupported ASAR header marker")
    data_start = 8 + values[1]
    header_length = values[3]
    header_start = 16
    header_end = header_start + header_length
    if header_length <= 0 or header_end > len(raw) or data_start < header_end:
        raise _error("malformed ASAR header bounds")
    padding = raw[header_end:data_start]
    if any(byte != 0 for byte in padding):
        raise _error("ASAR header padding is not zero-filled")
    try:
        header = json.loads(raw[header_start:header_end].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _error("ASAR header JSON is malformed") from None
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise _error("ASAR header has no files dictionary")
    return raw, header, data_start, header_length


def _lookup_asar_entry(header: Mapping[str, Any], relative: str) -> dict[str, Any]:
    value: Any = header
    for component in relative.split("/"):
        if component == relative.split("/")[0]:
            value = value.get("files", {}).get(component) if isinstance(value, dict) else None
        else:
            value = value.get("files", {}).get(component) if isinstance(value, dict) else None
    if not isinstance(value, dict):
        raise _error("missing ASAR entry: " + relative)
    return value


def _entry_span(entry: Mapping[str, Any], data_start: int, archive_length: int, relative: str) -> tuple[int, int]:
    size = entry.get("size")
    offset = entry.get("offset")
    if not isinstance(size, int) or size < 0:
        raise _error("invalid ASAR size for " + relative)
    if isinstance(offset, str):
        if not offset.isdigit():
            raise _error("invalid ASAR offset for " + relative)
        offset_int = int(offset, 10)
    elif isinstance(offset, int) and offset >= 0:
        offset_int = offset
    else:
        raise _error("invalid ASAR offset for " + relative)
    start = data_start + offset_int
    end = start + size
    if start < data_start or end < start or end > archive_length:
        raise _error("ASAR entry escapes archive: " + relative)
    return start, end


def _asar_target_bytes(raw: bytes, header: Mapping[str, Any], data_start: int, relative: str) -> bytes:
    entry = _lookup_asar_entry(header, relative)
    start, end = _entry_span(entry, data_start, len(raw), relative)
    return raw[start:end]


def _integrity_hash_for_header(header_bytes: bytes) -> str:
    """Return the ElectronAsarIntegrity digest for the serialized ASAR header.

    Electron's Info.plist field is the distribution's header-level integrity
    value.  The per-file ASAR integrity entries remain separately checked by
    ``verify_asar``.  Keeping this calculation explicit also prevents the
    original stale value from being copied into a rebuilt bundle.
    """

    return _sha256_bytes(header_bytes)


def _replace_digest_fields(header_bytes: bytes, old: str, new: str, relative: str) -> bytes:
    old_bytes = old.encode("ascii")
    new_bytes = new.encode("ascii")
    count = header_bytes.count(old_bytes)
    if count != 2:
        raise _error("ASAR integrity fields for " + relative + " are malformed")
    replaced = header_bytes.replace(old_bytes, new_bytes)
    if replaced.count(new_bytes) < 2:
        raise _error("ASAR integrity fields were not updated for " + relative)
    return replaced


def patch_asar_payload(
    asar: bytes,
    *,
    root: os.PathLike[str] | str,
    generation: str,
    require_reviewed: bool = False,
) -> tuple[bytes, dict[str, str]]:
    """Patch host/main bytes in an ASAR while preserving all offsets."""

    if not isinstance(asar, bytes):
        raise _error("ASAR payload must be bytes")
    if require_reviewed and _sha256_bytes(asar) != ORIGINAL_ASAR_SHA256:
        raise _error("app.asar does not match the reviewed ZCode 3.12.3 bytes")
    root_path = _as_path(root, "root")
    generation = _validate_generation(generation)
    raw, header, data_start, header_length = _read_asar_bytes(asar)
    header_start = 16
    header_end = header_start + header_length
    host_entry = _lookup_asar_entry(header, HOST_PATH)
    main_entry = _lookup_asar_entry(header, MAIN_PATH)
    scheduler_entry = _lookup_asar_entry(header, SCHEDULER_PATH)
    host = _asar_target_bytes(raw, header, data_start, HOST_PATH)
    main = _asar_target_bytes(raw, header, data_start, MAIN_PATH)
    scheduler = _asar_target_bytes(raw, header, data_start, SCHEDULER_PATH)
    if require_reviewed and (
        len(host) != HOST_SIZE or len(main) != MAIN_SIZE or len(scheduler) != SCHEDULER_SIZE
    ):
        raise _error("reviewed ASAR component sizes do not match ZCode 3.12.3")
    if require_reviewed and (
        _sha256_bytes(host) != ORIGINAL_HOST_SHA256
        or _sha256_bytes(main) != ORIGINAL_MAIN_SHA256
        or _sha256_bytes(scheduler) != ORIGINAL_SCHEDULER_SHA256
    ):
        raise _error("ASAR component bytes do not match the reviewed ZCode 3.12.3 files")
    patched_host = patch_host_payload(host, require_reviewed=require_reviewed)
    patched_main = patch_main_payload(main, root_path, generation)
    patched_scheduler = patch_scheduler_payload(scheduler, require_reviewed=require_reviewed)
    host_hash = _sha256_bytes(patched_host)
    main_hash = _sha256_bytes(patched_main)
    scheduler_hash = _sha256_bytes(patched_scheduler)
    if require_reviewed and (
        host_hash != PATCHED_HOST_SHA256 or scheduler_hash != PATCHED_SCHEDULER_SHA256
    ):
        raise _error("host or scheduler patch digest did not match the reviewed proof")
    if len(patched_main) != len(main):
        raise _error("main patch changed byte length")
    output = bytearray(raw)
    original_components = {HOST_PATH: host, MAIN_PATH: main, SCHEDULER_PATH: scheduler}
    patched_components = {HOST_PATH: patched_host, MAIN_PATH: patched_main, SCHEDULER_PATH: patched_scheduler}
    for relative, patched_payload in patched_components.items():
        start, end = _entry_span(_lookup_asar_entry(header, relative), data_start, len(raw), relative)
        output[start:end] = patched_payload
    header_bytes = bytes(output[header_start:header_end])
    for relative, entry, new_hash in (
        (HOST_PATH, host_entry, host_hash),
        (MAIN_PATH, main_entry, main_hash),
        (SCHEDULER_PATH, scheduler_entry, scheduler_hash),
    ):
        integrity = entry.get("integrity")
        old_hash = integrity.get("hash") if isinstance(integrity, dict) else None
        if not isinstance(old_hash, str) or len(old_hash) != 64 or any(character not in _HEX64 for character in old_hash):
            raise _error("ASAR integrity metadata is malformed: " + relative)
        if _sha256_bytes(original_components[relative]) != old_hash:
            raise _error("ASAR source integrity is stale: " + relative)
        header_bytes = _replace_digest_fields(header_bytes, old_hash, new_hash, relative)
    output[header_start:header_end] = header_bytes
    result = bytes(output)
    # Validate the exact on-disk representation before handing it to the
    # caller.  This catches accidental offset movement and stale integrity
    # fields while keeping the mutation pure.
    verify_asar_bytes(
        result,
        expected_host_hash=host_hash,
        expected_main_hash=main_hash,
        expected_scheduler_hash=scheduler_hash,
        reviewed=require_reviewed,
    )
    return result, {
        "host_sha256": host_hash,
        "main_sha256": main_hash,
        "scheduler_sha256": scheduler_hash,
        "header_sha256": _integrity_hash_for_header(header_bytes),
        "asar_sha256": _sha256_bytes(result),
    }


def _read_asar_bytes(asar: bytes) -> tuple[bytes, dict[str, Any], int, int]:
    if len(asar) < 16:
        raise _error("app.asar header is truncated")
    values = [int.from_bytes(asar[offset : offset + 4], "little") for offset in range(0, 16, 4)]
    if values[0] != 4:
        raise _error("unsupported ASAR header marker")
    data_start = 8 + values[1]
    header_length = values[3]
    header_start = 16
    header_end = header_start + header_length
    if header_length <= 0 or header_end > len(asar) or data_start < header_end:
        raise _error("malformed ASAR header bounds")
    if any(byte != 0 for byte in asar[header_end:data_start]):
        raise _error("ASAR header padding is not zero-filled")
    try:
        header = json.loads(asar[header_start:header_end].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _error("ASAR header JSON is malformed") from None
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise _error("ASAR header has no files dictionary")
    return asar, header, data_start, header_length


def verify_asar_bytes(
    asar: bytes,
    *,
    expected_host_hash: str | None = None,
    expected_main_hash: str | None = None,
    expected_scheduler_hash: str | None = None,
    reviewed: bool = False,
) -> dict[str, str]:
    """Verify ASAR shape, component hashes, sizes, offsets and block hashes."""

    raw, header, data_start, _ = _read_asar_bytes(asar)
    component_hashes: dict[str, str] = {}
    spans: list[tuple[int, int, str]] = []
    for relative, expected_size, expected_hash in (
        (HOST_PATH, HOST_SIZE, expected_host_hash),
        (MAIN_PATH, MAIN_SIZE, expected_main_hash),
        (SCHEDULER_PATH, SCHEDULER_SIZE, expected_scheduler_hash),
    ):
        entry = _lookup_asar_entry(header, relative)
        start, end = _entry_span(entry, data_start, len(raw), relative)
        payload = raw[start:end]
        digest = _sha256_bytes(payload)
        if reviewed and len(payload) != expected_size:
            raise _error("ASAR component size changed: " + relative)
        if expected_hash is not None and digest != expected_hash:
            raise _error("ASAR component hash changed: " + relative)
        integrity = entry.get("integrity")
        if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA256":
            raise _error("ASAR component integrity metadata is malformed: " + relative)
        if integrity.get("hash") != digest:
            raise _error("ASAR component integrity hash is stale: " + relative)
        if reviewed and integrity.get("blockSize") != 4_194_304:
            raise _error("ASAR component block size is unexpected: " + relative)
        blocks = integrity.get("blocks")
        if not isinstance(blocks, list) or blocks != [digest]:
            raise _error("ASAR component block hash is stale: " + relative)
        component_hashes[relative] = digest
        spans.append((start, end, relative))
    spans.sort()
    for previous, current in zip(spans, spans[1:]):
        if current[0] < previous[1]:
            raise _error("ASAR component ranges overlap")
    return component_hashes


def _verified_source_info(source_app: Path) -> tuple[dict[str, Any], str, str, str, str]:
    """Validate public source metadata and return its complete trust tuple."""

    _validate_bundle_tree(source_app, source=True)
    info = _load_info(source_app / INFO_PATH)
    if info.get("CFBundleIdentifier") != ORIGINAL_BUNDLE_ID:
        raise _error("source bundle identifier is not the reviewed ZCode app")
    if info.get("CFBundleShortVersionString") != VERSION:
        raise _error("source ZCode version is not 3.12.3")
    if info.get("CFBundleVersion") != BUILD:
        raise _error("source ZCode build is not 3.12.3.7463")
    asar = source_app / ASAR_PATH
    cli = source_app / CLI_PATH
    asar_hash = _sha256_file(asar)
    cli_hash = _sha256_file(cli)
    if asar_hash != ORIGINAL_ASAR_SHA256:
        raise _error("source app.asar is not the reviewed public ZCode bytes")
    if cli_hash != ORIGINAL_CLI_SHA256:
        raise _error("source ZCode CLI is not the reviewed public bytes")
    _verify_signature(source_app)
    signature, identifier, team = _signature_metadata(source_app)
    if identifier != ORIGINAL_BUNDLE_ID or team != CUA_TEAM_ID:
        raise _error("source ZCode signature identity or team is not reviewed")
    return info, asar_hash, cli_hash, signature, bundle_digest(source_app, source=True)


def _validate_bundle_tree(app: Path, *, source: bool = False) -> None:
    if not app.is_absolute() or app.is_symlink():
        raise _error("application path must be a non-symlink absolute directory")
    if not app.is_dir():
        raise _error("application bundle is missing: " + str(app))
    # For a source app, its root need not yet be mode 700.  For private apps,
    # _private_root has already enforced owner-only state directories.
    list(_walk_bundle(app, source=source))


def _run_checked(command: list[str], *, allow_missing: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        if allow_missing and isinstance(error, FileNotFoundError):
            return subprocess.CompletedProcess(command, 0, "", "")
        raise _error("command failed to execute: " + command[0]) from None
    return result


def _verify_signature(app: Path) -> None:
    result = _run_checked(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    if result.returncode != 0:
        raise _error("codesign verification failed for " + str(app))


def _signature_metadata(app: Path) -> tuple[str, str, str]:
    result = _run_checked(["/usr/bin/codesign", "-dvvv", str(app)])
    if result.returncode != 0:
        raise _error("cannot inspect code signature for " + str(app))
    # The output is public signature metadata.  Keep only stable identity
    # lines, avoiding timestamps and paths in the manifest.
    lines = []
    for line in (result.stderr or result.stdout).splitlines():
        if line.startswith(("Identifier=", "TeamIdentifier=", "Authority=", "CodeDirectory ", "CDHash=", "CandidateCDHashFull=")):
            lines.append(line)
    if not lines:
        raise _error("code signature metadata is empty for " + str(app))
    identifier = next((line.split("=", 1)[1] for line in lines if line.startswith("Identifier=")), "")
    team = next((line.split("=", 1)[1] for line in lines if line.startswith("TeamIdentifier=")), "")
    return _sha256_bytes("\n".join(lines).encode("utf-8")), identifier, team


def _signature_fingerprint(app: Path) -> str:
    return _signature_metadata(app)[0]


def _main_entitlements(source_app: Path, staging_root: Path) -> Path:
    main = source_app / "Contents/MacOS/ZCode"
    result = _run_checked(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(main)])
    if result.returncode != 0 or not result.stdout:
        raise _error("cannot read original ZCode entitlements")
    try:
        plistlib.loads(result.stdout.encode())
    except (ValueError, plistlib.InvalidFileException):
        raise _error("original ZCode entitlements are malformed") from None
    target = staging_root / ".original-main-entitlements.plist"
    try:
        target.write_bytes(result.stdout.encode())
        target.chmod(0o600)
    except OSError as error:
        raise _error("cannot stage original entitlements: " + type(error).__name__) from None
    return target


def _copy_bundle(source: Path, destination_parent: Path) -> Path:
    """Copy with APFS clone support, falling back to ordinary recursive copy."""

    destination = destination_parent / source.name
    command = ["/bin/cp", "-cRp", str(source), str(destination)]
    result = _run_checked(command)
    if result.returncode != 0:
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination, ignore_errors=True)
            else:
                destination.unlink(missing_ok=True)
        # ``-c`` is unavailable on non-APFS filesystems.  The fallback still
        # preserves internal symlinks and does not follow external links.
        result = _run_checked(["/bin/cp", "-Rp", str(source), str(destination)])
    if result.returncode != 0:
        raise _error("could not clone source ZCode app")
    return destination


def _remove_quarantine(app: Path) -> None:
    probe = _run_checked(["/usr/bin/xattr", "-p", "com.apple.quarantine", str(app)], allow_missing=True)
    if probe.returncode != 0:
        return
    removed = _run_checked(["/usr/bin/xattr", "-dr", "com.apple.quarantine", str(app)])
    if removed.returncode != 0:
        raise _error("could not remove quarantine from rebuilt private app")


def _codesign_outer(app: Path, entitlements: Path) -> None:
    signed = _run_checked(
        [
            "/usr/bin/codesign",
            "-s",
            "-",
            "--force",
            "--options",
            "runtime",
            "--entitlements",
            str(entitlements),
            str(app),
        ]
    )
    if signed.returncode != 0:
        raise _error("codesign failed for rebuilt private app")
    _verify_signature(app)


def _patch_info(info_path: Path, asar_header_hash: str) -> None:
    info = _load_info(info_path)
    if info.get("CFBundleIdentifier") != ORIGINAL_BUNDLE_ID:
        raise _error("cloned Info.plist is not the reviewed ZCode app")
    if info.get("CFBundleName") != ORIGINAL_APP_NAME:
        raise _error("cloned Info.plist has an unexpected Electron app name")
    info.pop("CFBundleURLTypes", None)
    info["CFBundleIdentifier"] = PRIVATE_BUNDLE_ID
    # Electron locates sibling helper bundles from CFBundleName.  Keep the
    # vendor name so it still finds "ZCode Helper*.app" after cloning; the
    # private display/runtime identity is supplied separately below.
    info["CFBundleName"] = ORIGINAL_APP_NAME
    info["CFBundleDisplayName"] = PRIVATE_APP_NAME
    integrity = info.get("ElectronAsarIntegrity")
    if not isinstance(integrity, dict) or not isinstance(integrity.get("Resources/app.asar"), dict):
        raise _error("cloned Info.plist lacks ElectronAsarIntegrity metadata")
    entry = dict(integrity["Resources/app.asar"])
    entry["algorithm"] = "SHA256"
    entry["hash"] = asar_header_hash
    info["ElectronAsarIntegrity"] = dict(integrity, **{"Resources/app.asar": entry})
    try:
        info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=False))
        info_path.chmod(0o600)
    except OSError as error:
        raise _error("could not write rebuilt Info.plist: " + type(error).__name__) from None


def _replace_asar_file(app: Path, root: Path, generation: str) -> dict[str, str]:
    asar_path = app / ASAR_PATH
    asar = asar_path.read_bytes()
    patched, details = patch_asar_payload(asar, root=root, generation=generation, require_reviewed=True)
    try:
        asar_path.write_bytes(patched)
        asar_path.chmod(0o600)
    except OSError as error:
        raise _error("could not write rebuilt app.asar: " + type(error).__name__) from None
    return details


def _load_manifest(root: Path) -> dict[str, Any]:
    path = manifest_path(root)
    _assert_owner(path, "file", mode=0o600)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise _error("private ZCode manifest is malformed") from None
    if not isinstance(value, dict):
        raise _error("private ZCode manifest must be an object")
    return value


def _write_manifest(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name("." + path.name + ".tmp-" + secrets.token_hex(8))
    try:
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise _error("could not publish private ZCode manifest: " + type(error).__name__) from None


def _base_manifest(
    root: Path,
    app: Path,
    generation: str,
    info: Mapping[str, Any],
    details: Mapping[str, str],
    cli_sha256: str,
    signature: str,
) -> dict[str, Any]:
    profile = root / "state" / "zcode-private" / "user-data"
    session = root / "state" / "zcode-private" / "session"
    return {
        "schema": 1,
        "app_path": str(app),
        "generation": generation,
        "version": info["CFBundleShortVersionString"],
        "build": info["CFBundleVersion"],
        "bundle_id": info["CFBundleIdentifier"],
        "bundle_digest": bundle_digest(app),
        "asar_sha256": details["asar_sha256"],
        "asar_header_sha256": details["header_sha256"],
        "host_sha256": details["host_sha256"],
        "main_sha256": details["main_sha256"],
        "scheduler_sha256": details["scheduler_sha256"],
        "cli_sha256": cli_sha256,
        "profile_dir": str(profile),
        "session_dir": str(session),
        "snapshot_uploads_blocked": True,
        "auto_updates_blocked": True,
        "gui_egress_confined": False,
        "signature_fingerprint": signature,
        "cua_team_id": CUA_TEAM_ID,
    }


def _assert_manifest_shape(root: Path, manifest: Mapping[str, Any], generation: str | None) -> str:
    required = {
        "app_path",
        "generation",
        "version",
        "build",
        "bundle_id",
        "bundle_digest",
        "asar_sha256",
        "asar_header_sha256",
        "host_sha256",
        "main_sha256",
        "scheduler_sha256",
        "cli_sha256",
        "profile_dir",
        "session_dir",
    }
    if not required.issubset(manifest.keys()):
        raise _error("private ZCode manifest is missing required fields")
    actual_generation = _validate_generation(manifest["generation"])
    if generation is not None and actual_generation != _validate_generation(generation):
        raise _error("private generation does not match the manifest")
    app = private_app(root)
    if manifest.get("app_path") != str(app):
        raise _error("private ZCode manifest app path is unexpected")
    if manifest.get("profile_dir") != str(root / "state" / "zcode-private" / "user-data"):
        raise _error("private ZCode profile path is unexpected")
    if manifest.get("session_dir") != str(root / "state" / "zcode-private" / "session"):
        raise _error("private ZCode session path is unexpected")
    for field in (
        "bundle_digest",
        "asar_sha256",
        "asar_header_sha256",
        "host_sha256",
        "main_sha256",
        "scheduler_sha256",
        "cli_sha256",
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(character not in _HEX64 for character in value):
            raise _error("private ZCode manifest has malformed " + field)
    if manifest.get("schema") != 1:
        raise _error("private ZCode manifest schema is unexpected")
    if manifest.get("version") != VERSION or manifest.get("build") != BUILD:
        raise _error("private ZCode manifest has an unexpected ZCode version")
    if manifest.get("bundle_id") != PRIVATE_BUNDLE_ID:
        raise _error("private ZCode manifest bundle identifier is unexpected")
    if manifest.get("cua_team_id") != CUA_TEAM_ID:
        raise _error("private ZCode manifest CUA team identifier is unexpected")
    if (
        manifest.get("snapshot_uploads_blocked") is not True
        or manifest.get("auto_updates_blocked") is not True
        or manifest.get("gui_egress_confined") is not False
    ):
        raise _error("private ZCode manifest does not assert update and snapshot blocks")
    return actual_generation


def verify(root: os.PathLike[str] | str, generation: str | None = None) -> dict[str, Any]:
    """Verify the published private application and return its manifest."""

    root_path = _as_path(root, "root")
    _private_root(root_path)
    manifest = _load_manifest(root_path)
    actual_generation = _assert_manifest_shape(root_path, manifest, generation)
    app = private_app(root_path)
    _validate_bundle_tree(app)
    profile = root_path / "state" / "zcode-private" / "user-data"
    session = root_path / "state" / "zcode-private" / "session"
    _private_directory(profile)
    _private_directory(session)
    info = _load_info(app / INFO_PATH)
    if (
        info.get("CFBundleIdentifier") != PRIVATE_BUNDLE_ID
        or info.get("CFBundleShortVersionString") != VERSION
        or info.get("CFBundleVersion") != BUILD
        or info.get("CFBundleName") != ORIGINAL_APP_NAME
        or info.get("CFBundleDisplayName") != PRIVATE_APP_NAME
        or "CFBundleURLTypes" in info
    ):
        raise _error("private ZCode Info.plist invariants failed")
    asar_path = app / ASAR_PATH
    raw, header, data_start, header_length = _read_asar(asar_path)
    details = verify_asar_bytes(
        raw,
        expected_host_hash=manifest["host_sha256"],
        expected_main_hash=manifest["main_sha256"],
        expected_scheduler_hash=manifest["scheduler_sha256"],
        reviewed=True,
    )
    if manifest["host_sha256"] != PATCHED_HOST_SHA256:
        raise _error("private host payload is not the reviewed snapshot-blocked patch")
    if manifest["scheduler_sha256"] != PATCHED_SCHEDULER_SHA256:
        raise _error("private scheduler payload is not the reviewed share-blocked patch")
    if _sha256_bytes(raw) != manifest["asar_sha256"]:
        raise _error("private app.asar digest does not match the manifest")
    header_hash = _integrity_hash_for_header(raw[16 : 16 + header_length])
    if header_hash != manifest["asar_header_sha256"]:
        raise _error("private ASAR header digest does not match the manifest")
    integrity = info.get("ElectronAsarIntegrity", {}).get("Resources/app.asar")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA256" or integrity.get("hash") != header_hash:
        raise _error("ElectronAsarIntegrity does not match the rebuilt ASAR header")
    cli = app / CLI_PATH
    if _sha256_file(cli) != manifest["cli_sha256"]:
        raise _error("private ZCode CLI digest does not match the manifest")
    if bundle_digest(app) != manifest["bundle_digest"]:
        raise _error("private ZCode bundle tree digest does not match the manifest")
    _cua_team_id(app)
    # The main generation is bound into the patched payload.  This targeted
    # check catches a manifest swap even when an attacker recomputes a tree
    # digest without knowing the expected private generation.
    main = _asar_target_bytes(raw, header, data_start, MAIN_PATH)
    expected_backend_args = json.dumps(
        [
            "-I",
            str(root_path / "agentbelt.py"),
            "zcode-private-backend",
            "--generation",
            actual_generation,
            "app-server",
            "--stdio",
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    if b"ZCODE_AGENT_SERVER_COMMAND=\"/usr/bin/python3\"" not in main:
        raise _error("private backend command assignment is missing from main")
    if b"ZCODE_AGENT_SERVER_ARGS_JSON=JSON.stringify(" + expected_backend_args + b")" not in main:
        raise _error("private backend generation assignment is missing from main")
    if b'dr="ZCode Snapshot Blocked"' not in main or b"oc=!1" not in main:
        raise _error("private desktop identity assignment is missing from main")
    if b"async function uo(e=!1){return;}" not in main or b"async function vw(e){return;" not in main:
        raise _error("private updater no-op patches are missing from main")
    for anchor in (
        b'enabled:Z==="production"',
        b"jt.isPackaged||Ki()",
        b'B={kind:"idle",enabled:!0}',
        b'Z==="production"&&!n?await kv(',
        b"by(g,{iconPath:hH});",
    ):
        if anchor in main:
            raise _error("an original updater/deep-link anchor remains in main")
    scheduler = _asar_target_bytes(raw, header, data_start, SCHEDULER_PATH)
    for marker in (
        b'async publishWithAgent(n,r,i){throw new Le("share_disabled"',
        b'async publishInternal(n,r,i=this.zcodeAgentService){throw new Le("share_disabled"',
    ):
        if marker not in scheduler:
            raise _error("private share-blocked stub is missing from scheduler")
    if b"this.client.uploadArtifact(" in scheduler or b"this.client.createPreparation(" in scheduler:
        raise _error("a live share upload call remains in scheduler")
    _verify_signature(app)
    if manifest.get("signature_fingerprint") != _signature_fingerprint(app):
        raise _error("private app signature fingerprint changed")
    return dict(manifest)


def launch_plan(root: os.PathLike[str] | str) -> dict[str, Any]:
    """Return a verified app manifest plus the exact guarded launch environment."""

    manifest = verify(root)
    root_path = _as_path(root, "root")
    generation = _validate_generation(manifest["generation"])
    args = [
        "-I",
        str(root_path / "agentbelt.py"),
        "zcode-private-backend",
        "--generation",
        generation,
        "app-server",
        "--stdio",
    ]
    plan = dict(manifest)
    plan["environment"] = {
        "ZCODE_AGENT_SERVER_COMMAND": "/usr/bin/python3",
        "ZCODE_AGENT_SERVER_ARGS_JSON": json.dumps(args, ensure_ascii=True, separators=(",", ":")),
        "ZCODE_DISABLE_FIXED_REMOTE_DEBUGGING_PORT": "1",
        "ZCODE_DESKTOP_APPLICATION_NAME": PRIVATE_APP_NAME,
        "ZCODE_DESKTOP_USER_DATA_DIR": manifest["profile_dir"],
        "ZCODE_DESKTOP_SESSION_DATA_DIR": manifest["session_dir"],
    }
    return plan


def _preserve_cua_signature(source_app: Path, cloned_app: Path) -> None:
    source_helper = source_app / CUA_HELPER_PATH
    cloned_helper = cloned_app / CUA_HELPER_PATH
    if not source_helper.is_dir() or source_helper.is_symlink() or not cloned_helper.is_dir() or cloned_helper.is_symlink():
        raise _error("CUA helper shape changed during clone")
    if _cua_team_id(source_app) != CUA_TEAM_ID or _cua_team_id(cloned_app) != CUA_TEAM_ID:
        raise _error("CUA helper team identifier changed during clone")
    before = _signature_fingerprint(source_helper)
    after = _signature_fingerprint(cloned_helper)
    if before != after:
        raise _error("CUA helper signature changed during clone")


def _cua_team_id(app: Path) -> str:
    helper = app / CUA_HELPER_PATH
    if not helper.is_dir() or helper.is_symlink():
        raise _error("CUA helper is missing from the private ZCode bundle")
    result = _run_checked(["/usr/bin/codesign", "-dvvv", str(helper)])
    if result.returncode != 0:
        raise _error("cannot inspect the CUA helper signature")
    for line in (result.stderr or result.stdout).splitlines():
        if line.startswith("TeamIdentifier="):
            team = line.split("=", 1)[1].strip()
            if team != CUA_TEAM_ID:
                raise _error("CUA helper team identifier is not reviewed")
            return team
    raise _error("CUA helper signature has no team identifier")


def install(
    root: os.PathLike[str] | str,
    source_app: os.PathLike[str] | str = DEFAULT_SOURCE_APP,
    *,
    generation: str | None = None,
) -> dict[str, Any]:
    """Build and atomically publish a private snapshot-blocked ZCode copy."""

    root_path = _as_path(root, "root")
    source = _as_path(source_app, "source application")
    destination_root = _private_root(root_path, create=True)
    destination = private_app(root_path)
    if source == destination or source == destination.resolve(strict=False):
        raise _error("refusing to clone the private application as its own source")
    # Generation is fixed before any byte patching.  We do not derive it from
    # the current app or permit an empty value, avoiding an original fallback.
    selected_generation = _validate_generation(generation or secrets.token_hex(16))
    source_info, source_asar_hash, source_cli_hash, source_signature, source_tree_digest = _verified_source_info(source)
    if source_asar_hash != ORIGINAL_ASAR_SHA256 or source_cli_hash != ORIGINAL_CLI_SHA256:
        raise _error("source public ZCode hashes are not reviewed")
    staging = Path(tempfile.mkdtemp(prefix=".zcode-private-", dir=str(destination_root)))
    staging.chmod(0o700)
    backup: Path | None = None
    manifest_backup: Path | None = None
    published = False
    try:
        entitlements = _main_entitlements(source, staging)
        cloned = _copy_bundle(source, staging)
        _validate_bundle_tree(cloned)
        _verify_signature(cloned)
        _preserve_cua_signature(source, cloned)
        # Re-read and verify source immediately before changing the clone so a
        # source update during the copy cannot be accepted.
        source_info_after, source_asar_after, source_cli_after, source_signature_after, source_tree_after = _verified_source_info(source)
        if (
            source_info_after != source_info
            or source_asar_after != source_asar_hash
            or source_cli_after != source_cli_hash
            or source_signature_after != source_signature
            or source_tree_after != source_tree_digest
        ):
            raise _error("source ZCode changed during clone")
        details = _replace_asar_file(cloned, root_path, selected_generation)
        _patch_info(cloned / INFO_PATH, details["header_sha256"])
        _remove_quarantine(cloned)
        _validate_bundle_tree(cloned)
        _codesign_outer(cloned, entitlements)
        _preserve_cua_signature(source, cloned)
        if _cua_team_id(cloned) != CUA_TEAM_ID:
            raise _error("rebuilt CUA helper team identifier changed")
        _validate_bundle_tree(cloned)
        # The staged app is checked against all targeted invariants before it
        # can replace an existing publication.
        raw, _, _, _ = _read_asar(cloned / ASAR_PATH)
        verify_asar_bytes(raw, expected_host_hash=details["host_sha256"], expected_main_hash=details["main_sha256"])
        if _sha256_file(cloned / CLI_PATH) != ORIGINAL_CLI_SHA256:
            raise _error("clone CLI changed unexpectedly")
        staged_manifest = _base_manifest(
            root_path,
            cloned,
            selected_generation,
            {
                **source_info,
                "CFBundleIdentifier": PRIVATE_BUNDLE_ID,
                "CFBundleShortVersionString": VERSION,
                "CFBundleVersion": BUILD,
            },
            details,
            ORIGINAL_CLI_SHA256,
            _signature_fingerprint(cloned),
        )
        # The digest is path-independent, while the launch path is fixed at
        # the publication location.
        staged_manifest["app_path"] = str(destination)
        staged_manifest_path = staging / "manifest.json"
        _write_manifest(staged_manifest_path, staged_manifest)
        _private_directory(root_path / "state" / "zcode-private" / "user-data", create=True)
        _private_directory(root_path / "state" / "zcode-private" / "session", create=True)
        # Re-check the source immediately before publication as required by the
        # trust boundary.  This deliberately repeats signature verification.
        source_info_final, source_asar_final, source_cli_final, source_signature_final, source_tree_final = _verified_source_info(source)
        if (
            source_info_final != source_info
            or source_asar_final != source_asar_hash
            or source_cli_final != source_cli_hash
            or source_signature_final != source_signature
            or source_tree_final != source_tree_digest
        ):
            raise _error("source ZCode changed before publication")
        if destination.exists() or destination.is_symlink():
            _assert_owner(destination, "directory")
            _validate_bundle_tree(destination)
            backup = destination_root / ("backup-" + selected_generation + ".app")
            if backup.exists() or backup.is_symlink():
                raise _error("publication backup path already exists")
            os.replace(destination, backup)
        current_manifest = manifest_path(root_path)
        if current_manifest.exists() or current_manifest.is_symlink():
            _assert_owner(current_manifest, "file", mode=0o600)
            manifest_backup = destination_root / ("backup-" + selected_generation + ".manifest.json")
            if manifest_backup.exists() or manifest_backup.is_symlink():
                raise _error("manifest publication backup path already exists")
            os.replace(current_manifest, manifest_backup)
        os.replace(cloned, destination)
        published = True
        _write_manifest(current_manifest, staged_manifest)
        result = verify(root_path, selected_generation)
        return result
    except BaseException as error:
        if published:
            try:
                failed = destination_root / ("failed-" + selected_generation + ".app")
                if destination.exists() and not failed.exists():
                    os.replace(destination, failed)
            except OSError:
                pass
        if backup is not None and backup.exists() and not destination.exists():
            try:
                os.replace(backup, destination)
            except OSError:
                # Retain the backup for manual recovery and make the failure
                # explicit instead of silently accepting a missing app.
                pass
        current_manifest = manifest_path(root_path)
        if published and current_manifest.exists():
            try:
                failed_manifest = destination_root / ("failed-" + selected_generation + ".manifest.json")
                if not failed_manifest.exists():
                    os.replace(current_manifest, failed_manifest)
            except OSError:
                pass
        if manifest_backup is not None and manifest_backup.exists() and not current_manifest.exists():
            try:
                os.replace(manifest_backup, current_manifest)
            except OSError:
                pass
        if isinstance(error, ZcodePrivacyError):
            raise
        raise _error("private ZCode installation failed: " + type(error).__name__) from None
    finally:
        # Keep backups for recovery, but remove only the staging directory once
        # publication/rollback no longer needs it.
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "BUILD",
    "DEFAULT_SOURCE_APP",
    "PRIVATE_APP_NAME",
    "PRIVATE_BUNDLE_ID",
    "VERSION",
    "ZcodePrivacyError",
    "bundle_digest",
    "install",
    "launch_plan",
    "manifest_path",
    "patch_asar_payload",
    "patch_host_payload",
    "patch_main_payload",
    "private_app",
    "verify",
    "verify_asar_bytes",
]
