"""R1 task-scoped policy prototype, deliberately disconnected from launchers and ES.

This module performs no I/O, process discovery, clock reads or OS enforcement.
The future trusted supervisor must supply the current state, authenticated process
binding, OS-observed access and monotonic time. A caller able to invent those inputs
is outside this module's trust boundary. Paths are lexical, not verified OS objects.
"""
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import json
import re
from typing import FrozenSet, Optional, Tuple


OPERATIONS = frozenset({'read', 'write', 'execute'})
# APFS firmlink alias of the whole user data volume. A rule on it (or on an ancestor such as
# /System) would grant every user file under a second spelling, so rules may not touch it.
DATA_VOLUME = '/System/Volumes/Data'
MAX_RULES = 128
# Upper bound on the `names` of one name-scoped exception (schema 3).
MAX_EXCEPTION_NAMES = 8
MAX_JSON_BYTES = 65536
MAX_INTEGER = 2**63 - 1
# Conservative R1 exclusions. Only schema-3 `exceptions` lift these names, and only where
# allow/external already grant the access; no other grant bypasses them.
# This does not discover secrets stored under innocuous names or through aliases.
SENSITIVE_COMPONENTS = (
    '.env*', '*.env', '*.env.*', '*.pem', '*.key', '*.p12', '*.pfx', '*.keystore',
    'id_rsa*', 'id_ed25519*', 'auth.json', 'credentials', 'credentials.*',
    'secrets', 'secrets.*', '.ssh', '.aws', '.azure', '.kube', '.gnupg',
    '.npmrc', '.netrc', '.pypirc', '*.sqlite', '*.sqlite3', '*.db', '*.dump',
    '.git', '.agents', '.zcode', 'zcode.json',
)


class PolicyError(ValueError):
    """Invalid contract/event; messages never interpolate the supplied values."""


def _require(condition, message):
    if not condition:
        raise PolicyError(message)


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INTEGER


def _identifier(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', value) is not None


def _path(value):
    """Require a canonical *spelling* without consulting the real filesystem."""
    if type(value) is not str:
        return False
    try:
        if len(value.encode('utf-8')) > 4096:
            return False
    except UnicodeEncodeError:
        return False
    if not value.startswith('/') or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    return value == '/' or all(part not in ('', '.', '..') for part in value[1:].split('/'))


def _within(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def _ascii_fold(path):
    """Fold A-Z only, so denials match on case-insensitive APFS (`.git/HOOKS`).

    ASCII only: it can only widen a denial, and it is byte-identical in the Swift port,
    where full Unicode folding differs from str.casefold. Non-ASCII case variants depend on
    how ES spells the path, an R3 measurement.
    """
    return path.translate(_ASCII_LOWER)


def _data_volume_overlap(path, inside_only=False):
    """Case-insensitive: APFS resolves /system/volumes/data to the same firmlink."""
    folded, volume = path.casefold(), DATA_VOLUME.casefold()
    return _within(folded, volume) or (not inside_only and _within(volume, folded))


def _operations(value):
    return (type(value) is frozenset and bool(value)
            and all(type(operation) is str for operation in value) and value <= OPERATIONS)


@dataclass(frozen=True)
class PathRule:
    path: str = field(repr=False)
    scope: str
    operations: FrozenSet[str]
    # Schema 3, exceptions only: the sensitive names a tree exception may lift below its
    # root (name-scoped). None is an ordinary rule.
    names: Optional[FrozenSet[str]] = None

    def __post_init__(self):
        _require(_path(self.path), 'invalid rule path')
        _require(type(self.scope) is str and self.scope in ('exact', 'tree'), 'invalid rule scope')
        _require(_operations(self.operations), 'invalid rule operations')
        if self.names is not None:
            _require(type(self.names) is frozenset and 0 < len(self.names) <= MAX_EXCEPTION_NAMES
                     and all(type(name) is str for name in self.names), 'invalid exception names')
            _require(self.scope == 'tree', 'names only on tree exceptions')
            # A literal component compared with casefolded ones, so it must be printable ASCII in
            # lower case: str.casefold and Foundation's folding differ on non-ASCII, and any other
            # spelling could never be lifted.
            _require(all(_literal_name(name) for name in self.names),
                     'exception name is not a lowercase ASCII component')
            _require(all(_sensitive_name(name) for name in self.names), 'exception name is not sensitive')

    def matches(self, path):
        return path == self.path if self.scope == 'exact' else _within(path, self.path)

    def lifts(self, path):
        """`matches` for an exception: whether it lifts the sensitive-name ban on `path`.

        A name-scoped exception lifts only the sensitive components below its root that
        casefold to one of its names; any other sensitive name keeps the path denied. Its
        root holds no sensitive component (TaskContract), so every sensitive component of
        a matching path lies strictly below the root.
        """
        if not self.matches(path):
            return False
        if self.names is None:
            return True
        below = path[len(self.path.rstrip('/')) + 1:].split('/') if path != self.path else []
        return all(component.casefold() in self.names for component in below if _sensitive_name(component))

    def denies(self, path):
        """`matches` for a deny rule: ASCII case-insensitive, so a case variant cannot slip past it."""
        path, root = _ascii_fold(path), _ascii_fold(self.path)
        return path == root if self.scope == 'exact' else _within(path, root)


@dataclass(frozen=True)
class TaskContract:
    schema_version: int
    task_id: str
    revision: int
    workspace: str = field(repr=False)
    valid_from_ns: int
    expires_at_ns: int
    allow: Tuple[PathRule, ...]
    deny: Tuple[PathRule, ...]
    # Schema 2: operator-approved access outside the workspace (runtime trees, the agent's
    # isolated state). Never the whole filesystem; sensitive names and denials still win.
    external: Tuple[PathRule, ...] = ()
    # Schema 3: approver-visible exceptions to the sensitive-name exclusion, for example
    # a trust store (*.pem), the agent's own credentials in its isolated home, or the
    # workspace .git. They only lift the name ban where allow/external already grant the
    # operations; they never widen path grants, never allow execute, and denials still win.
    exceptions: Tuple[PathRule, ...] = ()

    def __post_init__(self):
        _require(type(self.schema_version) is int and self.schema_version in (1, 2, 3), 'unsupported schema version')
        _require(_identifier(self.task_id), 'invalid task identifier')
        _require(_integer(self.revision, 1), 'invalid policy revision')
        _require(_path(self.workspace) and self.workspace != '/' and not _data_volume_overlap(self.workspace, inside_only=True),
                 'invalid workspace')
        _require(_integer(self.valid_from_ns) and _integer(self.expires_at_ns)
                 and self.valid_from_ns < self.expires_at_ns, 'invalid policy lifetime')
        for rules in (self.allow, self.deny, self.external, self.exceptions):
            _require(type(rules) is tuple and len(rules) <= MAX_RULES
                     and all(type(rule) is PathRule for rule in rules), 'invalid policy rules')
        _require(self.schema_version >= 2 or not self.external, 'external rules need schema 2')
        _require(self.schema_version == 3 or not self.exceptions, 'exceptions need schema 3')
        _require(all(rule.names is None for rule in self.allow + self.deny + self.external),
                 'names only on tree exceptions')
        _require(all(rule.path != '/' for rule in self.external), 'external rule covers the filesystem root')
        _require(not any(_data_volume_overlap(rule.path) for rule in self.allow + self.external),
                 'rule covers the data volume alias')
        _require(all(_within(rule.path, self.workspace) for rule in self.allow),
                 'allow rule outside workspace')
        granting = self.allow + self.external
        for exception in self.exceptions:
            _require(exception.operations <= {'read', 'write'}, 'exception grants execute')
            _require(exception.path != '/' and not _data_volume_overlap(exception.path),
                     'rule covers the data volume alias')
            if exception.names is None:
                # Rooted at the sensitive name, so an exception never lifts names below an ordinary directory.
                _require(_sensitive_name(exception.path.rsplit('/', 1)[-1]), 'exception not rooted at a sensitive name')
            else:
                # Name-scoped: an ordinary root (a package cache) whose entries are not known in
                # advance. Its names are lifted strictly below it, so the root itself stays clean.
                _require(not _sensitive_name(exception.path), 'scoped exception path is sensitive')
            _require(all(any(operation in rule.operations and _covers(rule, exception) for rule in granting)
                         for operation in exception.operations), 'exception outside granted scope')


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    # Opaque, trusted execution-instance token; never populated from child metadata.
    # R2 must obtain boot/start/exec distinctions from the actual platform adapter.
    generation: str = field(repr=False)

    def __post_init__(self):
        _require(type(self.pid) is int and 0 < self.pid <= 2**31 - 1, 'invalid process identifier')
        _require(_identifier(self.generation), 'invalid process generation')


@dataclass(frozen=True)
class ProcessBinding:
    process: ProcessIdentity
    task_id: str
    revision: int

    def __post_init__(self):
        _require(type(self.process) is ProcessIdentity, 'invalid bound process')
        _require(_identifier(self.task_id), 'invalid bound task')
        _require(_integer(self.revision, 1), 'invalid bound revision')


@dataclass(frozen=True)
class TaskState:
    """Current authoritative supervisor snapshot, not a child-submitted document."""
    contract: TaskContract
    revoked: bool = False

    def __post_init__(self):
        _require(type(self.contract) is TaskContract, 'invalid task contract')
        _require(type(self.revoked) is bool, 'invalid revocation state')


@dataclass(frozen=True)
class FileAccess:
    process: ProcessIdentity
    path: str = field(repr=False)
    operations: FrozenSet[str]
    claimed_task_id: Optional[str] = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        _require(type(self.process) is ProcessIdentity, 'invalid requesting process')
        _require(_path(self.path), 'invalid access path')
        _require(_operations(self.operations), 'invalid access operations')
        _require(self.claimed_task_id is None or _identifier(self.claimed_task_id), 'invalid claimed task')


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    revision: Optional[int]
    cacheable: bool = field(default=False, init=False)
    enforcement: str = field(default='policy_only', init=False)


def evaluate(state, binding, access, *, now_ns):
    """Decide one synthetic/normalized file request using only explicit inputs.

    No allow result is cached. Every requested operation must be allowed, and any
    matching denial wins. Unknown/unbound inputs deny within this policy model;
    an ES adapter must separately route unrelated host processes, not globally
    apply this result to every system event.
    """
    if (type(state) is not TaskState or type(access) is not FileAccess
            or (binding is not None and type(binding) is not ProcessBinding)
            or not _integer(now_ns)):
        return Decision(False, 'invalid_input', None)
    contract = state.contract
    if binding is None:
        return Decision(False, 'unbound_process', contract.revision)
    if binding.process != access.process:
        return Decision(False, 'process_mismatch', contract.revision)
    if binding.task_id != contract.task_id:
        return Decision(False, 'task_mismatch', contract.revision)
    if binding.revision != contract.revision:
        return Decision(False, 'revision_mismatch', contract.revision)
    if state.revoked:
        return Decision(False, 'revoked', contract.revision)
    if now_ns < contract.valid_from_ns:
        return Decision(False, 'not_yet_valid', contract.revision)
    if now_ns >= contract.expires_at_ns:
        return Decision(False, 'expired', contract.revision)
    excepted = False
    if _sensitive_name(access.path):
        # Every requested operation must be covered by a schema-3 exception for this path.
        excepted = all(any(operation in rule.operations and rule.lifts(access.path) for rule in contract.exceptions)
                       for operation in access.operations)
        if not excepted:
            return Decision(False, 'sensitive_path', contract.revision)
    if any(rule.denies(access.path) and rule.operations & access.operations for rule in contract.deny):
        return Decision(False, 'explicit_deny', contract.revision)
    granting = contract.allow + contract.external
    if not all(any(operation in rule.operations and rule.matches(access.path) for rule in granting)
               for operation in access.operations):
        return Decision(False, 'outside_allow_scope', contract.revision)
    return Decision(True, 'allowed_by_exception' if excepted else 'allowed', contract.revision)


def _sensitive_name(path):
    return any(fnmatchcase(component.casefold(), pattern)
               for component in path.split('/') for pattern in SENSITIVE_COMPONENTS)


def _literal_name(name):
    """Printable ASCII (0x21-0x7E) in lower case, without '/' or the pattern '*'."""
    return (all('!' <= char <= '~' for char in name) and '/' not in name and '*' not in name
            and name == _ascii_fold(name))


def _covers(outer, inner):
    """Conservative containment of literal exact/tree path scopes."""
    if outer.scope == 'exact':
        return inner.scope == 'exact' and inner.path == outer.path
    return _within(inner.path, outer.path)


def _names_cover(outer, inner):
    """Conservative: an unscoped exception covers only unscoped ones, a scoped one only
    scoped ones whose names it includes."""
    if outer.names is None or inner.names is None:
        return outer.names is None and inner.names is None
    return inner.names <= outer.names


def is_attenuation(parent, child):
    """Check static child-policy restriction, not delegation or parent liveness.

    Parent denials must be preserved (or widened), even if currently outside the
    child's allow scopes. Runtime parent revocation and authenticated delegation
    belong to the future supervisor, not this structural predicate.
    """
    if type(parent) is not TaskContract or type(child) is not TaskContract:
        return False
    # A v1 child would regain the v1 runtime-exec exception its v2 parent does not have.
    if child.schema_version < parent.schema_version:
        return False
    if (parent.task_id == child.task_id or not _within(child.workspace, parent.workspace)
            or child.valid_from_ns < parent.valid_from_ns or child.expires_at_ns > parent.expires_at_ns):
        return False
    parent_granting = parent.allow + parent.external
    for child_rule in child.allow + child.external:
        for operation in child_rule.operations:
            if not any(operation in parent_rule.operations and _covers(parent_rule, child_rule)
                       for parent_rule in parent_granting):
                return False
    # A child may not lift a sensitive name its parent keeps banned.
    for child_rule in child.exceptions:
        for operation in child_rule.operations:
            if not any(operation in parent_rule.operations and _covers(parent_rule, child_rule)
                       and _names_cover(parent_rule, child_rule) for parent_rule in parent.exceptions):
                return False
    for parent_rule in parent.deny:
        for operation in parent_rule.operations:
            if not any(operation in child_rule.operations and _covers(child_rule, parent_rule)
                       for child_rule in child.deny):
                return False
    return True


def _fields(value, expected):
    _require(type(value) is dict and value.keys() == expected, 'invalid document fields')


RULE_FIELDS = frozenset({'path', 'scope', 'operations'})


def _parse_rules(value, exceptions=False):
    _require(type(value) is list and len(value) <= MAX_RULES, 'invalid rule list')
    rules = []
    for item in value:
        # Only an exception may carry `names`; without it the rule keeps the v1 shape.
        _require(type(item) is dict and (item.keys() == RULE_FIELDS
                                         or (exceptions and item.keys() == RULE_FIELDS | {'names'})),
                 'invalid document fields')
        operations = item['operations']
        _require(type(operations) is list and 0 < len(operations) <= len(OPERATIONS)
                 and all(type(operation) is str and operation in OPERATIONS for operation in operations),
                 'invalid rule operations')
        _require(len(set(operations)) == len(operations), 'duplicate rule operation')
        names = item.get('names')
        if 'names' in item:
            _require(type(names) is list and 0 < len(names) <= MAX_EXCEPTION_NAMES
                     and all(type(name) is str for name in names), 'invalid exception names')
            _require(len(set(names)) == len(names), 'duplicate exception name')
            names = frozenset(names)
        rules.append(PathRule(item['path'], item['scope'], frozenset(operations), names))
    return tuple(rules)


V1_FIELDS = frozenset({'schema_version', 'task_id', 'revision', 'workspace', 'valid_from_ns', 'expires_at_ns',
                       'allow', 'deny'})
V2_FIELDS = V1_FIELDS | {'external'}
V3_FIELDS = V2_FIELDS | {'exceptions'}


def contract_from_dict(document):
    """Strict v1/v2/v3 document decoding. Loading a document does not authorize it."""
    version = (document.get('schema_version') if type(document) is dict
               and type(document.get('schema_version')) is int else None)
    _fields(document, V3_FIELDS if version == 3 else V2_FIELDS if version == 2 else V1_FIELDS)
    exceptions = _parse_rules(document['exceptions'], exceptions=True) if version == 3 else ()
    external = _parse_rules(document['external']) if version in (2, 3) else ()
    return TaskContract(document['schema_version'], document['task_id'], document['revision'],
                        document['workspace'], document['valid_from_ns'], document['expires_at_ns'],
                        _parse_rules(document['allow']), _parse_rules(document['deny']), external, exceptions)


def contract_to_dict(contract):
    """Plain v1 document, with stable operation ordering and detached containers."""
    _require(type(contract) is TaskContract, 'invalid task contract')

    def rules(items):
        return [dict({'path': item.path, 'scope': item.scope, 'operations': sorted(item.operations)},
                     **({} if item.names is None else {'names': sorted(item.names)})) for item in items]

    document = {'schema_version': contract.schema_version, 'task_id': contract.task_id,
                'revision': contract.revision, 'workspace': contract.workspace,
                'valid_from_ns': contract.valid_from_ns, 'expires_at_ns': contract.expires_at_ns,
                'allow': rules(contract.allow), 'deny': rules(contract.deny)}
    if contract.schema_version >= 2:
        document['external'] = rules(contract.external)
    if contract.schema_version == 3:
        document['exceptions'] = rules(contract.exceptions)
    return document


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'duplicate document field')
        result[key] = value
    return result


def _reject_constant(unused):
    raise PolicyError('nonfinite document number')


def load_contract(text):
    """Decode bounded JSON; reject duplicates, nonfinite values and loose schemas."""
    _require(type(text) is str and len(text) <= MAX_JSON_BYTES, 'invalid document size or type')
    try:
        _require(len(text.encode('utf-8')) <= MAX_JSON_BYTES, 'invalid document size or encoding')
        document = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        # Includes UnicodeEncodeError/JSONDecodeError; do not echo their input fragments.
        raise PolicyError('invalid contract JSON') from None
    return contract_from_dict(document)
