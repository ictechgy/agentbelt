"""R2 task registry reference model: trusted lifecycle, launch binding and lineage.

A deterministic state machine for the authority that the future agentbelt Endpoint
Security system extension (or its root service) must own. It creates the TaskState
and ProcessBinding inputs that R1's evaluate() consumes. Two adapters that do not
exist yet feed it, and this module authenticates neither:

* control peers, authenticated by the local transport (audit token + code signature);
* process and file events, produced by the ES client from kernel-reported identities.

Nothing here is an OS enforcement result, and no ES callback may block on this Python
model. It fixes semantics for a native port; see docs/design/task-registry.md.
"""
import collections
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase
import hashlib
import json
import os
import secrets
import stat
from typing import FrozenSet, Optional, Tuple

import task_policy as policy


SCHEMA = 'agentbelt.task-registry'
TASK_STATES = ('active', 'revoked', 'interrupted')
# Operations on another process. A task port (even read-only) lets the holder read or
# rewrite that process, so an enrolled process may only act on processes of its own task.
PROCESS_OPERATIONS = frozenset({'task_port', 'task_read', 'signal', 'suspend_resume'})
MAX_PROPOSALS_PER_SUPERVISOR = 16
MAX_TICKETS_PER_SUPERVISOR = 8
MAX_TASKS = 1024
MAX_PROCESSES = 65536
MAX_RETIRED = 65536
MAX_STATE_BYTES = 4 * 2**20
DOCUMENT_VERSION = 2
DOCUMENT_FIELDS = {'schema', 'version', 'boot_id', 'sequence', 'last_now_ns', 'tasks', 'bindings',
                   'quarantine', 'tickets', 'retired', 'records', 'dropped_records', 'dropped_requests',
                   'dropped_retired'}
TICKET_FIELDS = {'child', 'task_id', 'image', 'spawner', 'expires_at_ns', 'state'}
TICKET_STATES = ('pending', 'bound', 'denied', 'expired', 'revoked')
# Tickets kept (as revoked) across a restart: every child that is not running a bound
# image. A denied exec leaves its child alive before exec, so a retry must stay closed.
RESTORED_TICKET_STATES = ('pending', 'denied', 'expired', 'revoked')
RECORD_FIELDS = {'sequence', 'event', 'task_id', 'revision', 'allowed', 'reason', 'operations', 'target'}


class RegistryError(ValueError):
    """Rejected control call or state document; messages never interpolate inputs."""


def _require(condition, message):
    if not condition:
        raise RegistryError(message)


def _is_process(value):
    return type(value) is policy.ProcessIdentity


@dataclass(frozen=True)
class Signer:
    """Code-signing identity the transport verified for a peer (Team ID + signing ID)."""
    team_id: str
    signing_id: str

    def __post_init__(self):
        _require(policy._identifier(self.team_id) and policy._identifier(self.signing_id), 'invalid signer')


@dataclass(frozen=True)
class Peer:
    """Transport-authenticated caller. Never constructed from message contents."""
    process: policy.ProcessIdentity
    signer: Signer

    def __post_init__(self):
        _require(_is_process(self.process) and type(self.signer) is Signer, 'invalid peer')


@dataclass(frozen=True)
class ExecutableImage:
    """Executable reported by the ES adapter; digest stands for its code identity (cdhash)."""
    path: str = field(repr=False)
    digest: str

    def __post_init__(self):
        _require(policy._path(self.path) and policy._identifier(self.digest), 'invalid executable image')


@dataclass(frozen=True)
class RegistryConfig:
    """Operator-installed trust roots. Supervisors propose; only approvers widen authority."""
    supervisors: FrozenSet[Signer]
    approvers: FrozenSet[Signer]
    ticket_ttl_ns: int = 5 * 10**9
    max_pending_requests: int = 32
    max_records: int = 1024

    def __post_init__(self):
        for signers in (self.supervisors, self.approvers):
            _require(type(signers) is frozenset and signers
                     and all(type(signer) is Signer for signer in signers), 'invalid signer set')
        # Separation of duties: one binary must not both propose and approve authority.
        _require(not self.supervisors & self.approvers, 'supervisor and approver signers overlap')
        _require(all(policy._integer(value, 1) for value in
                     (self.ticket_ttl_ns, self.max_pending_requests, self.max_records)), 'invalid limits')


@dataclass(frozen=True)
class Outcome:
    """Answer for one event. route: enforced, not_enrolled (unrelated host process) or invalid."""
    route: str
    allowed: bool
    reason: str
    task_id: Optional[str] = None
    revision: Optional[int] = None
    cacheable: bool = field(default=False, init=False)

    @property
    def enforcement(self):
        return 'policy_only' if self.route == 'enforced' else 'none'


@dataclass(frozen=True)
class ProposalView:
    """What the approver confirms, read from the registry rather than from the supervisor."""
    digest: str
    contract: policy.TaskContract
    parent_task_id: Optional[str]
    proposer: policy.ProcessIdentity = field(repr=False)


@dataclass(frozen=True)
class AccessRequest:
    """Denied in-workspace access awaiting an operator decision; content comes from the event."""
    request_id: str
    task_id: str
    revision: int
    path: str = field(repr=False)
    operations: FrozenSet[str]


@dataclass(frozen=True)
class ActionRecord:
    """Minimal action log entry: no file content, absolute paths or process tokens."""
    sequence: int
    event: str
    task_id: Optional[str]
    revision: Optional[int]
    allowed: bool
    reason: str
    operations: Tuple[str, ...]
    target: str


@dataclass
class _Task:
    contract: policy.TaskContract
    parent_task_id: Optional[str]
    state: str
    owner: policy.ProcessIdentity


@dataclass(frozen=True)
class _Grant:
    revision: int
    rule: policy.PathRule
    expires_at_ns: int


@dataclass
class _Ticket:
    """Single-use launch permission for one exact, not-yet-exec'd supervisor child."""
    task_id: str
    image: ExecutableImage
    spawner: policy.ProcessIdentity
    expires_at_ns: int
    state: str  # pending, bound, denied, expired or revoked


NOT_ENROLLED = Outcome('not_enrolled', True, 'not_enrolled')
INVALID = Outcome('invalid', False, 'invalid_input')


def _proposal_digest(contract, parent_task_id, proposer):
    # The proposer is part of what is approved: ownership decides who may launch and revise.
    document = {'contract': policy.contract_to_dict(contract), 'parent_task_id': parent_task_id,
                'proposer': [proposer.pid, proposer.generation]}
    text = json.dumps(document, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _sensitive(path):
    return any(fnmatchcase(component.casefold(), pattern)
               for component in path.split('/') for pattern in policy.SENSITIVE_COMPONENTS)


def _rule_covered(parent_contract, rule):
    granting = parent_contract.allow + parent_contract.external
    return all(any(operation in parent_rule.operations and policy._covers(parent_rule, rule)
                   for parent_rule in granting) for operation in rule.operations)


class Registry:
    """Authoritative task lifecycle and process lineage for one boot session.

    Control calls raise RegistryError. Event calls never raise: they return an Outcome.
    Unrelated processes are routed as not_enrolled so a global ES client cannot block
    host applications through this model.

    Every bound or quarantined identity belongs to an exec chain (one live process and
    its earlier images). Only an exit of a tracked identity releases its chain. PID-only
    matching is used for narrowing actions alone (interrupting, revoking tickets).

    `persist` is the durable store's write-ahead hook. It receives to_document() whenever
    a launch ticket opens or an exec binds a process, before that call answers, and any
    exception it raises means "not saved". A restart restores the last saved document,
    so a process can only run bound if the store already knows about it. None (the
    default) disables write-ahead; the host then saves on its own schedule.

    With a hook, every save goes through it (checkpoint() for the host's periodic save):
    a second writer could replace a newer write-ahead document with an older snapshot.
    The hook runs inside the call that triggered it and must not call back into the
    registry (the native port holds its lock then). It should log why a save failed;
    the registry only reports that it did (state_not_saved).
    """

    def __init__(self, config, *, boot_id, now_ns, persist=None):
        _require(type(config) is RegistryConfig, 'invalid registry configuration')
        _require(policy._identifier(boot_id) and policy._integer(now_ns), 'invalid boot session or clock')
        _require(persist is None or callable(persist), 'invalid persist hook')
        self._config, self._boot_id, self._now, self._persist = config, boot_id, now_ns, persist
        self._sequence = self._request_counter = 0
        self._dropped_records = self._dropped_requests = self._dropped_retired = 0
        self._tasks, self._bindings, self._quarantine, self._chains = {}, {}, set(), {}
        self._proposals, self._tickets, self._grants, self._requests = {}, {}, {}, {}
        self._supervisor_processes, self._spawned = set(), {}
        # Exited enrolled identities of this boot (insertion-ordered set). pidversions are
        # unique per boot, so no unrelated process can ever name one of them as its parent.
        self._retired = {}
        self._records = collections.deque(maxlen=config.max_records)

    # ---- clock, peers and chains ----------------------------------------------------------

    def _advance(self, now_ns):
        """Accept a nondecreasing trusted monotonic time; report regression without moving."""
        if now_ns < self._now:
            return False
        self._now = now_ns
        return True

    def _control_clock(self, now_ns):
        _require(policy._integer(now_ns) and self._advance(now_ns), 'invalid or regressed clock')

    def _enrolled(self, process):
        return process in self._bindings or process in self._quarantine

    def _enrolled_lineage(self, process):
        return self._enrolled(process) or process in self._retired

    def _retire(self, identity):
        if len(self._retired) >= MAX_RETIRED:
            # Eviction reopens the missed-fork-after-parent-exit gap for the oldest entry.
            del self._retired[next(iter(self._retired))]
            self._dropped_retired += 1
        self._retired[identity] = None

    def _authorize(self, peer, signers, now_ns):
        # A signed binary run from inside a task (or lost lineage) is still that task.
        _require(type(peer) is Peer and peer.signer in signers and not self._enrolled(peer.process),
                 'peer not authorized')
        self._control_clock(now_ns)
        if peer.signer in self._config.supervisors:
            # Forks of an authenticated supervisor instance become launch candidates.
            self._supervisor_processes.add(peer.process)

    def _bind(self, process, task_id, chain):
        self._bindings[process] = task_id
        self._chains[process] = chain

    def _isolate(self, process, chain):
        self._quarantine.add(process)
        self._chains[process] = chain

    def _saved(self):
        """Write-ahead: hand the current state to the store; False when it was not saved."""
        if self._persist is None:
            return True
        try:
            self._persist(self.to_document())
        except Exception:
            # Any store failure (I/O, size, encoding) counts as unsaved; callers then deny.
            return False
        return True

    def _bind_saved(self, entries):
        """Bind (process, task_id, chain) entries only if the store accepts the new state.

        On failure the entries are put back exactly as they were, so a denied exec leaves
        no binding behind that the durable state does not have either. That also holds
        when the hook raises something that is not an Exception, which then propagates.
        """
        previous = [(process, self._bindings.get(process), self._chains.get(process)) for process, _, _ in entries]
        for process, task_id, chain in entries:
            self._bind(process, task_id, chain)
        saved = False
        try:
            saved = self._saved()
        finally:
            if not saved:
                self._unbind(previous)
        return saved

    def _unbind(self, previous):
        for process, task_id, chain in reversed(previous):
            if task_id is None:
                self._bindings.pop(process, None)
            else:
                self._bindings[process] = task_id
            if chain is None:
                self._chains.pop(process, None)
            else:
                self._chains[process] = chain

    def checkpoint(self):
        """The host's periodic save, through the same hook as write-ahead."""
        _require(self._persist is not None, 'registry has no persist hook')
        _require(self._saved(), 'registry state could not be saved')

    # ---- control plane: proposals and lifecycle -----------------------------------------

    def propose(self, peer, contract, *, parent_task_id=None, now_ns):
        """Supervisor submits a new task or next revision; nothing is active until confirmed."""
        self._authorize(peer, self._config.supervisors, now_ns)
        _require(type(contract) is policy.TaskContract, 'invalid contract')
        _require(parent_task_id is None or policy._identifier(parent_task_id), 'invalid parent task')
        self._check_proposal(contract, parent_task_id, peer.process)
        digest = _proposal_digest(contract, parent_task_id, peer.process)
        _require(digest not in self._proposals, 'duplicate proposal')
        mine = sum(1 for proposal in self._proposals.values() if proposal.proposer == peer.process)
        _require(mine < MAX_PROPOSALS_PER_SUPERVISOR, 'too many pending proposals')
        self._proposals[digest] = ProposalView(digest, contract, parent_task_id, peer.process)
        return digest

    def _check_proposal(self, contract, parent_task_id, proposer):
        """Validate against current state; returns the effective parent task ID."""
        existing = self._tasks.get(contract.task_id)
        if existing is None:
            self._prune_terminal_tasks()
            _require(contract.revision == 1 and len(self._tasks) < MAX_TASKS, 'invalid new task')
            parent_id = parent_task_id
        else:
            _require(existing.state == 'active' and existing.owner == proposer, 'task not revisable')
            _require(parent_task_id in (None, existing.parent_task_id), 'parent cannot change')
            _require(contract.revision == existing.contract.revision + 1, 'revision must advance by one')
            # A lower schema drops v2 rules and regains v1's runtime-exec exception.
            _require(contract.schema_version >= existing.contract.schema_version, 'schema cannot be lowered')
            parent_id = existing.parent_task_id
        if parent_id is not None:
            parent = self._tasks.get(parent_id)
            _require(parent is not None and parent.state == 'active' and parent.owner == proposer,
                     'parent task not available')
            _require(policy.is_attenuation(parent.contract, contract), 'child task exceeds parent')
        return parent_id

    def pending_proposals(self, peer):
        """Approver-only: the canonical content behind each digest it may confirm."""
        self._check_reader(peer)
        return tuple(self._proposals.values())

    def confirm(self, peer, digest, *, now_ns):
        """Operator approval of one exact proposal digest, revalidated against current state."""
        self._authorize(peer, self._config.approvers, now_ns)
        proposal = self._proposals.pop(digest, None) if type(digest) is str else None
        _require(proposal is not None, 'unknown proposal')
        contract = proposal.contract
        parent_id = self._check_proposal(contract, proposal.parent_task_id, proposal.proposer)
        existing = self._tasks.get(contract.task_id)
        if existing is None:
            self._tasks[contract.task_id] = _Task(contract, parent_id, 'active', proposal.proposer)
        else:
            existing.contract = contract
            # Descendant grants were checked against the old parent; drop them conservatively.
            self._drop_task_authority(self._with_descendants(contract.task_id))
            self._revoke_uncovered_children(contract.task_id)
        self._record_lifecycle(contract.task_id, 'confirmed')

    def reject_proposal(self, peer, digest, *, now_ns):
        self._authorize(peer, self._config.approvers, now_ns)
        _require(type(digest) is str and self._proposals.pop(digest, None) is not None, 'unknown proposal')

    def revoke(self, peer, task_id, *, now_ns):
        """Supervisor or approver ends a task and all descendant tasks. Narrowing only."""
        self._authorize(peer, self._config.supervisors | self._config.approvers, now_ns)
        _require(type(task_id) is str and task_id in self._tasks, 'unknown task')
        self._set_state(self._with_descendants(task_id), 'revoked')

    def _with_descendants(self, task_id):
        found, frontier = {task_id}, [task_id]
        while frontier:
            current = frontier.pop()
            children = {child_id for child_id, task in self._tasks.items()
                        if task.parent_task_id == current and child_id not in found}
            found |= children
            frontier.extend(children)
        return found

    def _ancestors(self, task_id):
        """The task and its ancestors, nearest first; cycle-safe for restored documents."""
        chain, current = [], task_id
        while current is not None and current in self._tasks and current not in chain:
            chain.append(current)
            current = self._tasks[current].parent_task_id
        return [self._tasks[item] for item in chain]

    def _set_state(self, task_ids, state):
        # Interruption never downgrades a revocation.
        for task_id in sorted(task_ids):
            task = self._tasks[task_id]
            if task.state != 'revoked' and task.state != state:
                task.state = state
                self._record_lifecycle(task_id, state)
        self._drop_task_authority(task_ids)

    def _drop_task_authority(self, task_ids):
        """Grants, requests and pending launches never outlive the revision they were made for."""
        for task_id in task_ids:
            self._grants.pop(task_id, None)
        self._requests = {key: request for key, request in self._requests.items()
                          if request.task_id not in task_ids}
        for ticket in self._tickets.values():
            if ticket.task_id in task_ids and ticket.state == 'pending':
                ticket.state = 'revoked'

    def _revoke_uncovered_children(self, parent_id):
        parent = self._tasks[parent_id]
        for child_id, child in sorted(self._tasks.items()):
            if (child.parent_task_id == parent_id and child.state == 'active'
                    and not policy.is_attenuation(parent.contract, child.contract)):
                self._set_state(self._with_descendants(child_id), 'revoked')

    def _prune_terminal_tasks(self):
        """Forget ended tasks nothing refers to, so the task table cannot fill up for good."""
        while len(self._tasks) >= MAX_TASKS:
            referenced = set(self._bindings.values()) | {task.parent_task_id for task in self._tasks.values()}
            referenced |= {ticket.task_id for ticket in self._tickets.values()}
            prunable = [task_id for task_id, task in sorted(self._tasks.items())
                        if task.state != 'active' and task_id not in referenced]
            if not prunable:
                return
            for task_id in prunable:
                del self._tasks[task_id]

    # ---- control plane: launches ---------------------------------------------------------

    def register_launch(self, peer, task_id, image, child, *, now_ns):
        """Open the launch ticket for one exact fork child of this supervisor instance.

        The child must have been reported by on_fork from this supervisor and must not
        have exec'd yet; the supervisor keeps it waiting until this call returns.
        """
        self._authorize(peer, self._config.supervisors, now_ns)
        task = self._tasks.get(task_id) if type(task_id) is str else None
        _require(task is not None and task.state == 'active' and task.owner == peer.process
                 and task.contract.valid_from_ns <= self._now < task.contract.expires_at_ns,
                 'task not launchable')
        _require(type(image) is ExecutableImage, 'invalid executable image')
        _require(_is_process(child) and self._spawned.get(child) == peer.process
                 and child not in self._tickets and not self._enrolled(child), 'child not launchable')
        mine = sum(1 for ticket in self._tickets.values()
                   if ticket.spawner == peer.process and ticket.state == 'pending')
        _require(mine < MAX_TICKETS_PER_SUPERVISOR, 'too many pending launches')
        # Saturates like the native port, so the document stays within restore's bounds.
        expires_at_ns = min(self._now + self._config.ticket_ttl_ns, policy.MAX_INTEGER)
        ticket = _Ticket(task_id, image, peer.process, expires_at_ns, 'pending')
        self._tickets[child] = ticket
        saved = False
        try:
            saved = self._saved()
        finally:
            if not saved:
                # Unsaved, a restart would forget the ticket and let the waiting child run unbound.
                ticket.state = 'revoked'
        _require(saved, 'registry state could not be saved')

    def ticket_status(self, peer, child, *, now_ns):
        """none, pending, bound, denied, expired or revoked for one child of this supervisor.

        Anything other than bound means the supervisor must kill that child and report
        the launch as unprotected.
        """
        self._authorize(peer, self._config.supervisors, now_ns)
        ticket = self._tickets.get(child) if _is_process(child) else None
        if ticket is None or ticket.spawner != peer.process:
            return 'none'
        if ticket.state == 'pending' and self._now >= ticket.expires_at_ns:
            return 'expired'
        return ticket.state

    # ---- control plane: access requests and grants -----------------------------------------

    def _check_reader(self, peer):
        _require(type(peer) is Peer and peer.signer in self._config.approvers
                 and not self._enrolled(peer.process), 'peer not authorized')

    def pending_requests(self, peer):
        self._check_reader(peer)
        return tuple(self._requests.values())

    def approve_request(self, peer, request_id, *, expires_at_ns, now_ns):
        """Grant exactly the denied path and operations until expiry, for the current revision."""
        self._authorize(peer, self._config.approvers, now_ns)
        request = self._requests.get(request_id) if type(request_id) is str else None
        _require(request is not None, 'unknown request')
        task = self._tasks[request.task_id]
        _require(task.state == 'active' and task.contract.revision == request.revision, 'task not active')
        _require(policy._integer(expires_at_ns) and self._now < expires_at_ns <= task.contract.expires_at_ns,
                 'invalid grant lifetime')
        rule = policy.PathRule(request.path, 'exact', request.operations)
        # A delegated task's grant may not exceed what every ancestor contract allows.
        ancestors = self._ancestors(request.task_id)[1:]
        _require(all(_rule_covered(ancestor.contract, rule) for ancestor in ancestors), 'grant exceeds parent task')
        live = self._live_grants(request.task_id, request.revision)
        _require(len(task.contract.allow) + len(live) < policy.MAX_RULES, 'too many grants')
        self._grants[request.task_id] = live + [_Grant(request.revision, rule, expires_at_ns)]
        del self._requests[request_id]
        self._record_lifecycle(request.task_id, 'grant_approved')

    def reject_request(self, peer, request_id, *, now_ns):
        self._authorize(peer, self._config.approvers, now_ns)
        _require(type(request_id) is str and self._requests.pop(request_id, None) is not None,
                 'unknown request')

    def _live_grants(self, task_id, revision):
        return [grant for grant in self._grants.get(task_id, ())
                if grant.revision == revision and self._now < grant.expires_at_ns]

    def _queue_request(self, task, path, operations):
        """Only in-workspace denials are grantable in contract v1; duplicates collapse."""
        contract = task.contract
        if not policy._within(path, contract.workspace):
            return
        pending = [request for request in self._requests.values() if request.task_id == contract.task_id]
        if any(request.path == path and request.operations == operations for request in pending):
            return
        if len(pending) >= self._config.max_pending_requests:
            self._dropped_requests += 1
            return
        self._request_counter += 1
        request_id = 'req-%d' % self._request_counter
        self._requests[request_id] = AccessRequest(request_id, contract.task_id, contract.revision,
                                                   path, operations)

    # ---- event plane -----------------------------------------------------------------------

    def on_fork(self, parent, child, *, now_ns):
        """NOTIFY fork: the child inherits the parent's task or quarantine, nothing else."""
        if not (_is_process(parent) and _is_process(child) and policy._integer(now_ns)):
            return
        self._advance(now_ns)
        if self._enrolled(child):
            return  # A late or duplicated fork never re-assigns an identity already judged.
        if parent in self._bindings:
            self._bind(child, self._bindings[parent], child)
        elif parent in self._quarantine:
            self._isolate(child, child)
        elif parent in self._supervisor_processes:
            self._spawned[child] = parent

    def on_exec(self, process, parent, target, image, *, now_ns, script=None):
        """AUTH exec. process is the pre-exec identity, target the identity after exec.

        `script` is the #! script path when the image is its interpreter. A bound process
        needs execute on both. Ticketed launches ignore it: the supervisor refuses scripts.
        """
        # exec keeps the PID. A differing target cannot come from the kernel, and binding it
        # would let that PID's later exit release the whole exec chain.
        if not (_is_process(process) and _is_process(target) and process.pid == target.pid
                and policy._integer(now_ns)):
            return INVALID
        parent = parent if _is_process(parent) else None
        clock_ok = self._advance(now_ns)
        if process in self._bindings:
            return self._exec_bound(process, target, image, clock_ok, script)
        ticket = self._tickets.get(process)
        if ticket is not None:
            return self._exec_launch(process, parent, target, image, ticket, clock_ok)
        outcome = self._route_unbound(process, parent, 'exec')
        if outcome is NOT_ENROLLED:
            self._spawned.pop(process, None)
        return outcome

    def _exec_launch(self, process, parent, target, image, ticket, clock_ok):
        """Bind inside the exec authorization, before the new image runs its first instruction."""
        task = self._tasks.get(ticket.task_id)
        reason = self._launch_refusal(parent, image, ticket, task, clock_ok)
        revision = task.contract.revision if task is not None else None
        if reason is None:
            ticket.state = 'denied'  # until the binding is saved; a restart drops it either way
            if self._bind_saved([(process, ticket.task_id, process), (target, ticket.task_id, process)]):
                ticket.state = 'bound'
                self._spawned.pop(process, None)
                outcome = Outcome('enforced', True, 'launch_bound', ticket.task_id, revision)
            else:
                outcome = Outcome('enforced', False, 'state_not_saved', ticket.task_id, revision)
        else:
            if ticket.state == 'pending':
                ticket.state = 'expired' if reason == 'launch_ticket_expired' else 'denied'
            outcome = Outcome('enforced', False, reason, ticket.task_id, revision)
        self._record('launch', outcome, frozenset(), '.')
        return outcome

    def _launch_refusal(self, parent, image, ticket, task, clock_ok):
        """Every failed check denies the exec: a ticketed child never runs unbound."""
        if ticket.state != 'pending':
            return 'launch_ticket_closed'
        if not clock_ok:
            return 'clock_regression'
        if self._now >= ticket.expires_at_ns:
            return 'launch_ticket_expired'
        if parent != ticket.spawner or image != ticket.image:
            return 'launch_ticket_mismatch'
        if (task is None or task.state != 'active'
                or not task.contract.valid_from_ns <= self._now < task.contract.expires_at_ns):
            return 'task_not_active'
        return None

    def _exec_bound(self, process, target, image, clock_ok, script):
        task_id = self._bindings[process]
        task = self._tasks[task_id]
        if type(image) is not ExecutableImage:
            outcome = Outcome('enforced', False, 'invalid_input', task_id, task.contract.revision)
            self._record('exec', outcome, frozenset({'execute'}), 'invalid')
            return outcome
        outcome, path = self._exec_decision(process, task_id, image.path, clock_ok), image.path
        if outcome.allowed and script is not None:
            # The interpreter is allowed; the script it will run needs execute as well.
            script_outcome = self._exec_decision(process, task_id, script, clock_ok)
            if not script_outcome.allowed:
                outcome, path = script_outcome, script
        if outcome.allowed and not self._bind_saved([(target, task_id, self._chains[process])]):
            outcome = Outcome('enforced', False, 'state_not_saved', task_id, task.contract.revision)
        self._record('exec', outcome, frozenset({'execute'}), self._target(task, path, outcome))
        return outcome

    def _exec_decision(self, process, task_id, path, clock_ok):
        task = self._tasks[task_id]
        outcome = self._decide(process, task_id, path, frozenset({'execute'}), clock_ok)
        if (outcome.reason == 'outside_allow_scope' and task.contract.schema_version == 1
                and self._outside_lineage_workspaces(task_id, path)):
            # Contract v1 cannot name runtime executables; v2 must allow them via `external`.
            outcome = replace(outcome, allowed=True, reason='exec_outside_contract')
        return outcome

    def _outside_lineage_workspaces(self, task_id, path):
        # A child must not execute parent-workspace files the parent's own rules refuse.
        return not any(policy._within(path, task.contract.workspace) for task in self._ancestors(task_id))

    def on_exit(self, process, *, now_ns):
        """NOTIFY exit: release the exiting identity's exec chain; narrow what it owned."""
        if not (_is_process(process) and policy._integer(now_ns)):
            return
        self._advance(now_ns)
        chain = self._chains.get(process)
        if chain is not None:
            self._release_chain(chain)
        self._tickets.pop(process, None)
        self._spawned.pop(process, None)
        self._supervisor_processes.discard(process)
        self._narrow_for_exit(process.pid)

    def _release_chain(self, chain):
        members = [identity for identity, owner in self._chains.items() if owner == chain]
        for identity in members:
            del self._chains[identity]
            self._retire(identity)
            self._bindings.pop(identity, None)
            self._quarantine.discard(identity)
            self._tickets.pop(identity, None)
            self._spawned.pop(identity, None)

    def _narrow_for_exit(self, pid):
        """PID-matched and therefore only ever narrowing: a stale exit cannot grant anything."""
        for ticket in self._tickets.values():
            if ticket.spawner.pid == pid and ticket.state == 'pending':
                ticket.state = 'revoked'
        self._proposals = {digest: proposal for digest, proposal in self._proposals.items()
                           if proposal.proposer.pid != pid}
        owned = {task_id for task_id, task in self._tasks.items()
                 if task.owner.pid == pid and task.state == 'active'}
        for task_id in sorted(owned):
            self._set_state(self._with_descendants(task_id), 'interrupted')

    def authorize_file(self, process, parent, path, operations, *, now_ns, subtree=False):
        """AUTH file access. Only bound processes are evaluated; the rest are routed.

        `subtree` marks operations that carry everything below `path` along (rename, clone
        or link of a possible directory). They are also denied when any deny rule sits at
        or below `path`: moving the directory would otherwise leave the rule behind.
        """
        if not (_is_process(process) and policy._integer(now_ns)):
            return INVALID
        parent = parent if _is_process(parent) else None
        clock_ok = self._advance(now_ns)
        task_id = self._bindings.get(process)
        if task_id is None:
            return self._route_unbound(process, parent, 'file')
        task = self._tasks[task_id]
        outcome = self._decide(process, task_id, path, operations, clock_ok)
        if outcome.allowed and subtree and any(policy._within(policy._ascii_fold(rule.path), policy._ascii_fold(path))
                                               for rule in task.contract.deny):
            outcome = replace(outcome, allowed=False, reason='explicit_deny_below')
        if outcome.reason == 'outside_allow_scope':
            self._queue_request(task, path, operations)
        valid_operations = operations if policy._operations(operations) else frozenset()
        self._record('file', outcome, valid_operations, self._target(task, path, outcome))
        return outcome

    def authorize_process(self, process, parent, target, operation, *, now_ns):
        """AUTH on another process: task port, read-only task port, signal, suspend/resume.

        An enrolled process may act on itself and on processes bound to the same task.
        Anything else (unrelated apps, the supervisor, other tasks, an unknown target)
        is denied, so a task port cannot carry the agent into an unconfined process.
        Unrelated callers are routed like file events. `target` may be None when the
        kernel names none; that is outside the task.
        """
        if not (_is_process(process) and type(operation) is str and operation in PROCESS_OPERATIONS
                and policy._integer(now_ns)):
            return INVALID
        parent = parent if _is_process(parent) else None
        target = target if _is_process(target) else None
        self._advance(now_ns)
        task_id = self._bindings.get(process)
        if task_id is None:
            return self._route_unbound(process, parent, 'process')
        revision = self._tasks[task_id].contract.revision
        if target == process or (target is not None and self._bindings.get(target) == task_id):
            outcome = Outcome('enforced', True, 'same_task', task_id, revision)
        else:
            outcome = Outcome('enforced', False, 'process_outside_task', task_id, revision)
        self._record('process', outcome, frozenset(), 'process')
        return outcome

    def _route_unbound(self, process, parent, event):
        if process in self._quarantine:
            outcome = Outcome('enforced', False, 'tracking_lost')
        elif parent is not None and self._enrolled_lineage(parent):
            # The fork notification was lost or reordered, possibly before the parent exited;
            # never guess which task owns it.
            self._isolate(process, process)
            outcome = Outcome('enforced', False, 'unattributed_descendant')
        else:
            return NOT_ENROLLED
        self._record(event, outcome, frozenset(), 'unattributed')
        return outcome

    def _decide(self, process, task_id, path, operations, clock_ok):
        task = self._tasks[task_id]
        revision = task.contract.revision
        if not clock_ok:
            return Outcome('enforced', False, 'clock_regression', task_id, revision)
        if task.state == 'interrupted':
            return Outcome('enforced', False, 'interrupted', task_id, revision)
        try:
            access = policy.FileAccess(process, path, operations)
        except policy.PolicyError:
            return Outcome('enforced', False, 'invalid_input', task_id, revision)
        state = policy.TaskState(task.contract, revoked=task.state == 'revoked')
        binding = policy.ProcessBinding(process, task_id, revision)
        decision = policy.evaluate(state, binding, access, now_ns=self._now)
        if decision.reason == 'outside_allow_scope' and self._granted(task, state, binding, access):
            return Outcome('enforced', True, 'granted', task_id, revision)
        return Outcome('enforced', decision.allowed, decision.reason, task_id, revision)

    def _granted(self, task, state, binding, access):
        """Re-run R1 with live exact grants appended, so sensitive/deny checks still win."""
        rules = tuple(grant.rule for grant in self._live_grants(task.contract.task_id, task.contract.revision))
        if not rules:
            return False
        try:
            widened = replace(state, contract=replace(task.contract, allow=task.contract.allow + rules))
        except policy.PolicyError:
            # approve_request bounds grants; an invalid combination denies rather than raises.
            return False
        return policy.evaluate(widened, binding, access, now_ns=self._now).allowed

    # ---- records ---------------------------------------------------------------------------

    def _target(self, task, path, outcome):
        if not policy._path(path):
            return 'invalid'
        if outcome.reason in ('sensitive_path', 'explicit_deny', 'explicit_deny_below') or _sensitive(path):
            return 'withheld'
        workspace = task.contract.workspace
        if path == workspace:
            return '.'
        return path[len(workspace) + 1:] if policy._within(path, workspace) else 'outside_workspace'

    def _record(self, event, outcome, operations, target):
        if len(self._records) == self._records.maxlen:
            self._dropped_records += 1
        self._sequence += 1
        self._records.append(ActionRecord(self._sequence, event, outcome.task_id, outcome.revision,
                                          outcome.allowed, outcome.reason, tuple(sorted(operations)), target))

    def _record_lifecycle(self, task_id, reason):
        task = self._tasks.get(task_id)
        revision = task.contract.revision if task is not None else None
        self._record('lifecycle', Outcome('enforced', True, reason, task_id, revision), frozenset(), '.')

    def records(self):
        return tuple(self._records)

    # ---- persistence -----------------------------------------------------------------------

    def to_document(self):
        """Durable snapshot. Proposals, grants and requests are deliberately absent.

        Tickets are kept so that a child waiting between register_launch and its exec is
        still known after a restart: its exec is then refused instead of running unbound.
        """
        return {
            'schema': SCHEMA, 'version': DOCUMENT_VERSION, 'boot_id': self._boot_id, 'sequence': self._sequence,
            'last_now_ns': self._now,
            'tasks': [{'contract': policy.contract_to_dict(task.contract), 'parent_task_id': task.parent_task_id,
                       'state': task.state, 'owner': _identity_to(task.owner)}
                      for task_id, task in sorted(self._tasks.items())],
            'bindings': [{'process': _identity_to(process), 'chain': _identity_to(self._chains[process]),
                          'task_id': task_id}
                         for process, task_id in sorted(self._bindings.items(), key=lambda item: _key(item[0]))],
            'quarantine': [{'process': _identity_to(process), 'chain': _identity_to(self._chains[process])}
                           for process in sorted(self._quarantine, key=_key)],
            'tickets': [{'child': _identity_to(child), 'task_id': ticket.task_id,
                         'image': [ticket.image.path, ticket.image.digest], 'spawner': _identity_to(ticket.spawner),
                         'expires_at_ns': ticket.expires_at_ns, 'state': ticket.state}
                        for child, ticket in sorted(self._tickets.items(), key=lambda item: _key(item[0]))],
            'retired': [_identity_to(process) for process in self._retired],
            'records': [_record_to_dict(record) for record in self._records],
            'dropped_records': self._dropped_records, 'dropped_requests': self._dropped_requests,
            'dropped_retired': self._dropped_retired,
        }

    @classmethod
    def restore(cls, document, config, *, boot_id, now_ns, persist=None):
        """Fail-closed restart: no task stays active and no lineage is trusted as current.

        Same boot: live processes may have forked or exec'd while nothing observed them,
        so every previously bound identity becomes quarantined, and every waiting launch
        ticket is revoked. New boot: those PIDs name unrelated processes, so bindings and
        tickets are discarded. Either way tasks are interrupted. With write-ahead
        (`persist`) the document holds every ticket and exec binding that was answered;
        fork bindings (NOTIFY, never waited for) can still be missing; see the design notes.
        """
        try:
            return cls._restore(document, config, boot_id, now_ns, persist)
        except (policy.PolicyError, TypeError):
            raise RegistryError('invalid registry document') from None

    @classmethod
    def _restore(cls, document, config, boot_id, now_ns, persist):
        registry = cls(config, boot_id=boot_id, now_ns=now_ns, persist=persist)
        _require(type(document) is dict and document.keys() == DOCUMENT_FIELDS, 'invalid registry document')
        _require(document['schema'] == SCHEMA and type(document['version']) is int
                 and document['version'] == DOCUMENT_VERSION, 'unsupported registry document')
        _require(policy._identifier(document['boot_id']) and policy._integer(document['last_now_ns'])
                 and policy._integer(document['sequence']), 'invalid registry document')
        same_boot = document['boot_id'] == boot_id
        _require(not same_boot or now_ns >= document['last_now_ns'], 'clock regression across restart')
        registry._restore_tasks(document['tasks'])
        registry._restore_processes(document['bindings'], document['quarantine'], same_boot)
        registry._restore_tickets(document['tickets'], same_boot)
        registry._restore_retired(document['retired'], same_boot)
        registry._restore_records(document)
        registry._record('lifecycle', Outcome('enforced', True, 'registry_restored'), frozenset(), '.')
        return registry

    def _restore_tasks(self, items):
        _require(type(items) is list and len(items) <= MAX_TASKS, 'invalid task list')
        for item in items:
            _require(type(item) is dict and item.keys() == {'contract', 'parent_task_id', 'state', 'owner'},
                     'invalid task entry')
            contract = policy.contract_from_dict(item['contract'])
            parent_id, state = item['parent_task_id'], item['state']
            _require(contract.task_id not in self._tasks and type(state) is str and state in TASK_STATES
                     and (parent_id is None or policy._identifier(parent_id)), 'invalid task entry')
            restored_state = 'revoked' if state == 'revoked' else 'interrupted'
            self._tasks[contract.task_id] = _Task(contract, parent_id, restored_state,
                                                  _identity_from(item['owner']))
        _require(all(task.parent_task_id is None or task.parent_task_id in self._tasks
                     for task in self._tasks.values()), 'unknown parent task')

    def _restore_processes(self, bindings, quarantine, same_boot):
        _require(type(bindings) is list and type(quarantine) is list
                 and len(bindings) + len(quarantine) <= MAX_PROCESSES, 'invalid process list')
        entries = []
        for item in bindings:
            _require(type(item) is dict and item.keys() == {'process', 'chain', 'task_id'}
                     and type(item['task_id']) is str and item['task_id'] in self._tasks, 'invalid binding entry')
            entries.append(item)
        for item in quarantine:
            _require(type(item) is dict and item.keys() == {'process', 'chain'}, 'invalid quarantine entry')
            entries.append(item)
        identities = [(_identity_from(item['process']), _identity_from(item['chain'])) for item in entries]
        if same_boot:
            for process, chain in identities:
                self._isolate(process, chain)

    def _restore_tickets(self, items, same_boot):
        """Keep every ticket but bound ones, revoked: each refuses its child's exec from now on.

        A bound ticket is dropped: its child runs a bound image (quarantined now), and
        ticket_status must not report a launch as bound once the registry lost track of it.
        """
        _require(type(items) is list and len(items) <= MAX_PROCESSES, 'invalid ticket list')
        tickets, seen = {}, set()
        for item in items:
            _require(type(item) is dict and item.keys() == TICKET_FIELDS and type(item['task_id']) is str
                     and item['task_id'] in self._tasks and type(item['state']) is str
                     and item['state'] in TICKET_STATES and policy._integer(item['expires_at_ns'])
                     and type(item['image']) is list and len(item['image']) == 2
                     and all(type(value) is str for value in item['image']), 'invalid ticket entry')
            child = _identity_from(item['child'])
            _require(child not in seen, 'invalid ticket entry')
            seen.add(child)
            ticket = _Ticket(item['task_id'], ExecutableImage(*item['image']), _identity_from(item['spawner']),
                             item['expires_at_ns'], 'revoked')
            if item['state'] in RESTORED_TICKET_STATES:
                tickets[child] = ticket
        if same_boot:
            self._tickets.update(tickets)

    def _restore_retired(self, items, same_boot):
        _require(type(items) is list and len(items) <= MAX_RETIRED, 'invalid retired list')
        identities = [_identity_from(item) for item in items]
        if same_boot:
            for identity in identities:
                self._retire(identity)

    def _restore_records(self, document):
        items = document['records']
        _require(type(items) is list and len(items) <= self._config.max_records, 'invalid record list')
        self._records.extend(_record_from_dict(item) for item in items)
        for key in ('dropped_records', 'dropped_requests', 'dropped_retired'):
            _require(policy._integer(document[key]), 'invalid counter')
        self._dropped_records = document['dropped_records']
        self._dropped_requests = document['dropped_requests']
        self._dropped_retired = document['dropped_retired']
        self._sequence = document['sequence']


def _key(process):
    return process.pid, process.generation


def _identity_to(process):
    return [process.pid, process.generation]


def _identity_from(value):
    _require(type(value) is list and len(value) == 2, 'invalid process identity')
    return policy.ProcessIdentity(value[0], value[1])


def _record_to_dict(record):
    return {'sequence': record.sequence, 'event': record.event, 'task_id': record.task_id,
            'revision': record.revision, 'allowed': record.allowed, 'reason': record.reason,
            'operations': list(record.operations), 'target': record.target}


def _record_from_dict(item):
    _require(type(item) is dict and item.keys() == RECORD_FIELDS, 'invalid record entry')
    operations = item['operations']
    _require(type(operations) is list and all(type(op) is str and op in policy.OPERATIONS for op in operations)
             and policy._integer(item['sequence']) and type(item['allowed']) is bool
             and all(type(item[key]) is str for key in ('event', 'reason', 'target'))
             and (item['task_id'] is None or policy._identifier(item['task_id']))
             and (item['revision'] is None or policy._integer(item['revision'], 1)), 'invalid record entry')
    return ActionRecord(item['sequence'], item['event'], item['task_id'], item['revision'],
                        item['allowed'], item['reason'], tuple(operations), item['target'])


# ---- private state file ---------------------------------------------------------------------

def _open_store_directory(path):
    """Hold the parent directory; it must be ours and not writable by group or others."""
    _require(policy._path(path) and path != '/', 'invalid state path')
    directory, name = os.path.split(path)
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise RegistryError('state directory unavailable') from None
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        os.close(descriptor)
        raise RegistryError('state directory is not private')
    return descriptor, name


def save_registry(path, registry):
    """Save a registry that has no persist hook; one with a hook saves through checkpoint()."""
    _require(type(registry) is Registry, 'invalid registry')
    _require(registry._persist is None, 'registry saves through its persist hook')
    save_document(path, registry.to_document())


def save_document(path, document):
    """Atomically replace the state file through a held directory descriptor.

    This is what a persist hook calls: it takes the document it was handed and never
    reads the registry again.
    """
    try:
        data = json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (TypeError, ValueError):
        raise RegistryError('invalid registry document') from None
    _require(len(data) <= MAX_STATE_BYTES, 'registry state too large')
    directory, name = _open_store_directory(path)
    temporary = '.%s.%s.tmp' % (name, secrets.token_hex(8))
    try:
        _write_new_file(directory, temporary, data)
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError:
        _discard(directory, temporary)
        raise RegistryError('registry state could not be saved') from None
    finally:
        os.close(directory)


def _write_new_file(directory, name, data):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _discard(directory, name):
    try:
        os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass  # The failure happened before the temporary file existed.


def load_registry(path, config, *, boot_id, now_ns, persist=None):
    """Read a private, single-link, regular state file and restore it fail-closed."""
    directory, name = _open_store_directory(path)
    try:
        data = _read_private_file(directory, name)
    except OSError:
        raise RegistryError('registry state could not be read') from None
    finally:
        os.close(directory)
    try:
        document = json.loads(data.decode('utf-8'), object_pairs_hook=policy._unique_object,
                              parse_constant=policy._reject_constant)
    except (ValueError, RecursionError):
        raise RegistryError('invalid registry state encoding') from None
    return Registry.restore(document, config, boot_id=boot_id, now_ns=now_ns, persist=persist)


def _read_private_file(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_STATE_BYTES,
                 'registry state file is not private')
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, MAX_STATE_BYTES + 1 - size)
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= MAX_STATE_BYTES, 'registry state too large')
    finally:
        os.close(descriptor)
