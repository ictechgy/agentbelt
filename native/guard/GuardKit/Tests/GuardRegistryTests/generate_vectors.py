#!/usr/bin/python3
"""Differential vectors: drive the Python reference registry through random scenarios.

Every step records its inputs and the reference result (return value, error message,
event outcome, or the canonical JSON of the whole durable state). The Swift tests
replay the same steps against GuardRegistry and require identical results.
Synthetic identities and paths only; nothing on the host is opened except the modules.
"""
import argparse
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
import task_policy as policy  # noqa: E402
import task_registry as registry  # noqa: E402

SIGNERS = {
    'S': registry.Signer('TEAM000001', 'dev.agentbelt.supervisor'),
    'A': registry.Signer('TEAM000001', 'dev.agentbelt.approver'),
    'O': registry.Signer('TEAM000002', 'com.example.other'),
}
WORKSPACES = ['/w/a', '/w/b', '/w/a/sub']
TASK_IDS = ['ta', 'tb', 'tc', 'td']
IMAGES = [('/opt/agent', 'cd-agent'), ('/opt/other', 'cd-other'), ('/w/a/bin/run', 'cd-run'),
          ('/w/a/src/tool', 'cd-tool'), ('/usr/bin/python3', 'cd-python')]
OPERATION_SETS = [['read'], ['write'], ['execute'], ['read', 'write'], ['network'], []]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def identity(pid, generation):
    return policy.ProcessIdentity(pid, str(generation))


def identity_json(process):
    return None if process is None else [process.pid, process.generation]


def paths_for(workspace):
    return [workspace, workspace + '/src/x', workspace + '/docs/y', workspace + '/private/z', workspace + '/.env',
            workspace + '/bin/run', workspace + '/README', workspace + '/SRC/x', workspace + '/src/café',
            workspace + '/src/café', workspace + '/src/Straße.env', workspace + '/ſecrets',
            '/etc/hosts', '/w/b/q', '/w/a/../b', 'relative', '/w/a//x', '/w/a/src/x\n', '/w/a/src/\U0001F600',
            '/usr/lib/libSystem.B.dylib', '/usr/bin/python3', '/state/ta/cache/x', '/state/ta/.ssh/key', '/opt/agent',
            workspace + '/private', '/System/Volumes/Data' + workspace + '/src/x', workspace + '/src/\u212a',
            workspace + '/.git/config', '/state/ta/.ssh/config',
            # ASCII case variants of deny roots: denials fold A-Z (APFS is case-insensitive).
            workspace + '/PRIVATE/z', workspace + '/Private', workspace + '/DOCS/Secret', workspace + '/docs/secret',
            workspace + '/.GIT/HOOKS/pre-commit', workspace + '/.git/hooks/pre-commit', '/W/a/src/x',
            # Name-scoped exceptions (package caches): only the listed names below the root.
            workspace + '/.build/checkouts/dep/.git/config', workspace + '/.build/checkouts/dep/.env']


class Scenario:
    def __init__(self, seed, steps):
        self.random = random.Random(seed)
        self.seed = seed
        self.steps_wanted = steps
        self.now = 100
        ttl = self.random.choice([5, 20, 1000])
        self.config_args = {'ticket_ttl_ns': ttl, 'max_pending_requests': self.random.choice([2, 32]),
                            'max_records': self.random.choice([6, 1024])}
        self.config = registry.RegistryConfig(supervisors=frozenset({SIGNERS['S']}),
                                              approvers=frozenset({SIGNERS['A']}), **self.config_args)
        # The durable store: the last document it accepted, and whether it currently fails.
        self.saved, self.store_failing = None, False
        self.boot, self.boots = 'boot-1', 1
        self.registry = registry.Registry(self.config, boot_id='boot-1', now_ns=self.now, persist=self.persist)
        self.supervisors = [identity(500, 1), identity(501, 1)]
        self.approver = identity(600, 1)
        self.processes = [identity(pid, generation) for pid in range(1000, 1008) for generation in (1, 2, 3)]
        self.digests, self.request_ids, self.children, self.contracts = [], [], [], {}
        self.owners, self.agents, self.proposed, self.agent_tasks = {}, [], {}, {}
        self.steps = []

    # ---- inputs -------------------------------------------------------------------------

    def pick(self, items):
        return self.random.choice(items)

    def clock(self):
        roll = self.random.random()
        if roll < 0.04:
            return max(0, self.now - self.random.randint(1, 3))  # regression, not stored
        self.now += self.random.choice([0, 1, 1, 2, 5, 30])
        return self.now

    def peer(self):
        roll = self.random.random()
        if roll < 0.45:
            return self.pick(self.supervisors), 'S'
        if roll < 0.85:
            return self.approver, 'A'
        if roll < 0.93:
            pool = self.agents or self.processes
            return self.pick(pool), self.pick(['S', 'A'])  # usually an enrolled process
        return identity(700, 1), 'O'

    def process(self, allow_none=True):
        if allow_none and self.random.random() < 0.03:
            return None
        if self.agents and self.random.random() < 0.6:
            return self.pick(self.agents)
        return self.pick(self.processes + self.children + self.supervisors)

    def contract(self, task_id):
        workspace = self.pick(WORKSPACES)
        revision = self.random.choice([1, 1, 1, 2, 3])
        existing = self.contracts.get(task_id)
        if existing is not None and self.random.random() < 0.7:
            workspace, revision = existing.workspace, existing.revision + 1
        menu = [(workspace, 'tree', ['read']), (workspace + '/src', 'tree', ['write']),
                (workspace + '/bin/run', 'exact', ['execute']), (workspace + '/docs', 'tree', ['read', 'write']),
                (workspace + '/.build', 'tree', ['read', 'write'])]
        allow = [rule for rule in menu if self.random.random() < 0.6]
        deny = [(workspace + '/private', 'tree', ['read', 'write', 'execute'])] if self.random.random() < 0.8 else []
        if self.random.random() < 0.2:
            deny.append(('/w', 'tree', ['write']))
        if self.random.random() < 0.4:
            # Mixed-case deny rules, and a deny below the .git tree exception.
            deny.append((workspace + '/docs/Secret', 'exact', ['read']))
            deny.append((workspace + '/.git/hooks', 'tree', ['write']))
            deny.append((workspace + '/.build/checkouts/dep/.git/hooks', 'tree', ['write']))
        valid_from = self.random.choice([0, 0, 0, max(0, self.now - 10), self.now + 3])
        expires = self.now + self.random.choice([4, 40, 400, 4000, 40000, 40000])
        document = {'schema_version': 1, 'task_id': task_id, 'revision': revision, 'workspace': workspace,
                    'valid_from_ns': valid_from, 'expires_at_ns': expires,
                    'allow': [{'path': p, 'scope': s, 'operations': o} for p, s, o in allow],
                    'deny': [{'path': p, 'scope': s, 'operations': o} for p, s, o in deny]}
        if self.random.random() < 0.4:
            menu = [('/usr', 'tree', ['execute', 'read']), ('/usr/bin/python3', 'exact', ['execute']),
                    ('/state/' + task_id, 'tree', ['read', 'write']), ('/opt', 'tree', ['read'])]
            document['schema_version'] = 2
            document['external'] = [{'path': p, 'scope': s, 'operations': o}
                                    for p, s, o in menu if self.random.random() < 0.6]
            if self.random.random() < 0.5:
                # Schema 3: exceptions that stay inside what allow/external grant.
                document['schema_version'] = 3
                candidates = []
                if any(rule[0] == workspace and 'read' in rule[2] for rule in allow):
                    candidates.append({'path': workspace + '/.git', 'scope': 'tree', 'operations': ['read']})
                    candidates.append({'path': workspace + '/.env', 'scope': 'exact', 'operations': ['read']})
                if any(rule[0] == workspace + '/docs' for rule in allow):
                    candidates.append({'path': workspace + '/docs/.git', 'scope': 'tree',
                                       'operations': ['read', 'write']})
                # Name-scoped: lift only the listed names below an ordinary cache root.
                if any(rule[0] == workspace + '/.build' for rule in allow):
                    candidates.append({'path': workspace + '/.build/checkouts', 'scope': 'tree',
                                       'operations': ['read', 'write'], 'names': ['.git']})
                elif any(rule[0] == workspace and 'read' in rule[2] for rule in allow):
                    candidates.append({'path': workspace + '/.build/checkouts', 'scope': 'tree',
                                       'operations': ['read'], 'names': ['.git']})
                if any(rule[0] == workspace + '/docs' for rule in allow):
                    candidates.append({'path': workspace + '/docs/deps', 'scope': 'tree',
                                       'operations': ['read', 'write'], 'names': ['.git', '.env']})
                if any(rule['path'] == '/state/' + task_id for rule in document['external']):
                    candidates.append({'path': '/state/' + task_id + '/.ssh', 'scope': 'tree',
                                       'operations': ['read', 'write']})
                document['exceptions'] = [rule for rule in candidates if self.random.random() < 0.7]
        return policy.contract_from_dict(document)

    def persist(self, document):
        if self.store_failing:
            raise OSError('synthetic store failure')
        self.saved = canonical(document)

    # ---- step recording -------------------------------------------------------------------

    def control(self, op, args, call, encode=lambda value: value):
        try:
            expect = {'ok': encode(call())}
        except registry.RegistryError as error:
            expect = {'error': str(error)}
        self.steps.append({'op': op, 'args': args, 'expect': expect})
        return expect

    def event(self, op, args, call):
        outcome = call()
        expect = None if outcome is None else {
            'route': outcome.route, 'allowed': outcome.allowed, 'reason': outcome.reason,
            'task_id': outcome.task_id, 'revision': outcome.revision}
        self.steps.append({'op': op, 'args': args, 'expect': expect})

    # ---- operations -----------------------------------------------------------------------

    def step_propose(self):
        process, signer = (self.pick(self.supervisors), 'S') if self.random.random() < 0.8 else self.peer()
        task_id = self.pick(TASK_IDS)
        if task_id in self.owners and self.random.random() < 0.7:
            process, signer = self.owners[task_id], 'S'
        contract = self.contract(task_id)
        parent = self.pick([None] * 6 + TASK_IDS)
        now = self.clock()
        args = {'peer': [identity_json(process), signer], 'contract': policy.contract_to_dict(contract),
                'parent': parent, 'now': now}
        result = self.control('propose', args, lambda: self.registry.propose(
            registry.Peer(process, SIGNERS[signer]), contract, parent_task_id=parent, now_ns=now))
        if 'ok' in result:
            self.digests.append(result['ok'])
            self.proposed[result['ok']] = (contract, process)

    def step_confirm(self, op='confirm'):
        process, signer = self.peer() if self.random.random() < 0.3 else (self.approver, 'A')
        digest = self.pick(self.digests) if self.digests and self.random.random() < 0.9 else 'f' * 64
        now = self.clock()
        method = self.registry.confirm if op == 'confirm' else self.registry.reject_proposal
        result = self.control(op, {'peer': [identity_json(process), signer], 'digest': digest, 'now': now},
                              lambda: method(registry.Peer(process, SIGNERS[signer]), digest, now_ns=now))
        if 'ok' in result and op == 'confirm' and digest in self.proposed:
            contract, owner = self.proposed[digest]
            self.contracts[contract.task_id] = contract
            self.owners.setdefault(contract.task_id, owner)

    def step_revoke(self):
        process, signer = self.peer()
        task_id = self.pick(TASK_IDS + ['missing'])
        now = self.clock()
        self.control('revoke', {'peer': [identity_json(process), signer], 'task': task_id, 'now': now},
                     lambda: self.registry.revoke(registry.Peer(process, SIGNERS[signer]), task_id, now_ns=now))

    def step_launch_flow(self):
        """Owner forks a child, opens its ticket and usually lets it exec the ticketed image."""
        if not self.owners:
            return self.step_propose()
        task_id = self.pick(sorted(self.owners))
        owner = self.owners[task_id]
        child = identity(self.random.randint(3000, 3999), self.random.randint(1, 3))
        now = self.clock()
        self.event('fork', {'parent': identity_json(owner), 'child': identity_json(child), 'now': now},
                   lambda: self.registry.on_fork(owner, child, now_ns=now))
        path, digest = IMAGES[0]
        now = self.clock()
        self.control('register_launch', {'peer': [identity_json(owner), 'S'], 'task': task_id,
                                         'image': [path, digest], 'child': identity_json(child), 'now': now},
                     lambda: self.registry.register_launch(registry.Peer(owner, SIGNERS['S']), task_id,
                                                           registry.ExecutableImage(path, digest), child, now_ns=now))
        image = IMAGES[0] if self.random.random() < 0.85 else IMAGES[1]
        parent = owner if self.random.random() < 0.9 else self.pick(self.supervisors)
        target = identity(child.pid, int(child.generation) + 10)
        now = self.clock()
        self.maybe_failing_store(lambda: self.event(
            'exec', {'process': identity_json(child), 'parent': identity_json(parent),
                     'target': identity_json(target), 'image': list(image), 'now': now},
            lambda: self.registry.on_exec(child, parent, target, registry.ExecutableImage(*image), now_ns=now)))
        exec_step = [step for step in self.steps if step['op'] == 'exec'][-1]
        if exec_step['expect']['reason'] == 'launch_bound':
            self.agents.extend([child, target])
            self.agent_tasks[target] = task_id

    def step_agent_fork(self):
        if not self.agents:
            return self.step_launch_flow()
        parent = self.pick(self.agents)
        child = identity(self.random.randint(4000, 4999), self.random.randint(1, 3))
        now = self.clock()
        if self.random.random() < 0.85:
            self.event('fork', {'parent': identity_json(parent), 'child': identity_json(child), 'now': now},
                       lambda: self.registry.on_fork(parent, child, now_ns=now))
        self.agents.append(child)  # also used without its fork event: a missed notification

    def step_grant_flow(self):
        """A denied in-workspace access, the approver's decision, then the cooperative retry."""
        if not self.agents or not self.contracts:
            return self.step_launch_flow()
        agent = self.pick(self.agents)
        workspace = self.pick(sorted(self.contracts.values(), key=lambda c: c.task_id)).workspace
        path = self.pick([workspace + '/README', workspace + '/src/x', workspace + '/notes/n', workspace + '/private/z'])
        operations = self.pick([['write'], ['read', 'write'], ['execute']])
        for unused in range(2):
            now = self.clock()
            self.event('file', {'process': identity_json(agent), 'parent': None, 'path': path,
                                'operations': operations, 'now': now},
                       lambda: self.registry.authorize_file(agent, None, path, frozenset(operations), now_ns=now))
            if unused == 0:
                peer = registry.Peer(self.approver, SIGNERS['A'])
                result = self.control('pending_requests', {'peer': [identity_json(self.approver), 'A']},
                                      lambda: self.registry.pending_requests(peer),
                                      lambda items: [{'request_id': r.request_id, 'task_id': r.task_id,
                                                      'revision': r.revision, 'path': r.path,
                                                      'operations': sorted(r.operations)} for r in items])
                for item in result.get('ok', [])[-1:]:
                    now = self.clock()
                    expires = now + self.random.choice([3, 500, 30000])
                    request_id = item['request_id']
                    self.control('approve_request', {'peer': [identity_json(self.approver), 'A'],
                                                     'request': request_id, 'expires': expires, 'now': now},
                                 lambda: self.registry.approve_request(peer, request_id, expires_at_ns=expires,
                                                                       now_ns=now))

    def step_subtree_flow(self):
        """Rename/clone of a directory in the agent's own workspace, above or beside deny rules."""
        known = [(agent, task) for agent, task in self.agent_tasks.items() if task in self.contracts]
        if not known:
            return self.step_launch_flow()
        agent, task_id = self.pick(sorted(known, key=lambda item: (item[0].pid, item[0].generation)))
        workspace = self.contracts[task_id].workspace
        path = self.pick([workspace, workspace + '/docs', workspace + '/src', workspace + '/private',
                          workspace + '/private/z', '/w', workspace + '/PRIVATE', workspace + '/Docs',
                          workspace + '/docs/.git', workspace + '/docs/.GIT', workspace + '/.build/checkouts/dep',
                          workspace + '/.build/checkouts/dep/.git'])
        operations = self.pick([['read'], ['write'], ['read', 'write']])
        now = self.clock()
        self.event('file', {'process': identity_json(agent), 'parent': None, 'path': path, 'operations': operations,
                            'subtree': True, 'now': now},
                   lambda: self.registry.authorize_file(agent, None, path, frozenset(operations), now_ns=now,
                                                        subtree=True))

    def step_exception_flow(self):
        """Sensitive names under a schema-3 task: lifted only by matching exceptions."""
        known = [(agent, task) for agent, task in self.agent_tasks.items() if task in self.contracts]
        if not known:
            return self.step_launch_flow()
        agent, task_id = self.pick(sorted(known, key=lambda item: (item[0].pid, item[0].generation)))
        workspace = self.contracts[task_id].workspace
        path = self.pick([workspace + '/.git/config', workspace + '/.git/HEAD', workspace + '/.env',
                          '/state/' + task_id + '/.ssh/config', '/state/' + task_id + '/.aws/credentials',
                          workspace + '/docs/.git/hooks/x', workspace + '/docs/.GIT/hooks/x',
                          workspace + '/docs/.git/HOOKS/x', workspace + '/DOCS/.git/objects/y',
                          workspace + '/docs/.git/objects/y', workspace + '/docs/Secret', workspace + '/docs/SECRET',
                          workspace + '/.ENV',
                          # Name-scoped exceptions: case variants of a listed name, the root's own
                          # .git (strictly below the root), other sensitive names and denials below.
                          workspace + '/.build/checkouts/dep/.git/config', workspace + '/.build/checkouts/dep/.GIT/HEAD',
                          workspace + '/.build/checkouts/dep/.env', workspace + '/.build/checkouts/.git',
                          workspace + '/.build/checkouts/dep/.git/.env', workspace + '/.build/checkouts/dep/src/x',
                          workspace + '/.build/checkouts/dep/.git/hooks/x', workspace + '/.build/checkouts/dep/.GIT/HOOKS/x',
                          workspace + '/.BUILD/checkouts/dep/.git/config', workspace + '/.build/.git/config',
                          workspace + '/docs/deps/a/.env', workspace + '/docs/deps/a/.git/.ENV',
                          workspace + '/docs/deps/a/.git/id_rsa', workspace + '/.build/checkouts/dep/\uab70.pem',
                          workspace + '/docs/deps/a/.git/\u13a0.env'])
        if any(rule.names for rule in self.contracts[task_id].exceptions) and self.random.random() < 0.6:
            # Name-scoped contracts are rare; aim at their boundary: listed vs. other names below.
            path = self.pick([workspace + '/.build/checkouts/dep/.git/config', workspace + '/.build/checkouts/dep/.env',
                              workspace + '/.build/checkouts/dep/.GIT/x.pem', workspace + '/.build/checkouts/.git',
                              workspace + '/.build/checkouts/dep/.git/.env', workspace + '/docs/deps/a/.env',
                              workspace + '/docs/deps/a/.git/id_rsa', workspace + '/docs/deps/.GIT/.Env',
                              # Cherokee: Python and Foundation casefold it differently.
                              workspace + '/.build/checkouts/dep/.git/\uab70.pem',
                              workspace + '/docs/deps/a/\uab70.env', workspace + '/docs/deps/a/.git/\u13a0.ENV'])
        operations = self.pick([['read'], ['write'], ['read', 'write']])
        now = self.clock()
        self.event('file', {'process': identity_json(agent), 'parent': None, 'path': path, 'operations': operations,
                            'subtree': False, 'now': now},
                   lambda: self.registry.authorize_file(agent, None, path, frozenset(operations), now_ns=now))

    def step_process(self):
        """Task port / signal / suspend from an agent or another process to any target."""
        process = self.pick(self.agents) if self.agents and self.random.random() < 0.7 else self.process()
        target = self.pick([None] + self.agents + self.processes + self.supervisors + self.children)
        operation = self.pick(['task_port', 'task_read', 'signal', 'suspend_resume', 'ptrace'])
        # A parent exercises the lineage path (missed fork -> unattributed_descendant).
        parent = self.process() if self.random.random() < 0.5 else None
        now = self.clock()
        args = {'process': identity_json(process), 'parent': identity_json(parent), 'target': identity_json(target),
                'operation': operation, 'now': now}
        self.event('process', args, lambda: self.registry.authorize_process(process, parent, target, operation,
                                                                            now_ns=now))

    def step_spawn(self):
        supervisor = self.pick(self.supervisors)
        child = identity(self.random.randint(2000, 2011), self.random.randint(1, 3))
        self.children.append(child)
        now = self.clock()
        self.event('fork', {'parent': identity_json(supervisor), 'child': identity_json(child), 'now': now},
                   lambda: self.registry.on_fork(supervisor, child, now_ns=now))

    def step_register(self):
        process, signer = (self.pick(self.supervisors), 'S') if self.random.random() < 0.85 else self.peer()
        child = self.pick(self.children) if self.children else identity(2000, 1)
        task_id = self.pick(TASK_IDS)
        path, digest = self.pick(IMAGES)
        now = self.clock()
        args = {'peer': [identity_json(process), signer], 'task': task_id, 'image': [path, digest],
                'child': identity_json(child), 'now': now}
        self.control('register_launch', args, lambda: self.registry.register_launch(
            registry.Peer(process, SIGNERS[signer]), task_id, registry.ExecutableImage(path, digest), child, now_ns=now))

    def step_ticket_status(self):
        supervisor = self.pick(self.supervisors)
        child = self.pick(self.children) if self.children else identity(2000, 1)
        now = self.clock()
        self.control('ticket_status', {'peer': [identity_json(supervisor), 'S'], 'child': identity_json(child),
                                       'now': now},
                     lambda: self.registry.ticket_status(registry.Peer(supervisor, SIGNERS['S']), child, now_ns=now))

    def step_exec(self):
        roll = self.random.random()
        if roll < 0.5 and self.children:
            process = self.pick(self.children)
            parent = self.pick(self.supervisors) if self.random.random() < 0.85 else self.process()
        else:
            process, parent = self.process(), self.process()
        target = None if process is None else identity(process.pid, int(process.generation) + 10)
        if target is not None and self.random.random() < 0.05:
            target = identity(process.pid + 1, int(process.generation) + 10)  # impossible PID change
        if target is not None and self.random.random() < 0.5:
            self.processes.append(target)
        image = self.pick(IMAGES) if self.random.random() < 0.95 else None
        now = self.clock()
        script = self.pick([None, None, None, '/w/a/bin/run', '/w/a/src/tool', '/tmp/x.sh', '/w/a/.env', '/w/a/../b'])
        args = {'process': identity_json(process), 'parent': identity_json(parent), 'target': identity_json(target),
                'image': None if image is None else list(image), 'script': script, 'now': now}
        self.maybe_failing_store(lambda: self.event('exec', args, lambda: self.registry.on_exec(
            process, parent, target, None if image is None else registry.ExecutableImage(*image), now_ns=now,
            script=script)))

    def step_agent_exec(self):
        """A launched agent execs another image; the store fails for about half the answers."""
        if not self.agent_tasks:
            return self.step_launch_flow()
        agent = self.pick(sorted(self.agent_tasks, key=lambda item: (item.pid, item.generation)))
        target = identity(agent.pid, int(agent.generation) + 10)
        image = self.pick(IMAGES)
        now = self.clock()
        args = {'process': identity_json(agent), 'parent': None, 'target': identity_json(target),
                'image': list(image), 'script': None, 'now': now}
        call = lambda: self.event('exec', args, lambda: self.registry.on_exec(
            agent, None, target, registry.ExecutableImage(*image), now_ns=now))
        if self.store_failing or self.random.random() < 0.5:
            return call()
        self.set_store_failing(True)
        call()
        self.set_store_failing(False)

    def step_fork(self):
        parent, child = self.process(), identity(self.random.randint(1000, 1011), self.random.randint(1, 9))
        self.processes.append(child)
        now = self.clock()
        self.event('fork', {'parent': identity_json(parent), 'child': identity_json(child), 'now': now},
                   lambda: self.registry.on_fork(parent, child, now_ns=now))

    def step_exit(self):
        process = self.process() if self.random.random() < 0.9 else self.pick(self.supervisors)
        now = self.clock()
        self.event('exit', {'process': identity_json(process), 'now': now},
                   lambda: self.registry.on_exit(process, now_ns=now))

    def step_file(self):
        process, parent = self.process(), self.process()
        workspace = self.pick(WORKSPACES)
        if self.contracts and self.random.random() < 0.7:
            workspace = self.pick(sorted(self.contracts.values(), key=lambda c: c.task_id)).workspace
        path = self.pick(paths_for(workspace))
        operations = self.pick(OPERATION_SETS)
        subtree = self.random.random() < 0.25
        now = self.clock()
        args = {'process': identity_json(process), 'parent': identity_json(parent), 'path': path,
                'operations': operations, 'subtree': subtree, 'now': now}
        self.event('file', args, lambda: self.registry.authorize_file(
            process, parent, path, frozenset(operations), now_ns=now, subtree=subtree))

    def step_pending(self):
        process, signer = (self.approver, 'A') if self.random.random() < 0.9 else self.peer()
        peer = registry.Peer(process, SIGNERS[signer])
        if self.random.random() < 0.5:
            result = self.control('pending_requests', {'peer': [identity_json(process), signer]},
                                  lambda: self.registry.pending_requests(peer),
                                  lambda items: [{'request_id': r.request_id, 'task_id': r.task_id,
                                                  'revision': r.revision, 'path': r.path,
                                                  'operations': sorted(r.operations)} for r in items])
            if 'ok' in result:
                self.request_ids.extend(item['request_id'] for item in result['ok'])
        else:
            self.control('pending_proposals', {'peer': [identity_json(process), signer]},
                         lambda: self.registry.pending_proposals(peer),
                         lambda items: [{'digest': v.digest, 'contract': policy.contract_to_dict(v.contract),
                                         'parent_task_id': v.parent_task_id,
                                         'proposer': identity_json(v.proposer)} for v in items])

    def step_approve(self, op='approve_request'):
        process, signer = (self.approver, 'A') if self.random.random() < 0.85 else self.peer()
        request_id = self.pick(self.request_ids) if self.request_ids and self.random.random() < 0.9 else 'req-999'
        now = self.clock()
        expires = now + self.random.choice([-1, 0, 5, 50, 5000])
        peer = registry.Peer(process, SIGNERS[signer])
        if op == 'approve_request':
            self.control(op, {'peer': [identity_json(process), signer], 'request': request_id,
                              'expires': expires, 'now': now},
                         lambda: self.registry.approve_request(peer, request_id, expires_at_ns=expires, now_ns=now))
        else:
            self.control(op, {'peer': [identity_json(process), signer], 'request': request_id, 'now': now},
                         lambda: self.registry.reject_request(peer, request_id, now_ns=now))

    def step_snapshot(self):
        self.steps.append({'op': 'snapshot', 'args': {}, 'expect': canonical(self.registry.to_document())})

    def step_restore(self):
        boot = self.pick(['boot-1', 'boot-1', 'boot-2'])
        now = self.clock() if boot == 'boot-1' else self.random.randint(0, 50)
        document = json.loads(canonical(self.registry.to_document()))
        self.restore_from('restore', document, boot, now)

    def restore_from(self, op, document, boot, now):
        try:
            restored = registry.Registry.restore(document, self.config, boot_id=boot, now_ns=now,
                                                 persist=self.persist)
            expect = {'ok': None}
        except registry.RegistryError as error:
            restored, expect = None, {'error': str(error)}
        self.steps.append({'op': op, 'args': {'boot_id': boot, 'now': now}, 'expect': expect})
        if restored is not None:
            self.registry = restored
            if boot != self.boot:
                self.now = now
            self.boot = boot

    def step_crash_restore(self):
        """Restart from what the store last accepted, not from the live state."""
        if self.saved is None:
            return self.step_checkpoint()
        if self.random.random() < 0.75:
            boot, now = self.boot, self.clock()
        else:
            self.boots += 1
            boot, now = 'boot-%d' % self.boots, self.random.randint(0, 50)
        self.restore_from('crash_restore', json.loads(self.saved), boot, now)

    # Damaged ticket entries: both implementations must refuse them with the same message.
    CORRUPTIONS = [{'kind': 'version', 'value': 1}, {'kind': 'drop_tickets'}, {'kind': 'ticket_duplicate'},
                   {'kind': 'ticket_set', 'field': 'state', 'value': 'open'},
                   {'kind': 'ticket_set', 'field': 'task_id', 'value': 'missing'},
                   {'kind': 'ticket_set', 'field': 'image', 'value': ['/opt/agent']},
                   {'kind': 'ticket_set', 'field': 'image', 'value': ['relative', 'cd-agent']},
                   {'kind': 'ticket_set', 'field': 'expires_at_ns', 'value': -1},
                   {'kind': 'ticket_set', 'field': 'child', 'value': [1]},
                   {'kind': 'ticket_set', 'field': 'spawner', 'value': 'x'},
                   {'kind': 'ticket_set', 'field': 'extra', 'value': 1}]

    def step_corrupt_restore(self):
        """Restore a damaged copy of the live document; the registry itself stays as it is."""
        document = json.loads(canonical(self.registry.to_document()))
        corruption = self.pick(self.CORRUPTIONS if document['tickets'] else self.CORRUPTIONS[:2])
        apply_corruption(document, corruption)
        now = self.clock()
        try:
            registry.Registry.restore(document, self.config, boot_id=self.boot, now_ns=now)
            expect = {'ok': None}
        except registry.RegistryError as error:
            expect = {'error': str(error)}
        self.steps.append({'op': 'corrupt_restore', 'args': {'corruption': corruption, 'boot_id': self.boot,
                                                             'now': now}, 'expect': expect})

    def step_store_mode(self):
        self.set_store_failing(self.random.random() < 0.3)

    def step_checkpoint(self):
        """The host's own periodic save, through the same hook as write-ahead."""
        self.control('checkpoint', {}, self.registry.checkpoint)

    def set_store_failing(self, failing):
        self.store_failing = failing
        self.steps.append({'op': 'store_mode', 'args': {'failing': failing}, 'expect': None})

    def maybe_failing_store(self, call):
        """Run one exec step, sometimes with the store failing just for that answer."""
        if self.store_failing or self.random.random() >= 0.15:
            return call()
        self.set_store_failing(True)
        call()
        self.set_store_failing(False)

    def step_saved(self):
        self.steps.append({'op': 'saved', 'args': {}, 'expect': self.saved})

    def run(self):
        operations = [(self.step_propose, 8), (self.step_confirm, 6), (self.step_launch_flow, 6),
                      (self.step_agent_fork, 4), (self.step_grant_flow, 4), (self.step_subtree_flow, 4),
                      (self.step_process, 3), (self.step_exception_flow, 4), (lambda: self.step_confirm('reject_proposal'), 1),
                      (self.step_revoke, 2), (self.step_spawn, 5), (self.step_register, 6), (self.step_ticket_status, 2),
                      (self.step_exec, 7), (self.step_agent_exec, 2), (self.step_fork, 4), (self.step_exit, 3), (self.step_file, 16),
                      (self.step_pending, 3), (self.step_approve, 3), (lambda: self.step_approve('reject_request'), 1),
                      (self.step_snapshot, 2), (self.step_restore, 1), (self.step_crash_restore, 2),
                      (self.step_store_mode, 2), (self.step_checkpoint, 1), (self.step_saved, 2),
                      (self.step_corrupt_restore, 1)]
        functions, weights = zip(*operations)
        for unused in range(self.steps_wanted):
            self.random.choices(functions, weights)[0]()
        self.step_snapshot()
        return {'seed': self.seed, 'config': self.config_args, 'steps': self.steps}


def apply_corruption(document, corruption):
    """Mirrored by DifferentialTests.corrupted(_:_:); tickets[0] is the lowest child identity."""
    kind = corruption['kind']
    if kind == 'version':
        document['version'] = corruption['value']
    elif kind == 'drop_tickets':
        del document['tickets']
    elif kind == 'ticket_duplicate':
        document['tickets'].append(document['tickets'][0])
    else:
        document['tickets'][0][corruption['field']] = corruption['value']


def contract_corpus(seed, count):
    """Accept/reject expectations for load_contract over valid and mutated documents."""
    generator = random.Random(seed)
    base = {'schema_version': 1, 'task_id': 'task-a', 'revision': 1, 'workspace': '/w/a', 'valid_from_ns': 0,
            'expires_at_ns': 10, 'allow': [{'path': '/w/a', 'scope': 'tree', 'operations': ['read', 'write']}],
            'deny': [{'path': '/w/a/private', 'scope': 'exact', 'operations': ['execute']}]}
    texts = [json.dumps(base), '[]', 'null', '{', ' ' * 70000, '[' * 100 + ']' * 100,
             json.dumps(base).replace('"revision": 1', '"revision": 1, "revision": 2'),
             json.dumps(base).replace('10', 'NaN'), json.dumps(base).replace('10', '1e1'),
             json.dumps(base).replace('10', '-0'), json.dumps(base).replace('"/w/a"', '"/w/\\u0061"'),
             json.dumps(base).replace('"task-a"', '"task-\\ud800"')]
    v2 = dict(json.loads(json.dumps(base)), schema_version=2,
              external=[{'path': '/usr', 'scope': 'tree', 'operations': ['read', 'execute']}])
    texts += [json.dumps(v2), json.dumps(dict(v2, external=[{'path': '/', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, external={})), json.dumps(dict(base, external=[])),
              json.dumps({key: value for key, value in v2.items() if key != 'external'}),
              json.dumps(dict(v2, schema_version=3)),
              json.dumps(dict(v2, external=[{'path': '/usr/../etc', 'scope': 'tree', 'operations': ['read']}])),
              '"' + '\u00e9' * 40000 + '"',
              json.dumps(dict(v2, external=[{'path': '/System', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, external=[{'path': '/System/Volumes/Data/Users', 'scope': 'tree',
                                             'operations': ['read']}])),
              json.dumps(dict(v2, external=[{'path': '/System/Library', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(base, workspace='/System/Volumes/Data/w/a', allow=[], deny=[])),
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/w/a/.git', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/w/a/.git', 'scope': 'tree', 'operations': ['execute']}])),
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/w/a/src', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/Users/x/.ssh', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, schema_version=3)), json.dumps(dict(v2, exceptions=[])),
              # Must be rooted at the sensitive name: a directory below one, or a workspace under one, is refused.
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/w/a/.git/objects', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/w/a/.GIT', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, schema_version=3, exceptions=[
                  {'path': '/w/a/src/key.PEM', 'scope': 'exact', 'operations': ['read', 'write']}])),
              json.dumps(dict(v2, schema_version=3, workspace='/w/secrets', allow=[
                  {'path': '/w/secrets', 'scope': 'tree', 'operations': ['read', 'write']}], deny=[], exceptions=[
                  {'path': '/w/secrets', 'scope': 'tree', 'operations': ['read']}])),
              json.dumps(dict(v2, schema_version=3, workspace='/w/secrets/proj', allow=[
                  {'path': '/w/secrets/proj', 'scope': 'tree', 'operations': ['read', 'write']}], deny=[], exceptions=[
                  {'path': '/w/secrets/proj', 'scope': 'tree', 'operations': ['read']}]))]
    v3 = dict(v2, schema_version=3, exceptions=[])

    def scoped(path='/w/a/.build/checkouts', names=('.git',), operations=('read', 'write'), scope='tree'):
        return {'path': path, 'scope': scope, 'operations': list(operations), 'names': list(names)}
    # Name-scoped exceptions: accepted shapes, then every rejection.
    texts += [json.dumps(dict(v3, exceptions=[scoped()])),
              json.dumps(dict(v3, exceptions=[scoped(names=('.git', '.env')), scoped(names=('x.pem',))])),
              json.dumps(dict(v3, exceptions=[{'path': '/w/a/.git', 'scope': 'tree', 'operations': ['read']},
                                              scoped('/w/a/.build/checkouts/dep', operations=('read',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=())])),
              json.dumps(dict(v3, exceptions=[dict(scoped(), names='.git')])),
              json.dumps(dict(v3, exceptions=[dict(scoped(), names=None)])),
              json.dumps(dict(v3, exceptions=[scoped(names=('.git', 1))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('.git', '.env', '.aws', '.ssh', '.kube', '.azure',
                                                           '.gnupg', '.netrc', '.npmrc'))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('.git', '.git'))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('src',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('dep/.git',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('',))])),
              # Names are literal lowercase ASCII: Python and Foundation casefold non-ASCII differently.
              json.dumps(dict(v3, exceptions=[scoped(names=('.GIT',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('\uab70.pem',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('\u13a0.pem',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('\u00df.pem',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('*.pem',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('.env\t',))])),
              json.dumps(dict(v3, exceptions=[scoped(names=('.git', '.Env'))])),
              json.dumps(dict(v3, exceptions=[scoped(scope='exact')])),
              json.dumps(dict(v3, exceptions=[scoped(scope='glob')])),
              json.dumps(dict(v3, exceptions=[scoped('/w/a/../b', names=())])),
              json.dumps(dict(v3, exceptions=[scoped(operations=('read', 'execute'))])),
              json.dumps(dict(v3, exceptions=[scoped('/w/a/.git/modules')])),
              json.dumps(dict(v3, exceptions=[scoped('/w/a/.build/.ENV/checkouts')])),
              json.dumps(dict(v3, exceptions=[scoped('/usr/lib/cache', operations=('read', 'write'))])),
              json.dumps(dict(v3, exceptions=[scoped('/')])),
              json.dumps(dict(v3, allow=v3['allow'] + [scoped('/w/a/.build')])),
              json.dumps(dict(v3, deny=v3['deny'] + [scoped('/w/a/.build')])),
              json.dumps(dict(v3, external=v3['external'] + [scoped('/usr/lib', operations=('read',))])),
              json.dumps(dict(v2, external=v2['external'] + [scoped('/usr/lib', operations=('read',))])),
              json.dumps(dict(v3, exceptions=[dict(scoped(), extra=1)]))]
    mutations = [('schema_version', True), ('schema_version', 2), ('revision', 0), ('revision', '1'),
                 ('revision', 1.0), ('valid_from_ns', 10), ('expires_at_ns', 2 ** 63 - 1),
                 ('task_id', 'a' * 129), ('task_id', ''), ('workspace', '/'), ('workspace', '/w/a/'),
                 ('allow', {}), ('deny', None), ('extra', 1)]
    for key, value in mutations:
        document = json.loads(json.dumps(base))
        document[key] = value
        texts.append(json.dumps(document))
    rule_values = [('path', '/w/b'), ('path', '/w/a/../b'), ('scope', 'glob'), ('operations', []),
                   ('operations', ['read', 'read']), ('operations', ['network']), ('operations', 'read'),
                   ('priority', 1)]
    for key, value in rule_values:
        for which in ('allow', 'deny'):
            document = json.loads(json.dumps(base))
            document[which][0][key] = value
            texts.append(json.dumps(document))
    for unused in range(count):
        text = list(json.dumps(base))
        for unused in range(generator.randint(1, 3)):
            position = generator.randrange(len(text))
            text[position] = generator.choice('{}[],:"0123456789aetrw/ -\\')
        texts.append(''.join(text))
    corpus = []
    for text in texts:
        try:
            contract = policy.load_contract(text)
            corpus.append({'text': text, 'ok': canonical(policy.contract_to_dict(contract))})
        except policy.PolicyError as error:
            corpus.append({'text': text, 'error': str(error)})
    return corpus


def attenuation_corpus(seed, count):
    """Parent/child contract pairs with the reference is_attenuation verdict."""
    generator = random.Random(seed)
    rules = [('/w/a', 'tree', ['read']), ('/w/a/src', 'tree', ['read', 'write']), ('/w/a/src/x', 'exact', ['read']),
             ('/w/a/bin/run', 'exact', ['execute']), ('/w/a/src', 'exact', ['write'])]
    external = [('/usr', 'tree', ['execute', 'read']), ('/usr/lib', 'tree', ['read']), ('/opt/x', 'exact', ['execute'])]
    denies = [('/w/a/private', 'tree', ['read', 'write', 'execute']), ('/w/a/private', 'exact', ['read']),
              ('/w', 'tree', ['write'])]

    def document(task_id, workspace):
        schema = generator.choice([1, 2, 3])
        pick = lambda menu: [{'path': p, 'scope': s, 'operations': o} for p, s, o in menu if generator.random() < 0.5]
        body = {'schema_version': schema, 'task_id': task_id, 'revision': 1, 'workspace': workspace,
                'valid_from_ns': generator.choice([0, 5]), 'expires_at_ns': generator.choice([50, 100]),
                'allow': [rule for rule in pick(rules) if rule['path'].startswith(workspace)], 'deny': pick(denies)}
        if schema >= 2:
            body['external'] = pick(external)
        if schema == 3:
            body['exceptions'] = [rule for rule in [{'path': '/w/a/.git', 'scope': 'tree', 'operations': ['read']},
                                                    {'path': '/w/a/src/.env', 'scope': 'exact', 'operations': ['read']},
                                                    {'path': '/w/a/.build/checkouts', 'scope': 'tree',
                                                     'operations': ['read'], 'names': ['.git']},
                                                    {'path': '/w/a/deps', 'scope': 'tree', 'operations': ['read'],
                                                     'names': ['.env', '.git']}]
                                  if generator.random() < 0.5 and any(
                                      r['path'] == '/w/a' and 'read' in r['operations'] for r in body['allow'])]
        return body

    def narrowed(parent):
        # A child built by shrinking the parent: often valid, with the schema varied on purpose.
        child = json.loads(json.dumps(parent))
        child['task_id'] = 'child'
        child['allow'] = [rule for rule in child['allow'] if generator.random() < 0.7]
        child['schema_version'] = generator.choice([1, 2, 3, parent['schema_version']])
        if child['schema_version'] >= 2:
            child['external'] = [rule for rule in parent.get('external', []) if generator.random() < 0.7]
        else:
            child.pop('external', None)
        if child['schema_version'] == 3:
            readable = any(r['path'] == '/w/a' and 'read' in r['operations'] for r in child['allow'])
            child['exceptions'] = [rule for rule in parent.get('exceptions', []) if generator.random() < 0.7 and readable]
            if readable and generator.random() < 0.4:
                # An exception the parent may not have: attenuation must refuse it unless covered.
                child['exceptions'].append({'path': '/w/a/src/x.pem', 'scope': 'exact', 'operations': ['read']})
            if readable and generator.random() < 0.5:
                # Name-scoped: covered only by a scoped parent with the same or more names.
                child['exceptions'].append(generator.choice([
                    {'path': '/w/a/.build/checkouts/dep', 'scope': 'tree', 'operations': ['read'], 'names': ['.git']},
                    {'path': '/w/a/.build/checkouts', 'scope': 'tree', 'operations': ['read'], 'names': ['.env', '.git']},
                    {'path': '/w/a/deps/x', 'scope': 'tree', 'operations': ['read'], 'names': ['.git']},
                    {'path': '/w/a/deps', 'scope': 'tree', 'operations': ['read'], 'names': ['.env']},
                    {'path': '/w/a/.build/checkouts/dep/.git', 'scope': 'tree', 'operations': ['read']}]))
        else:
            child.pop('exceptions', None)
        if generator.random() < 0.3:
            child['deny'] = child['deny'] + [{'path': '/w/a/src/x', 'scope': 'exact', 'operations': ['write']}]
        return child

    pairs = []
    for unused in range(count):
        parent = document('parent', '/w/a')
        if generator.random() < 0.5:
            child = narrowed(parent)
        else:
            child = document(generator.choice(['child', 'parent']), generator.choice(['/w/a', '/w/a/src']))
        verdict = policy.is_attenuation(policy.contract_from_dict(parent), policy.contract_from_dict(child))
        pairs.append({'parent': parent, 'child': child, 'attenuation': verdict})
    return pairs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--scenarios', type=int, default=120)
    parser.add_argument('--steps', type=int, default=160)
    parser.add_argument('--seed', type=int, default=0)
    options = parser.parse_args()
    vectors = {'scenarios': [Scenario(options.seed + index, options.steps).run()
                             for index in range(options.scenarios)],
               'contracts': contract_corpus(options.seed, 400),
               'attenuation': attenuation_corpus(options.seed, 600)}
    Path(options.out).write_text(json.dumps(vectors, ensure_ascii=True))


if __name__ == '__main__':
    main()
