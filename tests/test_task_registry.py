"""Synthetic R2 supervisor/registry model; no ES client, launcher, credentials or network.

Process identities, executable digests, signers and clocks are fabricated test values.
The only filesystem use is the store tests, confined to a private temporary directory.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import task_policy as policy
import task_registry as registry


SUPERVISOR = registry.Signer('TEAM000001', 'dev.agentbelt.supervisor')
APPROVER = registry.Signer('TEAM000001', 'dev.agentbelt.approver')
STRANGER = registry.Signer('TEAM999999', 'com.example.tool')
AGENT_IMAGE = registry.ExecutableImage('/opt/agents/agent', 'sha256-agent')
OTHER_IMAGE = registry.ExecutableImage('/usr/bin/helper', 'sha256-helper')
LAUNCHD = policy.ProcessIdentity(1, 'launchd')


def contract(task_id='task-a', workspace='/projects/a', revision=1, expires_at_ns=10**6, **changes):
    document = {
        'schema_version': 1, 'task_id': task_id, 'revision': revision, 'workspace': workspace,
        'valid_from_ns': 0, 'expires_at_ns': expires_at_ns,
        'allow': [
            {'path': workspace, 'scope': 'tree', 'operations': ['read']},
            {'path': workspace + '/src', 'scope': 'tree', 'operations': ['write']},
            {'path': workspace + '/bin/check', 'scope': 'exact', 'operations': ['execute']},
        ],
        'deny': [{'path': workspace + '/private', 'scope': 'tree', 'operations': ['read', 'write', 'execute']}],
    }
    document.update(changes)
    return policy.contract_from_dict(document)


def proc(pid, generation):
    return policy.ProcessIdentity(pid, generation)


class Harness:
    """Drives one registry the way the future transport and ES adapter would."""

    def __init__(self, test, **config_changes):
        self.test = test
        self.clock = 100
        options = dict(supervisors=frozenset({SUPERVISOR}), approvers=frozenset({APPROVER}))
        options.update(config_changes)
        self.config = registry.RegistryConfig(**options)
        self.registry = registry.Registry(self.config, boot_id='boot-1', now_ns=self.clock)
        self.supervisor = registry.Peer(proc(500, 's1'), SUPERVISOR)
        self.approver = registry.Peer(proc(600, 'a1'), APPROVER)
        self.next_pid = 1000

    def tick(self, amount=1):
        self.clock += amount
        return self.clock

    def activate(self, task, parent_task_id=None, supervisor=None):
        digest = self.registry.propose(supervisor or self.supervisor, task,
                                       parent_task_id=parent_task_id, now_ns=self.tick())
        self.registry.confirm(self.approver, digest, now_ns=self.tick())
        return digest

    def spawn(self, supervisor=None):
        """fork() of the supervisor: the child waits, running supervisor code, until released."""
        self.next_pid += 1
        child = proc(self.next_pid, 'fork')
        self.registry.on_fork((supervisor or self.supervisor).process, child, now_ns=self.tick())
        return child

    def ticket(self, task_id, image=AGENT_IMAGE, supervisor=None):
        supervisor = supervisor or self.supervisor
        child = self.spawn(supervisor)
        self.registry.register_launch(supervisor, task_id, image, child, now_ns=self.tick())
        return child

    def exec_child(self, child, image=AGENT_IMAGE, supervisor=None):
        target = proc(child.pid, 'exec1')
        outcome = self.registry.on_exec(child, (supervisor or self.supervisor).process, target, image,
                                        now_ns=self.tick())
        return target, outcome

    def launch(self, task_id, image=AGENT_IMAGE, supervisor=None):
        child = self.ticket(task_id, image, supervisor)
        target, outcome = self.exec_child(child, image, supervisor)
        self.test.assertEqual((outcome.route, outcome.allowed, outcome.reason),
                              ('enforced', True, 'launch_bound'))
        return target

    def status(self, child, supervisor=None):
        return self.registry.ticket_status(supervisor or self.supervisor, child, now_ns=self.tick())

    def file(self, process, path, operations=('read',), parent=LAUNCHD):
        return self.registry.authorize_file(process, parent, path, frozenset(operations), now_ns=self.tick())

    def assert_decision(self, outcome, allowed, reason, route='enforced'):
        self.test.assertEqual((outcome.route, outcome.allowed, outcome.reason), (route, allowed, reason))


class LaunchBindingTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())

    def test_ticketed_exec_binds_before_the_first_file_access(self):
        child = self.h.ticket('task-a')
        agent, outcome = self.h.exec_child(child)
        self.h.assert_decision(outcome, True, 'launch_bound')
        self.h.assert_decision(self.h.file(agent, '/projects/a/README.md'), True, 'allowed')
        self.h.assert_decision(self.h.file(agent, '/projects/b/README.md'), False, 'outside_allow_scope')
        self.assertEqual(self.h.status(child), 'bound')

    def test_pre_exec_identity_is_bound_too(self):
        # If the exec fails after authorization, the old image keeps running.
        child = self.h.ticket('task-a')
        self.h.exec_child(child)
        self.h.assert_decision(self.h.file(child, '/projects/b/x'), False, 'outside_allow_scope')

    def test_same_executable_in_two_tasks_keeps_authority_separate(self):
        self.h.activate(contract('task-b', '/projects/b'))
        agent_a = self.h.launch('task-a')
        agent_b = self.h.launch('task-b')
        for agent, own, other in [(agent_a, '/projects/a/x', '/projects/b/x'),
                                  (agent_b, '/projects/b/x', '/projects/a/x')]:
            with self.subTest(agent=agent):
                self.assertTrue(self.h.file(agent, own).allowed)
                self.assertFalse(self.h.file(agent, other).allowed)

    def test_late_exec_cannot_take_another_childs_ticket(self):
        h = Harness(self, ticket_ttl_ns=10)
        h.activate(contract())
        h.activate(contract('task-b', '/projects/b'))
        late = h.ticket('task-a')
        h.tick(10)
        self.assertEqual(h.status(late), 'expired')
        intended = h.ticket('task-b')
        h.assert_decision(h.exec_child(late)[1], False, 'launch_ticket_expired')
        agent_b, outcome = h.exec_child(intended)
        h.assert_decision(outcome, True, 'launch_bound')
        self.assertEqual(outcome.task_id, 'task-b')
        h.assert_decision(h.file(agent_b, '/projects/a/x'), False, 'outside_allow_scope')

    def test_ticket_needs_an_unexeced_fork_child_of_the_caller(self):
        other_supervisor = registry.Peer(proc(501, 's2'), SUPERVISOR)
        self.h.registry.propose(other_supervisor, contract('task-o', '/projects/o'), now_ns=self.h.tick())
        foreign = self.h.spawn(other_supervisor)
        ticketed = self.h.ticket('task-a')
        for child in [proc(7000, 'never-forked'), foreign, ticketed, (7001, 'fork')]:
            with self.subTest(child=child), self.assertRaises(registry.RegistryError):
                self.h.registry.register_launch(self.h.supervisor, 'task-a', AGENT_IMAGE, child,
                                                now_ns=self.h.tick())

    def test_pending_tickets_per_supervisor_are_bounded(self):
        for unused in range(registry.MAX_TICKETS_PER_SUPERVISOR):
            self.h.ticket('task-a')
        with self.assertRaises(registry.RegistryError):
            self.h.ticket('task-a')

    def test_mismatched_image_or_parent_denies_and_closes_the_ticket(self):
        for image, parent in [(OTHER_IMAGE, None), (replace(AGENT_IMAGE, digest='sha256-tampered'), None),
                              (AGENT_IMAGE, proc(700, 'term'))]:
            with self.subTest(image=image, parent=parent):
                child = self.h.ticket('task-a')
                outcome = self.h.registry.on_exec(child, parent or self.h.supervisor.process,
                                                  proc(child.pid, 'exec1'), image, now_ns=self.h.tick())
                self.h.assert_decision(outcome, False, 'launch_ticket_mismatch')
                self.assertEqual(self.h.status(child), 'denied')
                self.h.assert_decision(self.h.exec_child(child)[1], False, 'launch_ticket_closed')

    def test_expired_ticket_denies_the_exec(self):
        child = self.h.ticket('task-a')
        self.h.tick(self.h.config.ticket_ttl_ns)
        self.h.assert_decision(self.h.exec_child(child)[1], False, 'launch_ticket_expired')
        self.assertEqual(self.h.status(child), 'expired')

    def test_contract_expiring_before_the_ticket_denies_the_exec(self):
        h = Harness(self)
        h.activate(contract(expires_at_ns=h.clock + 6))
        child = h.ticket('task-a')
        h.tick(5)
        h.assert_decision(h.exec_child(child)[1], False, 'task_not_active')

    def test_clock_regression_blocks_a_launch_binding(self):
        child = self.h.ticket('task-a')
        outcome = self.h.registry.on_exec(child, self.h.supervisor.process, proc(child.pid, 'exec1'),
                                          AGENT_IMAGE, now_ns=self.h.clock - 1)
        self.h.assert_decision(outcome, False, 'clock_regression')

    def test_unticketed_supervisor_helpers_and_terminals_are_not_enrolled(self):
        helper = self.h.spawn()
        self.assertEqual(self.h.exec_child(helper, OTHER_IMAGE)[1].route, 'not_enrolled')
        self.h.ticket('task-a')
        terminal_child = proc(701, 'fork')
        outcome = self.h.registry.on_exec(terminal_child, proc(700, 'term'), proc(701, 'exec1'),
                                          AGENT_IMAGE, now_ns=self.h.tick())
        self.assertEqual(outcome.route, 'not_enrolled')
        self.h.assert_decision(self.h.file(proc(701, 'exec1'), '/projects/b/x'), True, 'not_enrolled',
                               route='not_enrolled')

    def test_tickets_require_an_active_task_in_its_validity_window_owned_by_the_caller(self):
        self.h.registry.propose(self.h.supervisor, contract('task-p', '/projects/p'), now_ns=self.h.tick())
        self.h.activate(contract('task-future', '/projects/f', valid_from_ns=10**5))
        other_supervisor = registry.Peer(proc(501, 's2'), SUPERVISOR)
        for peer, task_id in [(self.h.supervisor, 'task-p'), (self.h.supervisor, 'missing'),
                              (self.h.supervisor, 'task-future'), (other_supervisor, 'task-a')]:
            with self.subTest(task_id=task_id), self.assertRaises(registry.RegistryError):
                self.h.registry.register_launch(peer, task_id, AGENT_IMAGE, self.h.spawn(peer),
                                                now_ns=self.h.tick())
        self.h.registry.revoke(self.h.supervisor, 'task-a', now_ns=self.h.tick())
        with self.assertRaises(registry.RegistryError):
            self.h.ticket('task-a')

    def test_revision_or_revocation_closes_pending_tickets(self):
        child = self.h.ticket('task-a')
        self.h.activate(contract(revision=2))
        self.assertEqual(self.h.status(child), 'revoked')
        self.h.assert_decision(self.h.exec_child(child)[1], False, 'launch_ticket_closed')
        child = self.h.ticket('task-a')
        self.h.registry.revoke(self.h.approver, 'task-a', now_ns=self.h.tick())
        self.h.assert_decision(self.h.exec_child(child)[1], False, 'launch_ticket_closed')

    def test_unrelated_host_access_passes_through_and_is_not_recorded(self):
        before = len(self.h.registry.records())
        outcome = self.h.file(proc(800, 'other'), '/Users/someone/private.txt', parent=proc(801, 'x'))
        self.h.assert_decision(outcome, True, 'not_enrolled', route='not_enrolled')
        self.assertEqual(outcome.enforcement, 'none')
        self.assertEqual(len(self.h.registry.records()), before)


class LineageTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())
        self.agent = self.h.launch('task-a')

    def fork_exec(self, parent, image, pid=3000):
        child = proc(pid, 'fork')
        self.h.registry.on_fork(parent, child, now_ns=self.h.tick())
        target = proc(pid, 'exec1')
        return child, target, self.h.registry.on_exec(child, parent, target, image, now_ns=self.h.tick())

    def test_forked_and_execed_children_inherit_the_task(self):
        child, target, outcome = self.fork_exec(self.agent, OTHER_IMAGE)
        self.h.assert_decision(outcome, True, 'exec_outside_contract')
        for process in [child, target]:
            with self.subTest(process=process):
                self.h.assert_decision(self.h.file(process, '/projects/b/x', parent=self.agent),
                                       False, 'outside_allow_scope')

    def test_workspace_executables_follow_execute_rules(self):
        allowed = registry.ExecutableImage('/projects/a/bin/check', 'sha256-check')
        denied = registry.ExecutableImage('/projects/a/src/tool', 'sha256-tool')
        self.h.assert_decision(self.fork_exec(self.agent, allowed, 3001)[2], True, 'allowed')
        self.h.assert_decision(self.fork_exec(self.agent, denied, 3002)[2], False, 'outside_allow_scope')

    def test_reparented_child_stays_bound_after_parent_exit(self):
        child, target, unused = self.fork_exec(self.agent, OTHER_IMAGE)
        self.h.registry.on_exit(self.agent, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(target, '/projects/b/x', parent=LAUNCHD), False, 'outside_allow_scope')
        self.h.assert_decision(self.h.file(target, '/projects/a/x', parent=LAUNCHD), True, 'allowed')

    def test_pid_reuse_after_exit_does_not_inherit_authority(self):
        pid = self.agent.pid
        self.h.registry.on_exit(self.agent, now_ns=self.h.tick())
        reused = proc(pid, 'reused')
        self.h.assert_decision(self.h.file(reused, '/projects/b/x', parent=proc(900, 'shell')),
                               True, 'not_enrolled', route='not_enrolled')

    def test_exit_retires_every_image_generation_of_that_pid(self):
        child, target, unused = self.fork_exec(self.agent, OTHER_IMAGE)
        self.h.registry.on_exit(target, now_ns=self.h.tick())
        bound = {tuple(item['process']) for item in self.h.registry.to_document()['bindings']}
        self.assertNotIn((child.pid, child.generation), bound)
        self.assertNotIn((target.pid, target.generation), bound)

    def test_stale_exit_for_a_reused_pid_does_not_release_a_live_agent(self):
        self.h.registry.on_exit(proc(self.agent.pid, 'stale-previous'), now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(self.agent, '/Users/victim/secret.txt'), False, 'outside_allow_scope')

    def test_child_task_cannot_execute_parent_workspace_files_the_parent_refuses(self):
        self.h.activate(narrow_child(), parent_task_id='task-a')
        child_agent = self.h.launch('task-child')
        script = registry.ExecutableImage('/projects/a/docs/build.sh', 'sha256-build')
        for agent, pid in [(self.agent, 3100), (child_agent, 3101)]:
            with self.subTest(agent=agent):
                self.h.assert_decision(self.fork_exec(agent, script, pid)[2], False, 'outside_allow_scope')

    def test_missed_fork_child_is_quarantined_even_after_its_parent_exited(self):
        missed = proc(4500, 'missed')
        self.h.registry.on_exit(self.agent, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(missed, '/Users/victim/.ssh/config', parent=self.agent),
                               False, 'unattributed_descendant')
        self.h.registry.on_fork(self.agent, missed, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(missed, '/projects/a/x'), False, 'tracking_lost')

    def test_retired_identities_survive_a_same_boot_restart(self):
        self.h.registry.on_exit(self.agent, now_ns=self.h.tick())
        restored = registry.Registry.restore(self.h.registry.to_document(), self.h.config, boot_id='boot-1',
                                             now_ns=self.h.tick())
        outcome = restored.authorize_file(proc(4600, 'missed'), self.agent, '/x', frozenset({'read'}),
                                          now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'unattributed_descendant')

    def test_new_boot_discards_tombstones(self):
        self.h.registry.on_exit(self.agent, now_ns=self.h.tick())
        restored = registry.Registry.restore(self.h.registry.to_document(), self.h.config, boot_id='boot-2',
                                             now_ns=5)
        self.assertEqual(restored.to_document()['retired'], [])
        outcome = restored.authorize_file(proc(4600, 'x'), self.agent, '/x', frozenset({'read'}), now_ns=6)
        self.assertEqual(outcome.route, 'not_enrolled')

    def test_retired_set_is_bounded_and_counts_evictions(self):
        with mock.patch.object(registry, 'MAX_RETIRED', 2):
            for pid in range(3):
                child = proc(4700 + pid, 'fork')
                self.h.registry.on_fork(self.agent, child, now_ns=self.h.tick())
                self.h.registry.on_exit(child, now_ns=self.h.tick())
        document = self.h.registry.to_document()
        self.assertEqual(len(document['retired']), 2)
        self.assertEqual(document['dropped_retired'], 1)

    def test_late_fork_does_not_rebind_a_quarantined_process(self):
        orphan = proc(4300, 'unknown')
        self.h.file(orphan, '/projects/a/x', parent=self.agent)
        self.h.registry.on_fork(self.agent, orphan, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(orphan, '/projects/a/x'), False, 'tracking_lost')

    def test_malformed_parent_does_not_block_unrelated_processes(self):
        for parent in [(0, 'kernel'), [0, 'kernel'], {}]:
            with self.subTest(parent=parent):
                outcome = self.h.registry.authorize_file(proc(4400, 'x'), parent, '/tmp/x', frozenset({'read'}),
                                                         now_ns=self.h.tick())
                self.h.assert_decision(outcome, True, 'not_enrolled', route='not_enrolled')
                outcome = self.h.registry.on_exec(proc(4401, 'f'), parent, proc(4401, 'e'), OTHER_IMAGE,
                                                  now_ns=self.h.tick())
                self.assertEqual(outcome.route, 'not_enrolled')

    def test_missed_fork_quarantines_the_unattributed_descendant(self):
        orphan = proc(4000, 'unknown')
        self.h.assert_decision(self.h.file(orphan, '/projects/a/x', parent=self.agent),
                               False, 'unattributed_descendant')
        self.h.assert_decision(self.h.file(orphan, '/projects/a/x', parent=LAUNCHD), False, 'tracking_lost')
        grandchild = proc(4001, 'unknown')
        self.h.registry.on_fork(orphan, grandchild, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(grandchild, '/projects/a/x'), False, 'tracking_lost')
        outcome = self.h.registry.on_exec(proc(4002, 'fork'), orphan, proc(4002, 'exec1'),
                                          OTHER_IMAGE, now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'unattributed_descendant')

    def test_exec_target_must_keep_the_pid(self):
        outcome = self.h.registry.on_exec(self.agent, LAUNCHD, proc(self.agent.pid + 1, 'other'), OTHER_IMAGE,
                                          now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'invalid_input', route='invalid')
        self.h.assert_decision(self.h.file(self.agent, '/projects/b/x'), False, 'outside_allow_scope')

    def test_revision_cannot_lower_the_schema(self):
        h = Harness(self)
        document = policy.contract_to_dict(contract())
        document.update(schema_version=2, external=[])
        h.activate(policy.contract_from_dict(document))
        with self.assertRaises(registry.RegistryError) as caught:
            h.registry.propose(h.supervisor, contract(revision=2), now_ns=h.tick())
        self.assertEqual(str(caught.exception), 'schema cannot be lowered')

    def test_moving_a_directory_above_a_deny_rule_is_denied(self):
        h = Harness(self)
        document = policy.contract_to_dict(contract())
        document['allow'] = [{'path': '/projects/a', 'scope': 'tree', 'operations': ['read', 'write']}]
        h.activate(policy.contract_from_dict(document))
        agent = h.launch('task-a')
        for path, allowed, reason in [('/projects/a', False, 'explicit_deny_below'),
                                      ('/projects/a/private', False, 'explicit_deny'),
                                      ('/projects/a/src', True, 'allowed')]:
            with self.subTest(path=path):
                outcome = h.registry.authorize_file(agent, LAUNCHD, path, frozenset({'write'}), now_ns=h.tick(),
                                                    subtree=True)
                h.assert_decision(outcome, allowed, reason)
        # A plain (non-subtree) write to the same directory entry is unaffected.
        h.assert_decision(h.file(agent, '/projects/a/README', ('write',)), True, 'allowed')
        self.assertEqual(h.registry.records()[-4].target, 'withheld')

    def test_subtree_check_folds_ascii_case(self):
        h = Harness(self)
        document = policy.contract_to_dict(contract())
        document['allow'] = [{'path': '/projects/a', 'scope': 'tree', 'operations': ['read', 'write']}]
        document['deny'] = [{'path': '/projects/a/Docs/Private', 'scope': 'tree', 'operations': ['write']}]
        h.activate(policy.contract_from_dict(document))
        agent = h.launch('task-a')
        # docs and Docs name the same directory on case-insensitive APFS.
        outcome = h.registry.authorize_file(agent, LAUNCHD, '/projects/a/docs', frozenset({'write'}), now_ns=h.tick(),
                                            subtree=True)
        h.assert_decision(outcome, False, 'explicit_deny_below')

    def test_process_operations_stay_inside_the_task(self):
        h = Harness(self)
        h.activate(contract())
        h.activate(contract('task-b', '/projects/b'))
        agent, other_task = h.launch('task-a'), h.launch('task-b')
        child = proc(7300, 'f')
        h.registry.on_fork(agent, child, now_ns=h.tick())
        for actor, target, operation, allowed, reason in [
                (agent, agent, 'task_port', True, 'same_task'),
                (agent, child, 'signal', True, 'same_task'),
                (agent, other_task, 'task_port', False, 'process_outside_task'),
                (agent, h.supervisor.process, 'task_read', False, 'process_outside_task'),
                (agent, proc(900, 'shell'), 'suspend_resume', False, 'process_outside_task'),
                (agent, None, 'suspend_resume', False, 'process_outside_task')]:
            with self.subTest(target=target, operation=operation):
                outcome = h.registry.authorize_process(actor, LAUNCHD, target, operation, now_ns=h.tick())
                h.assert_decision(outcome, allowed, reason)
        unrelated = h.registry.authorize_process(proc(901, 'x'), LAUNCHD, agent, 'task_port', now_ns=h.tick())
        h.assert_decision(unrelated, True, 'not_enrolled', route='not_enrolled')
        invalid = h.registry.authorize_process(agent, LAUNCHD, agent, 'ptrace', now_ns=h.tick())
        h.assert_decision(invalid, False, 'invalid_input', route='invalid')

    def test_interpreted_script_needs_execute_too(self):
        h = Harness(self)
        h.activate(contract())
        agent = h.launch('task-a')
        shell = registry.ExecutableImage('/bin/sh', 'sha256-sh')
        for script, pid, allowed, reason in [('/projects/a/bin/check', 7200, True, 'exec_outside_contract'),
                                             ('/projects/a/src/tool.sh', 7201, False, 'outside_allow_scope'),
                                             ('/projects/a/.env', 7202, False, 'sensitive_path')]:
            with self.subTest(script=script):
                h.registry.on_fork(agent, proc(pid, 'f'), now_ns=h.tick())
                outcome = h.registry.on_exec(proc(pid, 'f'), agent, proc(pid, 'e'), shell, now_ns=h.tick(),
                                             script=script)
                h.assert_decision(outcome, allowed, reason)

    def test_schema_two_exec_needs_an_external_execute_rule(self):
        h = Harness(self)
        document = policy.contract_to_dict(contract('task-v2', '/projects/v2'))
        document.update(schema_version=2, external=[
            {'path': '/usr/bin/python3', 'scope': 'exact', 'operations': ['execute']}])
        h.activate(policy.contract_from_dict(document))
        agent = h.launch('task-v2')
        python = registry.ExecutableImage('/usr/bin/python3', 'sha256-python')
        shell = registry.ExecutableImage('/bin/sh', 'sha256-sh')
        for image, pid, allowed, reason in [(python, 7100, True, 'allowed'),
                                            (shell, 7101, False, 'outside_allow_scope')]:
            with self.subTest(image=image):
                h.registry.on_fork(agent, proc(pid, 'f'), now_ns=h.tick())
                outcome = h.registry.on_exec(proc(pid, 'f'), agent, proc(pid, 'e'), image, now_ns=h.tick())
                h.assert_decision(outcome, allowed, reason)

    def test_unknown_process_with_unrelated_parent_is_not_enrolled(self):
        self.h.assert_decision(self.h.file(proc(4100, 'x'), '/projects/a/x', parent=proc(4101, 'y')),
                               True, 'not_enrolled', route='not_enrolled')

    def test_claimed_task_identity_in_events_is_not_an_input(self):
        # The event API has no task/env/argv field; only lineage selects authority.
        with self.assertRaises(TypeError):
            self.h.registry.authorize_file(proc(4200, 'x'), LAUNCHD, '/projects/a/x', frozenset({'read'}),
                                           now_ns=self.h.tick(), task_id='task-a')


class ControlAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)

    def test_only_configured_roles_reach_their_operations(self):
        stranger = registry.Peer(proc(610, 'st'), STRANGER)
        for peer in [stranger, self.h.approver]:
            with self.subTest(peer=peer), self.assertRaises(registry.RegistryError):
                self.h.registry.propose(peer, contract(), now_ns=self.h.tick())
        digest = self.h.registry.propose(self.h.supervisor, contract(), now_ns=self.h.tick())
        for peer in [stranger, self.h.supervisor]:
            with self.subTest(peer=peer), self.assertRaises(registry.RegistryError):
                self.h.registry.confirm(peer, digest, now_ns=self.h.tick())

    def test_configuration_separates_supervisor_and_approver_signers(self):
        for supervisors, approvers in [(frozenset({SUPERVISOR}), frozenset({SUPERVISOR})),
                                       (frozenset({SUPERVISOR}), frozenset({APPROVER, SUPERVISOR})),
                                       (frozenset(), frozenset({APPROVER})),
                                       ({SUPERVISOR}, frozenset({APPROVER}))]:
            with self.subTest(supervisors=supervisors, approvers=approvers), \
                    self.assertRaises(registry.RegistryError):
                registry.RegistryConfig(supervisors=supervisors, approvers=approvers)

    def test_bound_process_cannot_use_signed_control_binaries(self):
        self.h.activate(contract())
        agent = self.h.launch('task-a')
        digest = self.h.registry.propose(self.h.supervisor, contract(revision=2), now_ns=self.h.tick())
        forged_supervisor = registry.Peer(agent, SUPERVISOR)
        forged_approver = registry.Peer(agent, APPROVER)
        for call in [lambda: self.h.registry.propose(forged_supervisor, contract('task-x', '/projects/x'),
                                                     now_ns=self.h.tick()),
                     lambda: self.h.registry.register_launch(forged_supervisor, 'task-a', AGENT_IMAGE, agent,
                                                             now_ns=self.h.tick()),
                     lambda: self.h.registry.confirm(forged_approver, digest, now_ns=self.h.tick())]:
            with self.subTest(call=call), self.assertRaises(registry.RegistryError):
                call()

    def test_quarantined_process_cannot_use_control_operations(self):
        self.h.activate(contract())
        agent = self.h.launch('task-a')
        orphan = proc(4000, 'unknown')
        self.h.file(orphan, '/projects/a/x', parent=agent)
        with self.assertRaises(registry.RegistryError):
            self.h.registry.propose(registry.Peer(orphan, SUPERVISOR), contract('task-y', '/projects/y'),
                                    now_ns=self.h.tick())

    def test_confirmation_is_bound_to_the_exact_proposed_contract(self):
        digest = self.h.registry.propose(self.h.supervisor, contract(), now_ns=self.h.tick())
        other = self.h.registry.propose(self.h.supervisor, contract(allow=[]), now_ns=self.h.tick())
        self.assertNotEqual(digest, other)
        with self.assertRaises(registry.RegistryError):
            self.h.registry.confirm(self.h.approver, 'f' * 64, now_ns=self.h.tick())
        with self.assertRaises(registry.RegistryError):
            self.h.ticket('task-a')
        self.h.registry.confirm(self.h.approver, other, now_ns=self.h.tick())
        with self.assertRaises(registry.RegistryError):
            self.h.registry.confirm(self.h.approver, digest, now_ns=self.h.tick())
        agent = self.h.launch('task-a')
        self.h.assert_decision(self.h.file(agent, '/projects/a/x'), False, 'outside_allow_scope')

    def test_approver_reads_proposal_content_and_owner_is_part_of_the_digest(self):
        first = self.h.registry.propose(self.h.supervisor, contract(), now_ns=self.h.tick())
        second_supervisor = registry.Peer(proc(501, 's2'), SUPERVISOR)
        second = self.h.registry.propose(second_supervisor, contract(), now_ns=self.h.tick())
        self.assertNotEqual(first, second)
        with self.assertRaises(registry.RegistryError):
            self.h.registry.propose(self.h.supervisor, contract(), now_ns=self.h.tick())
        views = {view.digest: view for view in self.h.registry.pending_proposals(self.h.approver)}
        self.assertEqual(views[first].contract, contract())
        self.assertEqual(views[second].proposer, second_supervisor.process)
        with self.assertRaises(registry.RegistryError):
            self.h.registry.pending_proposals(self.h.supervisor)
        self.h.registry.confirm(self.h.approver, first, now_ns=self.h.tick())
        with self.assertRaises(registry.RegistryError):
            self.h.registry.register_launch(second_supervisor, 'task-a', AGENT_IMAGE,
                                            self.h.spawn(second_supervisor), now_ns=self.h.tick())
        self.h.launch('task-a')

    def test_child_task_must_be_proposed_by_the_parent_owner(self):
        self.h.activate(contract())
        other_supervisor = registry.Peer(proc(501, 's2'), SUPERVISOR)
        with self.assertRaises(registry.RegistryError):
            self.h.registry.propose(other_supervisor, narrow_child(), parent_task_id='task-a', now_ns=self.h.tick())

    def test_terminal_tasks_are_pruned_when_the_table_is_full(self):
        with mock.patch.object(registry, 'MAX_TASKS', 3):
            for index in range(3):
                self.h.activate(contract('task-%d' % index, '/projects/%d' % index))
                self.h.registry.revoke(self.h.approver, 'task-%d' % index, now_ns=self.h.tick())
            self.h.activate(contract('task-next', '/projects/next'))
            self.h.activate(contract('task-live', '/projects/live'))
            live_agent = self.h.launch('task-live')
            live_child = proc(8800, 'fork')
            self.h.registry.on_fork(live_agent, live_child, now_ns=self.h.tick())
            self.h.registry.on_exit(live_agent, now_ns=self.h.tick())
            self.h.registry.revoke(self.h.approver, 'task-live', now_ns=self.h.tick())
            self.h.activate(contract('task-last', '/projects/last'))
            self.h.registry.revoke(self.h.approver, 'task-next', now_ns=self.h.tick())
            self.h.registry.revoke(self.h.approver, 'task-last', now_ns=self.h.tick())
            self.h.activate(contract('task-after', '/projects/after'))
        remaining = {task['contract']['task_id'] for task in self.h.registry.to_document()['tasks']}
        self.assertIn('task-live', remaining)  # still referenced by a bound process
        self.h.assert_decision(self.h.file(live_child, '/projects/live/x'), False, 'revoked')

    def test_pruning_never_removes_active_tasks(self):
        with mock.patch.object(registry, 'MAX_TASKS', 2):
            self.h.activate(contract('task-1', '/projects/1'))
            self.h.activate(contract('task-2', '/projects/2'))
            with self.assertRaises(registry.RegistryError):
                self.h.registry.propose(self.h.supervisor, contract('task-3', '/projects/3'), now_ns=self.h.tick())
        remaining = {task['contract']['task_id'] for task in self.h.registry.to_document()['tasks']}
        self.assertEqual(remaining, {'task-1', 'task-2'})

    def test_ticket_status_is_private_to_the_spawning_supervisor(self):
        self.h.activate(contract())
        child = self.h.ticket('task-a')
        other_supervisor = registry.Peer(proc(501, 's2'), SUPERVISOR)
        self.assertEqual(self.h.status(child, other_supervisor), 'none')
        self.assertEqual(self.h.status(child), 'pending')

    def test_rejected_proposal_cannot_be_confirmed(self):
        digest = self.h.registry.propose(self.h.supervisor, contract(), now_ns=self.h.tick())
        self.h.registry.reject_proposal(self.h.approver, digest, now_ns=self.h.tick())
        with self.assertRaises(registry.RegistryError):
            self.h.registry.confirm(self.h.approver, digest, now_ns=self.h.tick())

    def test_revision_must_advance_by_one_and_applies_atomically_to_bound_processes(self):
        self.h.activate(contract())
        agent = self.h.launch('task-a')
        self.assertTrue(self.h.file(agent, '/projects/a/README.md').allowed)
        for revision in [1, 3]:
            with self.subTest(revision=revision), self.assertRaises(registry.RegistryError):
                self.h.activate(contract(revision=revision, allow=[]))
        self.h.activate(contract(revision=2, allow=[]))
        outcome = self.h.file(agent, '/projects/a/README.md')
        self.h.assert_decision(outcome, False, 'outside_allow_scope')
        self.assertEqual(outcome.revision, 2)

    def test_child_task_must_be_an_attenuation_of_an_active_parent(self):
        self.h.activate(contract())
        wide_child = contract('task-child', '/projects/a', allow=[
            {'path': '/projects/a', 'scope': 'tree', 'operations': ['write']}])
        for task, parent in [(wide_child, 'task-a'), (contract('task-child', '/projects/a/src'), 'missing')]:
            with self.subTest(parent=parent), self.assertRaises(registry.RegistryError):
                self.h.registry.propose(self.h.supervisor, task, parent_task_id=parent, now_ns=self.h.tick())

    def test_revocation_propagates_to_descendant_tasks(self):
        self.h.activate(contract())
        self.h.activate(narrow_child(), parent_task_id='task-a')
        child_agent = self.h.launch('task-child')
        self.h.assert_decision(self.h.file(child_agent, '/projects/a/src/x'), True, 'allowed')
        self.h.registry.revoke(self.h.approver, 'task-a', now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(child_agent, '/projects/a/src/x'), False, 'revoked')

    def test_parent_revision_that_no_longer_covers_child_revokes_child(self):
        self.h.activate(contract())
        self.h.activate(narrow_child(), parent_task_id='task-a')
        child_agent = self.h.launch('task-child')
        self.h.activate(contract(revision=2, allow=[
            {'path': '/projects/a', 'scope': 'tree', 'operations': ['read']}]))
        self.h.assert_decision(self.h.file(child_agent, '/projects/a/src/x'), False, 'revoked')

    def test_rejections_do_not_echo_untrusted_values(self):
        marker = 'SYNTHETIC-PRIVATE-MARKER'
        for call in [lambda: self.h.registry.confirm(self.h.approver, marker, now_ns=self.h.tick()),
                     lambda: self.h.registry.register_launch(self.h.supervisor, marker, AGENT_IMAGE, self.h.spawn(),
                                                             now_ns=self.h.tick()),
                     lambda: self.h.registry.revoke(self.h.supervisor, marker, now_ns=self.h.tick())]:
            with self.subTest(call=call), self.assertRaises(registry.RegistryError) as caught:
                call()
            self.assertNotIn(marker, str(caught.exception))


def narrow_child():
    return contract('task-child', '/projects/a/src', expires_at_ns=10**5, allow=[
        {'path': '/projects/a/src', 'scope': 'tree', 'operations': ['read', 'write']}],
        deny=[{'path': '/projects/a/private', 'scope': 'tree', 'operations': ['read', 'write', 'execute']}])


class GrantTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())
        self.agent = self.h.launch('task-a')

    def pending(self):
        return self.h.registry.pending_requests(self.h.approver)

    def test_blocked_access_becomes_one_pending_request_and_approval_allows_retry(self):
        for unused in range(3):
            self.h.assert_decision(self.h.file(self.agent, '/projects/a/docs/x.md', ('write',)),
                                   False, 'outside_allow_scope')
        requests = self.pending()
        self.assertEqual(len(requests), 1)
        self.assertEqual((requests[0].task_id, requests[0].operations), ('task-a', frozenset({'write'})))
        self.h.registry.approve_request(self.h.approver, requests[0].request_id,
                                        expires_at_ns=self.h.clock + 50, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(self.agent, '/projects/a/docs/x.md', ('write',)), True, 'granted')
        self.assertEqual(self.pending(), ())
        self.h.tick(50)
        self.h.assert_decision(self.h.file(self.agent, '/projects/a/docs/x.md', ('write',)),
                               False, 'outside_allow_scope')

    def test_grant_covers_only_the_exact_path_operations_and_task(self):
        self.h.activate(contract('task-b', '/projects/b'))
        other_agent = self.h.launch('task-b')
        self.h.file(self.agent, '/projects/a/docs/x.md', ('write',))
        request = self.pending()[0]
        self.h.registry.approve_request(self.h.approver, request.request_id,
                                        expires_at_ns=10**5, now_ns=self.h.tick())
        for process, path, operations in [(self.agent, '/projects/a/docs/y.md', ('write',)),
                                          (self.agent, '/projects/a/docs/x.md', ('execute',)),
                                          (other_agent, '/projects/a/docs/x.md', ('write',))]:
            with self.subTest(path=path, operations=operations):
                self.assertFalse(self.h.file(process, path, operations).allowed)

    def test_sensitive_and_explicitly_denied_targets_never_become_requests(self):
        for path in ['/projects/a/.env', '/projects/a/private/key.txt']:
            self.assertFalse(self.h.file(self.agent, path).allowed)
        self.assertEqual(self.pending(), ())

    def test_approval_is_limited_by_role_contract_lifetime_and_request_existence(self):
        self.h.file(self.agent, '/projects/a/docs/x.md', ('write',))
        request = self.pending()[0]
        for peer, request_id, expiry in [(self.h.supervisor, request.request_id, 500),
                                         (self.h.approver, 'req-missing', 500),
                                         (self.h.approver, request.request_id, 10**6 + 1),
                                         (self.h.approver, request.request_id, self.h.clock)]:
            with self.subTest(request_id=request_id, expiry=expiry), self.assertRaises(registry.RegistryError):
                self.h.registry.approve_request(peer, request_id, expires_at_ns=expiry, now_ns=self.h.tick())
        self.h.registry.reject_request(self.h.approver, request.request_id, now_ns=self.h.tick())
        self.assertEqual(self.pending(), ())

    def test_revision_change_discards_grants_and_pending_requests(self):
        self.h.file(self.agent, '/projects/a/docs/x.md', ('write',))
        self.h.registry.approve_request(self.h.approver, self.pending()[0].request_id,
                                        expires_at_ns=10**5, now_ns=self.h.tick())
        self.h.file(self.agent, '/projects/a/docs/y.md', ('write',))
        self.h.activate(contract(revision=2))
        self.assertEqual(self.pending(), ())
        self.h.assert_decision(self.h.file(self.agent, '/projects/a/docs/x.md', ('write',)),
                               False, 'outside_allow_scope')

    def test_pending_request_queue_is_bounded(self):
        h = Harness(self, max_pending_requests=2)
        h.activate(contract())
        agent = h.launch('task-a')
        for index in range(4):
            h.file(agent, '/projects/a/docs/%d.md' % index, ('write',))
        self.assertEqual(len(h.registry.pending_requests(h.approver)), 2)
        self.assertEqual(h.registry.to_document()['dropped_requests'], 2)

    def test_outside_workspace_denials_are_not_grantable_requests(self):
        self.assertFalse(self.h.file(self.agent, '/Users/someone/notes.txt').allowed)
        self.assertEqual(self.pending(), ())

    def test_child_grant_is_bounded_by_the_parent_and_dropped_by_a_parent_revision(self):
        reader = contract('task-reader', '/projects/a', expires_at_ns=10**5,
                          allow=[{'path': '/projects/a/src', 'scope': 'tree', 'operations': ['read']}])
        self.h.activate(reader, parent_task_id='task-a')
        child_agent = self.h.launch('task-reader')
        self.h.file(child_agent, '/projects/a/README.md')
        self.h.file(child_agent, '/projects/a/src/tool', ('execute',))
        by_operations = {request.operations: request for request in self.pending()}
        with self.assertRaises(registry.RegistryError):
            self.h.registry.approve_request(self.h.approver, by_operations[frozenset({'execute'})].request_id,
                                            expires_at_ns=10**5, now_ns=self.h.tick())
        self.h.registry.approve_request(self.h.approver, by_operations[frozenset({'read'})].request_id,
                                        expires_at_ns=10**5, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(child_agent, '/projects/a/README.md'), True, 'granted')
        self.h.activate(contract(revision=2))
        self.h.assert_decision(self.h.file(child_agent, '/projects/a/README.md'), False, 'outside_allow_scope')

    def test_only_approvers_can_list_requests(self):
        with self.assertRaises(registry.RegistryError):
            self.h.registry.pending_requests(self.h.supervisor)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())
        self.agent = self.h.launch('task-a')

    def test_supervisor_exit_interrupts_owned_tasks_and_their_children(self):
        self.h.activate(narrow_child(), parent_task_id='task-a')
        child_agent = self.h.launch('task-child')
        waiting = self.h.ticket('task-a')
        self.h.registry.on_exit(self.h.supervisor.process, now_ns=self.h.tick())
        for agent in [self.agent, child_agent]:
            self.h.assert_decision(self.h.file(agent, '/projects/a/src/x'), False, 'interrupted')
        # The orphaned, still waiting child can never exec into the task.
        self.h.assert_decision(self.h.exec_child(waiting)[1], False, 'launch_ticket_closed')

    def test_interruption_never_downgrades_a_revocation(self):
        self.h.activate(narrow_child(), parent_task_id='task-a')
        child_agent = self.h.launch('task-child')
        self.h.registry.revoke(self.h.supervisor, 'task-child', now_ns=self.h.tick())
        self.h.registry.on_exit(self.h.supervisor.process, now_ns=self.h.tick())
        self.h.assert_decision(self.h.file(child_agent, '/projects/a/src/x'), False, 'revoked')
        states = {task['contract']['task_id']: task['state'] for task in self.h.registry.to_document()['tasks']}
        self.assertEqual(states, {'task-a': 'interrupted', 'task-child': 'revoked'})

    def test_proposals_die_with_their_proposer(self):
        digest = self.h.registry.propose(self.h.supervisor, contract('task-b', '/projects/b'),
                                         now_ns=self.h.tick())
        self.h.registry.on_exit(self.h.supervisor.process, now_ns=self.h.tick())
        with self.assertRaises(registry.RegistryError):
            self.h.registry.confirm(self.h.approver, digest, now_ns=self.h.tick())

    def test_interrupted_task_cannot_be_revised_or_relaunched(self):
        self.h.registry.on_exit(self.h.supervisor.process, now_ns=self.h.tick())
        new_supervisor = registry.Peer(proc(501, 's2'), SUPERVISOR)
        with self.assertRaises(registry.RegistryError):
            self.h.registry.propose(new_supervisor, contract(revision=2), now_ns=self.h.tick())

    def test_contract_expiry_denies_later_access(self):
        h = Harness(self)
        h.activate(contract(expires_at_ns=200))
        agent = h.launch('task-a')
        h.clock = 200
        h.assert_decision(h.file(agent, '/projects/a/x'), False, 'expired')

    def test_clock_regression_fails_closed_only_for_enrolled_processes(self):
        stale = self.h.clock - 10
        outcome = self.h.registry.authorize_file(self.agent, LAUNCHD, '/projects/a/x', frozenset({'read'}),
                                                 now_ns=stale)
        self.h.assert_decision(outcome, False, 'clock_regression')
        outcome = self.h.registry.authorize_file(proc(900, 'x'), LAUNCHD, '/x', frozenset({'read'}),
                                                 now_ns=stale)
        self.assertEqual(outcome.route, 'not_enrolled')
        with self.assertRaises(registry.RegistryError):
            self.h.registry.revoke(self.h.supervisor, 'task-a', now_ns=stale)

    def test_invalid_event_inputs_fail_closed_for_enrolled_processes(self):
        for path, operations in [('/projects/a/../b', {'read'}), ('/projects/a/x\ny', {'read'}),
                                 ('/projects/a/x', {'network'}), ('/projects/a/x', set())]:
            with self.subTest(path=path, operations=operations):
                outcome = self.h.registry.authorize_file(self.agent, LAUNCHD, path, frozenset(operations),
                                                         now_ns=self.h.tick())
                self.h.assert_decision(outcome, False, 'invalid_input')
        for process, now_ns in [((self.agent.pid, 'exec1'), self.h.tick()), (self.agent, True)]:
            with self.subTest(process=process, now_ns=now_ns):
                outcome = self.h.registry.authorize_file(process, LAUNCHD, '/projects/a/x', frozenset({'read'}),
                                                         now_ns=now_ns)
                self.h.assert_decision(outcome, False, 'invalid_input', route='invalid')

    def test_unusual_host_paths_do_not_block_unrelated_processes(self):
        outcome = self.h.registry.authorize_file(proc(900, 'x'), LAUNCHD, '/tmp/odd\nname',
                                                 frozenset({'read'}), now_ns=self.h.tick())
        self.h.assert_decision(outcome, True, 'not_enrolled', route='not_enrolled')


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())
        self.agent = self.h.launch('task-a')
        self.h.file(self.agent, '/projects/a/docs/x.md', ('write',))

    def restore(self, boot_id='boot-1', now_ns=None, document=None):
        document = self.h.registry.to_document() if document is None else document
        return registry.Registry.restore(json.loads(json.dumps(document)), self.h.config, boot_id=boot_id,
                                         now_ns=self.h.tick() if now_ns is None else now_ns)

    def test_same_boot_restart_interrupts_tasks_and_quarantines_known_processes(self):
        restored = self.restore()
        now = self.h.tick()
        outcome = restored.authorize_file(self.agent, LAUNCHD, '/projects/a/x', frozenset({'read'}), now_ns=now)
        self.h.assert_decision(outcome, False, 'tracking_lost')
        missed_child = proc(6000, 'missed')
        outcome = restored.authorize_file(missed_child, self.agent, '/projects/a/x', frozenset({'read'}),
                                          now_ns=now + 1)
        self.h.assert_decision(outcome, False, 'unattributed_descendant')
        states = {task['contract']['task_id']: task['state'] for task in restored.to_document()['tasks']}
        self.assertEqual(states, {'task-a': 'interrupted'})
        self.assertEqual(restored.pending_requests(self.h.approver), ())
        with self.assertRaises(registry.RegistryError):
            restored.register_launch(self.h.supervisor, 'task-a', AGENT_IMAGE, proc(9000, 'fork'), now_ns=now + 2)

    def test_restart_closes_waiting_tickets_and_drops_unconfirmed_proposals(self):
        digest = self.h.registry.propose(self.h.supervisor, contract('task-b', '/projects/b'), now_ns=self.h.tick())
        waiting = self.h.ticket('task-a')
        restored = self.restore()
        with self.assertRaises(registry.RegistryError):
            restored.confirm(self.h.approver, digest, now_ns=self.h.tick())
        # The ticket survives only to refuse the exec: the waiting child never runs unbound.
        self.assertEqual(restored.ticket_status(self.h.supervisor, waiting, now_ns=self.h.tick()), 'revoked')
        outcome = restored.on_exec(waiting, self.h.supervisor.process, proc(waiting.pid, 'e'), AGENT_IMAGE,
                                   now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'launch_ticket_closed')

    def test_new_boot_drops_tickets(self):
        self.h.ticket('task-a')
        restored = self.restore(boot_id='boot-2', now_ns=5)
        self.assertEqual(restored.to_document()['tickets'], [])

    def test_restart_drops_bound_tickets_and_keeps_the_rest_closed(self):
        # setUp's launch left a bound ticket: after a restart it reports "none", never
        # "bound", since protection of the running agent is lost. A denied child is still
        # alive before exec; its retry must stay closed across the restart.
        denied = self.h.ticket('task-a')
        self.h.exec_child(denied, image=OTHER_IMAGE)
        waiting = self.h.ticket('task-a')
        restored = self.restore()
        self.assertEqual([item['state'] for item in restored.to_document()['tickets']], ['revoked', 'revoked'])
        for child, status in [(proc(self.agent.pid, 'fork'), 'none'), (denied, 'revoked'), (waiting, 'revoked')]:
            with self.subTest(child=child):
                self.assertEqual(restored.ticket_status(self.h.supervisor, child, now_ns=self.h.tick()), status)
        retry = restored.on_exec(denied, self.h.supervisor.process, proc(denied.pid, 'retry'), AGENT_IMAGE,
                                 now_ns=self.h.tick())
        self.h.assert_decision(retry, False, 'launch_ticket_closed')

    def test_ticket_expiry_saturates_so_the_document_stays_restorable(self):
        h = Harness(self, ticket_ttl_ns=policy.MAX_INTEGER)
        h.activate(contract())
        h.ticket('task-a')
        self.assertEqual(h.registry.to_document()['tickets'][0]['expires_at_ns'], policy.MAX_INTEGER)
        registry.Registry.restore(json.loads(json.dumps(h.registry.to_document())), h.config, boot_id='boot-1',
                                  now_ns=h.tick())

    def test_new_boot_interrupts_tasks_without_quarantining_reused_pids(self):
        restored = self.restore(boot_id='boot-2', now_ns=5)
        outcome = restored.authorize_file(self.agent, LAUNCHD, '/projects/b/x', frozenset({'read'}), now_ns=6)
        self.assertEqual(outcome.route, 'not_enrolled')
        self.assertEqual(restored.to_document()['tasks'][0]['state'], 'interrupted')

    def test_new_task_can_launch_after_restart(self):
        restored = self.restore()
        self.h.registry = restored
        self.h.activate(contract('task-c', '/projects/c'))
        agent = self.h.launch('task-c')
        self.h.assert_decision(self.h.file(agent, '/projects/c/x'), True, 'allowed')

    def test_same_boot_clock_regression_is_rejected(self):
        with self.assertRaises(registry.RegistryError):
            self.restore(now_ns=self.h.clock - 1)

    def test_revoked_state_survives_restart(self):
        self.h.registry.revoke(self.h.supervisor, 'task-a', now_ns=self.h.tick())
        restored = self.restore()
        self.assertEqual(restored.to_document()['tasks'][0]['state'], 'revoked')

    def test_malformed_documents_are_rejected(self):
        valid = self.h.registry.to_document()
        mutations = [lambda d: d.update(schema='other'), lambda d: d.update(extra=True),
                     lambda d: d.pop('bindings'), lambda d: d.update(sequence=-1),
                     lambda d: d['tasks'][0].update(state='active-ish'),
                     lambda d: d['bindings'].append({'process': [1, 'x'], 'task_id': 'missing'}),
                     lambda d: d['tasks'].append(d['tasks'][0]),
                     lambda d: d['bindings'][0].update(task_id=['task-a']),
                     lambda d: d['bindings'][0].pop('chain'),
                     lambda d: d.update(version=1), lambda d: d.pop('tickets'),
                     lambda d: d['tickets'][0].update(state='open'),
                     lambda d: d['tickets'][0].update(task_id='missing'),
                     lambda d: d['tickets'][0].update(image=['/opt/agents/agent']),
                     lambda d: d['tickets'][0].update(expires_at_ns=-1),
                     lambda d: d['tickets'][0].update(extra=1),
                     lambda d: d['tickets'].append(d['tickets'][0])]
        for mutation in mutations:
            document = json.loads(json.dumps(valid))
            mutation(document)
            with self.subTest(mutation=mutation), self.assertRaises(registry.RegistryError):
                self.restore(document=document)

    def test_document_contains_no_request_paths_in_records(self):
        text = json.dumps(self.h.registry.to_document()['records'])
        self.assertNotIn('/projects/', text)


class WriteAheadTests(unittest.TestCase):
    """State that lets a process run bound (a ticket, an exec binding) is saved before the answer.

    The persist hook stands in for the durable store: restoring from the last document it
    received is what a crash right after the answer would leave behind.
    """

    def setUp(self):
        self.h = Harness(self)
        self.saved = []
        self.failing = False
        self.h.registry = registry.Registry(self.h.config, boot_id='boot-1', now_ns=self.h.clock,
                                            persist=self.persist)
        self.h.activate(contract())

    def persist(self, document):
        if self.failing:
            raise OSError('synthetic store failure')
        self.saved.append(json.loads(json.dumps(document)))

    def crash_restore(self):
        return registry.Registry.restore(self.saved[-1], self.h.config, boot_id='boot-1', now_ns=self.h.tick())

    def test_ticket_is_saved_before_register_launch_returns(self):
        waiting = self.h.ticket('task-a')
        self.assertEqual([item['child'] for item in self.saved[-1]['tickets']], [[waiting.pid, waiting.generation]])
        restored = self.crash_restore()
        self.assertEqual(restored.ticket_status(self.h.supervisor, waiting, now_ns=self.h.tick()), 'revoked')
        outcome = restored.on_exec(waiting, self.h.supervisor.process, proc(waiting.pid, 'e'), AGENT_IMAGE,
                                   now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'launch_ticket_closed')

    def test_launch_binding_is_saved_before_the_exec_is_answered(self):
        agent = self.h.launch('task-a')
        bound = {tuple(item['process']) for item in self.saved[-1]['bindings']}
        self.assertIn((agent.pid, agent.generation), bound)
        restored = self.crash_restore()
        outcome = restored.authorize_file(agent, self.h.supervisor.process, '/projects/a/x', frozenset({'read'}),
                                          now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'tracking_lost')

    def test_exec_binding_of_a_bound_process_is_saved_before_the_answer(self):
        agent = self.h.launch('task-a')
        target = proc(agent.pid, 'exec2')
        outcome = self.h.registry.on_exec(agent, self.h.supervisor.process, target,
                                          registry.ExecutableImage('/projects/a/bin/check', 'sha256-check'),
                                          now_ns=self.h.tick())
        self.h.assert_decision(outcome, True, 'allowed')
        restored = self.crash_restore()
        # Without the save, the new image's parent (the supervisor) would route it not_enrolled.
        outcome = restored.authorize_file(target, self.h.supervisor.process, '/projects/b/x', frozenset({'read'}),
                                          now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'tracking_lost')

    def test_failed_save_revokes_the_new_ticket(self):
        self.failing = True
        child = self.h.spawn()
        with self.assertRaisesRegex(registry.RegistryError, 'registry state could not be saved'):
            self.h.registry.register_launch(self.h.supervisor, 'task-a', AGENT_IMAGE, child, now_ns=self.h.tick())
        self.assertEqual(self.h.status(child), 'revoked')
        target, outcome = self.h.exec_child(child)
        self.h.assert_decision(outcome, False, 'launch_ticket_closed')

    def test_failed_save_denies_the_launch_exec_and_leaves_nothing_bound(self):
        child = self.h.ticket('task-a')
        self.failing = True
        target, outcome = self.h.exec_child(child)
        self.h.assert_decision(outcome, False, 'state_not_saved')
        self.assertEqual(self.h.status(child), 'denied')
        self.assertEqual(self.h.registry.to_document()['bindings'], [])
        self.assertEqual(self.h.registry.records()[-1].reason, 'state_not_saved')

    def test_failed_save_denies_a_bound_exec_and_keeps_the_process_bound(self):
        agent = self.h.launch('task-a')
        self.failing = True
        target = proc(agent.pid, 'exec2')
        outcome = self.h.registry.on_exec(agent, self.h.supervisor.process, target,
                                          registry.ExecutableImage('/projects/a/bin/check', 'sha256-check'),
                                          now_ns=self.h.tick())
        self.h.assert_decision(outcome, False, 'state_not_saved')
        bound = {tuple(item['process']) for item in self.h.registry.to_document()['bindings']}
        self.assertNotIn((target.pid, target.generation), bound)
        self.h.assert_decision(self.h.file(agent, '/projects/a/README.md'), True, 'allowed')

    def test_checkpoint_saves_through_the_hook_only(self):
        count = len(self.saved)
        self.h.registry.checkpoint()
        self.assertEqual(len(self.saved), count + 1)
        self.failing = True
        with self.assertRaisesRegex(registry.RegistryError, 'registry state could not be saved'):
            self.h.registry.checkpoint()
        with self.assertRaisesRegex(registry.RegistryError, 'registry has no persist hook'):
            registry.Registry(self.h.config, boot_id='boot-1', now_ns=1).checkpoint()

    def test_direct_save_is_refused_for_a_registry_with_a_hook(self):
        # A second writer could replace a newer write-ahead document with an older snapshot.
        with self.assertRaisesRegex(registry.RegistryError, 'registry saves through its persist hook'):
            registry.save_registry('/nonexistent/registry.json', self.h.registry)

    def test_interrupting_hook_rolls_back_before_propagating(self):
        agent = self.h.launch('task-a')
        target = proc(agent.pid, 'exec2')

        def interrupted(document):
            raise KeyboardInterrupt
        self.h.registry._persist = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.h.registry.on_exec(agent, self.h.supervisor.process, target,
                                    registry.ExecutableImage('/projects/a/bin/check', 'sha256-check'),
                                    now_ns=self.h.tick())
        bound = {tuple(item['process']) for item in self.h.registry.to_document()['bindings']}
        self.assertNotIn((target.pid, target.generation), bound)
        child = self.h.spawn()
        with self.assertRaises(KeyboardInterrupt):
            self.h.registry.register_launch(self.h.supervisor, 'task-a', AGENT_IMAGE, child, now_ns=self.h.tick())
        self.h.registry._persist = self.persist
        self.assertEqual(self.h.status(child), 'revoked')

    def test_denied_exec_is_not_saved(self):
        agent = self.h.launch('task-a')
        count = len(self.saved)
        outcome = self.h.registry.on_exec(agent, self.h.supervisor.process, proc(agent.pid, 'exec2'),
                                          registry.ExecutableImage('/projects/a/private/tool', 'sha256-tool'),
                                          now_ns=self.h.tick())
        self.assertFalse(outcome.allowed)
        self.assertEqual(len(self.saved), count)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(os.path.realpath(self.temporary.name)) / 'store'
        self.directory.mkdir(mode=0o700)
        self.path = str(self.directory / 'registry.json')

    def tearDown(self):
        self.temporary.cleanup()

    def load(self):
        return registry.load_registry(self.path, self.h.config, boot_id='boot-1', now_ns=self.h.tick())

    def test_save_document_is_what_a_persist_hook_uses(self):
        hooked = registry.Registry(self.h.config, boot_id='boot-1', now_ns=self.h.tick(),
                                   persist=lambda document: registry.save_document(self.path, document))
        hooked.checkpoint()
        self.assertEqual(self.load().to_document()['tasks'], [])
        with self.assertRaises(registry.RegistryError):
            registry.save_document(self.path, {'records': 'x' * (4 * 2**20)})

    def test_save_and_load_roundtrip_is_private_and_atomic(self):
        registry.save_registry(self.path, self.h.registry)
        registry.save_registry(self.path, self.h.registry)
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(sorted(os.listdir(self.directory)), ['registry.json'])
        restored = self.load()
        self.assertEqual(restored.to_document()['tasks'][0]['contract']['task_id'], 'task-a')

    def test_rejects_symlinked_hardlinked_and_permissive_state(self):
        registry.save_registry(self.path, self.h.registry)
        target = self.directory / 'real.json'
        os.replace(self.path, target)
        os.symlink(target, self.path)
        with self.assertRaises(registry.RegistryError):
            self.load()
        os.unlink(self.path)
        os.link(target, self.path)
        with self.assertRaises(registry.RegistryError):
            self.load()
        os.unlink(target)
        os.chmod(self.path, 0o644)
        with self.assertRaises(registry.RegistryError):
            self.load()

    def test_refuses_group_or_world_writable_directory(self):
        os.chmod(self.directory, 0o770)
        with self.assertRaises(registry.RegistryError):
            registry.save_registry(self.path, self.h.registry)

    def test_rejects_duplicate_keys_and_oversized_state(self):
        text = json.dumps(self.h.registry.to_document())
        for body in [text.replace('"sequence":', '"sequence": 1, "sequence":', 1), ' ' * (4 * 2**20 + 1)]:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write(body)
            with self.subTest(size=len(body)), self.assertRaises(registry.RegistryError):
                self.load()


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.h.activate(contract())
        self.agent = self.h.launch('task-a')

    def test_records_use_sanitized_targets(self):
        self.h.file(self.agent, '/projects/a/src/view.py')
        self.h.file(self.agent, '/projects/a/.env')
        self.h.file(self.agent, '/Users/someone/notes.txt')
        targets = [record.target for record in self.h.registry.records()[-3:]]
        self.assertEqual(targets, ['src/view.py', 'withheld', 'outside_workspace'])
        self.assertNotIn('/Users/', repr(self.h.registry.records()))

    def test_record_buffer_is_bounded_and_counts_losses(self):
        h = Harness(self, max_records=4)
        h.activate(contract())
        agent = h.launch('task-a')
        for unused in range(10):
            h.file(agent, '/projects/a/x')
        self.assertEqual(len(h.registry.records()), 4)
        self.assertGreater(h.registry.to_document()['dropped_records'], 0)

    def test_outcome_representation_contains_no_paths_or_process_tokens(self):
        outcome = self.h.file(self.agent, '/projects/a/src/view.py')
        self.assertFalse(outcome.cacheable)
        self.assertEqual(outcome.enforcement, 'policy_only')
        self.assertNotIn('/projects/', repr(outcome))
        self.assertNotIn('exec1', repr(outcome))


if __name__ == '__main__':
    unittest.main()
