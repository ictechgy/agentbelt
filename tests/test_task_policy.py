"""Synthetic R1 policy decisions; no filesystem, credentials, network or ES access."""
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import task_policy as policy


def contract_document(task_id='task-a', workspace='/projects/a'):
    return {
        'schema_version': 1,
        'task_id': task_id,
        'revision': 1,
        'workspace': workspace,
        'valid_from_ns': 100,
        'expires_at_ns': 1000,
        'allow': [
            {'path': workspace, 'scope': 'tree', 'operations': ['read']},
            {'path': workspace + '/src/login', 'scope': 'tree', 'operations': ['write']},
            {'path': workspace + '/tests/login', 'scope': 'tree', 'operations': ['write']},
            {'path': workspace + '/bin/check', 'scope': 'exact', 'operations': ['execute']},
        ],
        'deny': [
            {'path': workspace + '/private', 'scope': 'tree',
             'operations': ['read', 'write', 'execute']},
        ],
    }


class ContractTests(unittest.TestCase):
    def test_contract_roundtrip_keeps_policy_and_immutable_rules(self):
        contract = policy.load_contract(json.dumps(contract_document()))
        self.assertEqual(policy.contract_from_dict(policy.contract_to_dict(contract)), contract)
        with self.assertRaises(FrozenInstanceError):
            contract.revision = 2
        with self.assertRaises(AttributeError):
            contract.allow[0].operations.add('write')

    def test_input_mutation_cannot_change_a_loaded_contract(self):
        document = contract_document()
        contract = policy.contract_from_dict(document)
        document['allow'][0]['operations'].append('write')
        document['allow'].clear()
        self.assertEqual(contract.allow[0].operations, frozenset({'read'}))

    def test_rejects_missing_unknown_and_unsupported_fields(self):
        for mutation in [lambda d: d.pop('deny'),
                         lambda d: d.update(schema_version=2),
                         lambda d: d.update(model_approved=True),
                         lambda d: d['allow'][0].update(priority=100),
                         lambda d: d['allow'][0].update(scope='glob')]:
            with self.subTest(mutation=mutation):
                document = contract_document()
                mutation(document)
                with self.assertRaises(policy.PolicyError):
                    policy.contract_from_dict(document)

    def test_rejects_coercion_nonfinite_and_invalid_lifetimes(self):
        for field, value in [('schema_version', True), ('revision', True), ('revision', 0),
                             ('revision', '1'), ('valid_from_ns', -1), ('valid_from_ns', 1000),
                             ('expires_at_ns', 100), ('expires_at_ns', float('inf')),
                             ('expires_at_ns', float('nan')), ('expires_at_ns', 2**63),
                             ('task_id', ''), ('task_id', '../task'), ('task_id', 'a' * 129),
                             ('allow', {}), ('deny', None)]:
            with self.subTest(field=field, value=value):
                document = contract_document()
                document[field] = value
                with self.assertRaises(policy.PolicyError):
                    policy.contract_from_dict(document)

    def test_rejects_ambiguous_paths_without_resolving_host_files(self):
        for path in ['relative', '/projects/a/../b', '/projects/./a', '/projects//a',
                     '//projects/a', '/projects/a/', '/projects/a\x00x', '/projects/a\nx',
                     '/projects/a/' + 'a' * 4096, '/projects/a/\ud800']:
            with self.subTest(path=repr(path)):
                document = contract_document()
                document['allow'][0]['path'] = path
                with self.assertRaises(policy.PolicyError):
                    policy.contract_from_dict(document)

    def test_cannot_allow_files_outside_workspace_or_use_root_workspace(self):
        for workspace, allowed in [('/projects/a', '/'), ('/projects/a', '/projects/ab'),
                                   ('/projects/a', '/usr/bin'), ('/', '/')]:
            with self.subTest(workspace=workspace, allowed=allowed):
                document = contract_document(workspace=workspace)
                document['allow'][0]['path'] = allowed
                with self.assertRaises(policy.PolicyError):
                    policy.contract_from_dict(document)

    def test_rejects_invalid_or_duplicate_operation_sets(self):
        for operations in [[], ['read', 'read'], ['network'], ['READ'], 'read', [True]]:
            with self.subTest(operations=operations):
                document = contract_document()
                document['allow'][0]['operations'] = operations
                with self.assertRaises(policy.PolicyError):
                    policy.contract_from_dict(document)

    def test_json_duplicates_constants_and_oversized_input_are_rejected(self):
        valid = json.dumps(contract_document())
        cases = ['[]', 'null', '{', valid.replace('"revision": 1', '"revision": 1, "revision": 2'),
                 valid.replace('"path": "/projects/a"',
                               '"path": "/projects/a", "path": "/projects/b"'),
                 valid.replace('1000', 'NaN'), valid.replace('1000', 'Infinity'), ' ' * 65537]
        for document in cases:
            with self.subTest(document=document[:30]), self.assertRaises(policy.PolicyError):
                policy.load_contract(document)

    def test_errors_do_not_echo_untrusted_values(self):
        marker = 'SYNTHETIC_PRIVATE_VALUE'
        with self.assertRaises(policy.PolicyError) as caught:
            policy.load_contract('{"' + marker + '":')
        self.assertNotIn(marker, str(caught.exception))
        document = contract_document()
        document[marker] = marker
        with self.assertRaises(policy.PolicyError) as caught:
            policy.contract_from_dict(document)
        self.assertNotIn(marker, str(caught.exception))


    def test_example_contract_matches_the_executable_schema(self):
        text = (Path(__file__).resolve().parents[1] / 'examples/task-policy.json').read_text()
        contract = policy.load_contract(text)
        self.assertEqual(contract.task_id, 'login-ui-example')
        self.assertEqual(contract.workspace, '/synthetic/project')

    def test_direct_construction_rejects_mutable_and_mistyped_authority(self):
        contract = policy.contract_from_dict(contract_document())
        process = policy.ProcessIdentity(101, 'boot.start.exec')
        for constructor in [lambda: replace(contract, allow=list(contract.allow)),
                            lambda: policy.TaskState(contract, revoked='false'),
                            lambda: policy.ProcessIdentity(True, 'generation'),
                            lambda: policy.ProcessIdentity(101, ''),
                            lambda: policy.ProcessIdentity(2**31, 'generation'),
                            lambda: policy.ProcessBinding(process, 'task-a', True),
                            lambda: policy.PathRule('/projects/a', 'tree', {'read'}),
                            lambda: policy.FileAccess(process, '/projects/a', frozenset({'read'}), []),
                            lambda: replace(contract, allow=contract.allow[:1] * 129)]:
            with self.subTest(constructor=constructor), self.assertRaises(policy.PolicyError):
                constructor()

    def test_deep_json_and_byte_limit_return_a_sanitized_policy_error(self):
        for text in ['[' * 2000 + ']' * 2000, '"' + '가' * 30000 + '"', '"\ud800"']:
            with self.subTest(size=len(text)), self.assertRaises(policy.PolicyError):
                policy.load_contract(text)


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.contract = policy.contract_from_dict(contract_document())
        self.state = policy.TaskState(self.contract)
        self.process = policy.ProcessIdentity(101, 'boot1.start1.exec0')
        self.binding = policy.ProcessBinding(self.process, 'task-a', 1)

    def access(self, path='/projects/a/src/login/view.py', operations=('read',), **kwargs):
        return policy.FileAccess(self.process, path, frozenset(operations), **kwargs)

    def decide(self, access=None, **kwargs):
        return policy.evaluate(kwargs.pop('state', self.state),
                               kwargs.pop('binding', self.binding),
                               access if access is not None else self.access(),
                               now_ns=kwargs.pop('now_ns', 200), **kwargs)

    def test_read_write_and_execution_have_distinct_scopes(self):
        for path, operations, allowed in [
            ('/projects/a/src/login/view.py', ('read',), True),
            ('/projects/a/src/login/view.py', ('write',), True),
            ('/projects/a/tests/login/test.py', ('read', 'write'), True),
            ('/projects/a/README.md', ('read',), True),
            ('/projects/a/README.md', ('write',), False),
            ('/projects/a/bin/check', ('execute',), True),
            ('/projects/a/bin/check/child', ('execute',), False),
            ('/projects/a/src/login/view.py', ('execute',), False),
        ]:
            with self.subTest(path=path, operations=operations):
                self.assertEqual(self.decide(self.access(path, operations)).allowed, allowed)

    def test_all_operations_in_combined_request_must_be_allowed(self):
        result = self.decide(self.access('/projects/a/README.md', ('read', 'write')))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, 'outside_allow_scope')

    def test_component_boundaries_prevent_prefix_confusion(self):
        for path in ['/projects/ab/source.py', '/projects/a-other/source.py',
                     '/projects/a/src/login-old/view.py']:
            with self.subTest(path=path):
                self.assertFalse(self.decide(self.access(path, ('write',))).allowed)

    def test_explicit_denial_overrides_allow_rules_regardless_of_order(self):
        broad = policy.PathRule('/projects/a', 'tree', frozenset({'read', 'write', 'execute'}))
        for rules in [(broad,) + self.contract.allow, self.contract.allow + (broad,)]:
            state = policy.TaskState(replace(self.contract, allow=rules))
            result = self.decide(self.access('/projects/a/private/data.txt'), state=state)
            self.assertFalse(result.allowed)
            self.assertEqual(result.reason, 'explicit_deny')

    def test_sensitive_components_cannot_be_reallowed(self):
        broad = policy.PathRule('/projects/a', 'tree', frozenset({'read', 'write', 'execute'}))
        state = policy.TaskState(replace(self.contract, allow=(broad,)))
        for suffix in ['.env', '.Env.local', '.ssh/config', 'nested/AUTH.JSON', 'nested/key.PEM',
                       'credentials/anything', 'secrets.txt', '.agents/mcp.json', '.zcode/settings',
                       'zcode.json', 'data.sqlite3', '.git/config', '.npmrc', 'id_rsa.pub']:
            for operation in ['read', 'write', 'execute']:
                with self.subTest(suffix=suffix, operation=operation):
                    result = self.decide(self.access('/projects/a/' + suffix, (operation,)), state=state)
                    self.assertFalse(result.allowed)
                    self.assertEqual(result.reason, 'sensitive_path')

    def test_identical_program_does_not_share_project_authority(self):
        # Executable paths deliberately are not authorization identities.
        other = policy.TaskState(policy.contract_from_dict(contract_document('task-b', '/projects/b')))
        other_process = policy.ProcessIdentity(202, 'boot1.start2.exec0')
        other_binding = policy.ProcessBinding(other_process, 'task-b', 1)
        for unused in range(3):
            self.assertTrue(self.decide().allowed)
            result = policy.evaluate(other, other_binding,
                                     policy.FileAccess(other_process, self.access().path, frozenset({'read'})),
                                     now_ns=200)
            self.assertFalse(result.allowed)
            self.assertFalse(result.cacheable)
            self.assertFalse(self.decide(state=other).allowed)

    def test_pid_reuse_or_exec_generation_change_requires_new_binding(self):
        for process in [policy.ProcessIdentity(101, 'boot1.start2.exec0'),
                        policy.ProcessIdentity(101, 'boot1.start1.exec1'),
                        policy.ProcessIdentity(102, 'boot1.start1.exec0')]:
            with self.subTest(process=process):
                result = self.decide(replace(self.access(), process=process))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, 'process_mismatch')

    def test_missing_binding_and_other_task_binding_are_denied(self):
        for binding, reason in [(None, 'unbound_process'),
                                (replace(self.binding, task_id='task-b'), 'task_mismatch')]:
            with self.subTest(reason=reason):
                result = self.decide(binding=binding)
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, reason)

    def test_claimed_task_id_is_metadata_and_cannot_mint_authority(self):
        forged = self.access('/projects/b/source.py', claimed_task_id='task-b')
        self.assertFalse(self.decide(forged).allowed)
        self.assertFalse(self.decide(forged, binding=None).allowed)
        own = self.access(claimed_task_id='task-b')
        self.assertTrue(self.decide(own).allowed)

    def test_revision_change_invalidates_old_binding_before_new_policy_applies(self):
        broad = policy.PathRule('/projects/a', 'tree', frozenset({'read', 'write'}))
        state = policy.TaskState(replace(self.contract, revision=2, allow=(broad,)))
        result = self.decide(self.access('/projects/a/README.md', ('write',)), state=state)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, 'revision_mismatch')
        self.assertTrue(self.decide(self.access('/projects/a/README.md', ('write',)), state=state,
                                    binding=replace(self.binding, revision=2)).allowed)

    def test_time_boundaries_and_revocation(self):
        for now_ns, allowed, reason in [(99, False, 'not_yet_valid'), (100, True, 'allowed'),
                                        (999, True, 'allowed'), (1000, False, 'expired')]:
            with self.subTest(now_ns=now_ns):
                result = self.decide(now_ns=now_ns)
                self.assertEqual((result.allowed, result.reason), (allowed, reason))
        result = self.decide(state=replace(self.state, revoked=True))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, 'revoked')

    def test_no_stored_allow_survives_a_narrower_policy(self):
        self.assertTrue(self.decide().allowed)
        state = policy.TaskState(replace(self.contract, revision=2, allow=()))
        self.assertFalse(self.decide(state=state, binding=replace(self.binding, revision=2)).allowed)

    def test_invalid_evaluation_inputs_cannot_return_allow(self):
        for now_ns in [True, -1, '200', float('nan'), 2**63]:
            with self.subTest(now_ns=now_ns):
                result = self.decide(now_ns=now_ns)
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, 'invalid_input')
        self.assertFalse(policy.evaluate(None, self.binding, self.access(), now_ns=200).allowed)
        self.assertFalse(policy.evaluate(self.state, {}, self.access(), now_ns=200).allowed)
        self.assertFalse(policy.evaluate(self.state, self.binding, {}, now_ns=200).allowed)

    def test_receipt_is_deterministic_uncached_and_does_not_claim_os_enforcement(self):
        result = self.decide()
        self.assertEqual(result, self.decide())
        self.assertFalse(result.cacheable)
        self.assertEqual(result.enforcement, 'policy_only')
        self.assertEqual(result.revision, 1)
        self.assertNotIn('/projects/', repr(result))
        self.assertNotIn('boot1', repr(result))

    def test_access_cannot_contain_unknown_operations_or_noncanonical_paths(self):
        for path, operations in [('/projects/a/../b', ('read',)), ('/projects/a', ()),
                                 ('/projects/a', ('network',))]:
            with self.subTest(path=path, operations=operations), self.assertRaises(policy.PolicyError):
                self.access(path, operations)


class AttenuationTests(unittest.TestCase):
    def setUp(self):
        self.parent = policy.contract_from_dict(contract_document())
        self.child = replace(self.parent, task_id='task-child', workspace='/projects/a/src/login',
                             valid_from_ns=200, expires_at_ns=800,
                             allow=(policy.PathRule('/projects/a/src/login', 'tree', frozenset({'read', 'write'})),))

    def test_child_can_narrow_paths_operations_and_lifetime(self):
        self.assertTrue(policy.is_attenuation(self.parent, self.child))
        exact = policy.PathRule('/projects/a/src/login/view.py', 'exact', frozenset({'read'}))
        self.assertTrue(policy.is_attenuation(self.parent, replace(self.child, allow=(exact,))))
        self.assertTrue(policy.is_attenuation(self.parent, replace(self.child, allow=())))

    def test_child_cannot_widen_time_workspace_or_operations(self):
        for child in [replace(self.child, valid_from_ns=99),
                      replace(self.child, expires_at_ns=1001),
                      replace(self.parent, task_id='task-child', workspace='/projects'),
                      replace(self.child, allow=(policy.PathRule('/projects/a/src/login', 'tree',
                                                               frozenset({'execute'})),)),
                      replace(self.child, task_id=self.parent.task_id)]:
            with self.subTest(child=child):
                self.assertFalse(policy.is_attenuation(self.parent, child))

    def test_child_cannot_remove_or_weaken_parent_denials(self):
        for deny in [(), (policy.PathRule('/projects/a/private', 'exact', frozenset({'read'})),)]:
            self.assertFalse(policy.is_attenuation(self.parent, replace(self.child, deny=deny)))
        stricter = policy.PathRule('/projects/a', 'tree', frozenset({'read', 'write', 'execute'}))
        self.assertTrue(policy.is_attenuation(self.parent, replace(self.child, deny=(stricter,))))

    def test_exact_allow_cannot_become_a_subtree_allow(self):
        exact = policy.PathRule('/projects/a/bin/check', 'exact', frozenset({'execute'}))
        parent = replace(self.parent, allow=(exact,))
        child = replace(parent, task_id='task-child', allow=(replace(exact, scope='tree'),))
        self.assertFalse(policy.is_attenuation(parent, child))

    def test_attenuation_preserves_denials_over_an_operation_path_matrix(self):
        parent_process = policy.ProcessIdentity(1, 'parent')
        child_process = policy.ProcessIdentity(2, 'child')
        parent_binding = policy.ProcessBinding(parent_process, self.parent.task_id, 1)
        child_binding = policy.ProcessBinding(child_process, self.child.task_id, 1)
        for suffix in ['src/login', 'src/login/view.py', 'src/login/.env', 'README.md',
                       'private/file', 'bin/check', 'src/login-other/file']:
            for operation in ['read', 'write', 'execute']:
                path = '/projects/a/' + suffix
                parent_result = policy.evaluate(policy.TaskState(self.parent), parent_binding,
                    policy.FileAccess(parent_process, path, frozenset({operation})), now_ns=300)
                child_result = policy.evaluate(policy.TaskState(self.child), child_binding,
                    policy.FileAccess(child_process, path, frozenset({operation})), now_ns=300)
                with self.subTest(path=path, operation=operation):
                    if child_result.allowed:
                        self.assertTrue(parent_result.allowed)


def v2_document(**changes):
    document = contract_document()
    document.update(schema_version=2, external=[
        {'path': '/usr', 'scope': 'tree', 'operations': ['read', 'execute']},
        {'path': '/state/home', 'scope': 'tree', 'operations': ['read', 'write']},
    ])
    document.update(changes)
    return document


class SchemaTwoTests(unittest.TestCase):
    """Schema 2 adds operator-approved `external` rules outside the workspace."""

    def setUp(self):
        self.contract = policy.contract_from_dict(v2_document())
        self.process = policy.ProcessIdentity(101, 'g1')
        self.binding = policy.ProcessBinding(self.process, 'task-a', 1)

    def decide(self, path, operations, contract=None):
        state = policy.TaskState(contract or self.contract)
        return policy.evaluate(state, self.binding, policy.FileAccess(self.process, path, frozenset(operations)),
                               now_ns=200)

    def test_roundtrip_keeps_external_rules_and_v1_documents_are_unchanged(self):
        self.assertEqual(policy.contract_from_dict(policy.contract_to_dict(self.contract)), self.contract)
        self.assertIn('external', policy.contract_to_dict(self.contract))
        self.assertNotIn('external', policy.contract_to_dict(policy.contract_from_dict(contract_document())))

    def test_external_rules_grant_only_their_operations(self):
        for path, operations, allowed in [('/usr/lib/libSystem.B.dylib', ('read',), True),
                                          ('/usr/bin/python3', ('execute',), True),
                                          ('/usr/lib/x', ('write',), False),
                                          ('/state/home/.cache/x', ('read', 'write'), True),
                                          ('/state/other', ('read',), False),
                                          ('/etc/hosts', ('read',), False)]:
            with self.subTest(path=path, operations=operations):
                self.assertEqual(self.decide(path, operations).allowed, allowed)

    def test_sensitive_names_and_denials_still_win_over_external_rules(self):
        self.assertEqual(self.decide('/state/home/.ssh/id_ed25519', ('read',)).reason, 'sensitive_path')
        denied = policy.contract_from_dict(v2_document(deny=[
            {'path': '/state/home/secret-store', 'scope': 'tree', 'operations': ['read']}]))
        self.assertEqual(self.decide('/state/home/secret-store/x', ('read',), denied).reason, 'explicit_deny')

    def test_schema_and_root_constraints(self):
        document = contract_document()
        document['external'] = []
        for bad in [document, v2_document(external=[{'path': '/', 'scope': 'tree', 'operations': ['read']}])]:
            with self.subTest(bad=bad), self.assertRaises(policy.PolicyError):
                policy.contract_from_dict(bad)
        missing = v2_document()
        missing.pop('external')
        with self.assertRaises(policy.PolicyError):
            policy.contract_from_dict(missing)
        with self.assertRaises(policy.PolicyError):
            replace(policy.contract_from_dict(contract_document()),
                    external=(policy.PathRule('/usr', 'tree', frozenset({'read'})),))

    def test_child_external_rules_must_be_covered_by_the_parent(self):
        child = replace(self.contract, task_id='task-child', workspace='/projects/a/src/login', allow=(),
                        external=(policy.PathRule('/usr/lib', 'tree', frozenset({'read'})),))
        self.assertTrue(policy.is_attenuation(self.contract, child))
        wider = replace(child, external=(policy.PathRule('/opt', 'tree', frozenset({'read'})),))
        self.assertFalse(policy.is_attenuation(self.contract, wider))
        writer = replace(child, external=(policy.PathRule('/usr/lib', 'tree', frozenset({'write'})),))
        self.assertFalse(policy.is_attenuation(self.contract, writer))


def v3_document(**changes):
    document = v2_document()
    document['allow'] = document['allow'] + [
        {'path': '/projects/a/.git', 'scope': 'tree', 'operations': ['read', 'write']}]
    document['external'] = document['external'] + [
        {'path': '/private/etc/ssl/cert.pem', 'scope': 'exact', 'operations': ['read']}]
    document.update(schema_version=3, exceptions=[
        {'path': '/private/etc/ssl/cert.pem', 'scope': 'exact', 'operations': ['read']},
        {'path': '/state/home/.local/share/agent/auth.json', 'scope': 'exact', 'operations': ['read', 'write']},
        {'path': '/projects/a/.git', 'scope': 'tree', 'operations': ['read']},
    ])
    document.update(changes)
    return document


class SchemaThreeExceptionTests(unittest.TestCase):
    """Schema 3 lifts the sensitive-name ban only where allow/external already grant access."""

    def setUp(self):
        self.contract = policy.contract_from_dict(v3_document())
        self.process = policy.ProcessIdentity(101, 'g1')
        self.binding = policy.ProcessBinding(self.process, 'task-a', 1)

    def decide(self, path, operations, contract=None):
        return policy.evaluate(policy.TaskState(contract or self.contract), self.binding,
                               policy.FileAccess(self.process, path, frozenset(operations)), now_ns=200)

    def test_exceptions_lift_only_their_paths_and_operations(self):
        for path, operations, reason in [
                ('/private/etc/ssl/cert.pem', ('read',), 'allowed_by_exception'),
                ('/private/etc/ssl/cert.pem', ('write',), 'sensitive_path'),
                ('/state/home/.local/share/agent/auth.json', ('read', 'write'), 'allowed_by_exception'),
                ('/projects/a/.git/config', ('read',), 'allowed_by_exception'),
                ('/projects/a/.git/config', ('write',), 'sensitive_path'),
                ('/projects/a/.env', ('read',), 'sensitive_path'),
                ('/state/home/.ssh/id_ed25519', ('read',), 'sensitive_path'),
                ('/projects/a/src/login/view.py', ('read',), 'allowed')]:
            with self.subTest(path=path, operations=operations):
                self.assertEqual(self.decide(path, operations).reason, reason)

    def test_explicit_denials_still_win_over_exceptions(self):
        denied = policy.contract_from_dict(v3_document(deny=[
            {'path': '/projects/a/.git/hooks', 'scope': 'tree', 'operations': ['read', 'write', 'execute']}]))
        self.assertEqual(self.decide('/projects/a/.git/hooks/pre-commit', ('read',), denied).reason, 'explicit_deny')

    def test_denials_match_ascii_case_variants(self):
        # APFS is case-insensitive: .git/HOOKS is the same directory as .git/hooks. Only
        # denials fold; allow and exception paths stay exact, which can only deny more.
        def contract(deny):
            return policy.contract_from_dict(v3_document(deny=deny, exceptions=[
                {'path': '/projects/a/.git', 'scope': 'tree', 'operations': ['read', 'write']}]))
        denied = contract([{'path': '/projects/a/.git/hooks', 'scope': 'tree', 'operations': ['write']},
                           {'path': '/projects/a/.git/Generated', 'scope': 'exact', 'operations': ['write']}])
        for path in ['/projects/a/.git/HOOKS/pre-commit', '/projects/a/.git/Hooks', '/projects/a/.git/generated',
                     '/projects/a/.git/GENERATED']:
            with self.subTest(path=path):
                self.assertEqual(self.decide(path, ('write',), denied).reason, 'explicit_deny')
        self.assertEqual(self.decide('/projects/a/.git/generated/x', ('write',), denied).reason, 'allowed_by_exception')
        self.assertEqual(self.decide('/projects/a/.GIT/refs', ('write',), denied).reason, 'sensitive_path')
        # Non-ASCII is not folded (the Swift port must agree byte for byte).
        unicode_denied = contract([{'path': '/projects/a/.git/\u00e9t\u00e9', 'scope': 'exact', 'operations': ['write']}])
        self.assertEqual(self.decide('/projects/a/.git/\u00c9T\u00c9', ('write',), unicode_denied).reason,
                         'allowed_by_exception')
        self.assertEqual(self.decide('/projects/a/.git/\u00e9T\u00e9', ('write',), unicode_denied).reason,
                         'explicit_deny')

    def test_invalid_exceptions_are_rejected(self):
        cases = [
            [{'path': '/projects/a/.git', 'scope': 'tree', 'operations': ['execute']}],
            [{'path': '/projects/a/src', 'scope': 'tree', 'operations': ['read']}],
            [{'path': '/Users/someone/.ssh', 'scope': 'tree', 'operations': ['read']}],
            [{'path': '/projects/a/.git', 'scope': 'tree', 'operations': ['read', 'write', 'write']}],
            # Not rooted at the sensitive name: it would lift the names below an ordinary directory.
            [{'path': '/projects/a/.git/objects', 'scope': 'tree', 'operations': ['read']}],
        ]
        for exceptions in cases:
            with self.subTest(exceptions=exceptions), self.assertRaises(policy.PolicyError):
                policy.contract_from_dict(v3_document(exceptions=exceptions))
        with self.assertRaises(policy.PolicyError):
            policy.contract_from_dict(v2_document(exceptions=[]))
        with self.assertRaisesRegex(policy.PolicyError, 'exception not rooted at a sensitive name'):
            policy.contract_from_dict(v3_document(exceptions=[
                {'path': '/projects/a/.git/objects', 'scope': 'tree', 'operations': ['read']}]))
        # A workspace below a sensitive directory cannot be excepted wholesale.
        nested = v3_document(workspace='/secrets/proj', allow=[
            {'path': '/secrets/proj', 'scope': 'tree', 'operations': ['read', 'write']}], deny=[],
            exceptions=[{'path': '/secrets/proj', 'scope': 'tree', 'operations': ['read']}])
        with self.assertRaisesRegex(policy.PolicyError, 'exception not rooted at a sensitive name'):
            policy.contract_from_dict(nested)
        without = v3_document()
        without.pop('exceptions')
        with self.assertRaises(policy.PolicyError):
            policy.contract_from_dict(without)

    def test_roundtrip_and_attenuation(self):
        self.assertEqual(policy.contract_from_dict(policy.contract_to_dict(self.contract)), self.contract)
        child = replace(self.contract, task_id='task-child', exceptions=self.contract.exceptions[:1])
        self.assertTrue(policy.is_attenuation(self.contract, child))
        wider = replace(self.contract, task_id='task-child', exceptions=(
            policy.PathRule('/projects/a/.git', 'tree', frozenset({'read', 'write'})),))
        self.assertFalse(policy.is_attenuation(self.contract, wider))
        v2_parent = policy.contract_from_dict(v2_document())
        pem = policy.PathRule('/usr/lib/x.pem', 'exact', frozenset({'read'}))
        # Valid on its own (the exception is covered by its external rule), but the v2 parent
        # has no exceptions, so the child may not lift the name ban.
        self.assertFalse(policy.is_attenuation(v2_parent, replace(child, allow=(), external=(pem,), exceptions=(pem,))))


CACHE = '/projects/a/.build/checkouts'


def scoped_document(**changes):
    """v3 with a writable package cache and a name-scoped `.git` exception below it."""
    document = v3_document()
    document['allow'] = document['allow'] + [
        {'path': '/projects/a/.build', 'scope': 'tree', 'operations': ['read', 'write']}]
    document['exceptions'] = document['exceptions'] + [
        {'path': CACHE, 'scope': 'tree', 'operations': ['read', 'write'], 'names': ['.git']},
        {'path': '/state/home/.cargo/git', 'scope': 'tree', 'operations': ['read', 'write'], 'names': ['.git']}]
    document.update(changes)
    return document


def scoped(path, operations=('read',), names=('.git',)):
    return {'path': path, 'scope': 'tree', 'operations': list(operations), 'names': list(names)}


class NameScopedExceptionTests(unittest.TestCase):
    """Tree exceptions that lift only listed sensitive names below an ordinary root."""

    def setUp(self):
        self.contract = policy.contract_from_dict(scoped_document())
        self.process = policy.ProcessIdentity(101, 'g1')
        self.binding = policy.ProcessBinding(self.process, 'task-a', 1)

    def decide(self, path, operations, contract=None):
        return policy.evaluate(policy.TaskState(contract or self.contract), self.binding,
                               policy.FileAccess(self.process, path, frozenset(operations)), now_ns=200)

    def test_only_the_listed_names_below_the_root_are_lifted(self):
        for path, operations, reason in [
                (CACHE + '/dep/.git/config', ('read', 'write'), 'allowed_by_exception'),
                (CACHE + '/dep/.GIT/HEAD', ('read', 'write'), 'allowed_by_exception'),
                (CACHE + '/.git', ('write',), 'allowed_by_exception'),
                (CACHE + '/a/.git/modules/b/.git/objects/x', ('read',), 'allowed_by_exception'),
                (CACHE + '/dep/src/main.swift', ('read', 'write'), 'allowed'),
                (CACHE + '/dep/.env', ('read',), 'sensitive_path'),
                (CACHE + '/dep/.git/.env', ('read',), 'sensitive_path'),
                (CACHE + '/dep/.git/keys/deploy.pem', ('read',), 'sensitive_path'),
                (CACHE + '/dep/.git/config', ('execute',), 'sensitive_path'),
                ('/projects/a/.BUILD/checkouts/dep/.git/config', ('read',), 'sensitive_path'),
                ('/projects/a/.build/.git/config', ('read',), 'sensitive_path'),
                # Casefold agreement with Swift is not assumed for non-ASCII: never a listed name.
                (CACHE + '/dep/\uab70.pem', ('read',), 'sensitive_path'),
                (CACHE + '/dep/.git/\u13a0.pem', ('read',), 'sensitive_path'),
                ('/state/home/.cargo/git/checkouts/dep-1/abc/.git/HEAD', ('read', 'write'), 'allowed_by_exception'),
                ('/state/home/.cargo/credentials.toml', ('read',), 'sensitive_path'),
                # Unscoped exceptions keep their semantics: everything below the root is lifted.
                ('/projects/a/.git/.env', ('read',), 'allowed_by_exception')]:
            with self.subTest(path=path, operations=operations):
                self.assertEqual(self.decide(path, operations).reason, reason)

    def test_several_names_and_denials(self):
        several = policy.contract_from_dict(scoped_document(exceptions=[
            scoped(CACHE, ('read', 'write'), ('.git', '.env'))]))
        self.assertEqual(self.decide(CACHE + '/dep/.env', ('read',), several).reason, 'allowed_by_exception')
        self.assertEqual(self.decide(CACHE + '/dep/.git/.ENV', ('read',), several).reason, 'allowed_by_exception')
        self.assertEqual(self.decide(CACHE + '/dep/id_rsa', ('read',), several).reason, 'sensitive_path')
        pem = policy.contract_from_dict(scoped_document(exceptions=[scoped(CACHE, names=('x.pem',))]))
        self.assertEqual(self.decide(CACHE + '/dep/X.PEM', ('read',), pem).reason, 'allowed_by_exception')
        self.assertEqual(self.decide(CACHE + '/dep/\uab70.pem', ('read',), pem).reason, 'sensitive_path')
        denied = policy.contract_from_dict(scoped_document(deny=[
            {'path': CACHE + '/dep/.git/hooks', 'scope': 'tree', 'operations': ['write']}]))
        for path in [CACHE + '/dep/.git/hooks/pre-commit', CACHE + '/dep/.GIT/HOOKS/pre-commit']:
            with self.subTest(path=path):
                self.assertEqual(self.decide(path, ('write',), denied).reason, 'explicit_deny')
        self.assertEqual(self.decide(CACHE + '/dep/.git/hooks/pre-commit', ('read',), denied).reason,
                         'allowed_by_exception')

    def test_roundtrip_emits_sorted_names_only_when_present(self):
        loaded = policy.load_contract(json.dumps(scoped_document()))
        self.assertEqual(loaded, self.contract)
        document = policy.contract_to_dict(self.contract)
        self.assertEqual(policy.contract_from_dict(document), self.contract)
        self.assertEqual([rule.get('names') for rule in document['exceptions']], [None, None, None, ['.git'], ['.git']])
        several = policy.contract_from_dict(scoped_document(exceptions=[scoped(CACHE, names=('.git', '.env'))]))
        self.assertEqual(policy.contract_to_dict(several)['exceptions'][0]['names'], ['.env', '.git'])
        # Existing v1/v2/v3 documents serialize (and therefore digest) exactly as before.
        example = json.loads((Path(__file__).resolve().parents[1] / 'examples/task-policy.json').read_text())
        for original in [contract_document(), v2_document(), v3_document(), example]:
            expected = json.loads(json.dumps(original))
            for key in ('allow', 'deny', 'external', 'exceptions'):
                for rule in expected.get(key, []):
                    rule['operations'] = sorted(rule['operations'])
            with self.subTest(schema=original['schema_version']):
                self.assertEqual(policy.contract_to_dict(policy.contract_from_dict(original)), expected)

    def test_proposal_digests_of_documents_without_names_are_unchanged(self):
        # Golden values from the serializer before `names` existed (rules with exactly path,
        # scope and sorted operations); an approver's confirmed digest must not move.
        import task_registry as registry
        example = json.loads((Path(__file__).resolve().parents[1] / 'examples/task-policy.json').read_text())
        proposer = policy.ProcessIdentity(500, 'g1')
        for document, digest in [
                (example, '2ac22056ee547fc48489bacc39d157dccc211b003c8c7c45fe7feccff68ed288'),
                (v2_document(), '355e1134227f1b5fa4524dae1fc30a8ade17dd0f215b121558e20c51be022fb1'),
                (v3_document(), '690f02a243db98c0ba6d5f8620602e1317d77979932b0753800633bb77dcb207')]:
            with self.subTest(schema=document['schema_version']):
                contract = policy.contract_from_dict(document)
                self.assertEqual(registry._proposal_digest(contract, None, proposer), digest)

    def test_invalid_names_are_rejected(self):
        tree = {'path': CACHE, 'scope': 'tree', 'operations': ['read']}
        cases = [
            (dict(tree, names=[]), 'invalid exception names'),
            (dict(tree, names='.git'), 'invalid exception names'),
            (dict(tree, names=[1]), 'invalid exception names'),
            (dict(tree, names=['.git', '.env', '.aws', '.ssh', '.kube', '.azure', '.gnupg', '.netrc', '.npmrc']),
             'invalid exception names'),
            (dict(tree, names=['.git', '.git']), 'duplicate exception name'),
            (dict(tree, names=['src']), 'exception name is not sensitive'),
            (dict(tree, names=['']), 'exception name is not sensitive'),
            (dict(tree, names=['.gitx', '.git']), 'exception name is not sensitive'),
            # Literal lowercase ASCII only: str.casefold and Foundation folding differ on
            # non-ASCII (U+AB70 CHEROKEE SMALL LETTER A), and other spellings are dead names.
            (dict(tree, names=['dep/.git']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['.GIT']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['.git', '.Env']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['\uab70.pem']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['\u13a0.pem']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['\u00df.pem']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['*.pem']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['.env\t']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['.git ']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, names=['.git\x7f']), 'exception name is not a lowercase ASCII component'),
            (dict(tree, scope='exact', names=['.git']), 'names only on tree exceptions'),
            (dict(tree, operations=['read', 'execute'], names=['.git']), 'exception grants execute'),
            # The root itself must be clean: the names are lifted strictly below it.
            (scoped('/projects/a/.git/modules'), 'scoped exception path is sensitive'),
            (scoped('/projects/a/.build/.ENV/checkouts'), 'scoped exception path is sensitive'),
            # Coverage still applies: /projects/a/src is only readable.
            (scoped('/projects/a/src', ('write',)), 'exception outside granted scope'),
        ]
        for rule, message in cases:
            with self.subTest(rule=rule), self.assertRaisesRegex(policy.PolicyError, '^' + message + '$'):
                policy.contract_from_dict(scoped_document(exceptions=[rule]))
        for which in ('allow', 'deny', 'external'):
            document = scoped_document()
            document[which] = document[which] + [scoped('/projects/a/.build')]
            with self.subTest(which=which), self.assertRaisesRegex(policy.PolicyError, '^invalid document fields$'):
                policy.contract_from_dict(document)
        # Direct construction bypasses the document shape, not the contract check.
        rule = policy.PathRule('/projects/a/.build', 'tree', frozenset({'read'}), frozenset({'.git'}))
        for which in ('allow', 'deny', 'external'):
            with self.subTest(which=which), self.assertRaisesRegex(policy.PolicyError, '^names only on tree exceptions$'):
                replace(self.contract, **{which: getattr(self.contract, which) + (rule,)})
        for names in [frozenset(), ['.git'], frozenset({b'.git'})]:
            with self.subTest(names=names), self.assertRaisesRegex(policy.PolicyError, '^invalid exception names$'):
                policy.PathRule(CACHE, 'tree', frozenset({'read'}), names)

    def test_attenuation_requires_a_scoped_parent_with_the_names(self):
        def child(*exceptions):
            return replace(self.contract, task_id='task-child',
                           exceptions=tuple(policy.contract_from_dict(scoped_document(exceptions=list(exceptions))).exceptions))
        self.assertTrue(policy.is_attenuation(self.contract, child(scoped(CACHE, ('read', 'write')))))
        self.assertTrue(policy.is_attenuation(self.contract, child(scoped(CACHE + '/dep'))))
        # Names the parent does not lift, operations it does not lift, or a path outside it.
        self.assertFalse(policy.is_attenuation(self.contract, child(scoped(CACHE, names=('.git', '.env')))))
        self.assertFalse(policy.is_attenuation(self.contract, child(scoped('/projects/a/.build'))))
        read_only = replace(self.contract, exceptions=(policy.PathRule(CACHE, 'tree', frozenset({'read'}),
                                                                       frozenset({'.git'})),))
        self.assertFalse(policy.is_attenuation(read_only, child(scoped(CACHE, ('read', 'write')))))
        # An unscoped child below a scoped parent would lift every name below its root.
        unscoped = {'path': CACHE + '/dep/.git', 'scope': 'tree', 'operations': ['read']}
        self.assertFalse(policy.is_attenuation(self.contract, child(unscoped)))
        wide = replace(self.contract, exceptions=self.contract.exceptions[:3] + (
            policy.PathRule(CACHE, 'tree', frozenset({'read', 'write'}), frozenset({'.git', '.env'})),))
        self.assertTrue(policy.is_attenuation(wide, child(scoped(CACHE + '/dep'))))
        # Conservative in both directions, even where the paths nest.
        plain = policy.PathRule('/projects/a/.git', 'tree', frozenset({'read'}))
        names = policy.PathRule('/projects/a/.git', 'tree', frozenset({'read'}), frozenset({'.git'}))
        self.assertFalse(policy._names_cover(plain, names))
        self.assertFalse(policy._names_cover(names, plain))
        self.assertTrue(policy._names_cover(plain, plain))


class ReviewHardeningTests(unittest.TestCase):
    def test_v1_child_is_not_an_attenuation_of_a_v2_parent(self):
        parent = policy.contract_from_dict(v2_document())
        child = replace(policy.contract_from_dict(contract_document()), task_id='task-child')
        self.assertFalse(policy.is_attenuation(parent, child))
        self.assertTrue(policy.is_attenuation(parent, replace(child, schema_version=2)))

    def test_rules_and_workspaces_may_not_touch_the_data_volume_alias(self):
        for external in [[{'path': '/System', 'scope': 'tree', 'operations': ['read']}],
                         [{'path': '/System/Volumes', 'scope': 'tree', 'operations': ['read']}],
                         [{'path': '/System/Volumes/Data/Users', 'scope': 'tree', 'operations': ['read']}]]:
            with self.subTest(external=external), self.assertRaises(policy.PolicyError):
                policy.contract_from_dict(v2_document(external=external))
        policy.contract_from_dict(v2_document(external=[
            {'path': '/System/Library', 'scope': 'tree', 'operations': ['read']},
            {'path': '/System/Volumes/Preboot/Cryptexes', 'scope': 'tree', 'operations': ['read']}]))
        for workspace in ['/System/Volumes/Data/Users/me/p', '/system/volumes/data/Users/me/p']:
            with self.subTest(workspace=workspace), self.assertRaises(policy.PolicyError):
                policy.contract_from_dict(contract_document(workspace=workspace))
        with self.assertRaises(policy.PolicyError):
            policy.contract_from_dict(v2_document(external=[
                {'path': '/SYSTEM/Volumes/data', 'scope': 'tree', 'operations': ['read']}]))


if __name__ == '__main__':
    unittest.main()
