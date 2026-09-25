"""Per-agent schema-2 external baselines; synthetic paths only.

No agent is launched and no path in a rule or access request is opened. The drift tests
read agentbelt's own source files (agentbelt.py, sandbox_runner.mjs, adapters/kimi_cli.py,
the R3 probe Contract.swift) to keep the translation aligned with the Seatbelt policy.
The only filesystem use is one symlink in a private temporary directory.
"""
import ast
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import task_policy as policy
import task_profiles as profiles


GUARD = '/Users/owner/.local/share/agentbelt'
WORKSPACE = '/Users/owner/projects/app'
NODE_PREFIX = '/Users/owner/.nvm/versions/node/v22.11.0'
NODE_BINARY = NODE_PREFIX + '/bin/node'
SHORT_TMP = GUARD + '/state/t/AbCdEfGhIjKlMnOpQrStUv'
TTY = '/dev/ttys012'
PROCESS = policy.ProcessIdentity(4242, 'generation-1')


def home_of(mode):
    return GUARD + '/state/homes/' + mode + '/0123456789abcdef0123'


def mode_profiles():
    """One synthetic launch per mode, returned as (profile, executed binary)."""
    opencode_binary = GUARD + '/state/opencode-runtime/launch-100-abc/opencode'
    kimi_binary = GUARD + '/state/kimi-runtime/launch-100-abc/kimi'
    return {
        'opencode': (profiles.opencode_profile(
            binary=opencode_binary, home=home_of('opencode'), runtime_home=GUARD + '/state/control-abc/runtime-home',
            config_file=GUARD + '/state/opencode-config.json', auth_file=GUARD + '/state/opencode-auth.json',
            guard_root=GUARD, node_binary=NODE_BINARY, node_prefix=NODE_PREFIX, homebrew_prefix='/opt/homebrew',
            tty_path=TTY), opencode_binary),
        'kimi': (profiles.kimi_profile(
            binary=kimi_binary, home=home_of('kimi'), watch_bootstrap=GUARD + '/kimi_watch_bootstrap.cjs',
            guard_root=GUARD, node_binary=NODE_BINARY, node_prefix=NODE_PREFIX, homebrew_prefix='/opt/homebrew'),
            kimi_binary),
        'zcode': (profiles.zcode_backend_profile(
            application='/Applications/ZCode.app', home=home_of('zcode'), guard_root=GUARD,
            riskgate_policy='/Users/owner/.config/riskgate/riskgate.yaml', node_binary=NODE_BINARY,
            node_prefix=NODE_PREFIX, tmpdir=SHORT_TMP, homebrew_prefix='/opt/homebrew'),
            NODE_BINARY),
        'probe': (profiles.probe_profile(binary='/opt/probes/r3-probe', home='/private/tmp/agentbelt-501/probe-home'),
                  '/opt/probes/r3-probe'),
    }


def build(profile, **changes):
    arguments = dict(task_id='task-a', revision=1, workspace=WORKSPACE, valid_from_ns=0, expires_at_ns=1000,
                     mode_profile=profile)
    arguments.update(changes)
    return profiles.build_contract(**arguments)


def decide(document, path, *operations):
    contract = policy.contract_from_dict(document)
    binding = policy.ProcessBinding(PROCESS, contract.task_id, contract.revision)
    access = policy.FileAccess(PROCESS, path, frozenset(operations))
    return policy.evaluate(policy.TaskState(contract), binding, access, now_ns=5)


def with_rule(profile, path, scope='tree', operations=('read',)):
    return replace(profile, external=profile.external + (
        profiles.ProfileRule(path, scope, frozenset(operations), 'test', 'test'),))


class ModeContractTests(unittest.TestCase):
    def test_every_mode_builds_a_loadable_contract(self):
        for mode, (profile, _) in mode_profiles().items():
            with self.subTest(mode=mode):
                document = build(profile)
                contract = policy.load_contract(json.dumps(document))
                self.assertEqual(contract.schema_version, 3)
                self.assertEqual(policy.contract_to_dict(contract), document)
                for rules in (contract.external, contract.deny, contract.exceptions):
                    self.assertLessEqual(len(rules), policy.MAX_RULES)
        # Without any exception the document stays schema 2.
        probe = build(mode_profiles()['probe'][0], repository_read=False)
        self.assertEqual(policy.contract_from_dict(probe).schema_version, 2)
        self.assertNotIn('exceptions', probe)

    def test_agent_binary_runtime_and_home_are_usable(self):
        for mode, (profile, binary) in mode_profiles().items():
            document = build(profile)
            home = home_of(mode) if mode != 'probe' else '/private/tmp/agentbelt-501/probe-home'
            for path, operations in [(binary, ('execute', 'read')),
                                     ('/usr/lib/libSystem.B.dylib', ('read', 'execute')),
                                     ('/System/Library/Frameworks/Security.framework/Security', ('read', 'execute')),
                                     ('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e',
                                      ('read', 'execute')),
                                     (home + '/.cache/tool/state', ('read', 'write')),
                                     (home + '/tmp/build/test-binary', ('write', 'execute')),
                                     (WORKSPACE + '/src/main.ts', ('read', 'write'))]:
                with self.subTest(mode=mode, path=path):
                    self.assertTrue(decide(document, path, *operations).allowed)

    def test_coding_modes_mirror_seatbelt_runtime_reads(self):
        for mode in ('opencode', 'kimi', 'zcode'):
            document = build(mode_profiles()[mode][0])
            for path, operations in [('/bin/bash', ('execute',)), ('/usr/bin/git', ('execute',)),
                                     ('/Library/Developer/CommandLineTools/usr/bin/git', ('execute',)),
                                     ('/usr/share/zoneinfo/UTC', ('read',)), ('/private/etc/hosts', ('read',)),
                                     (NODE_BINARY, ('execute',)), (NODE_PREFIX + '/lib/node_modules/npm/bin/npm-cli.js', ('execute',)),
                                     ('/opt/homebrew/Cellar/ripgrep/14.1.0/bin/rg', ('execute',)), ('/etc', ('read',))]:
                with self.subTest(mode=mode, path=path):
                    self.assertTrue(decide(document, path, *operations).allowed)
            with self.subTest(mode=mode, path='/usr/share'):
                self.assertFalse(decide(document, '/usr/share/tool', 'execute').allowed)

    def test_outside_paths_stay_denied(self):
        for mode, (profile, _) in mode_profiles().items():
            document = build(profile)
            for path, operations in [('/Users/someone/secret', ('read',)), ('/Users/owner/projects/other/src/a.ts', ('read',)),
                                     ('/Users/owner/Documents/notes.txt', ('read',)),
                                     ('/opt/homebrew/var/log/service.log', ('read',)),
                                     ('/System/Volumes/Data/Users/owner/projects/app/src/main.ts', ('read',)),
                                     ('/system/volumes/data/Users/owner/Documents/notes.txt', ('read',)), ('/', ('read',)),
                                     ('/usr/local/bin/tool', ('execute',)), ('/usr/lib/libz.dylib', ('write',)),
                                     ('/Applications/Other.app/Contents/MacOS/Other', ('execute',)),
                                     (GUARD + '/state/homes/' + mode + '/ffffffffffffffffffff/notes', ('read',)),
                                     (GUARD + '/state/compatibility.json', ('read',)),
                                     ('/private/var/folders/xy/abc/T/TemporaryItems/f', ('write',))]:
                with self.subTest(mode=mode, path=path):
                    self.assertFalse(decide(document, path, *operations).allowed)

    def test_seeded_home_files_and_homebrew_data_are_explicitly_denied(self):
        for mode in ('opencode', 'kimi', 'zcode'):
            document = build(mode_profiles()[mode][0])
            for path in [home_of(mode) + '/.gitconfig', home_of(mode) + '/AGENTBELT_ENVIRONMENT.md']:
                with self.subTest(mode=mode, path=path):
                    self.assertTrue(decide(document, path, 'read').allowed)
                    self.assertEqual(decide(document, path, 'write').reason, 'explicit_deny')
            self.assertEqual(decide(document, '/opt/homebrew/var/log/x', 'read').reason, 'explicit_deny')
        kimi = build(mode_profiles()['kimi'][0])
        self.assertEqual(decide(kimi, home_of('kimi') + '/.kimi-code/region', 'write').reason, 'explicit_deny')
        opencode = build(mode_profiles()['opencode'][0])
        runtime_config = GUARD + '/state/control-abc/runtime-home/.config/opencode/plugin/orca.js'
        self.assertTrue(decide(opencode, runtime_config, 'read').allowed)
        self.assertEqual(decide(opencode, runtime_config, 'write').reason, 'explicit_deny')

    def test_other_sensitive_names_stay_denied(self):
        for mode, (profile, _) in mode_profiles().items():
            document = build(profile, repository_write=True)
            home = home_of(mode) if mode != 'probe' else '/private/tmp/agentbelt-501/probe-home'
            for path in [home + '/.ssh/id_ed25519', home + '/project/.env', WORKSPACE + '/.env.local',
                         WORKSPACE + '/config/server.key', home + '/.aws/credentials', WORKSPACE + '/.npmrc',
                         '/private/etc/ssl/private.pem', home + '/.kimi-code/config/auth.json']:
                with self.subTest(mode=mode, path=path):
                    self.assertEqual(decide(document, path, 'read').reason, 'sensitive_path')
            external = [rule['path'] for rule in document['external']]
            self.assertEqual([path for path in external if profiles.is_sensitive(path)],
                             [path for path in profiles.TRUST_STORE_FILES if path in external])
        for mode in ('opencode', 'kimi', 'zcode'):
            self.assertEqual(mode_profiles()[mode][0].sensitive_conflicts, ())

    def test_npm_user_config_is_a_read_only_exception(self):
        for mode in ('opencode', 'kimi', 'zcode'):
            document = build(mode_profiles()[mode][0])
            npmrc = home_of(mode) + '/.npmrc'
            with self.subTest(mode=mode):
                self.assertIn({'path': npmrc, 'scope': 'exact', 'operations': ['read']}, document['exceptions'])
                self.assertEqual(decide(document, npmrc, 'read').reason, 'allowed_by_exception')
                self.assertEqual(decide(document, npmrc, 'write').reason, 'sensitive_path')
                self.assertEqual(decide(document, home_of(mode) + '/project/.npmrc', 'read').reason, 'sensitive_path')
        self.assertEqual(decide(build(mode_profiles()['probe'][0]), '/private/tmp/agentbelt-501/probe-home/.npmrc',
                                'read').reason, 'sensitive_path')

    def test_trust_stores_are_read_only_exceptions(self):
        for mode in ('opencode', 'kimi', 'zcode'):
            document = build(mode_profiles()[mode][0])
            for path in profiles.TRUST_STORE_FILES:
                with self.subTest(mode=mode, path=path):
                    self.assertEqual(decide(document, path, 'read').reason, 'allowed_by_exception')
                    self.assertEqual(decide(document, path, 'write').reason, 'sensitive_path')
        # The probe profile has no trust store at all.
        self.assertEqual(decide(build(mode_profiles()['probe'][0]), '/private/etc/ssl/cert.pem', 'read').reason,
                         'sensitive_path')

    def test_agent_state_exceptions_stay_inside_the_isolated_home(self):
        opencode = build(mode_profiles()['opencode'][0])
        auth = home_of('opencode') + '/.local/share/opencode/auth.json'
        self.assertEqual(decide(opencode, auth, 'read').reason, 'allowed_by_exception')
        # A hard link to the guard's state/opencode-auth.json: read-only exception, and the
        # Seatbelt write lock stays as an explicit denial behind it.
        self.assertEqual(decide(opencode, auth, 'write').reason, 'sensitive_path')
        self.assertIn({'path': auth, 'scope': 'tree', 'operations': ['write']}, opencode['deny'])
        kimi = build(mode_profiles()['kimi'][0])
        token = home_of('kimi') + '/.kimi-code/credentials/kimi-code.json'
        self.assertEqual(decide(kimi, token, 'read', 'write').reason, 'allowed_by_exception')
        self.assertEqual(decide(kimi, GUARD + '/state/homes/kimi/ffffffffffffffffffff/.kimi-code/credentials/x',
                                'read').reason, 'sensitive_path')
        zcode = build(mode_profiles()['zcode'][0])
        state = home_of('zcode') + '/.zcode'
        for path in [state + '/v2/zcode-builtin.json', state + '/cli/db/db.sqlite', state + '/cli/db/db.sqlite-wal']:
            with self.subTest(path=path):
                self.assertEqual(decide(zcode, path, 'read', 'write').reason, 'allowed_by_exception')
        self.assertEqual(decide(zcode, state + '/cli/config.json', 'read').reason, 'allowed_by_exception')
        self.assertEqual(decide(zcode, state + '/cli/config.json', 'write').reason, 'explicit_deny')
        self.assertEqual(decide(zcode, state + '/bin/tool', 'execute').reason, 'sensitive_path')
        self.assertEqual(decide(zcode, WORKSPACE + '/.zcode/config.json', 'read').reason, 'sensitive_path')

    def test_repository_access_is_per_task(self):
        profile = mode_profiles()['kimi'][0]
        read_only = build(profile)
        writable = build(profile, repository_write=True)
        closed = build(profile, repository_read=False)
        objects = WORKSPACE + '/.git/objects/ab/cdef'
        self.assertEqual(decide(read_only, objects, 'read').reason, 'allowed_by_exception')
        self.assertEqual(decide(read_only, objects, 'write').reason, 'sensitive_path')
        self.assertEqual(decide(writable, objects, 'read', 'write').reason, 'allowed_by_exception')
        self.assertEqual(decide(closed, objects, 'read').reason, 'sensitive_path')
        for path in [WORKSPACE + '/.git/hooks/pre-commit', WORKSPACE + '/.git/config']:
            with self.subTest(path=path):
                self.assertEqual(decide(writable, path, 'read').reason, 'allowed_by_exception')
                self.assertEqual(decide(writable, path, 'write').reason, 'explicit_deny')
        self.assertEqual(decide(writable, objects, 'execute').reason, 'sensitive_path')
        # Redirections host git would follow, the entry itself, and case variants stay locked.
        for path in ['/.git/commondir', '/.git/modules/sub/config', '/.git/modules/sub/hooks/post-checkout',
                     '/.git/worktrees/w/commondir', '/.git/worktrees/w/config.worktree', '/.git',
                     '/.git/HOOKS/pre-commit', '/.git/Config', '/.git/COMMONDIR']:
            with self.subTest(path=path):
                self.assertEqual(decide(writable, WORKSPACE + path, 'write').reason, 'explicit_deny')
        # A nested repository is not the excepted one: the sensitive name denies it.
        for path in ['/sub/.git/config', '/sub/.git', '/sub/.GIT', '/.GIT/config']:
            with self.subTest(path=path):
                self.assertEqual(decide(writable, WORKSPACE + path, 'write').reason, 'sensitive_path')
        self.assertEqual(decide(writable, WORKSPACE + '/.git/refs/heads/main', 'write').reason, 'allowed_by_exception')
        self.assertEqual(decide(writable, WORKSPACE + '/.git/.env', 'read').reason, 'allowed_by_exception')

    def test_package_manager_git_caches_lift_only_git(self):
        for mode in ('opencode', 'kimi', 'zcode'):
            document = build(mode_profiles()[mode][0])
            home = home_of(mode)
            scoped = [(rule['path'], rule['operations']) for rule in document['exceptions'] if rule.get('names') == ['.git']]
            self.assertEqual(scoped, [(home + '/.pub-cache/git', ['read', 'write']), (home + '/.cargo/git', ['read', 'write']),
                                      (WORKSPACE + '/.build/checkouts', ['read', 'write'])])
            for path, operations, reason in [
                    (WORKSPACE + '/.build/checkouts/swift-nio/.git/config', ('read', 'write'), 'allowed_by_exception'),
                    (WORKSPACE + '/.build/checkouts/swift-nio/.GIT/HEAD', ('write',), 'allowed_by_exception'),
                    (WORKSPACE + '/.build/checkouts/swift-nio/.env', ('read',), 'sensitive_path'),
                    (WORKSPACE + '/.build/checkouts/swift-nio/.git/x.pem', ('read',), 'sensitive_path'),
                    (WORKSPACE + '/.build/repositories/swift-nio/.git/HEAD', ('read',), 'sensitive_path'),
                    (home + '/.pub-cache/git/pkg-abc/.git/HEAD', ('read', 'write'), 'allowed_by_exception'),
                    (home + '/.cargo/git/checkouts/dep-1/abc/.git/index', ('read', 'write'), 'allowed_by_exception'),
                    (home + '/.cargo/git/db/dep-1/.git/.env', ('read',), 'sensitive_path'),
                    (home + '/.cargo/registry/src/.git/HEAD', ('read',), 'sensitive_path'),
                    (home + '/.cargo/git/checkouts/dep-1/abc/.git/hooks/x', ('execute',), 'sensitive_path')]:
                with self.subTest(mode=mode, path=path):
                    self.assertEqual(decide(document, path, *operations).reason, reason)
        # Only where Seatbelt has them: not in the probe, not in OpenCode's runtime home, and
        # the workspace cache only when the workspace is writable.
        probe = build(mode_profiles()['probe'][0])
        self.assertFalse([rule for rule in probe['exceptions'] if 'names' in rule])
        opencode = build(mode_profiles()['opencode'][0])
        self.assertEqual(decide(opencode, GUARD + '/state/control-abc/runtime-home/.cargo/git/a/.git/HEAD', 'read').reason,
                         'sensitive_path')
        read_only = build(mode_profiles()['kimi'][0], workspace_allow=(policy.PathRule(WORKSPACE, 'tree', frozenset({'read'})),))
        self.assertNotIn(WORKSPACE + '/.build/checkouts', [rule['path'] for rule in read_only['exceptions']])
        self.assertEqual(decide(read_only, WORKSPACE + '/.build/checkouts/dep/.git/HEAD', 'read').reason, 'sensitive_path')

    def test_device_writes_are_exact(self):
        opencode = build(mode_profiles()['opencode'][0])
        for path in ['/dev/null', '/dev/zero', '/dev/tty', TTY]:
            with self.subTest(path=path):
                self.assertTrue(decide(opencode, path, 'read', 'write').allowed)
        for path in ['/dev/disk0', '/dev/rdisk0', '/dev/ttys013', '/dev/random', '/dev/bpf0', '/dev']:
            with self.subTest(path=path):
                self.assertFalse(decide(opencode, path, 'write').allowed)
        self.assertFalse(decide(build(mode_profiles()['kimi'][0]), TTY, 'write').allowed)
        for tty in ['/dev/ttys', '/dev/ttys12345', '/dev/tty0', '/dev/ttysa', '/dev/disk0', '/dev/ttys01/x']:
            with self.subTest(tty=tty):
                with self.assertRaises(profiles.ProfileError):
                    profiles.kimi_profile(binary=GUARD + '/state/kimi-runtime/launch-1-a/kimi', home=home_of('kimi'),
                                          watch_bootstrap=GUARD + '/kimi_watch_bootstrap.cjs', guard_root=GUARD,
                                          tty_path=tty)

    def test_zcode_reads_guard_files_exactly_and_blocks_workspace_config(self):
        document = build(mode_profiles()['zcode'][0])
        self.assertTrue(decide(document, GUARD + '/zcode_hook.py', 'read').allowed)
        self.assertTrue(decide(document, GUARD + '/vendor/yaml/__init__.py', 'read').allowed)
        self.assertTrue(decide(document, '/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs', 'read').allowed)
        self.assertTrue(decide(document, SHORT_TMP + '/znr-1.sock', 'write').allowed)
        self.assertFalse(decide(document, GUARD + '/state/opencode-auth.json', 'read').allowed)
        self.assertFalse(decide(document, GUARD + '/zcode_hook.py', 'write').allowed)
        blocked = [rule for rule in document['deny'] if rule['path'] == WORKSPACE + '/zcode.json']
        self.assertEqual(blocked, [{'path': WORKSPACE + '/zcode.json', 'scope': 'tree',
                                    'operations': ['execute', 'read', 'write']}])

    def test_private_zcode_bundle_tree_is_allowlisted_but_its_profile_is_not(self):
        bundle = GUARD + '/state/zcode-private/ZCode.app'
        profile = profiles.zcode_backend_profile(
            application=bundle, home=home_of('zcode'), guard_root=GUARD, riskgate_policy='/Users/owner/.config/riskgate/r.yaml',
            node_binary=NODE_BINARY, node_prefix=NODE_PREFIX)
        document = build(profile)
        self.assertTrue(decide(document, bundle + '/Contents/Resources/glm/zcode.cjs', 'read').allowed)
        self.assertFalse(decide(document, GUARD + '/state/zcode-private/user-data/Cookies', 'read').allowed)

    def test_covered_rules_are_not_duplicated(self):
        profile = profiles.kimi_profile(
            binary=GUARD + '/state/kimi-runtime/launch-1-a/kimi', home=home_of('kimi'),
            watch_bootstrap=GUARD + '/kimi_watch_bootstrap.cjs', guard_root=GUARD, node_prefix='/opt/homebrew',
            node_binary='/opt/homebrew/Cellar/node/22.11.0/bin/node', homebrew_prefix='/opt/homebrew',
            tmpdir=home_of('kimi') + '/tmp')
        paths = [rule.path for rule in profile.external]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertNotIn('/opt/homebrew/Cellar/node/22.11.0/bin/node', paths)
        self.assertNotIn(home_of('kimi') + '/tmp', paths)
        self.assertIn('/opt/homebrew/lib/node_modules', paths)
        self.assertEqual(profile.writable_roots, (home_of('kimi'),))
        build(profile)

    def test_every_rule_has_a_review_record(self):
        for mode, (profile, _) in mode_profiles().items():
            for rule in profile.external + profile.deny:
                with self.subTest(mode=mode, path=rule.path):
                    self.assertTrue(rule.why and rule.source)


class RefusalTests(unittest.TestCase):
    def assertRefused(self, profile, **changes):
        with self.assertRaises(profiles.ProfileError):
            build(profile, **changes)

    def test_broad_roots_and_workspace_relatives_are_refused(self):
        profile = mode_profiles()['opencode'][0]
        for path in ['/', '/System', '/Users', '/users', '/Users/owner', '/opt/homebrew', '/opt', '/private',
                     '/private/var', '/var/folders', '/Library', '/usr', '/Volumes', '/Applications',
                     '/Users/owner/projects', WORKSPACE, WORKSPACE + '/src', GUARD, GUARD + '/state',
                     GUARD + '/state/homes', GUARD + '/state/homes/opencode', GUARD + '/state/zcode-private',
                     '/System/Volumes/Data', '/System/Volumes/Data/Users/owner', '/system/volumes/data/opt/x',
                     '/System/Volumes']:
            with self.subTest(path=path):
                self.assertRefused(with_rule(profile, path))

    def test_exact_rules_on_the_workspace_or_data_volume_are_refused(self):
        profile = mode_profiles()['kimi'][0]
        for path in ['/Users/owner/projects', WORKSPACE, WORKSPACE + '/bin/tool', '/System/Volumes/Data/usr/bin/env']:
            with self.subTest(path=path):
                self.assertRefused(with_rule(profile, path, 'exact', ('read', 'execute')))

    def test_write_outside_the_isolated_home_or_tmpdir_is_refused(self):
        profile = mode_profiles()['zcode'][0]
        for path, scope in [('/usr/local/bin', 'tree'), ('/tmp/agentbelt-501/x', 'tree'), ('/private/etc/hosts', 'exact'),
                            ('/dev', 'tree'), ('/dev/disk0', 'exact'), ('/dev/ttys', 'tree'), ('/dev/random', 'exact'),
                            ('/private/var/folders/xy/abc/T/TemporaryItems', 'tree'),
                            (GUARD + '/state/homes/zcode/ffffffffffffffffffff', 'tree'),
                            ('/opt/tools', 'tree')]:
            with self.subTest(path=path):
                self.assertRefused(with_rule(profile, path, scope, ('write',)))

    def test_shallow_or_guard_covering_homes_are_refused(self):
        for home in ['/Users/owner', '/private/tmp', '/opt/work']:
            with self.subTest(home=home):
                self.assertRefused(profiles.probe_profile(binary='/opt/probes/r3-probe', home=home))
        profile = profiles.kimi_profile(binary=GUARD + '/state/kimi-runtime/launch-1-a/kimi', home=GUARD + '/state',
                                        watch_bootstrap=GUARD + '/kimi_watch_bootstrap.cjs', guard_root=GUARD)
        self.assertRefused(profile)
        inside_workspace = profiles.probe_profile(binary='/opt/probes/r3-probe', home=WORKSPACE + '/.home')
        self.assertRefused(inside_workspace)

    def test_writable_roots_must_be_isolated_launch_roots(self):
        # Deep enough and outside the workspace, but not a home or TMPDIR agentbelt creates.
        kimi = dict(binary=GUARD + '/state/kimi-runtime/launch-1-a/kimi', watch_bootstrap=GUARD + '/kimi_watch_bootstrap.cjs',
                    guard_root=GUARD)
        for home in ['/Users/owner/Library', '/Users/owner/otherproj', '/Users/owner/Documents', GUARD + '/state/homes',
                     GUARD + '/state/homes/kimi', GUARD + '/state/homes/kimi/0123456789abcdef012',
                     GUARD + '/state/control-abc/other', '/private/tmp/agentbelt-501']:
            with self.subTest(home=home):
                self.assertRefused(profiles.kimi_profile(home=home, **kimi))
        for tmpdir in ['/private/var/folders/xy/abc/T', GUARD + '/state/t', GUARD + '/state/t/short']:
            with self.subTest(tmpdir=tmpdir):
                self.assertRefused(profiles.kimi_profile(home=home_of('kimi'), tmpdir=tmpdir, **kimi))
        # The probe has no guard root, so only the /private/tmp/agentbelt-<uid> shape is isolated.
        for home in [GUARD + '/state', home_of('probe'), '/private/tmp/other/home']:
            with self.subTest(probe_home=home):
                self.assertRefused(profiles.probe_profile(binary='/opt/probes/r3-probe', home=home))
        profiles.validate_profile(profiles.kimi_profile(home=home_of('kimi'), tmpdir='/private/tmp/agentbelt-501/'
                                                        + 'A' * 22, **kimi), WORKSPACE)

    def test_duplicate_overlapping_and_dead_rules_are_refused(self):
        profile = mode_profiles()['probe'][0]
        self.assertRefused(with_rule(profile, '/usr/lib', 'tree', ('read', 'execute')))
        self.assertRefused(with_rule(profile, '/usr/lib/swift', 'tree', ('read',)))
        self.assertRefused(with_rule(profile, '/opt/probes/r3-probe', 'exact', ('read',)))
        self.assertRefused(with_rule(profile, '/usr/lib/dyld', 'exact', ('read',)))
        self.assertRefused(with_rule(profile, '/opt/keys/server.pem', 'exact', ('read',)))
        self.assertRefused(with_rule(profile, '/opt/tools/.ssh', 'tree', ('read',)))
        for path in ['/etc/ssl/openssl.cnf', '/var/run/resolv.conf', '/tmp/x', '/VAR/db']:
            with self.subTest(path=path):
                self.assertRefused(with_rule(profile, path, 'exact', ('read',)))

    def test_exceptions_outside_the_approved_set_are_refused(self):
        profile = mode_profiles()['kimi'][0]
        home = home_of('kimi')
        def with_exception(path, scope='exact', operations=('read',)):
            rule = profiles.ProfileRule(path, scope, frozenset(operations), 'test', 'test')
            return replace(profile, exceptions=profile.exceptions + (rule,))
        def with_scoped(path, names, operations=('read', 'write')):
            rule = profiles.ProfileRule(path, 'tree', frozenset(operations), 'test', 'test', frozenset(names))
            return replace(profile, exceptions=profile.exceptions + (rule,))
        for candidate in [with_exception(home + '/.ssh', 'tree'), with_exception(home + '/.ssh/id_rsa'),
                          with_exception(home + '/.kimi-code', 'tree'), with_exception(home + '/.npmrc', 'exact', ('read', 'write')),
                          with_exception(home + '/.npmrc', 'tree'),
                          with_exception(home + '/.kimi-code/credentials', 'tree', ('read', 'execute')),
                          with_exception('/private/etc/ssl/cert.pem', 'exact', ('read', 'write')),
                          with_exception('/private/etc/ssl', 'tree'), with_exception('/Users/owner/.ssh/id_rsa'),
                          with_exception(GUARD + '/state/homes/kimi/ffffffffffffffffffff/.kimi-code/credentials', 'tree'),
                          with_exception(home + '/.local/share/opencode/auth.json', 'tree'),
                          with_exception(SHORT_TMP + '/.zcode', 'tree'),
                          replace(profile, isolated_homes=('/Users/owner/elsewhere/home',)),
                          # Name-scoped: only `.git` below the launch home's git tool caches.
                          with_scoped(home + '/.cargo', ('.git',)), with_scoped(home + '/.cargo/git', ('.git', '.env')),
                          with_scoped(home + '/.cargo/git', ('.env',)), with_scoped(SHORT_TMP + '/.cargo/git', ('.git',)),
                          with_scoped(GUARD + '/state/homes/kimi/ffffffffffffffffffff/.cargo/git', ('.git',)),
                          with_scoped(home + '/.pub-cache/git', ('.git',), ('read', 'execute')),
                          replace(profile, workspace_git_caches=('.build',)),
                          replace(profile, workspace_git_caches=('.build/checkouts', 'vendor'))]:
            with self.subTest(exceptions=[rule.path for rule in candidate.exceptions][-1:]):
                with self.assertRaises(policy.PolicyError):
                    build(candidate)

    def test_rule_limits_are_enforced(self):
        profile = mode_profiles()['probe'][0]
        extra = tuple(profiles.ProfileRule('/opt/tools/tool-' + str(index), 'exact', frozenset({'read'}), 'test', 'test')
                      for index in range(policy.MAX_RULES))
        self.assertRefused(replace(profile, external=profile.external + extra))
        denials = tuple(policy.PathRule('/opt/denied/' + str(index), 'exact', frozenset({'read'}))
                        for index in range(policy.MAX_RULES + 1))
        with self.assertRaises(policy.PolicyError):
            build(profile, deny=denials)
        self.assertRefused(replace(profile, external=()))

    def test_workspace_allow_stays_inside_the_workspace(self):
        profile = mode_profiles()['probe'][0]
        outside = (policy.PathRule('/Users/owner/projects', 'tree', frozenset({'read'})),)
        with self.assertRaises(policy.PolicyError):
            build(profile, workspace_allow=outside)
        narrow = (policy.PathRule(WORKSPACE + '/src', 'tree', frozenset({'read'})),)
        document = build(profile, workspace_allow=narrow, repository_read=False)
        self.assertFalse(decide(document, WORKSPACE + '/src/a.ts', 'write').allowed)
        # A repository exception needs a covering workspace grant; it never widens one.
        with self.assertRaises(policy.PolicyError):
            build(profile, workspace_allow=narrow)
        with self.assertRaises(policy.PolicyError):
            build(profile, workspace_allow=(policy.PathRule(WORKSPACE, 'tree', frozenset({'read'})),),
                  repository_write=True)
        for workspace in ['/', 'relative', '/System/Volumes/Data/Users/owner/app']:
            with self.subTest(workspace=workspace):
                with self.assertRaises(policy.PolicyError):
                    build(profile, workspace=workspace)


class LaunchPathTests(unittest.TestCase):
    def test_resolution_uses_the_injected_lookup_and_requires_a_canonical_result(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'home'
            target.mkdir()
            link = Path(directory) / 'link'
            link.symlink_to(target)
            self.assertEqual(profiles.resolved_launch_path(str(link), realpath=os.path.realpath),
                             os.path.realpath(str(target)))
        for result in ['relative/path', '/', '/a//b', '/a/../b']:
            with self.subTest(result=result):
                with self.assertRaises(profiles.ProfileError):
                    profiles.resolved_launch_path('/x', realpath=lambda unused: result)


def _function(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)


def _assigned_list(function, name):
    return next(node.value for node in ast.walk(function) if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))


class SeatbeltDriftTests(unittest.TestCase):
    """The ES baseline is a translation of these sources; a change there must change it too."""

    @classmethod
    def setUpClass(cls):
        cls.agentbelt = ast.parse((REPO / 'agentbelt.py').read_text())

    def test_system_reads_match_sandbox_policy(self):
        listed = ast.literal_eval(_assigned_list(_function(self.agentbelt, 'sandbox_policy'), 'system_reads'))
        self.assertEqual([entry[0] for entry in profiles.SEATBELT_SYSTEM_READS], listed)

    def test_homebrew_reads_and_denials_match_sandbox_policy(self):
        function = _function(self.agentbelt, 'sandbox_policy')
        homebrew = [node.args[0].value for node in ast.walk(_assigned_list(function, 'executable_reads'))
                    if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'Path'
                    and node.args and isinstance(node.args[0], ast.Constant)]
        self.assertEqual(['/opt/homebrew/' + entry[0] for entry in profiles.HOMEBREW_READS], homebrew)
        denied = ast.literal_eval(_assigned_list(function, 'deny_homebrew_data'))
        self.assertEqual(['/opt/homebrew/' + relative for relative in profiles.HOMEBREW_DENY], denied)

    def test_zcode_reads_and_workspace_config_match_main(self):
        reads = _assigned_list(_function(self.agentbelt, 'main'), 'reads')
        relatives = {node.right.value for node in ast.walk(reads)
                     if isinstance(node, ast.BinOp) and isinstance(node.right, ast.Constant)}
        # `base_config` is a name in the list; its value is asserted separately.
        self.assertIn("base_config = ROOT / 'state/zcode-agent-config.json'", (REPO / 'agentbelt.py').read_text())
        relatives.add('state/zcode-agent-config.json')
        profile = mode_profiles()['zcode'][0]
        granted = {rule.path[len(GUARD) + 1:] for rule in profile.external
                   if rule.path.startswith(GUARD + '/') and rule.path not in profile.writable_roots}
        self.assertEqual(relatives, granted)
        config = next(node.value for node in self.agentbelt.body if isinstance(node, ast.Assign)
                      and getattr(node.targets[0], 'id', None) == 'ZCODE_WORKSPACE_CONFIG_PATHS')
        self.assertEqual(tuple(ast.literal_eval(config)), profiles.ZCODE_WORKSPACE_CONFIG_PATHS)

    def test_repository_locks_match_git_lock(self):
        source = (REPO / 'git_lock.mjs').read_text()
        names = ast.literal_eval(re.search(r"const LOCKED = (\[[^\]]*\]);", source).group(1))
        self.assertEqual(tuple('.git/' + name.replace('\\.', '.') for name in names), profiles.REPOSITORY_LOCKED)
        # sandbox_policy() keeps its original denyWrite entries; they must stay a subset.
        policy_source = ast.get_source_segment((REPO / 'agentbelt.py').read_text(),
                                               _function(self.agentbelt, 'sandbox_policy'))
        locked = re.findall(r"str\(workspace / '(\.git/[^']+)'\)", policy_source)
        self.assertTrue(locked and set(locked) <= set(profiles.REPOSITORY_LOCKED))
        runner = (REPO / 'sandbox_runner.mjs').read_text()
        self.assertIn("import { gitLockRules, gitToolRules, resolveRoot } from './git_lock.mjs';", runner)
        self.assertIn('for (const root of lockRoots) argv[index + 2] += gitLockRules(root);', runner)
        self.assertIn('for (const root of result.data.filesystem.allowWrite) {', runner)
        self.assertIn("env['AGENTBELT_GIT_LOCK_ROOT'] = str(Path(workspace).resolve())",
                      (REPO / 'agentbelt.py').read_text())

    def test_git_tool_caches_match_agentbelt(self):
        # git_tool_caches returns [<workspace> / '.build/checkouts', home / '.pub-cache/git', home / '.cargo/git'].
        returned = next(node.value for node in ast.walk(_function(self.agentbelt, 'git_tool_caches'))
                        if isinstance(node, ast.Return))
        joined = [node for node in ast.walk(returned) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)]
        relatives = [(ast.unparse(node.left), node.right.value) for node in joined]
        self.assertEqual(relatives, [('Path(workspace).resolve()', profiles.GIT_TOOL_WORKSPACE_CACHE)]
                         + [('home', relative) for relative in profiles.GIT_TOOL_HOME_CACHES])
        # `home` there is run_confined's isolated home (the profile's first isolated home).
        source = (REPO / 'agentbelt.py').read_text()
        self.assertIn("env['AGENTBELT_GIT_TOOL_CACHES'] = json.dumps(git_tool_caches(workspace, home))", source)
        for mode in ('opencode', 'kimi', 'zcode'):
            profile = mode_profiles()[mode][0]
            self.assertEqual(profile.workspace_git_caches, (profiles.GIT_TOOL_WORKSPACE_CACHE,))
            self.assertEqual(sorted(rule.path for rule in profile.exceptions if rule.names is not None),
                             sorted(home_of(mode) + '/' + relative for relative in profiles.GIT_TOOL_HOME_CACHES))

    def test_runner_symlink_literals_match(self):
        runner = (REPO / 'sandbox_runner.mjs').read_text()
        block = re.search(r'\(allow file-read-data file-read-metadata\n((?:  \(literal "[^"]+"\).*\n)+)', runner)
        self.assertIsNotNone(block)
        literals = re.findall(r'\(literal "([^"]+)"\)', block.group(1))
        self.assertEqual([entry[0] for entry in profiles.RUNNER_SYMLINK_READS], literals)

    def test_kimi_locked_paths_match_adapter(self):
        source = (REPO / 'adapters/kimi_cli.py').read_text()
        for line in ["KIMI_HOME_RELATIVE = '.kimi-code'", "REGION_MARKER_RELATIVE = KIMI_HOME_RELATIVE + '/region'",
                     "INSTRUCTIONS_RELATIVE = KIMI_HOME_RELATIVE + '/AGENTS.md'",
                     "WATCH_BOOTSTRAP = ROOT / 'kimi_watch_bootstrap.cjs'"]:
            with self.subTest(line=line):
                self.assertIn(line, source)

    def test_probe_runtime_matches_the_r3_fixture(self):
        swift = (REPO / 'native/guard/R3Probes/Sources/R3ProbesKit/Contract.swift').read_text()
        trees = json.loads(re.search(r'runtimeTrees = (\[[^\]]+\])', swift).group(1))
        probe = mode_profiles()['probe'][0]
        self.assertEqual([rule.path for rule in probe.external if rule.scope == 'tree'][:len(trees)], trees)
        self.assertIn('/bin/sh', [rule.path for rule in probe.external if rule.scope == 'exact'])


if __name__ == '__main__':
    unittest.main()
