"""Profile domain lists must stay inside the reviewed host sets (LAUNCHERS-REVIEW finding A).

kimi already enforced a reviewed subset, but the opencode/zcode-family profiles merged their `domains` list unchecked;
a broadened state file would have silently widened the backend allowlist. These tests pin the fail-closed validation.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g


def write_profile(root, name, data):
    state = root / 'state'
    state.mkdir(exist_ok=True)
    (state / name).write_text(json.dumps(data))


class ProfileDomainsTests(unittest.TestCase):
    def test_reviewed_opencode_domains_cover_the_real_profile(self):
        # 설치본 프로필의 모든 항목이 리뷰된 제공자 호스트 집합 안에 있어야 한다.
        reviewed = g.reviewed_opencode_domains()
        for domain in ['api.z.ai:443', 'opencode.ai:443',
                       'token-plan.ap-southeast-1.maas.aliyuncs.com:443']:
            self.assertIn(domain, reviewed)

    def test_accepts_a_subset_and_preserves_order(self):
        reviewed = frozenset({'a.example:443', 'b.example:443'})
        self.assertEqual(g.profile_domains({'domains': ['b.example:443', 'a.example:443']}, reviewed, 'x'),
                         ['b.example:443', 'a.example:443'])

    def test_rejects_unreviewed_host(self):
        with self.assertRaises(g.GuardError):
            g.profile_domains({'domains': ['evil.example.com:443']}, frozenset({'a.example:443'}), 'x')

    def test_rejects_unreviewed_port(self):
        with self.assertRaises(g.GuardError):
            g.profile_domains({'domains': ['a.example:444']}, frozenset({'a.example:443'}), 'x')

    def test_rejects_non_list_and_non_string(self):
        for bad in ('a.example:443', {'a': 1}, ['a.example:443', 443], None):
            with self.assertRaises(g.GuardError, msg=repr(bad)):
                g.profile_domains({'domains': bad}, frozenset({'a.example:443'}), 'x')

    def test_required_rejects_empty_but_optional_allows(self):
        with self.assertRaises(g.GuardError):
            g.profile_domains({'domains': []}, frozenset({'a:443'}), 'x', required=True)
        self.assertEqual(g.profile_domains({'domains': []}, frozenset({'a:443'}), 'x'), [])

    def test_opencode_profile_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(g, 'ROOT', root):
                with self.assertRaises(g.GuardError):
                    g.load_opencode_profile()
                write_profile(root, 'opencode-profile.json',
                              {'domains': ['api.z.ai:443', 'tracker.example.com:443'], 'providers': []})
                with self.assertRaises(g.GuardError):
                    g.load_opencode_profile()
                write_profile(root, 'opencode-profile.json', {'domains': ['api.z.ai:443']})
                self.assertEqual(g.load_opencode_profile()['domains'], ['api.z.ai:443'])

    def test_zcode_profile_domains(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(g, 'ROOT', root):
                self.assertEqual(g.zcode_profile_domains(), [])
                write_profile(root, 'zcode-profile.json', {'domains': ['api.z.ai:443', 'evil:443']})
                with self.assertRaises(g.GuardError):
                    g.zcode_profile_domains()
                write_profile(root, 'zcode-profile.json', {'domains': ['api.z.ai:443']})
                self.assertEqual(g.zcode_profile_domains(), ['api.z.ai:443'])
                write_profile(root, 'zcode-profile.json', {'domains': []})
                self.assertEqual(g.zcode_profile_domains(), [])

    def test_autoclaw_domains(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.object(g, 'ROOT', root):
                with self.assertRaises(g.GuardError):
                    g.autoclaw_domains()
                write_profile(root, 'autoclaw-profile.json', {'domains': ['evil:443']})
                with self.assertRaises(g.GuardError):
                    g.autoclaw_domains()
                write_profile(root, 'autoclaw-profile.json', {'domains': []})
                self.assertEqual(g.autoclaw_domains(), [])


if __name__ == '__main__':
    unittest.main()
