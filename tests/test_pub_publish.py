"""Regression that wires pub.dev credentials only into allowed workspaces so that dart pub publish works under safecode."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agentbelt as g

CREDENTIAL_PATH = 'dart/pub-credentials.json'  # Under $XDG_CONFIG_HOME.


class GrantTests(unittest.TestCase):
    def test_grant_applies_only_to_listed_workspaces(self):
        with tempfile.TemporaryDirectory(prefix='pubgrant-', dir=Path.home()) as tmp:
            listed = Path(tmp) / 'listed'; listed.mkdir()
            other = Path(tmp) / 'other'; other.mkdir()
            settings = {'enabled': True, 'workspaces': [str(listed)]}
            with patch.object(g, 'pub_publish_settings', lambda: settings):
                self.assertEqual(g.pub_publish_grant(listed), settings)
                self.assertIsNone(g.pub_publish_grant(other))
            with patch.object(g, 'pub_publish_settings', lambda: dict(settings, enabled=False)):
                self.assertIsNone(g.pub_publish_grant(listed))
            with patch.object(g, 'pub_publish_settings', lambda: None):
                self.assertIsNone(g.pub_publish_grant(listed))

    def test_publish_domains_cover_pub_dev_upload_and_oauth_refresh(self):
        for host in ['pub.dev:443', 'storage.googleapis.com:443', 'accounts.google.com:443', 'oauth2.googleapis.com:443']:
            self.assertIn(host, g.PUB_PUBLISH_DOMAINS)


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='publink-', dir=Path.home())
        self.home = Path(self.tmp.name) / 'home'; self.home.mkdir(mode=0o700)
        self.source = Path(self.tmp.name) / 'pub-credentials.json'
        self.source.write_text('{"synthetic": true}\n'); self.source.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_credentials_become_a_hardlink_inside_the_config_dir(self):
        config_home = self.home / '.config'
        g.link_pub_credentials(config_home, self.source)
        linked = config_home / CREDENTIAL_PATH
        self.assertTrue(linked.is_file())
        self.assertFalse(linked.is_symlink())
        self.assertEqual(linked.stat().st_ino, self.source.stat().st_ino)
        g.link_pub_credentials(config_home, self.source)  # idempotent
        self.assertEqual(linked.stat().st_ino, self.source.stat().st_ino)

    def test_refuses_to_replace_an_unrelated_file(self):
        config_home = self.home / '.config'
        target = config_home / CREDENTIAL_PATH
        target.parent.mkdir(parents=True)
        target.write_text('{"planted": true}')
        with self.assertRaises(g.GuardError):
            g.link_pub_credentials(config_home, self.source)

    def test_missing_or_shared_source_is_refused(self):
        config_home = self.home / '.config'
        with self.assertRaises(g.GuardError):
            g.link_pub_credentials(config_home, self.source.with_name('absent.json'))
        self.source.chmod(0o644)
        with self.assertRaises(g.GuardError):
            g.link_pub_credentials(config_home, self.source)

    def test_sandbox_can_read_and_refresh_the_linked_credentials(self):
        """On token refresh pub rewrites the same file in place. Had it been a symbolic link, this would have been EPERM."""
        work = Path(self.tmp.name) / 'work'; work.mkdir()
        (work / 'p.sh').write_text('f="$XDG_CONFIG_HOME/' + CREDENTIAL_PATH + '"; cat "$f"; printf \'{"refreshed": true}\' > "$f" && echo WROTE || echo WRITE_DENIED\n')
        with tempfile.TemporaryFile() as out:
            status = g.run_confined('exec', work, ['/bin/bash', str(work / 'p.sh')], ephemeral=True,
                                    config_credentials=[('dart/pub-credentials.json', self.source)], stdout=out)
            out.seek(0); text = out.read().decode(errors='replace')
        self.assertEqual(status, 0, text)
        self.assertIn('synthetic', text)
        self.assertIn('WROTE', text)
        self.assertIn('refreshed', self.source.read_text())


class SafecodeWiringTests(unittest.TestCase):
    def launch(self, grant):
        captured = {}

        def fake_run_confined(mode, workspace, command, *args, **kwargs):
            captured.update(kwargs, mode=mode, workspace=workspace, positional=args)
            return 0

        with tempfile.TemporaryDirectory(prefix='pubwire-', dir=Path.home()) as tmp:
            previous = os.getcwd(); os.chdir(tmp)
            try:
                with patch.object(g, 'run_confined', fake_run_confined), \
                     patch.object(g, 'verify_opencode_binary', lambda: None), \
                     patch.object(g, 'stage_opencode_binary', lambda: g.OPENCODE), \
                     patch.object(g, 'orca_integration', lambda: None), \
                     patch.object(g, 'packet_relay_settings', lambda: None), \
                     patch.object(g, 'pub_publish_settings', lambda: grant(Path(tmp).resolve())), \
                     patch.object(g, 'development_options', lambda: {'devPorts': [], 'packageDomains': ['pub.dev:443']}):
                    (ROOT / 'state/opencode-auth.json').is_file() or self.skipTest('no opencode auth fixture')
                    self.assertEqual(g.main(['safecode']), 0)
            finally:
                os.chdir(previous)
        return captured

    def test_granted_workspace_gets_oauth_domains_and_credential_link(self):
        captured = self.launch(lambda ws: {'enabled': True, 'workspaces': [str(ws)]})
        domains = captured['positional'][0]
        self.assertIn('accounts.google.com:443', domains)
        self.assertIn('oauth2.googleapis.com:443', domains)
        self.assertIn('pub-credentials', captured['notice_extra'])
        creds = captured['config_credentials']
        self.assertEqual([r for r, _ in creds], ['dart/pub-credentials.json'])

    def test_other_workspaces_get_nothing(self):
        captured = self.launch(lambda ws: {'enabled': True, 'workspaces': [str(Path.home() / 'Desktop/somewhere-else')]})
        domains = captured['positional'][0]
        self.assertNotIn('accounts.google.com:443', domains)
        self.assertNotIn('pub-credentials', captured.get('notice_extra', ''))
        self.assertEqual(list(captured.get('config_credentials', [])), [])


if __name__ == '__main__':
    unittest.main()
