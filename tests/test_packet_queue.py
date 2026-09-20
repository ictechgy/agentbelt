"""Bounded queue work and descriptor-safe consumption of child-owned requests."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import agentbelt as g
from adapters import packet_relay


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'state').mkdir(mode=0o700)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.runs = []
        def runner(*args):
            self.runs.append(args)
            return 0, 'SYNTHETIC_REVIEW', ''
        self.relay = packet_relay.PacketRelay(self.work, self.home, runner=runner, settings={'maxPerHour': 1})
        self.relay.prepare(self.home, {'PATH': ''})
        self.patcher = patch.object(packet_relay, 'ROOT', self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def request(self, name, raw=None):
        path = self.relay.requests / (name + '.json')
        path.write_text(raw if raw is not None else json.dumps({'files': ['a.py'], 'question': 'review'}))
        return path

    def test_completed_request_is_consumed_and_result_remains_for_client(self):
        request = self.request('one')
        self.relay._handle(request)
        self.assertFalse(request.exists())
        self.assertEqual((self.relay.requests / 'one.result.md').read_text(), 'SYNTHETIC_REVIEW')
        self.assertEqual(len(self.runs), 1)

    def test_invalid_requests_also_spend_the_rate_budget(self):
        self.relay._handle(self.request('bad', '{invalid'))
        self.relay._handle(self.request('later'))
        self.assertEqual(self.runs, [])
        self.assertIn('limit', (self.relay.requests / 'later.error.txt').read_text())
        self.assertEqual(list(self.relay.requests.glob('*.json')), [])

    def test_poll_is_bounded_and_old_results_are_reclaimed(self):
        for index in range(300):
            path = self.relay.requests / ('old-' + str(index) + '.error.txt')
            path.write_text('old response')
            os.utime(path, (1, 1))
        counts = []
        try:
            for _ in range(5):
                counts.append(self.relay._poll())
            self.assertTrue(all(count <= 128 for count in counts))
            self.assertEqual(list(self.relay.requests.iterdir()), [])
        finally:
            self.relay._close_scan()

    def test_queue_symlink_cannot_read_write_or_remove_a_host_file(self):
        outside = self.root / 'outside'
        outside.mkdir()
        marker = outside / 'one.json'
        marker.write_text('SYNTHETIC_HOST_FILE')
        self.relay.requests.rmdir()
        self.relay.requests.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((g.GuardError, OSError)):
            self.relay._handle(self.relay.requests / 'one.json')
        self.assertEqual(marker.read_text(), 'SYNTHETIC_HOST_FILE')
        self.assertEqual(list(outside.iterdir()), [marker])

    def test_shutdown_does_not_start_another_queued_request(self):
        self.request('one')
        self.request('two')
        def finish_and_stop(*args):
            self.relay.stop.set()
            return 0, 'DONE', ''
        self.relay.runner = finish_and_stop
        try:
            self.relay._poll()
            self.assertEqual(len(list(self.relay.requests.glob('*.json'))), 1)
            self.assertEqual(len(list(self.relay.requests.glob('*.result.md'))), 1)
            self.assertEqual(list(self.relay.requests.glob('*.error.txt')), [])
        finally:
            self.relay._close_scan()


if __name__ == '__main__':
    unittest.main()
