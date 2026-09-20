"""Direct tests for descriptor-relative launcher/watcher queue helpers."""

import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shot_queue  # noqa: E402


class ShotQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name) / 'workspace'
        self.workspace.mkdir()
        self.queue_fd = shot_queue.open_shot_queue(self.workspace, create=True)
        self.addCleanup(os.close, self.queue_fd)
        self.queue = self.workspace / 'shots'

    def test_bounded_regular_lock_round_trip(self):
        self.assertTrue(shot_queue.acquire_lock(self.queue_fd, 12345))
        self.assertEqual(shot_queue.read_lock_pid(self.queue_fd), 12345)
        self.assertFalse(shot_queue.acquire_lock(self.queue_fd, 67890))

    def test_lock_reader_rejects_symlink_hardlink_and_oversized_input(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.write_text('12345')
        lock = self.queue / '.watcher.lock'
        lock.symlink_to(outside)
        self.assertIsNone(shot_queue.read_lock_pid(self.queue_fd))
        lock.unlink()
        os.link(outside, lock)
        self.assertIsNone(shot_queue.read_lock_pid(self.queue_fd))
        lock.unlink()
        lock.write_bytes(b'1' * (shot_queue.MAX_CONTROL_BYTES + 1))
        self.assertIsNone(shot_queue.read_lock_pid(self.queue_fd))

    def test_log_open_rejects_symlink_and_hardlink_without_changing_target(self):
        outside = Path(self.tmp.name) / 'outside.log'
        outside.write_bytes(b'ORIGINAL')
        log = self.queue / '.watcher.log'
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    log.symlink_to(outside)
                else:
                    os.link(outside, log)
                with self.assertRaises(OSError):
                    shot_queue.open_queue_log(self.queue_fd)
                self.assertEqual(outside.read_bytes(), b'ORIGINAL')
                log.unlink()

    def test_log_descriptor_stays_on_pinned_queue_after_ancestor_swap(self):
        log_fd = shot_queue.open_queue_log(self.queue_fd)
        held = self.workspace / 'held-shots'
        self.queue.rename(held)
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        self.queue.symlink_to(outside, target_is_directory=True)
        try:
            os.write(log_fd, b'PINNED')
        finally:
            os.close(log_fd)
        self.assertEqual((held / '.watcher.log').read_bytes(), b'PINNED')
        self.assertFalse((outside / '.watcher.log').exists())

    def test_atomic_write_replaces_symlink_and_hardlink_without_following(self):
        outside = Path(self.tmp.name) / 'outside.txt'
        outside.write_bytes(b'ORIGINAL')
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                target = self.queue / (kind + '.err.txt')
                if kind == 'symlink':
                    target.symlink_to(outside)
                else:
                    os.link(outside, target)
                shot_queue.atomic_write(self.queue_fd, target.name, b'SAFE ERROR')
                self.assertEqual(outside.read_bytes(), b'ORIGINAL')
                self.assertEqual(target.read_bytes(), b'SAFE ERROR')
                self.assertEqual(target.stat().st_nlink, 1)


if __name__ == '__main__':
    unittest.main()
