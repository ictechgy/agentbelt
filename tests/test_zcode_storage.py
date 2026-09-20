"""Desktop DB startup keeps the bundled storage Worker and guarded model Agent."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from adapters import zcode_privacy as privacy


PROOF = Path(os.environ.get('AGENTBELT_ZCODE_PROOF_ROOT', '/missing-public-proof'))
SOURCE = PROOF / 'zcode-oss-3.12.3-2026-09-18/source/out/host/index.js'


def preparation_function(source):
    opening = b'async function Cte(e){'
    closing = b'}a(Cte,"prepareSessionStorage")'
    start = source.index(opening)
    return source[start:source.index(closing, start) + 1].decode()


@unittest.skipUnless(SOURCE.is_file(), 'set AGENTBELT_ZCODE_PROOF_ROOT for reviewed public HOST source')
class StorageStartupTests(unittest.TestCase):
    def invoke(self, scenario, original=False):
        source = SOURCE.read_bytes()
        function = preparation_function(source if original else privacy.patch_host_payload(source, require_reviewed=True))
        script = r'''
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {createInterface as QRe} from 'node:readline';
import {fileURLToPath} from 'node:url';
const a = (value) => value;
const Ci = (kind) => Object.assign(new Error(kind), {kind});
const XRe = async (value) => value;
const YRe = (value) => value;
const zQ = {parse: value => value};
const scenario = process.argv[2];
const events = {workers: [], acknowledgements: [], reports: [], observed: [], resolverCalls: 0};
const WM = () => {
  events.resolverCalls++;
  return {command: '/usr/bin/python3', args: ['-I', '/guard/agentbelt.py',
    'zcode-private-backend', '--generation', 'a'.repeat(32), 'app-server', '--stdio']};
};
const controller = new AbortController();
class _te extends EventEmitter {
  constructor(entry, options) {
    super();
    events.workers.push({entry: fileURLToPath(entry), argv: options.argv,
      runAsNode: options.env.ELECTRON_RUN_AS_NODE});
    this.stdin = new PassThrough(); this.stdout = new PassThrough(); this.stderr = new PassThrough();
    this.stdin.on('data', data => {
      events.acknowledgements.push(JSON.parse(data));
      if (scenario === 'failure') {
        this.stdout.write(JSON.stringify({method:'startup/storageState', params:{phase:'failed', errorCode:'sql_failed'}}) + '\n');
        setImmediate(() => this.emit('exit', 1));
      } else if (scenario === 'missing-prepared') {
        setImmediate(() => this.emit('exit', 0));
      } else {
        this.stdout.write(JSON.stringify({method:'startup/storagePrepared', params:{}}) + '\n');
        setImmediate(() => this.emit('exit', 0));
      }
    });
    setImmediate(() => {
      if (scenario === 'abort') { controller.abort(); return; }
      this.stdout.write(JSON.stringify({method:'startup/storagePath', params:{path:'/synthetic/db.sqlite'}}) + '\n');
    });
  }
  terminate() { events.terminated = true; setImmediate(() => this.emit('exit', 1)); }
}
''' + function + r'''
const preparedPaths = new Set(scenario === 'reuse' ? ['/synthetic/db.sqlite'] : []);
try {
  await Cte({cwd:'/synthetic/workspace', env:{}, signal:controller.signal, preparedPaths,
    observePath: async path => events.observed.push(path), report: phase => events.reports.push(phase)});
  events.completed = true;
} catch (error) { events.error = error.kind || error.message; }
events.preparedPaths = [...preparedPaths];
console.log(JSON.stringify(events));
'''
        with tempfile.TemporaryDirectory(prefix='zcode-storage-contract-') as temporary:
            resources = Path(temporary).resolve() / 'ZCode.app/Contents/Resources'
            module = resources / 'app.asar/out/host/storage-test.mjs'
            module.parent.mkdir(parents=True)
            module.write_text(script)
            result = subprocess.run([shutil.which('node'), str(module), scenario], capture_output=True,
                                    text=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            data['expectedEntry'] = str(resources / 'glm/zcode.cjs')
            return data

    def test_original_reproduces_unsupported_runtime_for_guard_command(self):
        result = self.invoke('success', original=True)
        self.assertEqual(result['error'], 'unsupported_runtime')
        self.assertEqual(result['workers'], [])

    def test_guarded_agent_does_not_replace_bundled_storage_only_worker(self):
        result = self.invoke('success')
        self.assertTrue(result['completed'])
        self.assertEqual(result['resolverCalls'], 0)
        self.assertEqual(result['workers'], [{'entry': result['expectedEntry'],
                         'argv': ['app-server', '--stdio', '--prepare-storage', '--cwd', '/synthetic/workspace'],
                         'runAsNode': '1'}])
        self.assertEqual(result['observed'], ['/synthetic/db.sqlite'])
        self.assertEqual(result['acknowledgements'], [{'method': 'startup/storagePathReady', 'reuse': False}])
        self.assertEqual(result['preparedPaths'], ['/synthetic/db.sqlite'])

    def test_prepared_database_is_reused_after_handshake(self):
        result = self.invoke('reuse')
        self.assertTrue(result['completed'])
        self.assertEqual(result['observed'], [])
        self.assertEqual(result['acknowledgements'][0]['reuse'], True)

    def test_database_failure_still_blocks_startup(self):
        result = self.invoke('failure')
        self.assertEqual(result['error'], 'sql_failed')
        self.assertNotIn('completed', result)
        self.assertEqual(result['preparedPaths'], [])

    def test_exit_without_prepared_notification_is_not_success(self):
        result = self.invoke('missing-prepared')
        self.assertEqual(result['error'], 'transport_closed')
        self.assertNotIn('completed', result)

    def test_abort_terminates_storage_worker(self):
        result = self.invoke('abort')
        self.assertTrue(result['terminated'])
        self.assertEqual(result['error'], 'transport_closed')


if __name__ == '__main__':
    unittest.main()
