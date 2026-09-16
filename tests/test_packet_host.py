import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('packet_guard_test',ROOT/'agentbelt.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

class PacketHostTests(unittest.TestCase):
    def test_safe_provider_list_does_not_advertise_unsupported_launches(self):
        with tempfile.TemporaryDirectory(prefix='packet-list-',dir=Path.home()) as tmp:
            result=subprocess.run([str(Path.home()/'.local/bin/packet-ask-safe'),'providers'],cwd=tmp,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('glm',result.stdout)
            self.assertNotIn('claude |',result.stdout)
            self.assertNotIn('kimi |',result.stdout)

    def test_key_setup_in_an_agent_tool_gives_terminal_instructions_without_reading_keys(self):
        with patch.object(g.sys.stdin,'isatty',return_value=False),patch.object(g.subprocess,'call') as execute:
            with self.assertRaisesRegex(g.GuardError,'Terminal'):
                g.packet_setup_key()
            execute.assert_not_called()

    def test_key_setup_uses_the_vendor_prompt_and_does_not_forward_unrelated_secrets(self):
        with patch.object(g.sys.stdin,'isatty',return_value=True),patch.object(g.sys.stderr,'isatty',return_value=True), \
             patch.dict(os.environ,{'AWS_SECRET_ACCESS_KEY':'SYNTHETIC_NEVER_FORWARD'}),patch.object(g.subprocess,'call',return_value=0) as execute:
            self.assertEqual(g.packet_setup_key(),0)
            command=execute.call_args.args[0];env=execute.call_args.kwargs['env']
            self.assertEqual(command[-5:],['credentials','set','glm','--access','command'])
            self.assertNotIn('AWS_SECRET_ACCESS_KEY',env)
            self.assertNotIn('SYNTHETIC_NEVER_FORWARD',' '.join(command))

if __name__=='__main__':unittest.main()
