"""The real Claude CLI against a local fake Anthropic server, without real keys."""
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[1]
class PacketIntegrationTests(unittest.TestCase):
    def test_actual_provider_can_receive_a_reply_through_the_guard(self):
        requests=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(b'{}')
            def do_POST(self):
                size=int(self.headers.get('Content-Length','0'))
                body=json.loads(self.rfile.read(size));requests.append(self.path)
                if 'count_tokens' in self.path:
                    self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{"input_tokens":10}');return
                events=[('message_start',{'type':'message_start','message':{'id':'msg_fixture','type':'message','role':'assistant','content':[],'model':body.get('model','fixture'),'stop_reason':None,'stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':0}}}),
                        ('content_block_start',{'type':'content_block_start','index':0,'content_block':{'type':'text','text':''}}),
                        ('content_block_delta',{'type':'content_block_delta','index':0,'delta':{'type':'text_delta','text':'YES'}}),
                        ('content_block_stop',{'type':'content_block_stop','index':0}),
                        ('message_delta',{'type':'message_delta','delta':{'stop_reason':'end_turn','stop_sequence':None},'usage':{'output_tokens':1}}),
                        ('message_stop',{'type':'message_stop'})]
                data=''.join('event: '+kind+'\ndata: '+json.dumps(value)+'\n\n' for kind,value in events).encode()
                self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='packet-provider-fixture-',dir=Path.home()) as work:
                subprocess.run(['/usr/bin/git','init','--quiet',work],check=True,capture_output=True,env={'HOME':str(Path.home()),'PATH':'/usr/bin:/bin','DEVELOPER_DIR':'/Library/Developer/CommandLineTools','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null'})
                inner="""import os,sys,runpy
import packet_ask.launch as launch
launch.GLM_ENDPOINT=sys.argv[2]
original_communicate=launch._communicate_bounded
def diagnostic(*args):
    output,error=original_communicate(*args)
    if error:sys.stderr.write('VENDOR_DIAGNOSTIC: '+error[-1600:].replace('SYNTHETIC_ONLY','[synthetic]'))
    return output,error
launch._communicate_bounded=diagnostic
os.environ['NO_PROXY']='';os.environ['no_proxy']=''
sys.argv=['packet-ask','research','--provider','glm','--effort','low','--timeout','25','--credential-source','env','--question-stdin']
runpy.run_path(os.environ['GUARD_PACKET_ENTRY'],run_name='__main__')
"""
                runner="""import sys
sys.path.insert(0,sys.argv[1]);import agent_guard as g
from pathlib import Path
sys.exit(g.run_confined('packet-fixture',Path(sys.argv[2]),[str(g.PACKET_PYTHON),'-I','-c',sys.argv[3],str(g.ROOT),sys.argv[4]],domains=[sys.argv[5]],extra_env={'PACKET_ASK_GLM_KEY':'SYNTHETIC_ONLY','PACKET_ASK_CLAUDE_BIN':str(g.CLAUDE.resolve()),'GUARD_PACKET_ENTRY':str(g.ROOT/'packet_entry.py'),'AGENT_GUARD_PACKET_ASK_VERSION':g.packet_ask_pinned_version()},ephemeral=True))
"""
                port=server.server_address[1]
                result=subprocess.run(['/usr/bin/python3','-I','-c',runner,str(ROOT),work,inner,f'http://127.0.0.1:{port}',f'127.0.0.1:{port}'],input='Is two plus two four? Answer YES.\n',capture_output=True,text=True,timeout=35)
                self.assertEqual(result.returncode,0,'provider exit='+str(result.returncode)+' requests='+str(len(requests))+' '+result.stderr[-800:])
                self.assertIn('YES',result.stdout)
                self.assertTrue(requests)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main()
