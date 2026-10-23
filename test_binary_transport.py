from test_support import vendor_path, external_path
"""Real local sockets/process pipes. No USB or block device nodes."""
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from adb_socket import Client, exact
from native_session import NativeSession

class BinaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def fixture(self):
        exe=self.root/'fixture'
        subprocess.run(['/usr/bin/gcc','-O2','-D_FORTIFY_SOURCE=3','-Wall','-Wextra','-Werror',
            str(Path(__file__).with_name('native_pipe_fixture.c')),'-lcrypto','-o',str(exe)],check=True)
        fd=os.open(self.root/'disk',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
        os.ftruncate(fd,4096)
        p=subprocess.Popen([str(exe),str(fd)],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
        os.close(fd)
        self.addCleanup(lambda: p.poll() is None and p.kill())
        n=NativeSession(p,{'capacity':4096},lambda:None)
        self.addCleanup(n.abort)
        return n

    def test_short_raw_pipe_writes_and_eintr_complete(self):
        n=self.fixture(); real=os.write;calls=[]
        def short(fd,data):
            calls.append(len(data))
            if len(calls)==1:raise InterruptedError()
            return real(fd,data[:17])
        with patch('native_session.os.write',side_effect=short):
            n.write(0,b'x'*512)
        self.assertGreater(len(calls),20)
        self.assertEqual(n.read(0,512),b'x'*512)

    def test_zero_write_poison_never_retries(self):
        n=self.fixture()
        with patch('native_session.os.write',return_value=0):
            with self.assertRaises(ValueError):n.write(0,b'x'*512)
        self.assertTrue(n.closed);self.assertIsNotNone(n.process.poll())
        with patch('native_session.os.write') as write:
            with self.assertRaises(ValueError):n.read(0,512)
            write.assert_not_called()

    def test_impossible_raw_write_counts_poison(self):
        for count in (None,-1,10000):
            n=self.fixture()
            with patch('native_session.os.write',return_value=count):
                with self.assertRaises(ValueError):n.write(0,b'x'*512)
            self.assertTrue(n.closed)
            n.abort();(self.root/'disk').unlink()

    def test_native_write_timeout_poison(self):
        n=self.fixture()
        with patch('native_session.select.select',return_value=([],[],[])):
            with self.assertRaises(TimeoutError):n.write(0,b'x'*512)
        self.assertTrue(n.closed);self.assertIsNotNone(n.process.poll())

    def test_actual_c_pipe_write_read_hash_quit(self):
        n=self.fixture();data=bytes(range(256))*2
        n.write(512,data)
        self.assertEqual(n.read(512,512),data)
        self.assertEqual((self.root/'disk').read_bytes()[512:1024],data)
        n.unlock();self.assertEqual(n.process.returncode,0)

    def test_actual_c_bad_hash_no_file_write(self):
        n=self.fixture()
        n._write(struct.pack('>cQI32s',b'W',0,512,bytes(32))+b'x'*512)
        n.process.stdin.close()
        self.assertEqual(n.process.wait(timeout=5),1)
        self.assertEqual((self.root/'disk').read_bytes(),bytes(4096))

    def test_actual_c_short_payload_and_malformed_no_write(self):
        for raw in (b'W',struct.pack('>cQI32s',b'X',0,512,bytes(32)),
                    struct.pack('>cQI32s',b'W',0,512,bytes(32))+b'short'):
            with self.subTest(raw=raw[:1]):
                n=self.fixture();n._write(raw);n.process.stdin.close()
                self.assertEqual(n.process.wait(timeout=5),1)
                self.assertEqual((self.root/'disk').read_bytes(),bytes(4096))
                n.abort();(self.root/'disk').unlink()

    def test_real_subprocess_bad_response_disconnect_cleanup(self):
        for raw in (b'',b'\0'*12,struct.pack('>I32s',512,bytes(32))+b'x'*512,
                    struct.pack('>I32s',999,bytes(32))):
            p=subprocess.Popen(['/usr/bin/python3','-c',
                'import sys;sys.stdin.buffer.read(45);sys.stdout.buffer.write('+repr(raw)+');sys.stdout.buffer.flush()'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
            n=NativeSession(p,{'capacity':4096},lambda:None)
            with self.assertRaises(ValueError):n.read(0,512)
            self.assertTrue(n.closed);self.assertIsNotNone(p.poll())

    def server(self, handler):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        port=listener.getsockname()[1];errors=[]
        def run():
            try:
                with listener.accept()[0] as s:
                    s.settimeout(5);handler(s)
            except BaseException as e:errors.append(e)
            finally:listener.close()
        thread=threading.Thread(target=run);thread.start()
        def finish():
            thread.join(6)
            self.assertFalse(thread.is_alive())
            if errors:raise errors[0]
        self.addCleanup(finish)
        return Client(os.getpid(),port,timeout=2)

    def service(self,s):
        return exact(s,int(exact(s,4),16))

    def test_actual_socket_query_and_no_autospawn_after_death(self):
        def handler(s):
            self.assertEqual(self.service(s),b'host:devices')
            s.sendall(b'OKAY0004TEST')
        client=self.server(handler)
        self.assertEqual(client.query('host:devices'),b'TEST')
        with self.assertRaises((OSError,ValueError)):client.query('host:devices')

    def test_owned_accepted_connection_refuses_other_pid(self):
        def handler(s):self.assertEqual(s.recv(1),b'')
        client=self.server(handler);client.pid=1
        with self.assertRaises((ValueError,PermissionError)):client.query('host:devices')

    def test_actual_socket_transport_binary_shell(self):
        # shell-v2 wire integration lives in test_adb_v2 (fragmentation, status,
        # binary payload and separate stderr), not a legacy shell success mock.
        from test_adb_v2 import Target, packet
        payload=bytes(range(256))*4
        def handler(s, command):
            self.assertEqual(command,b'shell,v2,raw:binary')
            self.assertEqual(exact(s,5),packet(4,b''))
            s.sendall(packet(1,payload)+packet(3,b'\0'))
        target=Target(handler);self.addCleanup(target.close)
        self.assertEqual(target.client().shell('123','binary'),payload)

    def test_actual_socket_push_sync_and_short_status(self):
        data=bytes(range(256))*300;source=self.root/'source';source.write_bytes(data);source.chmod(0o600)
        def handler(s):
            self.assertEqual(self.service(s),b'host:transport:123');s.sendall(b'OKAY')
            self.assertEqual(self.service(s),b'sync:');s.sendall(b'OKAY')
            for path,mode in ((b'/tmp',0o41777),(b'/tmp/helper',0)):
                tag,size=struct.unpack('<4sI',exact(s,8));self.assertEqual(tag,b'STAT')
                self.assertEqual(exact(s,size),path);s.sendall(struct.pack('<4sIII',b'STAT',mode,0,0))
            tag,size=struct.unpack('<4sI',exact(s,8));self.assertEqual(tag,b'SEND')
            self.assertEqual(exact(s,size),b'/tmp/helper,33152')
            actual=b''
            while True:
                tag,size=struct.unpack('<4sI',exact(s,8))
                if tag==b'DONE':break
                self.assertEqual(tag,b'DATA');actual+=exact(s,size)
            self.assertEqual(actual,data);s.sendall(b'OKAY'+bytes(4))
        self.server(handler).push('123',source,'/tmp/helper')

    def test_real_foreground_daemon_lifecycle_and_binary_pipe(self):
        from workspace import Workspace, snapshot
        from transport import PrivateADBServer
        from image import sha256
        # An executable mock daemon exercises real Popen, /proc listener and
        # accepted-connection ownership, bridge subprocess and teardown.
        with Workspace(self.root/'workspace',owner=os.geteuid()) as w:
            w.tree.mkdir()
            binary=w.tree/'adb'
            binary.write_text("""#!/usr/bin/python3
import socket,sys
port=int(sys.argv[2].rsplit(':',1)[1])
s=socket.socket();s.bind(('127.0.0.1',port));s.listen()
def exact(c,n):
 d=b''
 while len(d)<n:
  b=c.recv(n-len(d))
  if not b: raise EOFError()
  d+=b
 return d
while True:
 c,_=s.accept()
 try:
  service=exact(c,int(exact(c,4),16));c.sendall(b'OKAY')
  if service==b'host-serial:123:features': c.sendall(b'0008shell_v2')
  elif service==b'host:transport:123':
   service=exact(c,int(exact(c,4),16));c.sendall(b'OKAY')
   if service!=b'shell,v2,raw:echo-binary': raise ValueError(service)
   import struct
   data=b''
   while True:
    channel,n=struct.unpack('<BI',exact(c,5));block=exact(c,n)
    if channel==4:break
    if channel!=0:raise ValueError(channel)
    data+=block
   c.sendall(struct.pack('<BI',1,len(data))+data+struct.pack('<BIB',3,1,0))
  elif service==b'host:devices': c.sendall(b'0000')
  else: raise ValueError(service)
 except EOFError: pass
 finally:c.close()
""")
            binary.chmod(0o700);w.expected=snapshot(w.tree,os.geteuid())
            with PrivateADBServer(binary,sha256(binary),w) as server:
                self.assertEqual(Client(server.process.pid,server.port).query('host:devices'),b'')
                p=subprocess.Popen(['/usr/bin/python3',server.adapter,'--pid',str(server.process.pid),
                    '--port',str(server.port),'--','-s','123','shell','-T','echo-binary'],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                payload=bytes(range(256))*4
                out,err=p.communicate(payload,timeout=5)
                self.assertEqual(p.returncode,0,err);self.assertEqual(out,payload)
                pid,port=server.process.pid,server.port
            self.assertIsNotNone(server.process.poll())
            with self.assertRaises(OSError):Client(pid,port).query('host:devices')

    def test_reproducible_actual_static_aarch64_engineering_package(self):
        import json,tarfile
        from package import build,FILES
        compiler=external_path('AARCH64_CC', 'downloads/aarch64-linux-musl-gcc')
        if not compiler.is_file():self.skipTest('existing BSP aarch64 toolchain not present')
        a,b=self.root/'a.tar.gz',self.root/'b.tar.gz'
        manifest=build(a,compiler);build(b,compiler)
        self.assertEqual(a.read_bytes(),b.read_bytes())
        with tarfile.open(a) as t:
            names=t.getnames();prefix='admiral-jetson-installer/'
            self.assertEqual(set(names),{prefix+n for n in (*FILES,'recovery-io','engineering-manifest.json','engineering-release.json')})
            helper=t.extractfile(prefix+'recovery-io').read()
            self.assertEqual(hashlib.sha256(helper).hexdigest(),manifest['recovery']['helper']['sha256'])
            release=json.load(t.extractfile(prefix+'engineering-release.json'))
            self.assertFalse(release['hardware_qualified']);self.assertIsNone(release['engineering_provenance']['authorization'])
            self.assertEqual(release['recovery'],manifest['recovery'])
            self.assertFalse(any('keys/' in n or n.endswith(('.pem','.key','.tbz2')) for n in names))

    def test_actual_socket_malformed_and_disconnect(self):
        for reply in (b'BAD!',b'OKAY0004xx',b'FA'):
            def handler(s,reply=reply):self.service(s);s.sendall(reply)
            with self.assertRaises(ValueError):self.server(handler).query('host:devices')


    def test_native_legitimate_commands_continue_past_120s_and_total_budget_stops(self):
        clock=[0.]
        with patch('native_session.time.monotonic',side_effect=lambda:clock[0]):
            n=self.fixture()
            clock[0]=119.;n.write(0,b'x'*512)
            clock[0]=121.;self.assertEqual(n.read(0,512),b'x'*512)
            clock[0]=14399.;self.assertEqual(n.read(0,512),b'x'*512)
            clock[0]=14400.
            with self.assertRaisesRegex(TimeoutError,'runtime'):n.read(0,512)
            self.assertTrue(n.closed)

    def test_native_partial_frame_trickle_never_extends_operation(self):
        import io
        from unittest.mock import Mock
        clock=[0.]
        class Trickle(io.BytesIO):
            def read(self,n):clock[0]+=31.;return b'x'
        p=Mock();p.stdout=Trickle();p.poll.return_value=None
        with patch('native_session.time.monotonic',side_effect=lambda:clock[0]):
            n=NativeSession(p,{'capacity':4096},lambda:None)
            with self.assertRaisesRegex(TimeoutError,'frame'):n._read(36)
        self.assertEqual(clock[0],124.)

if __name__=='__main__':unittest.main(verbosity=2)
