from test_support import vendor_path, external_path
"""Local smart-socket target, actual adapter subprocesses; no USB/devices."""
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import adb_socket as adb
from native_session import NativeSession

def packet(channel, data): return struct.pack('<BI', channel, len(data)) + data

def service(s): return adb.exact(s, int(adb.exact(s, 4), 16))

class Target:
    def __init__(self, handler, features=b'shell_v2'):
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen()
        self.port=self.listener.getsockname()[1];self.errors=[];self.handler=handler;self.features=features
        self.stop=False;self.thread=threading.Thread(target=self.run);self.thread.start()
    def run(self):
        self.listener.settimeout(.1)
        while not self.stop:
            try:s,_=self.listener.accept()
            except socket.timeout:continue
            with s:
                s.settimeout(5)
                try:
                    request=service(s)
                    if request==b'host-serial:123:features':
                        s.sendall(b'OKAY'+('%04x'%len(self.features)).encode()+self.features);continue
                    if request!=b'host:transport:123':raise AssertionError(request)
                    s.sendall(b'OKAY');request=service(s);s.sendall(b'OKAY');self.handler(s,request)
                except BaseException as e:self.errors.append(e)
        self.listener.close()
    def close(self):
        self.stop=True;self.thread.join(6)
        if self.thread.is_alive():raise AssertionError('target thread leaked')
        if self.errors:raise self.errors[0]
    def client(self):return adb.Client(os.getpid(),self.port,timeout=2)
    def process(self,*args):
        return subprocess.Popen(['/usr/bin/python3',str(Path(adb.__file__)), '--pid',str(os.getpid()),'--port',str(self.port),'--','-s','123',*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)

class ADBV2Tests(unittest.TestCase):
    def target(self,handler,**kw):
        t=Target(handler,**kw);self.addCleanup(t.close);return t
    def test_fragmented_binary_stdout_separate_stderr(self):
        payload=bytes(range(256))*10
        def handler(s,cmd):
            self.assertEqual(cmd,b'shell,v2,raw:test')
            self.assertEqual(adb.exact(s,5),packet(4,b''))
            wire=packet(1,payload)+packet(2,b'diagnostic')+packet(3,b'\0')
            for i in range(0,len(wire),3):s.sendall(wire[i:i+3])
        t=self.target(handler);errors=[]
        with patch('adb_socket.fd_write',side_effect=lambda fd,b,d:errors.append((fd,b))):
            self.assertEqual(t.client().shell('123','test'),payload)
        self.assertEqual(errors,[(2,b'diagnostic')])
    def test_exit_nonzero_missing_duplicate_invalid_oversized(self):
        for raw in (packet(3,b'%'),b'',packet(1,b'x'),packet(3,b'\0')*2,
                    packet(3,b'\0\0'),struct.pack('<BI',1,65537),packet(9,b'x'),b'\x01\x01'):
            with self.subTest(raw=raw):
                def handler(s,cmd,raw=raw):adb.exact(s,5);s.sendall(raw)
                with self.assertRaises(ValueError):self.target(handler).client().shell('123','test')
    def test_unsupported_refused_without_shell(self):
        t=self.target(lambda *a:self.fail('legacy fallback'),features=b'cmd')
        with self.assertRaisesRegex(ValueError,'shell_v2'):t.client().shell('123','test')
    def test_actual_native_unlock_rejects_disconnect_and_remote_failure(self):
        for response in (b'',packet(3,b'\x01'),packet(3,b'\0')*2,packet(3,b'\0')):
            def handler(s,cmd,response=response):
                raw=b''
                while len(raw)<45:
                    channel,size=struct.unpack('<BI',adb.exact(s,5))
                    self.assertEqual(channel,0);raw+=adb.exact(s,size)
                self.assertEqual(raw,b'Q'+bytes(44))
                self.assertEqual(adb.exact(s,5),packet(4,b''))
                s.sendall(response)
            t=self.target(handler);p=t.process('shell','-T','helper')
            n=NativeSession(p,{'capacity':4096},lambda:None)
            if response==packet(3,b'\0'):
                try:n.unlock()
                except ValueError:raise AssertionError(p.stderr.read())
                self.assertEqual(p.returncode,0)
            else:
                with self.assertRaises(ValueError):n.unlock()
                self.assertNotEqual(p.returncode,0)
            n.abort();p.stderr.close()
    def test_persistent_native_file_fd_through_shell_v2(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);exe=root/'fixture'
            subprocess.run(['/usr/bin/gcc','-O2','-D_FORTIFY_SOURCE=3','-Wall','-Wextra','-Werror',str(Path(__file__).with_name('native_pipe_fixture.c')),'-lcrypto','-o',str(exe)],check=True)
            def handler(s,cmd):
                fd=os.open(root/'disk',os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600);os.ftruncate(fd,4096)
                p=subprocess.Popen([str(exe),str(fd)],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0);os.close(fd)
                def output():
                    while data:=os.read(p.stdout.fileno(),4096):s.sendall(packet(1,data))
                thread=threading.Thread(target=output);thread.start()
                while p.poll() is None:
                    channel,size=struct.unpack('<BI',adb.exact(s,5));data=adb.exact(s,size)
                    if channel==4:p.stdin.close();break
                    self.assertEqual(channel,0)
                    p.stdin.write(data)
                    # Q is final; do not wait for another stdin frame.
                    if data[:1]==b'Q':
                        self.assertEqual(adb.exact(s,5),packet(4,b''));break
                rc=p.wait(timeout=3);thread.join(3);p.stdin.close();p.stdout.close();s.sendall(packet(3,bytes([rc])))
            t=self.target(handler);p=t.process('shell','-T','helper');n=NativeSession(p,{'capacity':4096},lambda:None)
            try:
                data=bytes(range(256))*2;n.write(512,data);self.assertEqual(n.read(512,512),data);n.unlock()
                self.assertEqual((root/'disk').read_bytes()[512:1024],data)
            finally:n.abort();p.stderr.close()
    def test_directory_push_executable_bootstrap_and_full_filename(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'wr_sh.sh';source.write_text('#!/bin/sh\nprintf harmless-wrapper\n');source.chmod(0o755)
            for destination in ('/tmp','/tmp/','/tmp/explicit'):
                received=[]
                def handler(s,cmd):
                    self.assertEqual(cmd,b'sync:')
                    while True:
                        tag,size=struct.unpack('<4sI',adb.exact(s,8));raw=adb.exact(s,size)
                        if tag!=b'STAT':break
                        mode=stat.S_IFDIR|0o1777 if raw==b'/tmp' else 0
                        s.sendall(struct.pack('<4sIII',b'STAT',mode,0,0))
                    self.assertEqual(tag,b'SEND');name,mode=raw.decode().rsplit(',',1);received.append((name,int(mode)))
                    data=b''
                    while True:
                        tag,size=struct.unpack('<4sI',adb.exact(s,8))
                        if tag==b'DONE':break
                        self.assertEqual(tag,b'DATA');data+=adb.exact(s,size)
                    target=root/'received';target.write_bytes(data);target.chmod(int(mode)&0o777)
                    self.assertEqual(subprocess.check_output([str(target)]),b'harmless-wrapper')
                    for byte in b'OKAY'+bytes(4):s.sendall(bytes([byte]))
                t=self.target(handler);p=t.process('push',str(source),destination);out,err=p.communicate(timeout=5)
                self.assertEqual(p.returncode,0,err)
                self.assertEqual(received,[(destination if destination.endswith('explicit') else '/tmp/wr_sh.sh',stat.S_IFREG|0o755)])
    def test_push_symlink_and_fail_refused(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'nvdd';source.write_bytes(b'data');source.chmod(0o644)
            for symlink in (True,False):
                def handler(s,cmd,symlink=symlink):
                    while True:
                        tag,size=struct.unpack('<4sI',adb.exact(s,8));raw=adb.exact(s,size)
                        if tag!=b'STAT':break
                        mode=stat.S_IFDIR|0o755 if raw==b'/tmp' else (stat.S_IFLNK|0o777 if symlink else 0)
                        s.sendall(struct.pack('<4sIII',b'STAT',mode,0,0))
                        if stat.S_ISLNK(mode):return
                    self.assertEqual(tag,b'SEND');self.assertTrue(raw.endswith(b',33188'))
                    while True:
                        tag,size=struct.unpack('<4sI',adb.exact(s,8))
                        if tag==b'DONE':break
                        adb.exact(s,size)
                    s.sendall(b'FAIL'+struct.pack('<I',6)+b'denied')
                with self.assertRaises(ValueError):self.target(handler).client().push('123',source,'/tmp/nvdd')
    def test_mock_clock_slow_trickle_exact_status_body_and_short_writes(self):
        class Trickle:
            def __init__(self,data):self.data=data;self.clock=0.;self.timeouts=[];self.sent=b'';self.calls=0
            def settimeout(self,n):self.timeouts.append(n)
            def recv(self,n):self.clock+=.4;b,self.data=self.data[:1],self.data[1:];return b
            def send(self,data):
                self.calls+=1
                if self.calls==1:raise InterruptedError()
                self.clock+=.1;self.sent+=bytes(data[:1]);return 1
        for raw,size in ((b'OKAY',4),(b'0004',4),(b'abcd',4)):
            s=Trickle(raw)
            with patch('adb_socket.time.monotonic',side_effect=lambda:s.clock):
                with self.assertRaises(TimeoutError):adb.exact(s,size,1.)
            self.assertLess(s.clock,2.)
        s=Trickle(b'')
        with patch('adb_socket.time.monotonic',side_effect=lambda:s.clock):adb.send(s,b'abcd',1.)
        self.assertEqual(s.sent,b'abcd');self.assertEqual(s.calls,5)
    def test_vendor_actual_AdbPush_default_directory_through_adapter(self):
        import ast,types
        vendor=vendor_path('unified_flash/tools/flashtools/bootburn_t264_py/bootburn_adb.py')
        if not vendor.is_file(): self.skipTest('set NVIDIA_VENDOR_ROOT to the extracted pinned BSP')
        tree=ast.parse(vendor.read_text())
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='AdbPush')
        ns={'os':os,'time':time,'nverror':types.SimpleNamespace(NvError_Success=0),
            'AbnormalTermination':lambda *a: self.fail(str(a))}
        exec(compile(ast.Module(body=[method],type_ignores=[]),str(vendor),'exec'),ns)
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'nvdd';source.write_text('#!/bin/sh\necho harmless-nvdd\n');source.chmod(0o755)
            def handler(s,cmd):
                self.assertEqual(cmd,b'sync:')
                for name,mode in ((b'/tmp',stat.S_IFDIR|0o1777),(b'/tmp',stat.S_IFDIR|0o1777),(b'/tmp/nvdd',0)):
                    tag,size=struct.unpack('<4sI',adb.exact(s,8));self.assertEqual(tag,b'STAT');self.assertEqual(adb.exact(s,size),name)
                    s.sendall(struct.pack('<4sIII',b'STAT',mode,0,0))
                tag,size=struct.unpack('<4sI',adb.exact(s,8));self.assertEqual(tag,b'SEND')
                self.assertEqual(adb.exact(s,size),b'/tmp/nvdd,33261')
                data=b''
                while True:
                    tag,size=struct.unpack('<4sI',adb.exact(s,8))
                    if tag==b'DONE':break
                    data+=adb.exact(s,size)
                target=Path(td)/'target';target.write_bytes(data);target.chmod(0o755)
                self.assertEqual(subprocess.check_output([str(target)]),b'harmless-nvdd\n');s.sendall(b'OKAY'+bytes(4))
            t=self.target(handler)
            def execute(command):
                p=subprocess.run(command.split(),capture_output=True,timeout=5)
                self.assertEqual(p.returncode,0,p.stderr);return p.returncode
            obj=types.SimpleNamespace(f_AdbTool='/usr/bin/python3 '+str(Path(adb.__file__))+' --pid '+str(os.getpid())+' --port '+str(t.port)+' --',targetConfig=types.SimpleNamespace(s_AdbSerialNum='123'),shellUtils=types.SimpleNamespace(executeShellCommand=execute),log=lambda *a:None,vlog=lambda *a:None)
            ns['AdbPush'](obj,str(source))

    def test_whole_query_deadline_includes_connect_request_status_length_body(self):
        # Real sockets, deterministic advancing clock; a peer cannot reset the
        # deadline by making progress in a later protocol phase.
        def handler(s):
            self.assertEqual(service(s),b'host:devices');s.sendall(b'OKAY0004test')
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        errors=[]
        def run():
            try:
                with listener.accept()[0] as s:handler(s)
            except (OSError,ValueError):pass
            finally:listener.close()
        thread=threading.Thread(target=run);thread.start()
        real=adb.owned_socket;clock=[0.]
        def tick():clock[0]+=.11;return clock[0]
        try:
            with patch('adb_socket.time.monotonic',side_effect=tick):
                with self.assertRaises(TimeoutError):adb.Client(os.getpid(),listener.getsockname()[1],timeout=.9).query('host:devices')
        finally:thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_fortified_production_and_fixtures_O2_Werror(self):
        with tempfile.TemporaryDirectory() as td:
            for file in ('recovery-io.c','native_pipe_fixture.c','test_native_session.c','native_namespace_fixture.c','test_recovery_io.c'):
                command=['/usr/bin/gcc','-O2','-D_FORTIFY_SOURCE=3','-Wall','-Wextra','-Werror','-include','sys/sysmacros.h','-include','linux/fs.h',str(Path(__file__).with_name(file)),'-lcrypto','-o',str(Path(td)/'probe')]
                subprocess.run(command,check=True)


    def test_native_stream_legitimate_frames_past_120_idle_and_total_bounds(self):
        from contextlib import nullcontext
        class Wire:
            def __init__(self,events,clock):self.events=list(events);self.clock=clock;self.data=b''
            def recv(self,n):
                if not self.data:
                    at,self.data=self.events.pop(0);self.clock[0]=at
                result,self.data=self.data[:n],self.data[n:];return result
            def settimeout(self,n):pass
        for times,limit,expected_error in (((119.,121.,122.),14400,False),((119.,240.,241.),14400,True),((119.,121.,122.),120,True)):
            clock=[0.];wire=Wire([(times[0],packet(1,b'a')),(times[1],packet(1,b'b')),(times[2],packet(3,b'\0')),(times[2],b'')],clock)
            client=adb.Client(1,1,timeout=120);output=[]
            with patch('adb_socket.time.monotonic',side_effect=lambda:clock[0]),patch.object(client,'shell_socket',return_value=nullcontext(wire)),patch('adb_socket.select.select',return_value=([wire],[],[])):
                if expected_error:
                    with self.assertRaises(TimeoutError):client.shell_stream('123','helper',limit,output.append,lambda b:None,999)
                else:
                    client.shell_stream('123','helper',limit,output.append,lambda b:None,999)
                    self.assertEqual(output,[b'a',b'b'])

    def test_native_stream_partial_frame_trickle_has_absolute_operation_deadline(self):
        from contextlib import nullcontext
        clock=[0.]
        class Wire:
            def settimeout(self,n):pass
            def recv(self,n):clock[0]+=31.;return b'\x01'
        wire=Wire();client=adb.Client(1,1,timeout=120)
        with patch('adb_socket.time.monotonic',side_effect=lambda:clock[0]),patch.object(client,'shell_socket',return_value=nullcontext(wire)),patch('adb_socket.select.select',return_value=([wire],[],[])):
            with self.assertRaises(TimeoutError):client.shell_stream('123','helper',14400,lambda b:None,lambda b:None,999)
        self.assertEqual(clock[0],124.)

    def test_native_pipe_blocked_output_uses_remaining_frame_budget(self):
        # Real nonreading output pipe and socket adapter; shortened operation
        # budget, not a four-hour wait. The frame body consumes most of it.
        from contextlib import nullcontext
        for channel in (1, 2):
            with self.subTest(channel=channel):
                reader, writer = os.pipe()
                os.set_blocking(writer, False)
                try:
                    while True: os.write(writer, b'f' * 65536)
                except BlockingIOError:
                    pass
                os.set_blocking(writer, True)
                incoming, outgoing = socket.socketpair()
                stdin, hold = os.pipe()
                client = adb.Client(1, 1, timeout=.3)
                errors = []
                def peer():
                    try:
                        outgoing.sendall(struct.pack('<BI', channel, adb.FRAME))
                        time.sleep(.22)
                        outgoing.sendall(b'x' * adb.FRAME)
                    except BaseException as exc: errors.append(exc)
                thread = threading.Thread(target=peer)
                thread.start()
                real_write = adb.fd_write
                def sink(fd, data, deadline):
                    return real_write(writer, data, deadline)
                started = time.monotonic()
                try:
                    with patch.object(client, 'shell_socket', return_value=nullcontext(incoming)), patch('adb_socket.fd_write', side_effect=sink), patch('adb_socket.sys.stdin') as inp:
                        inp.fileno.return_value = stdin
                        with self.assertRaises(TimeoutError): client.pipe('123', 'helper')
                    elapsed = time.monotonic() - started
                    self.assertLess(elapsed, .46, 'output incorrectly receives a fresh or total lifetime budget')
                    self.assertGreater(elapsed, .25)
                finally:
                    thread.join(2)
                    incoming.close(); outgoing.close()
                    for fd in (reader, writer, stdin, hold): os.close(fd)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

    def test_literal_upstream_exit_fixture_and_close_stdin_output(self):
        # android-9.0.0_r1 adb/shell_service.cpp:683-686 and 715-721:
        # data()[0]=exit_code; Write(kIdExit, 1). Header is channel + LE length.
        # Independent review also executed upstream WaitForExit/Write and
        # corroborated channel=3,length=1,strb in pinned vendor adbd64.
        for wire, success in ((bytes.fromhex('010100000078030100000000'), True),
                              (bytes.fromhex('030100000025'), False),
                              (bytes.fromhex('030400000000000000'), False)):
            def handler(sock, command, wire=wire):
                self.assertEqual(adb.exact(sock, 5), bytes.fromhex('0400000000'))
                sock.sendall(wire)  # output continues after close-stdin
            client = self.target(handler).client()
            if success:
                self.assertEqual(client.shell('123', 'test'), b'x')
            else:
                with self.assertRaises(ValueError): client.shell('123', 'test')

if __name__=='__main__':unittest.main(verbosity=2)
