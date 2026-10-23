from test_support import vendor_path, external_path
"""Offline only: private fixtures, process mocks, no USB/block device operations."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from workspace import Workspace, snapshot
from native_session import NativeSession
from image import sha256
from vendor import Vendor, inspect_thor_payload
from transport import PrivateADBServer, ADB
import flow


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.umask = os.umask(0o022)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()
        os.umask(self.umask)

    def archive(self, name, files):
        p = self.root / name
        with tarfile.open(p, 'w') as t:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name.endswith('.sh') else 0o644
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        return p, {'size': p.stat().st_size, 'sha256': sha256(p)}

    def workspace(self):
        bsp, b = self.archive('bsp.tar', {'Linux_for_Tegra/apply_binaries.sh': b'#!/bin/sh\n# -I lbzip2\n# -I lbzip2\nmkdir -p rootfs/usr/lib\nprintf generated > rootfs/usr/lib/applied\n',
                                        'Linux_for_Tegra/vendor.py': b'# authenticated'})
        rootfs, r = self.archive('rootfs.tar', {'etc/release': b'pinned'})
        w = Workspace(self.root / 'session', owner=os.geteuid())
        self.addCleanup(w.close)
        w.prepare(bsp, rootfs, {'archive': b, 'sample_rootfs': r})
        return w

    def test_helper_private_copy_preserves_release_pin(self):
        w=self.workspace(); source=self.root/'helper';source.write_bytes(b'approved')
        record={'sha256':sha256(source),'size':source.stat().st_size}
        helper=w.authenticate_helper(source,record)
        source.write_bytes(b'replaced')
        self.assertEqual(helper.read_bytes(),b'approved')
        self.assertEqual(sha256(helper),record['sha256'])
        w.validate()
        helper.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'control artifact'):w.validate()

    def test_real_authenticated_extract_apply_manifest(self):
        w = self.workspace()
        self.assertEqual((w.tree / 'rootfs/usr/lib/applied').read_bytes(), b'generated')
        self.assertIn('rootfs/usr/lib/applied', w.expected)
        self.assertEqual(json.loads((w.root/'preparation-manifest.json').read_text())['tree'], w.expected)
        w.validate()
        self.assertEqual(w.run(['/bin/true']), '')

    def test_extra_shadow_module_refused_before_subprocess(self):
        w = self.workspace()
        (w.tree/'json.py').write_text('attacker')
        with patch.object(w, 'runner') as runner:
            with self.assertRaisesRegex(ValueError, 'tree changed'):
                w.run(['/bin/true'])
            runner.assert_not_called()

    def test_mutable_stamp_not_authority(self):
        w = self.workspace()
        (w.root/'preparation-manifest.json').write_text('{}')
        (w.tree/'rootfs/etc/release').write_text('evil')
        with self.assertRaisesRegex(ValueError,'tree changed'): w.validate()

    def test_authenticated_rootfs_absolute_links_materialized_contained(self):
        w=self.workspace()
        archive=self.root/'links.tar'
        with tarfile.open(archive,'w') as t:
            f=tarfile.TarInfo('usr/bin/tool');f.size=1;t.addfile(f,io.BytesIO(b'x'))
            l=tarfile.TarInfo('bin/tool');l.type=tarfile.SYMTYPE;l.linkname='/usr/bin/tool';t.addfile(l)
            l=tarfile.TarInfo('usr/bin/alias');l.type=tarfile.LNKTYPE;l.linkname='usr/bin/tool';t.addfile(l)
        record={'size':archive.stat().st_size,'sha256':sha256(archive)}
        w._archive(archive,record,'rootfs.tar',w.tree/'rootfs')
        self.assertEqual((w.tree/'rootfs/bin/tool').read_bytes(),b'x')
        self.assertEqual((w.tree/'rootfs/usr/bin/alias').stat().st_nlink,1)
        self.assertIn('rootfs/bin/tool',snapshot(w.tree,os.geteuid()))

    def test_pinned_compressor_adapter_and_changed_sites_refused(self):
        w=self.workspace()
        script=w.tree/'apply_binaries.sh'
        with patch('shutil.which',return_value=None):
            # workspace fixture was already adapted when host lacks lbzip2.
            script.write_text('#!/bin/sh\n# -I lbzip2\n# -I lbzip2\n')
            w._prepare_compressor()
            self.assertEqual(script.read_text().count('-I /usr/bin/bzip2'),2)
            self.assertEqual(w.inputs['compressor_adapter']['sites'],2)
            self.assertEqual(w.inputs['compressor_adapter']['script_sha256'],sha256(script))
            script.write_text('#!/bin/sh\n# -I lbzip2\n')
            with self.assertRaisesRegex(ValueError,'compressor sites changed'):w._prepare_compressor()

    def test_actual_generated_link_chain_normalized_before_snapshot(self):
        w=self.workspace()
        root=w.tree/'rootfs'
        for name in ('etc/systemd/system','usr/lib/systemd/system'):(root/name).mkdir(parents=True,exist_ok=True)
        (root/'usr/lib/systemd/system/nv-oobe.target').write_text('target')
        # Real NVIDIA overlay: relative default.target reaches absolute link.
        (root/'etc/systemd/system/default.target').symlink_to('nv-oobe.target')
        (root/'etc/systemd/system/nv-oobe.target').symlink_to('/usr/lib/systemd/system/nv-oobe.target')
        w._normalize_generated_rootfs_links()
        self.assertEqual((root/'etc/systemd/system/default.target').read_text(),'target')
        snapshot(w.tree,os.geteuid())
        (root/'etc/systemd/system/escape').symlink_to('../../../../../../outside')
        w._normalize_generated_rootfs_links()
        with self.assertRaisesRegex(ValueError,'escapes'):snapshot(w.tree,os.geteuid())

    def test_closed_session_refused(self):
        w = self.workspace(); w.close()
        with self.assertRaisesRegex(ValueError,'prepared/locked'): w.validate()

    def test_archive_bad_pin_no_apply(self):
        w = Workspace(self.root/'session',owner=os.geteuid()); self.addCleanup(w.close)
        a,r = self.archive('bad.tar',{'Linux_for_Tegra/evil':b'evil'}); r['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'authentication'): w._archive(a,r,'copy.tar',w.root)
        self.assertFalse(w.tree.exists())

    def test_workspace_parent_symlink_and_writable_refused(self):
        (self.root/'link').symlink_to(self.root)
        with self.assertRaises(OSError): Workspace(self.root/'link/x',owner=os.geteuid())
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'untrusted'): Workspace(self.root/'x',owner=os.geteuid())
        self.root.chmod(0o700)

    def test_vendor_uses_held_authority(self):
        w=self.workspace(); v=Vendor(w.tree,'thor','1-2',workspace=w)
        self.assertEqual(v.run(['/bin/printf','actual']), 'actual')
        (w.tree/'extra.py').write_text('evil')
        with self.assertRaisesRegex(ValueError,'tree changed'): v.run(['/bin/true'])

    def frame(self, payload):
        return struct.pack('>I32s',len(payload),hashlib.sha256(payload).digest())+payload

    def test_native_protocol_bounded_hash_and_write_readback(self):
        payload=b'a'*512
        p=Mock(); p.poll.return_value=None; p.stdin=io.BytesIO()
        p.stdout=io.BytesIO(self.frame(payload)+self.frame(hashlib.sha256(payload).digest()))
        n=NativeSession(p, {'capacity':4096}, lambda:None)
        self.assertEqual(n.read(0,512),payload)
        n.write(512,payload)
        frames=p.stdin.getvalue()
        self.assertEqual(frames[0:1],b'R');self.assertEqual(frames[45:46],b'W')
        self.assertEqual(frames[-512:],payload)
        with self.assertRaises(ValueError):n.write(4096,payload)
        with self.assertRaises(ValueError):n.read(0,4194816)

    def test_native_truncation_and_response_hash_fail_closed(self):
        for raw in [b'',self.frame(b'a'*512)[:-1],struct.pack('>I32s',512,bytes(32))+b'a'*512]:
            p=Mock();p.poll.return_value=None;p.stdin=io.BytesIO();p.stdout=io.BytesIO(raw)
            with self.assertRaises(ValueError):NativeSession(p,{'capacity':4096},lambda:None).read(0,512)

    def test_private_adb_start_cleanup_no_device_calls(self):
        w=self.workspace(); binary=w.tree/'adb';binary.write_bytes(b'pinned fixture');w.expected=snapshot(w.tree,os.geteuid())
        p=Mock();p.poll.return_value=None
        with patch.object(PrivateADBServer,'check'), patch('transport.socket.socket') as sock:
            sock.return_value.getsockname.return_value=('127.0.0.1',43219)
            popen=Mock(return_value=p)
            server=PrivateADBServer(binary,sha256(binary),w,popen=popen)
            command=popen.call_args.args[0]
            self.assertEqual(command[1:],['-L','tcp:127.0.0.1:43219','server','nodaemon'])
            self.assertEqual(server.clients,['-H','127.0.0.1','-P','43219'])
            self.assertNotIn('ADB_SERVER_SOCKET',popen.call_args.kwargs['env'])
            server.close();p.terminate.assert_called_once();p.wait.assert_called_once()

    def test_vendor_actual_runner_space_workspace(self):
        import ast,types
        w=self.workspace()
        source=vendor_path('unified_flash/tools/flashtools/bootburn_t264_py/flash_utilities.py')
        if not source.exists():self.skipTest('pinned source unavailable')
        # Rehome fixture under a whitespace path before sealing.
        old=w.root;new=old.with_name('session with spaces');old.rename(new)
        w.root=new;w.tree=new/'Linux_for_Tegra'
        path=w.tree/'unified_flash/tools/flashtools/bootburn_t264_py/flash_utilities.py'
        path.parent.mkdir(parents=True);path.write_bytes(source.read_bytes());w.expected=snapshot(w.tree,os.geteuid())
        server=Mock();server.process.pid=1234;server.port=43219
        w.bind_vendor_adb(server)
        tree=ast.parse(path.read_text())
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='executeShellCommand')
        ns={'os':os,'subprocess':subprocess,'nverror':types.SimpleNamespace(NvError_Success=0,NvError_Unknown=1)}
        exec(compile(ast.Module(body=[method],type_ignores=[]),str(path),'exec'),ns)
        obj=Mock();obj.sysMonitor=None
        target=w.root/'input';target.write_text('exact')
        # Vendor raw command uses our session prefix, not invented shell quoting.
        with patch('subprocess.check_output',return_value=b'ok') as run:
            self.assertEqual(ns['executeShellCommand'](obj,'/bin/cat '+str(target),True),'ok')
            self.assertEqual(run.call_args.args[0],['/bin/cat',str(target)])

    def test_vendor_adb_adapter_is_exact_and_owned(self):
        w=self.workspace()
        path=w.tree/'unified_flash/tools/flashtools/bootburn_t264_py/flash_utilities.py'
        path.parent.mkdir(parents=True)
        path.write_text('self.f_AdbTool = os.path.join(self.p_FlashPath, self.f_AdbTool + os_suffix)\ncommandList = command.split()\ncommandList = command.split()\n')
        w.expected=snapshot(w.tree,os.geteuid())
        server=Mock();server.process.pid=1234;server.port=43219;server.binary='/authenticated/adb'
        w.bind_vendor_adb(server)
        self.assertIn('vendor-adb-guard.py',path.read_text())
        guard=(w.root/'vendor-adb-guard.py').read_text()
        compile(guard,'guard','exec')
        self.assertIn("--port",guard)
        self.assertIn('runpy.run_path',guard)
        w.validate()

    def test_private_adb_early_exit_cleanup(self):
        w=self.workspace(); binary=w.tree/'adb';binary.write_bytes(b'pinned');w.expected=snapshot(w.tree,os.geteuid())
        p=Mock();p.poll.return_value=1
        with self.assertRaisesRegex(ValueError,'exited'):
            PrivateADBServer(binary,sha256(binary),w,popen=Mock(return_value=p))

    def test_private_adb_stolen_socket_refused(self):
        server=object.__new__(PrivateADBServer);server.process=Mock();server.process.poll.return_value=None
        server.process.pid=123;server.port=5038
        with patch('transport.Path.iterdir',return_value=[]), patch('transport.Path.read_text',return_value='header\n0: 0100007F:13AE 00000000:0000 0A 0 0 0 0 0 999\n'):
            with self.assertRaisesRegex(ValueError,'not owned'):server.check()

    def test_approval_binds_helper_package_and_identity(self):
        w=self.workspace(); helper=self.root/'helper';helper.write_bytes(b'helper');boot=self.root/'boot';boot.write_bytes(b'boot')
        code=self.root/'code';code.mkdir();(code/'code.py').write_text('code')
        def pin(package,board):return flow.approval_contract(w,{'release':'pinned'},code,helper,boot,package,board,{'serial':'disk'})[1]
        a=pin({'pkg':'one'},{'ecid':'a'})
        self.assertNotEqual(a,pin({'pkg':'two'},{'ecid':'a'}))
        self.assertNotEqual(a,pin({'pkg':'one'},{'ecid':'b'}))
        helper.write_bytes(b'changed');self.assertNotEqual(a,pin({'pkg':'one'},{'ecid':'a'}))

    def test_selected_blob_generated_by_actual_pinned_tool(self):
        tool = vendor_path('bootloader/tegrahost_v2')
        if not tool.is_file():
            self.skipTest('pinned NVIDIA tool not present')
        boot = self.root/'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img'
        boot.parent.mkdir(parents=True);boot.write_bytes(b'ANDROID!'+b'source-generated-not-hardware'*200)
        package = self.root/'unified_flash/out/bsp_images/flash_workspace/rcm-boot'
        package.mkdir(parents=True)
        signed = package/'kernel.bin';signed.write_bytes(boot.read_bytes())
        for command in [ ['--align','kernel.bin'], ['--appendsigheader','kernel.bin','zerosbk','--magicid','LNX'] ]:
            subprocess.run([str(tool),'--chip','0x26','0',*command],cwd=package,check=True,capture_output=True)
        (package/'dtb.bin').write_bytes(b'multi-entry-source-fixture'*200)
        (package/'blob.xml').write_text('<file_list mode="blob"><file name="dtb.bin" type="kernel_dtb"/><file name="kernel_sigheader.bin" type="kernel"/></file_list>')
        subprocess.run([str(tool),'--chip','0x26','0','--generateblob','blob.xml','rcm_blob.bin'],cwd=package,check=True,capture_output=True)
        self.assertEqual(inspect_thor_payload(self.root)['boot_sha256'],sha256(boot))
        raw=bytearray((package/'rcm_blob.bin').read_bytes());raw[-4]^=1
        (package/'rcm_blob.bin').write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'differs'):inspect_thor_payload(self.root)
        (package/'unused-good.bin').write_bytes(boot.read_bytes())
        with self.assertRaisesRegex(ValueError,'differs'):inspect_thor_payload(self.root)

    def _firsttest_orchestration(self, abort_stage=None, security='secure-boot-disabled-observed', changed_disk=False):
        import test_installer
        fixture=test_installer.InstallerTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        w=self.workspace(); (w.tree/'bootloader').mkdir()
        boot=w.tree/'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img'
        boot.parent.mkdir(parents=True);boot.write_bytes(b'boot')
        adb=w.tree/'unified_flash/tools/flashtools/flash/adb';adb.parent.mkdir(parents=True);adb.write_bytes(b'adb')
        w.expected=snapshot(w.tree,os.geteuid())
        helper=self.root/'helper';helper.write_bytes(b'helper')
        identity={'ecid':'0x123','br_cid':'cid'}
        vendor=Mock();vendor.probe.return_value=identity;vendor.uid.return_value=identity
        vendor.generate_qspi.return_value={}
        server=Mock();server.binary=str(adb);server.__enter__=Mock(return_value=server);server.__exit__=Mock(return_value=False)
        transport=Mock();transport.shell.return_value=b'BR_CID: 0x0000000000000000000000123\n'
        from writer import FileDisk
        disk=FileDisk(fixture.dest);physical=disk.identity()
        args=argparse.Namespace(board='thor',usb_port='1-2',helper=helper,image=fixture.image,journal=self.root/'journal', experimental_first_test=True, security_observation=lambda identity:security)
        release={'boards':{'thor':{'image':{'sha256':sha256(fixture.image)}}},
                 'recovery':{'helper':{'sha256':sha256(helper),'source_sha256':sha256(Path(__file__).with_name('recovery-io.c'))}}}
        approvals=[]
        def confirm(stage,contract,pin):
            approvals.append(stage)
            self.assertEqual(contract['helper_sha256'],release['recovery']['helper']['sha256'])
            helper.write_bytes(b'caller path mutated during '+stage.encode())
            return '' if stage == abort_stage else pin
        def target_factory(*a):
            self.assertEqual(a[3].read_bytes(),b'helper')
            self.assertNotEqual(a[3],helper)
            self.assertEqual(a[4],release['recovery']['helper']['sha256'])
            return disk
        disk_selections=[physical, dict(physical, serial='changed')] if changed_disk else [physical,physical]
        with patch('vendor.package_hashes',return_value={}),patch('vendor.inspect_thor_payload',return_value={'selected':'mocked'}):
            def execute():
                return flow.thor_session(w,args,release,confirm=confirm,select_disk=lambda t:disk_selections.pop(0),
                                    vendor_factory=Mock(return_value=vendor),server_factory=Mock(return_value=server),
                                    transport_factory=Mock(return_value=transport),disk_factory=target_factory, request_recovery=lambda identity:None)
            if abort_stage or security != 'secure-boot-disabled-observed' or changed_disk:
                with self.assertRaises(ValueError): execute()
                if abort_stage:
                    self.assertEqual(approvals[-1], abort_stage)
                if abort_stage == 'erase-nvme' or changed_disk:
                    vendor.provision_qspi.assert_called_once()
                if abort_stage == 'firmware' or security != 'secure-boot-disabled-observed':
                    vendor.provision_qspi.assert_not_called()
                self.assertEqual(fixture.dest.read_bytes(), bytes(fixture.dest.stat().st_size))
                return
            result=execute()
        self.assertEqual(approvals,['firmware','erase-nvme'])
        vendor.provision_qspi.assert_called_once_with({});self.assertEqual(vendor.ram_boot.call_count,2)
        self.assertEqual(result['partitions'][0]['name'],'efi')
        self.assertIn('No problems found',subprocess.check_output(['sgdisk','-v',fixture.dest],text=True))

    def test_thor_orchestration_to_real_file_writer(self):
        self._firsttest_orchestration()

    def test_firsttest_firmware_consent_abort_before_writes(self):
        self._firsttest_orchestration(abort_stage='firmware')

    def test_firsttest_nvme_consent_abort_before_disk_write(self):
        self._firsttest_orchestration(abort_stage='erase-nvme')

    def test_firsttest_security_unknown_before_persistent_writes(self):
        self._firsttest_orchestration(security='unknown')

    def test_firsttest_changed_nvme_aborts_disk_write(self):
        self._firsttest_orchestration(changed_disk=True)


if __name__=='__main__':unittest.main(verbosity=2)
