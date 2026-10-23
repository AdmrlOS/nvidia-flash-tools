from test_support import vendor_path, external_path
"""Actual pinned NVIDIA transformations with file-only boundaries, no devices."""
import ast
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from firmware import CAPACITY, BLOCK, plan_qspi, verify_qspi

SOURCE=vendor_path('unified_flash/tools/flashtools/bootburn_t264_py/bootburn_adb.py')

class FirmwareTests(unittest.TestCase):
    def fixture(self,root,name='bct',raw=b'18 bytes of BCT!!!!',size=1048576,start=0):
        payload=root/'fw.bin';payload.write_bytes(raw);payload.chmod(0o600)
        index=root/'FileToFlash.txt'
        index.write_text(' '.join(['/dev/block/810c5b0000.spi',name,'fw.bin',str(start),str(size),'1','0','0','0','0',hashlib.md5(raw).hexdigest(),'1'])+'\n');index.chmod(0o600)
        return index

    def vendor(self,chain='A'):
        if not SOURCE.exists(): self.skipTest('actual pinned NVIDIA source absent')
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'d36a93594b1af040ce3c2f6f1aade0fe0eff8a61fc42fadf3847b22d2440c023')
        tree=ast.parse(SOURCE.read_text());wanted={'FlashUsingADB','parseFileToFlashEntry','append_padding_to_file','dup_pt_to_fill_partition'}
        nodes=[n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name in wanted]
        def fail(*args):raise ValueError('actual vendor refused: '+repr(args))
        ns={'os':os,'re':re,'hashlib':hashlib,'tempfile':tempfile,'partitionInformation':SimpleNamespace,'AbnormalTermination':fail,'nverror':SimpleNamespace(NvError_Success=0,NvError_InvalidSize=1,NvError_InvalidArgument=2,NvError_SystemCommand=3)}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),ns)
        cls=type('ActualVendor',(),{k:ns[k] for k in wanted})
        class Files:
            def catFile(self,p):return Path(p).read_text()
            def removeFile(self,p):Path(p).unlink(missing_ok=True)
            def Copy(self,a,b):shutil.copyfile(a,b)
        obj=cls();obj.shellUtils=Files();obj.log=obj.vlog=lambda *a:None
        obj.targetConfig=SimpleNamespace(parsed_commandline={'s':False,'o':False,'O':False,'m':False,'clean':False},dieId='die0',BOOTBURN_PYTEST=False,n_FlashHypervisor=False,is_l4t=True,n_FlashLinux=True,headers=None,n_Asymmetric=False,s_L4TBootChainSelect=chain,s_EmmcErasedArray=[])
        obj.EraseQspi=Mock();obj.AdbShell=Mock(side_effect=AssertionError('no actual hardware commands allowed'))
        return obj

    def execute(self,obj,index,root):
        cwd=os.getcwd()
        try:obj.FlashUsingADB(str(index),[],str(root),None)
        finally:os.chdir(cwd)

    def test_actual_vendor_BCT_A_B_PT_badpage_transformations(self):
        for name,size,raw in [('bct',1048576,b'18 bytes of BCT!!!!'),('pt',4096,b'PT!'*170),('bad-page',524288,b'badpage')]:
            for chain in ('A','B'):
                with self.subTest(name=name,chain=chain),tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp);index=self.fixture(root,name,raw,size);plan=plan_qspi(index,chain=chain);obj=self.vendor(chain);sent=[]
                    obj.SendFileUsingADB=lambda part,*args:sent.append(Path(part.FileName).read_bytes()) or 0
                    self.execute(obj,index,root)
                    self.assertEqual(sent,[plan.programmed[0].data])
                    self.assertEqual(sum(len(p.data) for p in plan.ranges),CAPACITY)

    def reader(self,plan,corrupt=None):
        image=bytearray(b'\xff'*CAPACITY)
        for part in plan.programmed:image[part.offset:part.offset+len(part.data)]=part.data
        if corrupt is not None:image[corrupt]^=1
        client=Mock();client.shell.return_value=b'EXITCODE=0\n';position=[0,0]
        def shell(serial,command):
            if ' --outputbin ' in command:
                fields=command.split();position[:]=[int(fields[fields.index('--startoffset')+1]),int(fields[fields.index('--partsize')+1])]
            return b'EXITCODE=0\n'
        def pull(serial,remote,local):
            start,size=position;Path(local).write_bytes(image[start:start+size])
        client.shell.side_effect=shell;client.pull.side_effect=pull
        return client

    def test_full_readback_transformed_copies_padding_B_erased_block_and_gaps(self):
        for chain in ('A','B'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root);plan=plan_qspi(index,chain=chain)
                result=verify_qspi(self.reader(plan),'123',index,root,plan=plan)
                self.assertEqual(sum(r['size'] for r in result),CAPACITY)
                for corrupt in (0,18,BLOCK,BLOCK+18,2*BLOCK,2*BLOCK+18,3*BLOCK,CAPACITY-1):
                    with self.subTest(chain=chain,corrupt=corrupt),self.assertRaisesRegex(ValueError,'readback mismatch'):
                        verify_qspi(self.reader(plan,corrupt),'123',index,root,plan=plan)

    def test_PT_badpage_later_copy_corruption(self):
        for name,size in (('pt',4096),('bad-page',524288)):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root,name,b'payload',size);plan=plan_qspi(index)
                for offset in (7,size-1):
                    with self.assertRaisesRegex(ValueError,'readback mismatch'):
                        verify_qspi(self.reader(plan,offset),'123',index,root,plan=plan)

    def test_guard_actual_vendor_dry_preflight_before_erase_and_exact_send(self):
        from firmware_guard import install
        for name,size in (('bct',1048576),('pt',4096),('bad-page',524288)):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root,name,b'payload',size);plan=plan_qspi(index);obj=self.vendor();actual=[]
                p=plan.programmed[0]
                approved={name:{'key':[p.device,name,p.offset,size],'size':len(p.data),'sha256':hashlib.sha256(p.data).hexdigest()}}
                obj.SendFileUsingADB=lambda part,*a:actual.append(Path(part.FileName).read_bytes()) or 0
                install(type(obj),index,approved,'A');self.execute(obj,index,root)
                self.assertEqual(actual,[p.data]);obj.EraseQspi.assert_called_once()
                obj.EraseQspi.reset_mock();(root/'fw.bin').write_bytes(b'mutated')
                with self.assertRaisesRegex(ValueError,'transformed bytes'):self.execute(obj,index,root)
                obj.EraseQspi.assert_not_called()

    def test_wrong_approved_transformation_refused_before_erase(self):
        from firmware_guard import install
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);index=self.fixture(root);plan=plan_qspi(index);p=plan.programmed[0]
            obj=self.vendor();obj.SendFileUsingADB=Mock()
            approved={'bct':{'key':[p.device,'bct',p.offset,1048576],
                             'size':len(p.data),'sha256':'0'*64}}
            install(type(obj),index,approved,'A',root.parent)
            with self.assertRaisesRegex(ValueError,'transformed bytes'):self.execute(obj,index,root)
            obj.EraseQspi.assert_not_called();obj.SendFileUsingADB.assert_not_called()

    def test_unsupported_configuration_before_erase(self):
        from firmware_guard import install
        for field,value in (('headers','headers-dir'),('n_Asymmetric',True),('s_L4TBootChainSelect','B')):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root);obj=self.vendor();setattr(obj.targetConfig,field,value)
                install(type(obj),index,{},'A')
                with self.assertRaisesRegex(ValueError,'unsupported'):self.execute(obj,index,root)
                obj.EraseQspi.assert_not_called()

    def test_empty_sparse_BCH_header_badpage_refused_before_vendor_run(self):
        from vendor import Vendor,package_hashes
        for name,raw,size in (('bct',b'',1048576),('A_cpu',b'\x3a\xff\x26\xedpayload',4096),('bad-page',b'bad',512)):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root,name,raw,size)
                with self.assertRaises(ValueError):plan_qspi(index)
        for field in (8,9):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root);row=index.read_text().split();row[field]='unsupported!' if field == 8 else '99';index.write_text(' '.join(row)+'\n')
                with self.assertRaisesRegex(ValueError,'BCH/header'):plan_qspi(index)

    def test_vendor_provision_refuses_empty_before_run(self):
        from vendor import Vendor,package_hashes
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);images=root/'unified_flash/out/bsp_images/flash_workspace/flash-images';images.mkdir(parents=True)
            self.fixture(images,raw=b'')
            for directory in root.rglob('*'):
                if directory.is_dir(): directory.chmod(0o700)
            vendor=Vendor(root,'thor','1-2',runner=Mock());vendor.run=Mock()
            with self.assertRaisesRegex(ValueError,'empty'):vendor.provision_qspi(package_hashes(root))
            vendor.run.assert_not_called()


    def boundary(self,root,name='bct',fault=None):
        if not SOURCE.is_file(): self.skipTest('set NVIDIA_VENDOR_ROOT to the extracted pinned BSP')
        import subprocess
        from firmware import bind_programmed_plan
        from vendor import Vendor,package_hashes
        from workspace import Workspace,snapshot
        w=Workspace(root/'session',owner=os.geteuid());self.addCleanup(w.close)
        w.tree.mkdir(mode=0o700)
        bsp=w.tree/'unified_flash/out/bsp_images';images=bsp/'flash_workspace/flash-images';images.mkdir(parents=True)
        size={'bct':1048576,'bad-page':524288,'pt':4096}[name]
        index=self.fixture(images,name,b'payload',size)
        source=bsp/'tools/flashtools/bootburn_t264_py/bootburn_adb.py';source.parent.mkdir(parents=True);source.write_bytes(SOURCE.read_bytes())
        for path in w.tree.rglob('*'):path.chmod(0o700 if path.is_dir() else 0o600)
        w.expected=snapshot(w.tree,os.geteuid())
        w.vendor_server=Mock();w.vendor_server.binary='/no/hardware/adb';w.vendor_server.process.pid=123;w.vendor_server.port=43210
        vendor=Vendor(w.tree,'thor','1-2',workspace=w);vendor.approved_identity={'ecid':'0x123'}
        plan=bind_programmed_plan(vendor,index);approved=package_hashes(w.tree)
        tree=ast.parse(source.read_text());nodes=[n for n in tree.body if getattr(n,'lineno',0)>len(SOURCE.read_text().splitlines())]
        obj=self.vendor();namespace={'bootburn_adb':type(obj),'__file__':str(source)}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),namespace)
        sent=[]
        def send(part,*args):
            path=Path(part.FileName);sent.append(path.read_bytes())
            if fault=='tamperedtmp':path.write_bytes(b'changed after checked send')
            if fault=='unexpected':(path.parent/'unexpected.tmp').write_bytes(b'extra')
            if fault=='package':(images/'fw.bin').write_bytes(b'changed package')
            return 0
        obj.SendFileUsingADB=send
        def runner(argv,**kwargs):
            self.assertIn('-y',argv)
            self.execute(obj,index,images)
            return subprocess.CompletedProcess(argv,0,b'actual extracted FlashUsingADB completed')
        w.runner=Mock(side_effect=runner)
        return w,vendor,obj,plan,approved,images,sent

    def test_bound_generated_vendor_module_plan_hash_and_serial_command(self):
        import json
        from unittest.mock import patch
        from vendor import package_hashes
        for name in ('bct','bad-page','pt'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                w,vendor,obj,plan,approved,images,sent=self.boundary(Path(tmp),name)
                client=self.reader(plan)
                with patch('transport.ADB') as adb,patch('adb_socket.Client',return_value=client):
                    adb.return_value.serial='123'
                    vendor.provision_qspi(approved)
                obj.EraseQspi.assert_called_once();w.runner.assert_called_once()
                self.assertEqual(sent,[plan.programmed[0].data])
                self.assertEqual(sum(r['size'] for r in vendor.firmware_readback),CAPACITY)
                self.assertEqual(package_hashes(w.tree),approved);w.validate()
                evidence=list(w.root.glob('firmware-execution-*.json'));self.assertEqual(len(evidence),1)
                hashes=json.loads(evidence[0].read_text())['files']
                work=evidence[0].with_suffix('')
                self.assertEqual(hashes,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in work.iterdir()})
                self.assertIn(hashlib.sha256(sent[0]).hexdigest(),hashes.values())
                manifest=json.loads((w.root/'preparation-manifest.json').read_text())
                self.assertEqual(manifest['tree'],w.expected)

    def test_boundary_unexpected_tampered_scratch_changed_package_fail(self):
        from unittest.mock import patch
        for fault in ('unexpected','tamperedtmp','package'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                w,vendor,obj,plan,approved,images,sent=self.boundary(Path(tmp),fault=fault)
                with patch('adb_socket.Client') as client,self.assertRaisesRegex(ValueError,'scratch changed|package mutated'):
                    vendor.provision_qspi(approved)
                client.assert_not_called()
                self.assertTrue(list(w.root.glob('firmware-execution-*')))

    def test_boundary_changed_approved_package_refused_before_erase(self):
        with tempfile.TemporaryDirectory() as tmp:
            w,vendor,obj,plan,approved,images,sent=self.boundary(Path(tmp))
            (images/'fw.bin').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'tree changed'):vendor.provision_qspi(approved)
            obj.EraseQspi.assert_not_called();w.runner.assert_not_called()

    def test_static_signature_metadata_does_not_resign_in_actual_write_method(self):
        for header in ('0','8','9','12'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);index=self.fixture(root);row=index.read_text().split();row[8]='bct';row[9]=header;index.write_text(' '.join(row)+'\n')
                plan=plan_qspi(index);obj=self.vendor();sent=[]
                obj.SendFileUsingADB=lambda part,*a:sent.append(Path(part.FileName).read_bytes()) or 0
                self.execute(obj,index,root);self.assertEqual(sent,[plan.programmed[0].data])


    def test_actual_nvimagegen_generated_PT_expansion(self):
        import subprocess
        tool=SOURCE.parent.parent/'flash/nvimagegen'
        if not tool.is_file():self.skipTest('pinned generation tool absent')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            cfg=root/'layout.cfg';cfg.write_text('[device]\ntype=spi\ninstance=0\nlinux_name=/dev/block/810c5b0000.spi\nsize=0x4000000\n[partition]\nname=bct\nallocation_policy=sequential\nfilesystem_type=basic\nsize=1048576\npartition_attribute=0\ntype=boot_config_table\n[partition]\nname=pt\nallocation_policy=sequential\nfilesystem_type=basic\nsize=262144\npartition_attribute=0\ntype=partition_table\n')
            result=subprocess.run([str(tool),'--chip','0x26','--chipver','A01','--cfg',str(cfg),'--ptonly','--showpt'],cwd=root,capture_output=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            raw=(root/'2_PT.bin').read_bytes();self.assertEqual(len(raw),8704)
            for path in root.iterdir():path.chmod(0o600)
            index=self.fixture(root,'pt',raw,262144);plan=plan_qspi(index);obj=self.vendor();sent=[]
            obj.SendFileUsingADB=lambda part,*a:sent.append(Path(part.FileName).read_bytes()) or 0
            self.execute(obj,index,root);self.assertEqual(sent,[plan.programmed[0].data])
            self.assertEqual(len(sent[0]),len(raw)*(262144//len(raw)))

if __name__=='__main__':unittest.main(verbosity=2)
