from test_support import vendor_path, external_path
"""Actual pinned vendor filename/sign/index boundary; ordinary files only.

Only board/crypto generation is stubbed. No EEPROM or hardware is simulated.
"""
import ast
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import types
import unittest
import xml.etree.ElementTree as ElementTree
from unittest.mock import patch
from vendor import Vendor, package_hashes
from workspace import snapshot
import test_execution

SOURCE = vendor_path('bootloader')
PINS = {'tegraflash_internal.py':'1ee04eb3a363aa89e4e7c680c77ce391e2f28d5901086bd256c560ffc8d95ef1',
        'tegraflash_impl_t234.py':'a77d3b478d02396f0d7dded7369382a0e1ecac0d185a2ec232df872d0fa3abca',
        'tegraparser_v2':'2b5ec7c1bfa8ffad7d97957c98a449141fc7ed0aa6989142d3e53ed73b699f36'}
XML = '<partition_layout version="01.00.0000"><device type="spi" instance="0" sector_size="512" num_sectors="131072"><partition name="BCT" type="boot_config_table"><allocation_policy>sequential</allocation_policy><filesystem_type>basic</filesystem_type><size>1048576</size><file_system_attribute>0</file_system_attribute><allocation_attribute>8</allocation_attribute><percent_reserved>0</percent_reserved><filename>bct.bin</filename></partition></device></partition_layout>'


def fixture(workspace, fault=None):
    bl = workspace.tree/'bootloader'; bl.mkdir(exist_ok=True)
    for name, pin in PINS.items():
        if not (SOURCE/name).is_file():
            raise unittest.SkipTest('set NVIDIA_VENDOR_ROOT to the extracted pinned BSP')
        raw = (SOURCE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            raise AssertionError('actual vendor source pin differs: '+name)
        shutil.copyfile(SOURCE/name, bl/name)
    (bl/'tegraparser_v2').chmod(0o700)
    stock = bl/'generic/cfg/flash_t234_qspi.xml'
    stock.parent.mkdir(parents=True, exist_ok=True); stock.write_text(XML)
    (bl/'flashcmd.txt').write_text('./tegraflash.py --chip "0x23 9" --cmd sign')
    (bl/'flash.xml').write_text(XML)
    (bl/'bct.bin').write_bytes(b'file-only-BCT-no-device-metadata')
    workspace._seal_modes(); workspace.expected = snapshot(workspace.tree, os.geteuid())

    def method(filename, name, ns):
        tree = ast.parse((bl/filename).read_text())
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(bl/filename), 'exec'), ns)
        return ns[name]

    def edge(argv, **kwargs):
        if argv[0] != './flash.sh':
            # Only the real file-only parser repair may cross this edge.
            assert Path(argv[0]) == bl/'tegraparser_v2', argv
            return subprocess.run(argv, **kwargs)
        previous = Path.cwd(); os.chdir(bl)
        try:
            def toolrun(cmd, *a, **k):
                assert cmd[0] == str(bl/'tegraparser_v2'), cmd
                return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            ns = dict(os=os, ElementTree=ElementTree, paths={'TMP':str(bl)},
                      tegraflash_abs_path=os.path.abspath, tegraflash_symlink=os.symlink,
                      exec_file=lambda _: [str(bl/'tegraparser_v2')], run_command=toolrun)
            cfg = method('tegraflash_internal.py','tegraflash_update_img_path',ns)('flash.xml',None)
            assert cfg == 'flash.xml.tmp'
            subprocess.run([str(bl/'tegraparser_v2'),'--pt',cfg], check=True, capture_output=True)
            index = method('tegraflash_internal.py','tegraflash_generate_index_file',ns)
            vals = {'--encrypt_key':None,'--cfg':cfg,'--bins':None,'--tegraflash_v2':False,'--bl':None,
                    '--external_device':False,'--mb2_bct':None,'--mb2_cold_boot_bct':None}
            obj = types.SimpleNamespace(tegraparser_values={'--pt':'flash.xml.bin'},
                tegrahost_values={'--signed_list':'unused'},tegrabct_values={'--bct':'bct.bin',
                '--mb1_bct':None,'--mb1_cold_boot_bct':None,'--membct_rcm':None,'--membct_cold_boot':None,
                **{'--membct_rcm_'+str(i):None for i in range(4)}})
            for name in ('tegraflash_get_key_mode','tegraflash_parse_partitionlayout','tegraflash_sign_images','tegraflash_generate_bct','tegraflash_update_images'):
                setattr(obj,name,lambda *a:None)
            obj.tegraflash_copy_signed_binaries=lambda *a:[]
            obj.exec_file=lambda _:[str(bl/'tegraparser_v2')]
            obj.tegraflash_update_cfg_file=types.MethodType(method('tegraflash_impl_t234.py','tegraflash_update_cfg_file',dict(ElementTree=ElementTree,os=os,values=vals)),obj)
            signns=dict(values=vals,os=os,re=re,shutil=shutil,info_print=lambda *a:None,
                tegraflash_abs_path=os.path.abspath,run_command=toolrun,
                copy_br_bct_multi_chain=lambda out:shutil.copyfile('bct.bin',Path(out)/'bct.bin'),
                tegraflash_generate_index_file=index)
            method('tegraflash_impl_t234.py','tegraflash_sign',signns)(obj,{})
            assert (bl/'signed/flash.xml.tmp').is_file()
            assert not (bl/'signed/flash.xml').exists()
            if fault == 'decoy-only': (bl/'signed/flash.xml.tmp').rename(bl/'signed/flash.xml')
            if fault == 'decoy': (bl/'signed/flash.xml').write_text('<not-authority/>')
            if fault == 'emmc':
                p=bl/'signed/flash.xml.tmp'; p.write_text(p.read_text().replace('type="spi"','type="sdmmc_user"'))
            return subprocess.CompletedProcess(argv,0,b'actual extracted vendor sign completed\n')
        finally: os.chdir(previous)
    workspace.runner=edge
    return stock


class SignedCfgTests(unittest.TestCase):
    setUp = test_execution.ExecutionTests.setUp
    tearDown = test_execution.ExecutionTests.tearDown
    archive = test_execution.ExecutionTests.archive
    workspace = test_execution.ExecutionTests.workspace

    def generate(self, fault=None):
        w=self.workspace(); fixture(w,fault)
        v=Vendor(w.tree,'orin','1-2',workspace=w)
        return w,v

    def test_actual_vendor_sign_to_production_plan(self):
        w,v=self.generate('decoy'); package=v.generate_qspi(); w.validate()
        self.assertIn('bootloader/signed/flash.xml.tmp',package)
        self.assertEqual(package,package_hashes(w.tree))
        self.assertEqual(v.orin_plan['payloads'][0]['filename'],'bct.bin')
        # Provision must select the same current XML before any transport edge.
        transport=types.SimpleNamespace(bind=lambda: (_ for _ in ()).throw(RuntimeError('validated-plan-before-hardware')))
        with self.assertRaisesRegex(RuntimeError,'validated-plan-before-hardware'):
            __import__('orin_firmware').provision(v,transport)

    def test_decoy_cannot_authorize_missing_current_cfg(self):
        w,v=self.generate('decoy-only')
        with self.assertRaises((ValueError,FileNotFoundError)): v.generate_qspi()

    def test_stale_signed_output_rejected_before_generation(self):
        w,v=self.generate(); signed=w.tree/'bootloader/signed'; signed.mkdir()
        (signed/'flash.xml.tmp').write_text(XML)
        w._seal_modes(); w.expected=snapshot(w.tree,os.geteuid())
        with patch.object(w,'runner') as runner:
            with self.assertRaisesRegex(ValueError,'fresh'):v.generate_qspi()
            runner.assert_not_called()

    def test_generated_cfg_mutation_refused_by_workspace(self):
        w,v=self.generate(); v.generate_qspi()
        (w.tree/'bootloader/signed/flash.xml.tmp').write_text(XML+'\n')
        with self.assertRaisesRegex(ValueError,'tree changed'):w.validate()
