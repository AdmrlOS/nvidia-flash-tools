"""Fresh explicit carrier command, source-shaped generated argv, no USB."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from workspace import Workspace, snapshot
from vendor import Vendor


class OrinProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = Workspace(self.root/'session',owner=os.geteuid());self.addCleanup(self.workspace.close)
        self.tree = self.workspace.tree; (self.tree/'bootloader').mkdir(parents=True)
        (self.tree/'flash.sh').write_text('fixture')
        self.workspace._seal_modes()
        self.workspace.expected = snapshot(self.tree,os.geteuid())
        self.workspace.runner = self.edge
        self.outputs = []; self.bad = None
        self.vendor = Vendor(self.tree,'orin','1-2',workspace=self.workspace)

    def edge(self,argv,**kwargs):
        if argv[0] == './tegrarcm_v2':
            return subprocess.CompletedProcess(argv,0,b'BR_CID: 0x80002300000000000000000000000123\n')
        if argv[0] == './flash.sh':
            self.assertIn('--no-flash',argv);self.assertIn('--read-info',argv)
            (self.tree/'bootloader/readinfocmd.txt').write_text('rm cvm.bin;\n./tegraflash.py --chip "0x23 9" --cmd "readfuses fuse_t234.bin read.xml; dump eeprom cvm cvm.bin; dump try_custinfo custinfo_out.bin; reboot recovery";\n')
        elif argv[0] == '/usr/bin/python3':
            self.assertEqual(argv[-2:],['--instance','1-2'])
            sequence = [shlex.split(p) for p in argv[argv.index('--cmd')+1].split(';')]
            self.assertEqual(sequence[0],['readfuses','fuse_t234.bin','read.xml'])
            for part in sequence:
                if part[:2] == ['dump','eeprom']:
                    self.outputs.append(part[-1])
                    if self.bad == 'missing' and part[2] == 'cvb': continue
                    data = (b'cvb' if part[2] == 'cvb' else b'cvm').ljust(256,b'\0')
                    if self.bad == 'short': data = data[:-1]
                    (self.tree/'bootloader'/part[-1]).write_bytes(data)
            names = ('PublicKeyHash','BootSecurityInfo','SecurityMode','ArmJtagDisable','DebugAuthentication','SwReserved','OdmLock','PkcPubkeyHash1','PkcPubkeyHash2')
            (self.tree/'bootloader/fuse_t234.bin').write_text(''.join(n+': 00\n' for n in names))
        elif argv[0] == './chkbdinfo':
            flag,file = argv[1:]
            carrier = file.endswith('-cvb.bin')
            result = {'-i':'3768' if self.bad == 'mixed' and carrier else '3737' if carrier else '3701', '-k':'0000','-f':'fresh-fab','-r':'fresh-rev'}[flag]
            return subprocess.CompletedProcess(argv,0,result.encode())
        else: raise AssertionError(argv)
        return subprocess.CompletedProcess(argv,0,b'')

    def probe(self):
        with patch.object(self.vendor,'single_rcm'):
            return self.vendor.probe()

    def test_explicit_fresh_cvb_unique_each_probe(self):
        a=self.probe();b=self.probe()
        self.assertEqual(a,b);self.assertEqual(len(set(self.outputs)),4)
        self.assertEqual(a['carrier'],'3737-0000');self.workspace.validate()

    def test_cached_carrier_not_accepted(self):
        (self.tree/'bootloader/cvb.bin').write_bytes(b'old'.ljust(256,b'\0'))
        self.workspace._seal_modes()
        self.workspace.expected=snapshot(self.tree,os.geteuid())
        self.bad='missing'
        with self.assertRaises(FileNotFoundError):self.probe()

    def test_short_eeprom_refused(self):
        self.bad='short'
        with self.assertRaisesRegex(ValueError,'exact 256'):self.probe()

    def test_mixed_metadata_refused(self):
        self.bad='mixed'
        with self.assertRaisesRegex(ValueError,'allowlisted'):self.probe()

    def test_second_usb_on_real_ssh_binding_refused(self):
        from transport import SSH
        usb=self.root/'usb';selected=usb/'1-2';endpoint=selected/'1-2:1.0';endpoint.mkdir(parents=True)
        (selected/'idVendor').write_text('0955')
        net=self.root/'net';(net/'usb0').mkdir(parents=True);(net/'usb0/device').symlink_to(endpoint)
        transport=SSH('usb0','1-2',self.root/'known',sysfs=usb,netfs=net)
        transport.bind()
        (usb/'1-3').mkdir();(usb/'1-3/idVendor').write_text('0955')
        with self.assertRaisesRegex(ValueError,'exactly one'):transport.bind()

    def test_second_usb_before_probe_refused(self):
        usb=self.root/'usb';(usb/'1-2').mkdir(parents=True);(usb/'1-3').mkdir()
        for name in ('1-2','1-3'):(usb/name/'idVendor').write_text('0955')
        with self.assertRaisesRegex(ValueError,'exactly one'):self.vendor.single_rcm(usb)
