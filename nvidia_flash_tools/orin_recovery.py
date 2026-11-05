"""Selected Orin RAM boot and authenticated USB SSH setup; no wrapper execution."""
import hashlib
from pathlib import Path
import re
import shlex
import time

from nvidia_flash_tools.image import sha256


def seal(vendor):
    from nvidia_flash_tools.workspace import snapshot
    vendor.workspace._normalize_generated_rootfs_links()
    vendor.workspace._seal_modes()
    vendor.workspace.expected = snapshot(vendor.tree, vendor.workspace.owner)
    vendor.workspace.record('orin-adapter')


def fresh_eeproms(vendor):
    """Use generated read-info argv, explicitly dump BOTH fresh EEPROMs."""
    import secrets
    import stat
    bl = vendor.tree/'bootloader'
    vendor.workspace.remove_generated(['bootloader/readinfocmd.txt'])
    from nvidia_flash_tools.workspace import READINFO_CHIP_INFO_FAILURE
    returncode, output = vendor.run_tolerated(['./flash.sh','--no-flash','--read-info','--usb-instance',
                                               vendor.port,vendor.alias,'internal'])
    if returncode and (returncode != 1 or output.rstrip().splitlines()[-1:] != [READINFO_CHIP_INFO_FAILURE]):
        raise ValueError('flash.sh read-info generation failed (exit %d):\n%s' % (returncode, output[-4000:]))
    raw = (bl/'readinfocmd.txt').read_text().splitlines()
    lines = raw
    commands = [shlex.split(line.rstrip(';')) for line in lines if line.startswith('./tegraflash.py ')]
    if len(commands) != 1 or commands[0].count('--cmd') != 1:
        raise ValueError('missing unique generated T234 read-info executor')
    argv = commands[0]
    index = argv.index('--cmd')+1
    sequence = [shlex.split(part) for part in argv[index].split(';') if part.strip()]
    fuses = [part for part in sequence if part and part[0] == 'readfuses']
    if len(fuses) != 1 or len(fuses[0]) != 3 or ['dump','eeprom','cvm','cvm.bin'] not in sequence:
        raise ValueError('unknown generated T234 read-info grammar')
    if argv.count('--chip') != 1 or argv[argv.index('--chip')+1].split()[0] != '0x23':
        raise ValueError('wrong EEPROM executor chip')
    nonce = secrets.token_hex(16)
    outputs = {name+'.bin':'admiral-'+nonce+'-'+name+'.bin' for name in ('cvm','cvb')}
    for name in outputs.values():
        if (bl/name).exists(): raise ValueError('EEPROM session output already exists')
    if '--instance' in argv:
        if argv.count('--instance') != 1: raise ValueError('duplicate EEPROM instance')
        argv[argv.index('--instance')+1] = vendor.port
    else:
        argv += ['--instance',vendor.port]
    from nvidia_flash_tools import carrier
    if vendor.board in carrier.BOARDS:
        return _fresh_eeproms_unverified_carrier(vendor, bl, argv, index, fuses[0], outputs)
    argv[index] = '; '.join([shlex.join(fuses[0]),
                            'dump eeprom cvm '+outputs['cvm.bin'],
                            'dump eeprom cvb '+outputs['cvb.bin'],'reboot recovery'])
    vendor.run(['/usr/bin/python3',*argv],cwd=bl)
    for name in outputs.values():
        info = (bl/name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 256:
            raise ValueError('fresh EEPROM must be regular exact 256 bytes')
    return outputs


def _fresh_eeproms_unverified_carrier(vendor, bl, argv, index, fuses, outputs):
    """Strict fuses + module EEPROM; the carrier EEPROM dump is evidence, not a requirement.

    The Seeed J401 has no NVIDIA-format carrier EEPROM at the devkit address:
    MB2 answers "Could not read eeprom for module cvb" and tegraflash stops
    before its recovery reboot, leaving the MB2 applet running. The mandatory
    fuse and module reads therefore run first and end with their own recovery
    reboot; the carrier dump runs last, and its failure is recorded verbatim.
    Vendor.probe then has the operator power-cycle back into recovery. Only the
    first probe of a session dumps the carrier (see Vendor.carrier_record).
    """
    import stat
    module = list(argv)
    module[index] = '; '.join([shlex.join(fuses), 'dump eeprom cvm '+outputs['cvm.bin'],
                               'reboot recovery'])
    vendor.run(['/usr/bin/python3',*module],cwd=bl)
    info = (bl/outputs['cvm.bin']).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 256:
        raise ValueError('fresh EEPROM must be regular exact 256 bytes')
    if getattr(vendor, 'carrier_record', None) is not None:
        # Later probes in one session: the carrier dump was recorded, table-checked
        # and operator-confirmed by the first probe. Repeating it only re-leaves the
        # applet running (one more power cycle); fuses, cvm and UID stay fresh.
        return outputs
    carrier = list(argv)
    carrier[index] = 'dump eeprom cvb '+outputs['cvb.bin']+'; reboot recovery'
    returncode, output = vendor.run_tolerated(['/usr/bin/python3',*carrier],cwd=bl)
    vendor.cvb_dump = {'returncode':returncode, 'output':output}
    cvb = bl/outputs['cvb.bin']
    if returncode and (cvb.exists() or cvb.is_symlink()):
        # A failed dump's partial file is not evidence; the failure is.
        if vendor.workspace is not None:
            vendor.workspace.remove_generated(['bootloader/'+outputs['cvb.bin']])
        else:
            cvb.unlink()
    return outputs


def command(vendor, operation):
    argv = shlex.split((vendor.tree/'bootloader/flashcmd.txt').read_text())
    if not argv or argv[0] != './tegraflash.py' or argv.count('--cmd') != 1:
        raise ValueError('unsupported Orin generated executor')
    if argv[argv.index('--cmd')+1].strip() != operation:
        raise ValueError('unexpected Orin generated operation')
    # R39.2.1 T234 RCM boot is always odmsign's pre-signed path: zero-key signed
    # images plus --securedev ("images already signed"). Keys stay refused.
    refused = ('--key','--encrypt_key','--skipuid','--sparseupdate') + (() if operation == 'rcmboot' else ('--securedev',))
    if any(arg in argv for arg in refused):
        raise ValueError('unsupported secured/implicit Orin executor')
    if '--chip' not in argv or argv[argv.index('--chip')+1] not in ('0x23','0x23 0','0x23 9'):
        raise ValueError('generated Orin executor chip mismatch')
    if '--instance' in argv:
        if argv.count('--instance') != 1:
            raise ValueError('duplicate selected instance')
        argv[argv.index('--instance')+1] = vendor.port
    else:
        argv += ['--instance', vendor.port]
    return argv


def ram_boot(vendor, identity):
    expected = {key:identity[key] for key in ('br_cid','ecid')}
    if vendor.uid() != expected:
        raise ValueError('Orin changed before RAM generation')
    bl = vendor.tree/'bootloader'
    # Obtain stock recovery.img, rootfs utilities and generated recovery SSH keys.
    # --no-flash without --rcm-boot exits before tegraflash execution.
    vendor.run(['./flash.sh','--no-flash','--no-systemimg','--qspi-only',
                '-c','bootloader/generic/cfg/flash_t234_qspi.xml',
                '--usb-instance',vendor.port,vendor.recovery_alias,'internal'])
    if not (bl/'recovery.img').is_file():
        raise ValueError('flash.sh did not build bootloader/recovery.img for ' + vendor.recovery_alias)
    source = vendor.tree/'tools/kernel_flash/l4t_initrd_flash_internal.sh'
    text = source.read_text()
    match = re.search(r'^generate_flash_initrd\(\)\n\{\n.*?^\}',text,re.M|re.S)
    if not match:
        raise ValueError('pinned vendor recovery generator unavailable')
    method = match[0]
    pack = '\tfind . | cpio -H newc -o | gzip -9 -n > "${working_dir}/initrd.img"'
    if method.count(pack) != 1:
        raise ValueError('pinned Orin recovery pack boundary changed')
    # Recovery is a minimal initramfs, not an Ubuntu rootfs. Materialize the
    # exact absolute utility paths used by authenticated transport/helper flow.
    additions = '\tmkdir -p "${working_dir}/initrd/usr/bin"\n'
    additions += '\tcp "${ROOTFS_DIR}/usr/bin/sha256sum" "${working_dir}/initrd/usr/bin/sha256sum"\n'
    for tool in ('cat','readlink','chmod','rm','mktemp','true','dd','cut','sed','sha1sum','sync'):
        additions += '\tcp "${ROOTFS_DIR}/usr/bin/' + tool + '" "${working_dir}/initrd/bin/' + tool + '"\n'
    method = method.replace(pack,additions+pack)
    # Execute just this vendor preparation method. Never its enumerable main.
    scratch = vendor.tree/'admiral-orin-recovery'
    if scratch.exists():
        import shutil
        vendor.workspace.validate()
        shutil.rmtree(scratch)
    scratch.mkdir(mode=0o700)
    seal(vendor)
    script = vendor.tree/'admiral-orin-recovery-generator.sh'
    variables = {'working_dir':str(scratch), 'BOOTLOADER_DIR':str(bl),
                 'LINUX_BASE_DIR':str(vendor.tree), 'ROOTFS_DIR':str(vendor.tree/'rootfs'),
                 'INITRDDIR_L4T_DIR':str(source.parent/'initrd_flash'),
                 'INITRDBINDIR_L4T_DIR':str(source.parent/'bin'),
                 'BOOT_CTRL_CONF':str(vendor.tree/'rootfs/etc/nv_boot_control.conf'),
                 'L4T_INITRD_FLASH_DIR':str(source.parent), 'FLASH_IMG_MAP':'initrdflashimgmap.txt',
                 'FLASHING_KERNEL':'', 'boot_rootfs':'', 'UEFI_KEYS_CONF':'',
                 'network':'', 'ADB':'', 'UNIFIED_FLASH':'', 'enable_ufs_provision':'',
                 'external_device':'', 'erase_all':''}
    script.write_text('#!/bin/bash\nset -eo pipefail\n' +
                      '\n'.join(key+'='+shlex.quote(value) for key,value in variables.items()) +
                      '\nsign_bootimg() { :; }\n'+method+'\ngenerate_flash_initrd 0\n')
    script.chmod(0o700); seal(vendor)
    vendor.run(['/bin/bash',script])
    # Stock prepare_sshd_files placed these in recovery ramdisk before packing.
    public = scratch/'initrd/etc/ssh/ssh_host_ed25519_key.pub'
    fields = public.read_text().split()
    if len(fields) < 2 or fields[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',fields[1]):
        raise ValueError('missing stock generated recovery SSH host key')
    vendor.recovery_hostkey = fields[:2]
    # R39 t234 ignores --no_flash in flash.sh's own rcmboot branch, so that one
    # execution site is suppressed. On R39.2.1 T234 that branch is not reached:
    # odmsign_ext signs and only generates (rcmboot_blob) under --no-flash.
    flash = vendor.tree/'flash.sh'
    original = flash.read_text()
    needle = '\t\teval "${flashcmd} --no_flash";'
    if original.count(needle) != 1:
        raise ValueError('pinned RCM generation execution site changed')
    flash.write_text(original.replace(needle,'\t\t: # Admiral: generation only, selected executor runs separately'))
    seal(vendor)
    try:
        # -r: without it, --rcm-boot chroots into rootfs under qemu to refresh
        # the stock l4t_initrd.img, which -I replaces anyway (and the J40's
        # pinned sample-rootfs subset cannot run it).
        vendor.run(['./flash.sh','-r','--no-flash','--rcm-boot','--usb-instance',vendor.port,
                    '-I', str(scratch/'initrd.img'), vendor.alias,'internal'], {'BOOTIMG':'boot0.img'})
    finally:
        flash.write_text(original); seal(vendor)
    argv = command(vendor,'rcmboot')
    if argv.count('--bins') != 1:
        raise ValueError('missing selected recovery binary list')
    binaries = [part.split() for part in argv[argv.index('--bins')+1].split(';') if part.strip()]
    kernels = [part for part in binaries if part[0] == 'kernel']
    if len(kernels) != 1 or len(kernels[0]) != 2 or kernels[0][1] != 'boot.img':
        raise ValueError('unknown Orin selected RAM kernel reference')
    if sha256(bl/'boot.img') != sha256(bl/'boot0.img'):
        raise ValueError('selected Orin kernel differs from generated recovery')
    if not (bl/'boot.img').read_bytes().startswith(b'ANDROID!'):
        raise ValueError('unsupported Orin recovery boot image')
    from nvidia_flash_tools.orin_payload import hostkey
    vendor.recovery_hostkey = hostkey(bl/'boot.img',require_tools=True)
    vendor.recovery_payload = {'boot_sha256':sha256(bl/'boot.img'),
                               'generator_sha256':sha256(script),
                               'hostkey_sha256':hashlib.sha256(' '.join(vendor.recovery_hostkey).encode()).hexdigest(),
                               'executor_argv':argv}
    if vendor.uid() != expected:
        raise ValueError('Orin changed before selected RAM executor')
    import json
    executor = bl/'admiral-orin-payload.py'
    executor.write_bytes(Path(__file__).with_name('orin_payload.py').read_bytes())
    seal(vendor)
    output = vendor.run(['/usr/bin/python3',executor,str(bl),str(bl/'boot0.img'),
                         json.dumps(vendor.recovery_hostkey),json.dumps(argv),identity['br_cid']],cwd=bl)
    pins = re.findall(r'^ADMIRAL_VALIDATED_RCM_BLOB_SHA256=([0-9a-f]{64})$',output,re.M)
    if len(pins) != 1:
        raise ValueError('selected RAM executor did not validate its actual blob')
    vendor.recovery_payload['blob_sha256'] = pins[0]
    return vendor.recovery_payload


def transport(vendor, identity, *, timeout=120):
    from nvidia_flash_tools.transport import SSH, check_remote_ecid, usb_device
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        try:
            usb = usb_device(vendor.port)
            interfaces = [p.name for p in Path('/sys/class/net').iterdir()
                          if (p/'device').exists() and usb in (p/'device').resolve().parents]
            if len(interfaces) > 1:
                raise ValueError('ambiguous Orin USB network interface')
            if interfaces:
                known = vendor.workspace.root/'orin-recovery-known-hosts'
                # HostKeyAlias avoids IPv6 zone/name formatting ambiguity.
                known.write_text('admiral-orin-recovery '+' '.join(vendor.recovery_hostkey)+'\n')
                known.chmod(0o600)
                result = SSH(interfaces[0],vendor.port,known,ecid=identity['ecid'])
                result.wait_ready(timeout=max(1,deadline-time.monotonic()))
                check_remote_ecid(result, identity['ecid'])
                return result
        except FileNotFoundError:
            pass
        time.sleep(.25)
    raise TimeoutError('selected Orin USB recovery interface not ready')
