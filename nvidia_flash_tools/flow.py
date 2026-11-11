"""Engineering-only orchestration. Hardware qualification is NOT implied."""
import json
from pathlib import Path
import re

from nvidia_flash_tools.image import sha256
from nvidia_flash_tools.transport import ADB, SSH, check_remote_ecid
from nvidia_flash_tools.vendor import Vendor
from nvidia_flash_tools.writer import RecoveryDisk, write_image


def experimental_authorization(args):
    if getattr(args, 'experimental_first_test', False) is not True:
        raise ValueError('explicit experimental first-test risk consent required; use python3 thor.py install')
    if not callable(getattr(args, 'security_observation', None)):
        raise ValueError('current-board UEFI security observation required')


def installer_hashes(installer):
    """Bind root artifacts and relocated implementation code, not bytecode caches."""
    import stat
    installer = Path(installer)
    implementation = installer / 'nvidia_flash_tools'
    if implementation.is_symlink():
        raise ValueError('installer package symlink refused')
    paths = [p for p in installer.iterdir() if p.is_file() or p.is_symlink()]
    if implementation.is_dir():
        paths.extend(implementation.glob('*.py'))
    vendor_inputs = installer / 'vendor-inputs'
    if vendor_inputs.is_symlink():
        raise ValueError('installer vendor-inputs symlink refused')
    if vendor_inputs.is_dir():
        paths.extend(p for p in vendor_inputs.rglob('*') if p.is_file() or p.is_symlink())
    result = {}
    for path in sorted(paths):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('untrusted installer artifact: ' + str(path))
        result[str(path.relative_to(installer))] = sha256(path)
    return result


def approval_contract(workspace, release, installer, helper, recovery, package, board, disk):
    """Return exact approval bytes while the same session lock is held."""
    import hashlib
    from nvidia_flash_tools.security import regular_graph
    workspace.validate()
    from nvidia_flash_tools import carrier
    # A J401/MIC-733 identity must carry accepted cvb evidence AND the typed
    # confirmation before any digest exists; both are bound through physical_board.
    carrier.validate_bound(board)
    contract = {'schema': 2, 'release': release,
                'installer': installer_hashes(installer),
                'helper_sha256': sha256(helper), 'recovery_sha256': sha256(recovery),
                'firmware_package': package, 'physical_board': board, 'nvme': disk,
                'prepared_graph': workspace.expected}
    raw = json.dumps(contract, sort_keys=True, separators=(',', ':')).encode()
    return contract, hashlib.sha256(raw).hexdigest()


def thor_session(workspace, args, release, *, confirm, select_disk,
                 vendor_factory=Vendor, server_factory=None, transport_factory=ADB,
                 disk_factory=RecoveryDisk, request_recovery=None):
    """Complete orchestration beneath the hardware gate; injectable device edges.

    select_disk returns observed recovery sysfs identity, never a host disk.
    confirm must return exactly the displayed contract digest. Hardware tests
    inject all device edges; no approval JSON bypass exists.
    """
    from nvidia_flash_tools.transport import PrivateADBServer
    from nvidia_flash_tools.vendor import package_hashes, inspect_thor_payload
    if args.board != 'thor':
        raise ValueError('Orin signed firmware readback/selected RAM stage pending')
    experimental_authorization(args)
    workspace.validate()
    helper_record = release['recovery']['helper']
    if sha256(args.helper) != helper_record['sha256'] or sha256(Path(__file__).resolve().parent.parent/'recovery-io.c') != helper_record['source_sha256']:
        raise ValueError('helper source/binary not authenticated by release')
    approved_helper_sha256 = helper_record['sha256']
    helper = workspace.authenticate_helper(args.helper, helper_record)
    vendor = vendor_factory(workspace.tree, 'thor', args.usb_port, workspace=workspace)
    binary = workspace.tree / 'unified_flash/tools/flashtools/flash/adb'
    server_factory = server_factory or PrivateADBServer
    with server_factory(binary, sha256(binary), workspace) as server:
        if hasattr(workspace, 'bind_vendor_adb') and vendor_factory is Vendor:
            workspace.bind_vendor_adb(server)
        identity = dict(vendor.probe())
        # RAM-only first contact: discover the actual disk BEFORE any firmware erase.
        # No persistent flash command is authorized by this preflight.
        observation = args.security_observation(identity)
        if observation != 'secure-boot-disabled-observed':
            raise ValueError('unknown or incompatible UEFI Secure Boot; no keys enrolled or security disabled')
        identity['uefi_policy'] = observation
        vendor.ram_boot(identity)
        preflight_transport = transport_factory(binary, identity['ecid'], args.usb_port, server=server)
        preflight_transport.wait_ready()
        check_remote_ecid(preflight_transport, identity['ecid'])
        preflight_disk = select_disk(preflight_transport)
        if request_recovery is None:
            raise ValueError('physical same-board recovery reentry callback required')
        request_recovery(identity)
        reprobe = vendor.probe()
        if reprobe != {k:v for k,v in identity.items() if k != 'uefi_policy'}:
            raise ValueError('board changed after RAM-only preflight')
        package = vendor.generate_qspi()
        boot = workspace.tree / 'unified_flash/tools/flashtools/flashing_kernel/initramfs/t264/boot_flashing.img'
        contract, pin = approval_contract(workspace, release, Path(__file__).resolve().parent.parent,
                                          helper, boot, package, identity, preflight_disk)
        if confirm('firmware', contract, pin) != pin:
            raise ValueError('firmware approval not bound to generated package')
        workspace.validate()
        if vendor.uid() != {k: identity[k] for k in ('br_cid', 'ecid')} or package_hashes(workspace.tree) != package:
            raise ValueError('board/package changed after firmware approval')
        vendor.approved_identity = dict(identity)
        vendor.provision_qspi(package)
        if request_recovery is not None:
            request_recovery(identity)
        if vendor.probe() != {k:v for k,v in identity.items() if k != 'uefi_policy'}:
            raise ValueError('board changed after firmware stage')
        vendor.ram_boot(identity)
        payload = inspect_thor_payload(workspace.tree)
        transport = transport_factory(binary, identity['ecid'], args.usb_port, server=server)
        transport.wait_ready()
        check_remote_ecid(transport, identity['ecid'])
        disk = select_disk(transport)
        if disk != preflight_disk:
            raise ValueError('NVMe changed after first-contact preflight')
        generated = {'firmware': package, 'recovery_payload': payload}
        contract, pin = approval_contract(workspace, release, Path(__file__).resolve().parent.parent,
                                          helper, boot, generated, identity, disk)
        if confirm('erase-nvme', contract, pin) != pin:
            raise ValueError('NVMe erase approval not bound to physical identity')
        workspace.validate()
        target = disk_factory(transport, disk, identity['ecid'], helper, approved_helper_sha256)
        try:
            return write_image(args.image, target, release['boards']['thor']['image']['sha256'],
                               disk, identity, args.journal)
        finally:
            if hasattr(target, 'session') and not target.session.closed:
                target.session.abort()


def install(args, release, issues):
    experimental_authorization(args)
    if issues:
        raise ValueError('host prerequisites failed: ' + '; '.join(issues))
    # First field test uses the same guarded orchestration; no prior test record.
    from nvidia_flash_tools.security import trusted_directory
    import os
    fd = trusted_directory(Path(__file__).resolve().parent.parent)
    os.close(fd)
    fd = trusted_directory(Path(__file__).resolve().parent)
    os.close(fd)
    from nvidia_flash_tools.workspace import Workspace
    with Workspace(args.output) as workspace:
        workspace.prepare(args.nvidia_archive, args.sample_rootfs, release['nvidia'],
                          sample_rootfs_members(release, args.board), cache=prepared_cache(args))
        install_vendor_inputs(workspace, release, args.board)
        session = thor_session if args.board == 'thor' else orin_session
        return session(workspace, args, release, confirm=getattr(args, 'guided_approval', interactive_approval),
                            select_disk=(lambda t: select_recovery_disk(t, choose_single=True)) if hasattr(args, 'guided_approval') else select_recovery_disk,
                            request_recovery=lambda identity: input('Re-enter Force Recovery on the SAME board, then Enter: '))


def prepared_cache(args):
    """Verified prepared-workspace cache beside the trusted download cache (None: no cache)."""
    downloads = getattr(args, 'download_dir', None)
    return Path(downloads) / 'prepared' if downloads else None


def sample_rootfs_members(release, board):
    """Pinned sample-rootfs subset for boards whose vendor steps were traced (else None: all)."""
    from nvidia_flash_tools import vendor_inputs
    if board not in vendor_inputs.BOARDS:
        return None
    return vendor_inputs.load(release, board, Path(__file__).resolve().parent.parent)['rootfs_members']


def install_vendor_inputs(workspace, release, board):
    """Board-specific pinned inputs (recomputer-j40, mic-733-ao) from the authenticated bundle."""
    from nvidia_flash_tools import vendor_inputs
    if board in release.get('boards', {}) or board in vendor_inputs.BOARDS:
        return vendor_inputs.install(workspace, release, board, Path(__file__).resolve().parent.parent)


def orin_session(workspace, args, release, *, confirm, select_disk,
                 vendor_factory=Vendor, transport_factory=None,
                 disk_factory=RecoveryDisk, request_recovery=None):
    from nvidia_flash_tools.orin_recovery import transport as usb_transport
    from nvidia_flash_tools.vendor import package_hashes
    experimental_authorization(args)
    if request_recovery is None:
        raise ValueError('same-board physical recovery callback required before firmware erase')
    if args.board not in ('orin','orin-nx','recomputer-j40','mic-733-ao'):
        raise ValueError('exact Orin reference target required')
    workspace.validate()
    record = release['recovery']['helper']
    if sha256(Path(__file__).resolve().parent.parent/'recovery-io.c') != record['source_sha256']:
        raise ValueError('native helper source not authenticated')
    helper = workspace.authenticate_helper(args.helper,record)
    vendor = vendor_factory(workspace.tree,args.board,args.usb_port,workspace=workspace)
    vendor.carrier_power_cycle = request_recovery
    identity = dict(vendor.probe())
    observation = args.security_observation(identity)
    if observation != 'secure-boot-disabled-observed':
        raise ValueError('unknown/enabled UEFI Secure Boot; no security changes authorized')
    from nvidia_flash_tools import carrier
    if carrier.requires_confirmation(args.board):
        # Identity stage: the cvb evidence was already table-checked by probe().
        # The operator must additionally confirm the observed carrier by phrase.
        confirm_carrier = getattr(args, 'carrier_confirmation', None)
        if not callable(confirm_carrier):
            raise ValueError('board-specific carrier confirmation required')
        carrier.bind_confirmation(identity, confirm_carrier(identity), args.board)
    identity['uefi_policy'] = observation
    factory = transport_factory or usb_transport
    vendor.generate_qspi()
    vendor.ram_boot(identity)
    transport = factory(vendor,identity)
    check_remote_ecid(transport,identity['ecid'])
    disk = select_disk(transport)
    # Generation is complete before RAM recovery starts; approval includes both
    # the immutable signed SPI inputs and the selected RAM recovery graph.
    package = package_hashes(workspace.tree)
    boot = workspace.tree/'bootloader/boot0.img'
    generated = {'firmware':package,'programmed_plan':vendor.orin_plan,
                 'recovery':vendor.recovery_payload}
    from nvidia_flash_tools import orin_firmware
    if args.board in orin_firmware.MEASURE_BEFORE_APPROVAL:
        # Unmeasured module QSPI: read it now (read-only) so the operator sees it
        # and an unacceptable value stops before, not after, the approval.
        geometry = orin_firmware.qspi_geometry(transport)
        print('QSPI mtd0 measured in RAM recovery: ' + json.dumps(geometry, sort_keys=True))
        generated['qspi_geometry'] = geometry
    contract,pin = approval_contract(workspace,release,Path(__file__).resolve().parent.parent,
                                     helper,boot,generated,identity,disk)
    if confirm('firmware',contract,pin) != pin:
        raise ValueError('Orin firmware approval declined')
    workspace.validate()
    transport.bind(); check_remote_ecid(transport,identity['ecid'])
    if package_hashes(workspace.tree) != package or select_disk(transport) != disk:
        raise ValueError('Orin package/NVMe changed before firmware erase')
    vendor.approved_identity = dict(identity)
    vendor.orin_transport = transport
    vendor.provision_qspi(package)
    if request_recovery is None:
        raise ValueError('same-board physical recovery callback required')
    before = vendor.usb_devnum()
    request_recovery(identity)
    vendor.await_reenumeration(before)
    if carrier.stable(vendor.probe()) != carrier.stable(identity):
        raise ValueError('Orin board changed after firmware stage')
    vendor.ram_boot(identity)
    transport = factory(vendor,identity)
    check_remote_ecid(transport,identity['ecid'])
    if select_disk(transport) != disk:
        raise ValueError('Orin NVMe changed across recovery reboot')
    generated['firmware_readback'] = vendor.firmware_readback
    generated['recovery'] = vendor.recovery_payload
    contract,pin = approval_contract(workspace,release,Path(__file__).resolve().parent.parent,
                                     helper,boot,generated,identity,disk)
    if confirm('erase-nvme',contract,pin) != pin:
        raise ValueError('Orin NVMe approval declined')
    workspace.validate()
    target = disk_factory(transport,disk,identity['ecid'],helper,record['sha256'])
    try:
        return write_image(args.image,target,release['boards'][args.board]['image']['sha256'],
                           disk,identity,args.journal)
    finally:
        if hasattr(target,'session') and not target.session.closed:
            target.session.abort()


def interactive_approval(stage, contract, digest):
    print(json.dumps({'stage': stage, 'approval': contract, 'sha256': digest}, indent=2))
    return input('Type the complete approval SHA256 to authorize this destructive stage: ').strip()


def select_recovery_disk(transport, *, choose_single=False):
    """Read actual recovery sysfs. Never enumerate or open host block devices."""
    listing = transport.shell('/bin/sh', '-c', 'printf "%s\\n" /sys/class/block/nvme*n*').decode().splitlines()
    candidates = [Path(p).name for p in listing if re.fullmatch(r'/sys/class/block/nvme[0-9]+n[0-9]+', p)]
    if not candidates:
        raise ValueError('no recovery NVMe namespace')
    disks = []
    for name in candidates:
        def read(relative):
            return transport.shell('/bin/cat', '/sys/class/block/' + name + '/' + relative).decode().strip()
        device = transport.shell('/bin/readlink', '-f', '/sys/class/block/' + name + '/device').decode().strip()
        major, minor = map(int, read('dev').split(':'))
        disk = {'path': '/dev/' + name, 'serial': read('device/serial'), 'model': read('device/model'),
                'capacity': int(read('size')) * 512, 'sector': int(read('queue/logical_block_size')),
                'major': major, 'minor': minor, 'device': device}
        if disk['sector'] != 512 or not disk['serial'] or '/nvme/' not in device:
            raise ValueError('unsupported NVMe identity')
        disks.append(disk)
    print(json.dumps(disks, indent=2))
    if choose_single:
        if len(disks) != 1:
            raise ValueError('guided install requires exactly one recovery NVMe namespace; no automatic disk choice')
        return disks[0]
    selected = input('Type exact NVMe namespace path to ERASE: ').strip()
    matches = [d for d in disks if d['path'] == selected]
    if len(matches) != 1:
        raise ValueError('explicit unique NVMe selection required')
    return matches[0]


def prepare(args, release):
    from nvidia_flash_tools.workspace import Workspace
    if not args.output or not args.nvidia_archive or not args.sample_rootfs:
        raise ValueError('prepare requires --output, --nvidia-archive and --sample-rootfs')
    with Workspace(args.output) as workspace:
        workspace.prepare(args.nvidia_archive, args.sample_rootfs, release['nvidia'],
                          sample_rootfs_members(release, getattr(args, 'board', None)), cache=prepared_cache(args))
        install_vendor_inputs(workspace, release, getattr(args, 'board', None))
    print('Authenticated BSP/rootfs prepared and full apply_binaries output recorded. Closed workspaces cannot be resumed as execution authority; install makes its own fresh session.')
