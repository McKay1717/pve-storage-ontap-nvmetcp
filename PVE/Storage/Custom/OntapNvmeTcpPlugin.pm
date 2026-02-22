package PVE::Storage::Custom::OntapNvmeTcpPlugin;

# Copyright (C) 2026 Nicolas I. (McKay1717) <https://github.com/McKay1717>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;

use IO::Socket::IP;
use JSON;
use POSIX qw(strftime);

use PVE::JSONSchema;
use PVE::Tools qw(run_command file_read_firstline);

use PVE::Storage::OntapNvmeTcp::Api;

use base qw(PVE::Storage::Plugin);

# architecture: 1 VM disk = 1 NVMe namespace = 1 FlexVol volume
# multi-disk VMs are grouped in ONTAP consistency groups

my $SNAP_PREFIX = 'pve_snap_';
my $CG_PREFIX = 'pve_cg_vm_';
my $VOL_OVERHEAD = 1.05; # WAFL metadata headroom
my $MIN_NS_BYTES = 20 * 1024 * 1024; # ONTAP minimum (TPM/EFI)

# -- password management -----------------------------------------------
# sensitive properties live in /etc/pve/priv/storage/<storeid>.pw

sub _password_file {
    my ($storeid) = @_;

    return "/etc/pve/priv/storage/${storeid}.pw";
}

sub _read_password {
    my ($storeid) = @_;

    my $pwfile = _password_file($storeid);
    die "password file '$pwfile' not found for storage '$storeid'."
        . " Re-add the storage with --password to fix.\n"
        if !-f $pwfile;

    my $password = file_read_firstline($pwfile);
    chomp $password if defined($password);
    die "empty password in '$pwfile'\n" if !$password;

    return $password;
}

sub _save_password {
    my ($storeid, $password) = @_;

    my $pwfile = _password_file($storeid);
    mkdir '/etc/pve/priv/storage' if !-d '/etc/pve/priv/storage';
    PVE::Tools::file_set_contents($pwfile, "$password\n");
    chmod 0600, $pwfile;
}

# -- API client factory ------------------------------------------------

sub _api {
    my ($scfg, $storeid) = @_;

    return PVE::Storage::OntapNvmeTcp::Api->new(
        mgmt_ip    => $scfg->{mgmt_ip},
        username   => $scfg->{username},
        password   => _read_password($storeid),
        vserver    => $scfg->{vserver},
        verify_ssl => $scfg->{verify_ssl},
    );
}

# -- debug logging -----------------------------------------------------

sub _debug {
    my ($scfg, $level, $msg) = @_;

    my $debug = $scfg->{debug} // 0;
    return if $debug < $level;

    warn "ontapnvme :: $msg\n";
}

# -- host NQN ----------------------------------------------------------

sub _get_host_nqn {
    my $nqn = file_read_firstline('/etc/nvme/hostnqn');
    chomp $nqn if $nqn;
    die "cannot read host NQN from /etc/nvme/hostnqn\n" if !$nqn;

    return $nqn;
}

# -- naming conventions ------------------------------------------------
# PVE volname:  vm-<vmid>-disk-<idx>  (hyphens)
# ONTAP name:   vm_<vmid>_disk_<idx>  (underscores, ONTAP forbids -)
# ONTAP CG:     pve_cg_vm_<vmid>

sub _prefix {
    my ($scfg) = @_;

    return $scfg->{storage_prefix} // '';
}

sub _pve_to_ontap {
    my ($pve_name, $prefix) = @_;

    $prefix //= '';
    (my $ontap_name = $pve_name) =~ s/-/_/g;

    return "${prefix}${ontap_name}";
}

sub _ontap_to_pve {
    my ($ontap_name, $prefix) = @_;

    $prefix //= '';
    my $pve_name = $ontap_name;
    $pve_name =~ s/^\Q$prefix\E// if $prefix;
    $pve_name =~ s/^vm_([0-9]+)_disk_([0-9]+)$/vm-$1-disk-$2/;
    $pve_name =~ s/^vm_([0-9]+)_state_(.+)$/vm-$1-state-$2/;

    return $pve_name;
}

sub _ontap_name {
    my ($vmid, $disk_idx, $prefix) = @_;

    $prefix //= '';

    return "${prefix}vm_${vmid}_disk_${disk_idx}";
}

sub _parse_ontap_disk_name {
    my ($name, $prefix) = @_;

    $prefix //= '';
    $name =~ s/^\Q$prefix\E// if $prefix;

    return ($1, $2) if $name =~ m/^vm_([0-9]+)_disk_([0-9]+)$/;
    return ();
}

sub _cg_name {
    my ($vmid, $prefix) = @_;

    $prefix //= '';

    return "${prefix}${CG_PREFIX}${vmid}";
}

sub _snap_name {
    my ($snap) = @_;

    return "${SNAP_PREFIX}${snap}";
}

sub _parse_snap_name {
    my ($name) = @_;

    return $1 if $name =~ m/^\Q$SNAP_PREFIX\E(.+)$/;
    return undef;
}

# -- volume creation options -------------------------------------------

sub _vol_create_opts {
    my ($scfg) = @_;

    return (
        aggregate           => $scfg->{aggregate},
        snapshot_policy     => $scfg->{snapshot_policy} || 'none',
        encryption          => $scfg->{encryption},
        space_reserve       => $scfg->{space_reserve} || 'none',
        qos_policy          => $scfg->{qos_policy},
        adaptive_qos_policy => $scfg->{adaptive_qos_policy},
        snapshot_reserve    => $scfg->{snapshot_reserve},
        tiering_policy      => $scfg->{tiering_policy},
    );
}

# -- namespace lookup --------------------------------------------------

sub _find_ns_for_volume {
    my ($api, $vol_name) = @_;

    my $ns = $api->get_namespace_by_name(
        "/vol/$vol_name/$vol_name",
    );
    return $ns if $ns;

    # fallback: namespace name may differ from volume name
    my $nss = $api->list_namespaces("/vol/$vol_name/*");

    return ($nss && @$nss) ? $nss->[0] : undef;
}

# -- NVMe/TCP portal discovery -----------------------------------------

sub _get_portals {
    my ($scfg, $api) = @_;

    if ($scfg->{ontap_portal}) {
        my @portals = ($scfg->{ontap_portal});
        push @portals, $scfg->{ontap_portal2}
            if $scfg->{ontap_portal2};
        # untaint config values (pvedaemon -T)
        return [ map { /^([0-9a-fA-F.:]+)$/ ? $1 : $_ } @portals ];
    }

    my @addrs;
    eval {
        my $lifs = $api->get_nvme_lif_addresses();
        @addrs = @$lifs if $lifs;
    };
    if ($@ || !@addrs) {
        warn "unable to discover NVMe/TCP data LIFs: $@\n" if $@;
        die "no NVMe/TCP portals configured and auto-discovery"
            . " failed. Set 'ontap_portal' or ensure NVMe/TCP"
            . " data LIFs exist.\n";
    }

    # untaint API-derived addresses (pvedaemon -T)
    return [ map { /^([0-9a-fA-F.:]+)$/ ? $1 : $_ } @addrs ];
}

# -- NVMe/TCP connection management ------------------------------------

sub _nvme_connect_all {
    my ($portal) = @_;

    eval {
        run_command(
            ['nvme', 'connect-all', '-t', 'tcp', '-a', $portal],
            outfunc => sub { },
            errfunc => sub { },
            timeout => 30,
        );
    };
    warn "nvme connect-all to $portal: $@\n" if $@;
}

sub _nvme_ensure_connected {
    my ($scfg, $api) = @_;

    # skip if controllers already exist (avoids kernel log spam)
    my $connected = 0;
    eval {
        my @lines;
        run_command(
            ['nvme', 'list-subsys', '-o', 'json'],
            outfunc => sub { push @lines, shift; },
            errfunc => sub { },
            timeout => 5,
        );
        $connected = 1 if join('', @lines) =~ /tcp/i;
    };
    return if $connected;

    my $portals = _get_portals($scfg, $api);
    _nvme_connect_all($_) for @$portals;
}

sub _nvme_rescan {
    my ($scfg, $api) = @_;

    my $portals = _get_portals($scfg, $api);
    _nvme_connect_all($_) for @$portals;
    sleep 1;
}

# -- NVMe device resolution --------------------------------------------
# maps ONTAP namespace (UUID + path) -> local /dev/nvmeXnY
# three strategies: ontapdevices, sysfs UUID, nvme-list + sysfs

sub _normalize_uuid {
    my ($uuid) = @_;

    my $clean = lc($uuid // '');
    $clean =~ s/-//g;

    return $clean;
}

sub _run_json_cmd {
    my ($cmd, $timeout) = @_;

    my @lines;
    eval {
        run_command(
            $cmd,
            outfunc => sub { push @lines, shift; },
            errfunc => sub { },
            timeout => $timeout // 10,
        );
    };
    return undef if $@;

    my $raw = join('', @lines);
    return undef if !$raw;

    my $data;
    eval { $data = decode_json($raw); };

    return $@ ? undef : $data;
}

sub _find_nvme_device_for_namespace {
    my ($ns_uuid, $ns_path) = @_;

    return _find_dev_by_ontapdevices($ns_uuid, $ns_path)
        || _find_dev_by_sysfs($ns_uuid)
        || _find_dev_by_nvme_list($ns_uuid);
}

sub _find_dev_by_ontapdevices {
    my ($ns_uuid, $ns_path) = @_;

    my $data = _run_json_cmd(
        ['nvme', 'netapp', 'ontapdevices', '-o', 'json'],
        15,
    );
    return undef if !$data;

    my $devices = [];
    if (ref($data) eq 'HASH' && $data->{ONTAPdevices}) {
        $devices = $data->{ONTAPdevices};
    }
    elsif (ref($data) eq 'ARRAY') {
        $devices = $data;
    }

    my $clean_uuid = _normalize_uuid($ns_uuid);

    for my $dev (@$devices) {
        my $path = $dev->{Device} // $dev->{device} // next;
        my $nspath = $dev->{'Namespace Path'}
            // $dev->{namespacepath}
            // $dev->{namespace_path}
            // '';
        my $uuid = $dev->{UUID} // $dev->{uuid} // '';

        # untaint device path (from external JSON — taint mode)
        next if $path !~ m{^(/dev/nvme[0-9]+n[0-9]+)$};
        my $clean_path = $1;

        return $clean_path if $ns_path && $nspath eq $ns_path;
        return $clean_path
            if $clean_uuid && _normalize_uuid($uuid) eq $clean_uuid;
    }

    return undef;
}

sub _match_sysfs_uuid {
    my ($dev_name, $target_uuid) = @_;

    for my $attr ('nguid', 'uuid') {
        my $f = "/sys/class/block/$dev_name/$attr";
        next if !-f $f;
        my $val = file_read_firstline($f) // '';
        chomp $val;
        return 1 if _normalize_uuid($val) eq $target_uuid;
    }

    return 0;
}

sub _find_dev_by_sysfs {
    my ($ns_uuid) = @_;

    my $target = _normalize_uuid($ns_uuid);

    for my $sys (glob("/sys/class/block/nvme*n*")) {
        $sys =~ m|/sys/class/block/(nvme[0-9]+n[0-9]+)| or next;
        my $name = $1;
        return "/dev/$name" if _match_sysfs_uuid($name, $target);
    }

    return undef;
}

sub _find_dev_by_nvme_list {
    my ($ns_uuid) = @_;

    my $data = _run_json_cmd(['nvme', 'list', '-o', 'json']);
    return undef if !$data;

    my $target = _normalize_uuid($ns_uuid);

    for my $dev (@{$data->{Devices} // []}) {
        my $model = $dev->{ModelNumber} // '';
        next if $model !~ /ONTAP/i;

        my $node = $dev->{DevicePath} // $dev->{NameSpace} // next;
        next if $node !~ m|/dev/(nvme[0-9]+n[0-9]+)|;
        my $name = $1;

        # untaint (from external JSON — taint mode)
        return "/dev/$name" if _match_sysfs_uuid($name, $target);
    }

    return undef;
}

# -- free disk index allocator -----------------------------------------

sub _find_free_disk_idx {
    my ($api, $vmid, $prefix) = @_;

    $prefix //= '';
    my %used;

    my $ns_pattern = "/vol/${prefix}vm_${vmid}_disk_*"
        . "/${prefix}vm_${vmid}_disk_*";
    my $nss = $api->list_namespaces($ns_pattern);
    for my $ns (@$nss) {
        my $name = $ns->{name} // '';
        $used{$1} = 1
            if $name =~ m|/vol/\Q$prefix\Evm_[0-9]+_disk_([0-9]+)/|;
    }

    my $vols = $api->list_volumes_by_pattern(
        "${prefix}vm_${vmid}_disk_*",
    );
    for my $vol (@$vols) {
        $used{$1} = 1
            if $vol->{name}
            =~ m/^\Q$prefix\Evm_[0-9]+_disk_([0-9]+)$/;
    }

    for (my $i = 0; $i < 256; $i++) {
        return $i if !$used{$i};
    }

    die "no free disk index for VM $vmid (256 disks max)\n";
}

# -- consistency group management --------------------------------------

sub _ensure_cg {
    my ($api, $vmid, $vol_name, $prefix) = @_;

    $prefix //= '';
    my $cgname = _cg_name($vmid, $prefix);
    my $cg = $api->get_consistency_group($cgname);

    if (!$cg) {
        eval {
            $api->create_consistency_group($cgname, [$vol_name]);
        };
        if ($@) {
            warn "failed to create CG $cgname: $@\n";
            return undef;
        }
        return $api->get_consistency_group($cgname);
    }

    my $already = grep {
        ($_->{name} // '') eq $vol_name
    } @{$cg->{volumes} // []};

    if (!$already) {
        eval {
            $api->add_volume_to_consistency_group(
                $cg->{uuid}, $vol_name,
            );
        };
        warn "failed to add $vol_name to CG $cgname: $@\n" if $@;
        $cg = $api->get_consistency_group($cgname);
    }

    return $cg;
}

sub _cleanup_cg_if_empty {
    my ($api, $vmid, $prefix) = @_;

    $prefix //= '';
    my $cgname = _cg_name($vmid, $prefix);
    my $cg = $api->get_consistency_group($cgname);
    return if !$cg;

    if (!@{$cg->{volumes} // []}) {
        eval { $api->delete_consistency_group($cg->{uuid}); };
        warn "failed to delete empty CG $cgname: $@\n" if $@;
    }
}

# -- subsystem registration --------------------------------------------

sub _ensure_subsystem_and_host {
    my ($api, $subsystem_name) = @_;

    my $subsys = $api->get_subsystem($subsystem_name);
    if (!$subsys) {
        eval { $api->create_subsystem($subsystem_name, 'linux'); };
        warn "failed to create subsystem: $@\n" if $@;
        $subsys = $api->get_subsystem($subsystem_name);
    }
    if ($subsys) {
        my $nqn = _get_host_nqn();
        $api->add_host_to_subsystem($subsys->{uuid}, $nqn);
    }

    return $subsys;
}

# -- snapshot helpers (CG with per-volume fallback) --------------------

sub _get_cg_for_vm {
    my ($api, $vmid, $prefix) = @_;

    return $api->get_consistency_group(_cg_name($vmid, $prefix));
}

sub _get_vol_uuid {
    my ($api, $name, $prefix) = @_;

    my $ontap_name = _pve_to_ontap($name, $prefix);

    return $api->get_volume_uuid($ontap_name);
}

# =====================================================================
# Plugin registration
# =====================================================================

sub type { return 'ontapnvme'; }

sub api {
    # 13: $hints in activate_volume
    # 12: qemu_blockdev_options, volume_qemu_snapshot_method
    # 11: sensitive-properties, on_add/update/delete_hook
    return 13;
}

sub plugindata {
    return {
        content                => [{ images => 1 }, { images => 1 }],
        'sensitive-properties' => { password => 1 },
    };
}

sub properties {
    return {
        mgmt_ip => {
            description => "ONTAP cluster or SVM management IP.",
            type        => 'string',
            format      => 'pve-storage-server',
        },
        vserver => {
            description => "ONTAP SVM (Vserver) name.",
            type        => 'string',
        },
        subsystem => {
            description => "NVMe subsystem on the ONTAP array.",
            type        => 'string',
        },
        aggregate => {
            description => "ONTAP aggregate for volume creation.",
            type        => 'string',
        },
        ontap_portal => {
            description => "NVMe/TCP target portal IP override.",
            type        => 'string',
            format      => 'pve-storage-server',
            optional    => 1,
        },
        ontap_portal2 => {
            description => "Secondary NVMe/TCP target portal IP.",
            type        => 'string',
            format      => 'pve-storage-server',
            optional    => 1,
        },
        snapshot_policy => {
            description => "ONTAP snapshot policy (default: none).",
            type        => 'string',
            optional    => 1,
        },
        storage_prefix => {
            description => "Prefix for ONTAP object names.",
            type        => 'string',
            optional    => 1,
        },
        encryption => {
            description => "Volume encryption (default: true).",
            type        => 'boolean',
            optional    => 1,
        },
        space_reserve => {
            description => "Space guarantee: none or volume.",
            type        => 'string',
            optional    => 1,
        },
        qos_policy => {
            description => "QoS policy group.",
            type        => 'string',
            optional    => 1,
        },
        adaptive_qos_policy => {
            description => "Adaptive QoS policy group.",
            type        => 'string',
            optional    => 1,
        },
        snapshot_reserve => {
            description => "Snapshot reserve percent (0-90).",
            type        => 'integer',
            minimum     => 0,
            maximum     => 90,
            optional    => 1,
        },
        tiering_policy => {
            description => "FabricPool tiering policy.",
            type        => 'string',
            optional    => 1,
        },
        verify_ssl => {
            description => "Verify ONTAP TLS certificate (default: 0).",
            type        => 'boolean',
            optional    => 1,
        },
        debug => {
            description => "Debug logging level (0=off, 1=basic, 2=verbose).",
            type        => 'integer',
            minimum     => 0,
            maximum     => 2,
            optional    => 1,
        },
    };
}

sub options {
    return {
        mgmt_ip            => { fixed    => 1 },
        username            => { fixed    => 1 },
        password            => { optional => 1 },
        vserver             => { fixed    => 1 },
        subsystem           => { fixed    => 1 },
        aggregate           => { fixed    => 1 },
        ontap_portal        => { optional => 1 },
        ontap_portal2       => { optional => 1 },
        snapshot_policy     => { optional => 1 },
        storage_prefix      => { optional => 1 },
        encryption          => { optional => 1 },
        space_reserve       => { optional => 1 },
        qos_policy          => { optional => 1 },
        adaptive_qos_policy => { optional => 1 },
        snapshot_reserve    => { optional => 1 },
        tiering_policy      => { optional => 1 },
        verify_ssl          => { optional => 1 },
        debug               => { optional => 1 },
        nodes               => { optional => 1 },
        disable             => { optional => 1 },
        content             => { optional => 1 },
    };
}

# =====================================================================
# Lifecycle hooks
# =====================================================================

sub on_add_hook {
    my ($class, $storeid, $scfg, %param) = @_;

    my $password = $param{password};
    die "missing password for ONTAP storage '$storeid'\n"
        if !defined($password) || $password eq '';

    _save_password($storeid, $password);

    my $mgmt_ip = $scfg->{mgmt_ip}
        || die "mgmt_ip is required\n";
    my $username = $scfg->{username} // $param{username}
        || die "username is required\n";
    my $vserver = $scfg->{vserver}
        || die "vserver is required\n";

    eval {
        my $api = PVE::Storage::OntapNvmeTcp::Api->new(
            mgmt_ip    => $mgmt_ip,
            username   => $username,
            password   => $password,
            vserver    => $vserver,
            verify_ssl => $scfg->{verify_ssl},
        );
        $api->get_svm_uuid();

        _ensure_subsystem_and_host($api, $scfg->{subsystem})
            if $scfg->{subsystem};
    };
    if (my $err = $@) {
        unlink _password_file($storeid);
        die "ONTAP connection failed: $err\n";
    }

    return;
}

sub on_update_hook {
    my ($class, $storeid, $scfg, %param) = @_;

    _save_password($storeid, $param{password})
        if defined($param{password});

    return;
}

sub on_delete_hook {
    my ($class, $storeid, $scfg) = @_;

    my $pwfile = _password_file($storeid);
    unlink $pwfile if -f $pwfile;

    return;
}

# =====================================================================
# Volume operations
# =====================================================================

sub parse_volname {
    my ($class, $volname) = @_;

    if ($volname =~ m/^(vm-([0-9]+)-disk-([0-9]+))$/) {
        return ('images', $1, $2, undef, undef, undef, 'raw');
    }
    if ($volname =~ m/^(vm-([0-9]+)-state-\S+)$/) {
        return ('images', $1, $2, undef, undef, undef, 'raw');
    }

    die "unable to parse ONTAP NVMe volume name '$volname'\n";
}

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    _debug($scfg, 2, "path($volname, storeid=$storeid)");
    my $api = _api($scfg, $storeid);
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    my $ns = _find_ns_for_volume($api, $ontap_name);
    die "namespace not found in volume '$ontap_name'\n" if !$ns;

    my $dev = _find_nvme_device_for_namespace(
        $ns->{uuid}, $ns->{name},
    );

    if (!$dev) {
        my $portals = _get_portals($scfg, $api);
        _nvme_connect_all($_) for @$portals;
        sleep 2;
        $dev = _find_nvme_device_for_namespace(
            $ns->{uuid}, $ns->{name},
        );
    }

    if (!$dev) {
        warn "NVMe device not yet connected for $ns->{name}"
            . " (uuid=$ns->{uuid})\n";
        $dev = "/dev/ontap-nvme-pending/$ontap_name";
    }

    # safety: untaint device path (pvedaemon runs with -T)
    if ($dev =~ m{^(/dev/[A-Za-z0-9_./-]+)$}) {
        $dev = $1;
    }

    return wantarray ? ($dev, $vmid, $vtype) : $dev;
}

sub filesystem_path {
    my ($class, $scfg, $volname, $snapname) = @_;

    return $class->path($scfg, $volname, undef, $snapname);
}

sub alloc_image {
    my ($class, $storeid, $scfg, $vmid, $fmt, $name, $size) = @_;

    die "unsupported format '$fmt' - only raw is supported\n"
        if $fmt && $fmt ne 'raw';

    _debug($scfg, 1, "alloc_image($storeid, vmid=$vmid, size=$size)");

    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my ($vol_name, $pve_name);

    if ($name && $name =~ m/^vm-[0-9]+-state-/) {
        $vol_name = _pve_to_ontap($name, $prefix);
        $pve_name = $name;
    }
    elsif ($name) {
        my $ontap = _pve_to_ontap($name, $prefix);
        my ($vid, $idx) = _parse_ontap_disk_name($ontap, $prefix);
        die "invalid namespace name '$name'\n" if !defined($vid);
        $vol_name = _ontap_name($vid, $idx, $prefix);
        $pve_name = _ontap_to_pve($vol_name, $prefix);
    }
    else {
        my $idx = _find_free_disk_idx($api, $vmid, $prefix);
        $vol_name = _ontap_name($vmid, $idx, $prefix);
        $pve_name = _ontap_to_pve($vol_name, $prefix);
    }

    my $size_bytes = $size * 1024; # PVE passes KiB
    $size_bytes = $MIN_NS_BYTES if $size_bytes < $MIN_NS_BYTES;

    # step 1: create dedicated FlexVol
    my $vol_size = int($size_bytes * $VOL_OVERHEAD);
    $api->create_volume($vol_name, $vol_size, _vol_create_opts($scfg));

    # step 2: create NVMe namespace inside the volume
    my $result;
    eval {
        $result = $api->create_namespace(
            $vol_name, $vol_name, $size_bytes, 'linux',
        );
    };
    if ($@) {
        my $vuuid = $api->get_volume_uuid($vol_name);
        $api->delete_volume($vuuid) if $vuuid;
        die "failed to create namespace $vol_name: $@\n";
    }

    my $ns_uuid;
    if ($result->{records} && @{$result->{records}}) {
        $ns_uuid = $result->{records}[0]{uuid};
    }
    if (!$ns_uuid) {
        my $ns = $api->get_namespace_by_name(
            "/vol/$vol_name/$vol_name",
        );
        $ns_uuid = $ns->{uuid} if $ns;
    }
    die "failed to create namespace $vol_name\n" if !$ns_uuid;

    # step 3: map namespace to subsystem
    my $subsys = $api->get_subsystem($scfg->{subsystem});
    die "subsystem '$scfg->{subsystem}' not found\n" if !$subsys;
    $api->map_namespace_to_subsystem($subsys->{uuid}, $ns_uuid);

    # step 4: add volume to VM consistency group
    _ensure_cg($api, $vmid, $vol_name, $prefix);

    # step 5: discover new device on fabric
    _nvme_rescan($scfg, $api);

    return $pve_name;
}

sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    _debug($scfg, 1, "free_image($storeid, $volname)");
    my $api = _api($scfg, $storeid);
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    # unmap + delete namespace
    my $ns = _find_ns_for_volume($api, $ontap_name);
    if ($ns) {
        my $maps = $api->get_namespace_subsystem_map($ns->{uuid});
        for my $map (@$maps) {
            my $sub_uuid = $map->{subsystem}{uuid} // next;
            $api->unmap_namespace_from_subsystem(
                $sub_uuid, $ns->{uuid},
            );
        }
        $api->delete_namespace($ns->{uuid});
    }

    # delete volume
    my $vol_uuid = $api->get_volume_uuid($ontap_name);
    if ($vol_uuid) {
        eval { $api->delete_volume($vol_uuid); };
        warn "failed to delete volume $ontap_name: $@\n" if $@;
    }

    _cleanup_cg_if_empty($api, $vmid, _prefix($scfg));

    return undef;
}

sub list_images {
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;

    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $ckey = "ontapnvme_$storeid";

    if (!$cache->{$ckey}) {
        my $disk_ns = $api->list_namespaces(
            "/vol/${prefix}vm_*_disk_*/${prefix}vm_*_disk_*",
        ) // [];
        my $state_ns = $api->list_namespaces(
            "/vol/${prefix}vm_*_state_*/${prefix}vm_*_state_*",
        ) // [];
        $cache->{$ckey} = [@$disk_ns, @$state_ns];
    }

    my $re_vol = qr{
        /vol/(\Q$prefix\Evm_[0-9]+_(?:disk_[0-9]+|state_\S+))/
    }x;

    my $res = [];
    for my $ns (@{$cache->{$ckey}}) {
        my $full_name = $ns->{name} // next;
        next if $full_name !~ $re_vol;
        my $ontap_vol = $1;

        next if $ontap_vol !~ m/\Q$prefix\Evm_([0-9]+)_/;
        my $vid = $1;
        next if defined($vmid) && $vid != $vmid;

        my $pve_name = _ontap_to_pve($ontap_vol, $prefix);
        my $volid = "$storeid:$pve_name";

        if ($vollist) {
            next if !grep { $_ eq $volid } @$vollist;
        }

        push @$res, {
            volid  => $volid,
            name   => $pve_name,
            vmid   => $vid,
            size   => $ns->{space}{size} // 0,
            format => 'raw',
        };
    }

    return $res;
}

# =====================================================================
# Storage and volume activation
# =====================================================================

sub status {
    my ($class, $storeid, $scfg, $cache) = @_;

    my $api = _api($scfg, $storeid);
    my $space = $api->get_aggregate_space($scfg->{aggregate});

    return $space
        ? ($space->{total}, $space->{free}, $space->{used}, 1)
        : (0, 0, 0, 0);
}

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    die "nvme-cli not installed\n" if !-x '/usr/sbin/nvme';

    _debug($scfg, 1, "activate_storage($storeid)");

    my $api = _api($scfg, $storeid);
    _ensure_subsystem_and_host($api, $scfg->{subsystem});
    _nvme_ensure_connected($scfg, $api);

    return 1;
}

sub deactivate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    return 1;
}

sub activate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache,
        $hints) = @_;

    my $api = _api($scfg, $storeid);
    _nvme_ensure_connected($scfg, $api);

    return 1;
}

sub deactivate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    return 1;
}

# =====================================================================
# Volume size operations
# =====================================================================

sub volume_size_info {
    my ($class, $scfg, $storeid, $volname, $timeout) = @_;

    my ($vtype, $name) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    my $ns = _find_ns_for_volume($api, $ontap_name);
    return 0 if !$ns;

    my $size = $ns->{space}{size} // 0;
    my $used = $ns->{space}{used} // 0;

    return wantarray ? ($size, 'raw', $used, undef) : $size;
}

sub volume_resize {
    my ($class, $scfg, $storeid, $volname, $size, $running) = @_;

    my ($vtype, $name) = $class->parse_volname($volname);
    _debug($scfg, 1, "volume_resize($volname, size=$size)");
    my $api = _api($scfg, $storeid);
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    my $ns = $api->get_namespace_by_name(
        "/vol/$ontap_name/$ontap_name",
    );
    die "namespace not found for '$ontap_name'\n" if !$ns;

    $api->resize_namespace($ns->{uuid}, $size);

    my $vol_uuid = $api->get_volume_uuid($ontap_name);
    if ($vol_uuid) {
        my $new_vol = int($size * $VOL_OVERHEAD);
        eval { $api->resize_volume($vol_uuid, $new_vol); };
        warn "volume resize for $ontap_name: $@\n" if $@;
    }

    return 1;
}

# =====================================================================
# Snapshot operations (CG with per-volume fallback)
# =====================================================================

sub volume_snapshot {
    my ($class, $scfg, $storeid, $volname, $snap, $running) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    _debug($scfg, 1, "volume_snapshot($volname, snap=$snap)");
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);

    my $snap_name = _snap_name($snap);
    my $comment = "PVE snapshot for VM $vmid at "
        . strftime("%Y-%m-%d %H:%M:%S", localtime);

    # try CG-level snapshot first (atomic multi-disk)
    my $cg = _get_cg_for_vm($api, $vmid, $prefix);
    if ($cg) {
        my $existing = $api->get_cg_snapshot_by_name(
            $cg->{uuid}, $snap_name,
        );
        if (!$existing) {
            eval {
                $api->create_cg_snapshot(
                    $cg->{uuid}, $snap_name, $comment,
                );
            };
            return undef if !$@;
        }
        else {
            return undef;
        }
    }

    # fallback: per-volume snapshot
    my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
    die "volume '$name' not found\n" if !$vol_uuid;

    my $existing = $api->get_snapshot_by_name($vol_uuid, $snap_name);
    $api->create_snapshot($vol_uuid, $snap_name, $comment)
        if !$existing;

    return undef;
}

sub volume_snapshot_rollback {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $snap_name = _snap_name($snap);

    # try CG-level rollback
    my $cg = _get_cg_for_vm($api, $vmid, $prefix);
    if ($cg) {
        my $snap_obj = $api->get_cg_snapshot_by_name(
            $cg->{uuid}, $snap_name,
        );
        if ($snap_obj) {
            $api->restore_cg_snapshot(
                $cg->{uuid}, $snap_obj->{uuid},
            );
            return undef;
        }
    }

    # fallback: per-volume rollback
    my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
    die "volume '$name' not found\n" if !$vol_uuid;

    my $snap_obj = $api->get_snapshot_by_name($vol_uuid, $snap_name);
    die "snapshot '$snap' not found on volume '$name'\n"
        if !$snap_obj;

    $api->restore_snapshot($vol_uuid, $snap_obj->{uuid});

    return undef;
}

sub volume_snapshot_delete {
    my ($class, $scfg, $storeid, $volname, $snap, $running) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $snap_name = _snap_name($snap);

    # try CG-level delete
    my $cg = _get_cg_for_vm($api, $vmid, $prefix);
    if ($cg) {
        my $snap_obj = $api->get_cg_snapshot_by_name(
            $cg->{uuid}, $snap_name,
        );
        if ($snap_obj) {
            $api->delete_cg_snapshot(
                $cg->{uuid}, $snap_obj->{uuid},
            );
            return undef;
        }
    }

    # fallback: per-volume delete
    my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
    if ($vol_uuid) {
        my $snap_obj = $api->get_snapshot_by_name(
            $vol_uuid, $snap_name,
        );
        $api->delete_snapshot($vol_uuid, $snap_obj->{uuid})
            if $snap_obj;
    }

    return undef;
}

sub volume_snapshot_info {
    my ($class, $scfg, $storeid, $volname) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);

    my %seen;
    my %result;
    my $snap_filter = "${SNAP_PREFIX}*";

    # CG-level snapshots
    my $cg = _get_cg_for_vm($api, $vmid, $prefix);
    if ($cg) {
        for my $s (@{$api->list_cg_snapshots($cg->{uuid}, $snap_filter)}) {
            my $pve = _parse_snap_name($s->{name}) // next;
            next if $seen{$pve}++;
            $result{$pve} = {
                id        => $s->{uuid} // '',
                timestamp => $s->{create_time} // 0,
            };
        }
    }

    # per-volume snapshots
    my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
    if ($vol_uuid) {
        for my $s (@{$api->list_snapshots($vol_uuid, $snap_filter)}) {
            my $pve = _parse_snap_name($s->{name}) // next;
            next if $seen{$pve}++;
            $result{$pve} = {
                id        => $s->{uuid} // '',
                timestamp => $s->{create_time} // 0,
            };
        }
    }

    return \%result;
}

# =====================================================================
# Infrastructure
# =====================================================================

sub check_connection {
    my ($class, $storeid, $scfg) = @_;

    my $mgmt_ip = $scfg->{mgmt_ip};
    my $username = $scfg->{username};
    my $vserver = $scfg->{vserver};

    if (!($mgmt_ip && $username && $vserver)) {
        return 0 if !$mgmt_ip;
        eval {
            my $sock = IO::Socket::IP->new(
                PeerHost => $mgmt_ip,
                PeerPort => 443,
                Timeout  => 5,
                Type     => IO::Socket::IP::SOCK_STREAM(),
            );
            die "TCP connect failed\n" if !$sock;
            close($sock);
        };
        return $@ ? 0 : 1;
    }

    eval {
        my $api = _api($scfg, $storeid);
        $api->get_svm_uuid();
    };
    if ($@) {
        warn "ONTAP check_connection($storeid): $@\n";
        return 0;
    }

    return 1;
}

# =====================================================================
# Clone (full copy via dd — no FlexClone)
# =====================================================================

sub clone_image {
    my ($class, $scfg, $storeid, $volname, $vmid, $snap) = @_;

    die "linked clone not supported — only full clone\n" if $snap;

    _debug($scfg, 1, "clone_image($volname → vmid=$vmid)");

    my ($vtype, $name, $src_vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    # --- source size ---
    my $ns = _find_ns_for_volume($api, $ontap_name);
    die "source namespace not found for '$ontap_name'\n" if !$ns;
    my $size_bytes = $ns->{space}{size}
        // die "cannot determine source size\n";
    my $size_kib = int($size_bytes / 1024);

    # --- source device ---
    my $src_path = $class->path($scfg, $volname, $storeid);
    die "source device not available: $src_path\n"
        if !-b $src_path;

    # --- allocate destination ---
    my $dst_volname = eval {
        $class->alloc_image($storeid, $scfg, $vmid, 'raw',
            undef, $size_kib);
    };
    if (my $err = $@) {
        die "clone: failed to allocate destination: $err";
    }

    # --- destination device ---
    eval {
        my $dst_path = $class->path($scfg, $dst_volname, $storeid);

        # wait for NVMe device to appear (rescan done by alloc_image)
        my $retries = 10;
        while (!-b $dst_path && $retries-- > 0) {
            sleep 1;
            $dst_path = $class->path($scfg, $dst_volname, $storeid);
        }
        die "destination device not available: $dst_path\n"
            if !-b $dst_path;

        _debug($scfg, 1, "clone: dd $src_path → $dst_path"
            . " ($size_bytes bytes)");

        run_command(
            ['dd', "if=$src_path", "of=$dst_path",
             'bs=4M', "count=" . int($size_bytes / (4*1024*1024) + 1),
             'conv=fdatasync', 'status=progress'],
        );
    };
    if (my $err = $@) {
        # cleanup destination on failure
        eval { $class->free_image($storeid, $scfg, $dst_volname); };
        die "clone: copy failed: $err";
    }

    return $dst_volname;
}

sub volume_has_feature {
    my ($class, $scfg, $feature, $storeid, $volname, $snapname,
        $running) = @_;

    my $features = {
        copy       => { current => 1 },
        snapshot   => { current => 1, snap => 1 },
        sparseinit => { current => 1 },
    };

    my $key = $snapname ? 'snap' : 'current';

    return 1 if $features->{$feature} && $features->{$feature}{$key};
    return undef;
}

# =====================================================================
# QEMU integration (APIVER 12+)
# =====================================================================

sub qemu_blockdev_options {
    my ($class, $scfg, $storeid, $volname, $snapname, $fmt) = @_;

    # ONTAP NVMe namespaces are always thin-provisioned — UNMAP
    # reclaims space on the array.  detect-zeroes=unmap converts
    # guest zero-writes into UNMAPs for additional reclaim.
    return {
        driver          => 'host_device',
        filename        => scalar $class->path(
            $scfg, $volname, $storeid, $snapname,
        ),
        discard         => 'unmap',
        'detect-zeroes' => 'unmap',
    };
}

sub volume_qemu_snapshot_method {
    my ($class, $scfg, $storeid, $volname) = @_;

    return 'storage';
}

sub get_formats {
    my ($class, $scfg) = @_;

    return {
        formats        => { raw => 1 },
        default_format => 'raw',
    };
}

1;
