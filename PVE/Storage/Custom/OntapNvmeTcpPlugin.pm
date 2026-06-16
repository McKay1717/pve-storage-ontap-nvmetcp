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

use HTTP::Date qw(str2time);
use IO::Socket::IP;
use JSON;
use Socket ();
use POSIX qw(strftime);

use PVE::Cluster;
use PVE::JSONSchema;
use PVE::Tools qw(run_command file_read_firstline);

use PVE::Storage::OntapNvmeTcp::Api;

use base qw(PVE::Storage::Plugin);

# architecture: 1 VM disk = 1 NVMe namespace = 1 FlexVol volume
# multi-disk VMs are grouped in ONTAP consistency groups

my $SNAP_PREFIX = 'pve_snap_';
my $CG_PREFIX = 'pve_cg_vm_';
my $BASE_SNAP = 'pve_base'; # snapshot on a base image that linked clones spawn from
# common stem of pve_snap_* and pve_base: snapshot autodelete defers everything
# the plugin manages to last resort, sacrificing scheduled snapshots first
my $SNAP_DEFER_PREFIX = 'pve_';
my $VOL_OVERHEAD = 1.05; # WAFL metadata headroom
my $MIN_NS_BYTES = 20 * 1024 * 1024; # ONTAP minimum (TPM/EFI)

# per-process cache of API clients, keyed by storeid. Reused across calls so
# the LWP handle and the resolved SVM UUID survive within a daemon worker.
# Invalidated on storage update/delete (see hooks).
my %API_CACHE;

# per-process cache of each storage's NVMe/TCP portal list, so the hot
# activation path (every VM start) does not pay a REST LIF-discovery GET.
# Invalidated together with the API cache on storage update/delete.
my %PORTAL_CACHE;

# per-process cache "storeid/ontap_name" => { uuid, name } of resolved
# namespaces. Lets path() match a previously seen namespace to its device
# purely via sysfs, so VM starts keep working while the ONTAP management API
# is unreachable (the NVMe data path does not need it). Stale entries are
# harmless: device matching is always by namespace UUID against live sysfs,
# and a miss falls through to the REST lookup. Accepted trade-off: a cache hit
# also skips the ONTAP-side offline check (it runs on every miss) —
# availability during an API outage wins over freshest state.
my %NS_CACHE;

# capacity-warning state: per-storage timestamp of the last autosize sweep,
# and which volumes have already been warned about (re-armed on recovery)
my %CAPACITY_CHECK_TS;
my %CAPACITY_WARNED;

# per-storage timestamp of the last stranded-object sweep
my %STRANDED_CHECK_TS;

# -- password management -----------------------------------------------
# sensitive properties live in /etc/pve/priv/storage/<storeid>.pw

sub _secret_file {
    my ($storeid, $kind) = @_;

    # defence in depth: PVE validates storage IDs, but never build a filesystem
    # path from an id (or kind) that could escape the priv directory.
    die "invalid storage id\n"
        if !defined($storeid) || $storeid eq ''
        || $storeid =~ m{[/\x00]} || $storeid =~ m{\.\.};
    die "invalid secret kind\n" if !defined($kind) || $kind !~ m{\A[a-z]+\z};

    return "/etc/pve/priv/storage/${storeid}.${kind}";
}

sub _password_file { return _secret_file($_[0], 'pw'); }

sub _read_secret {
    my ($storeid, $kind) = @_;

    my $f = _secret_file($storeid, $kind);
    return undef if !-f $f;
    my $v = file_read_firstline($f);
    chomp $v if defined($v);
    return (defined($v) && $v ne '') ? $v : undef;
}

sub _save_secret {
    my ($storeid, $kind, $value) = @_;

    my $f = _secret_file($storeid, $kind);
    mkdir '/etc/pve/priv/storage', 0700 if !-d '/etc/pve/priv/storage';
    # apply 0600 atomically (the mode is set on the temp file before the rename)
    # so the secret is never briefly readable with default perms
    PVE::Tools::file_set_contents($f, "$value\n", 0600);
}

sub _delete_secret {
    my ($storeid, $kind) = @_;

    my $f = _secret_file($storeid, $kind);
    unlink $f if -f $f;
}

sub _read_password {
    my ($storeid) = @_;

    my $pw = _read_secret($storeid, 'pw');
    die "password file not found for storage '$storeid'."
        . " Re-add the storage with --password to fix.\n"
        if !defined($pw);

    return $pw;
}

sub _save_password { return _save_secret($_[0], 'pw', $_[1]); }

# NVMe in-band auth / TLS secrets for a storage, read back from the priv dir
sub _nvme_auth {
    my ($storeid) = @_;

    return {} if !$storeid;
    return {
        dhchap_secret => _read_secret($storeid, 'dhchap'),
        dhchap_ctrl   => _read_secret($storeid, 'dhchapc'),
        tls_psk       => _read_secret($storeid, 'tlspsk'),
    };
}

# -- API client factory ------------------------------------------------

sub _api {
    my ($scfg, $storeid) = @_;

    my $password = $storeid ? _read_password($storeid) : undef;

    # Rebuild the cached client when any connection-relevant field changed.
    # The password is included because it is synced cluster-wide via pmxcfs:
    # a password change on one node must invalidate the cached client on every
    # other node's long-lived daemons (e.g. pvestatd), not just locally.
    my $sig = join('|', map { $_ // '' }
        @{$scfg}{qw(mgmt_ip username vserver verify_ssl svm_scoped)}, $password);

    my $cached = $storeid ? $API_CACHE{$storeid} : undef;
    return $cached->{api}
        if $cached && $cached->{sig} eq $sig;

    my $api = PVE::Storage::OntapNvmeTcp::Api->new(
        mgmt_ip    => $scfg->{mgmt_ip},
        username   => $scfg->{username},
        password   => $password,
        vserver    => $scfg->{vserver},
        verify_ssl => $scfg->{verify_ssl},
        svm_scoped => $scfg->{svm_scoped},
    );

    $API_CACHE{$storeid} = { sig => $sig, api => $api } if $storeid;

    return $api;
}

sub _invalidate_api_cache {
    my ($storeid) = @_;

    return if !defined($storeid);
    delete $API_CACHE{$storeid};
    delete $PORTAL_CACHE{$storeid};
    delete @NS_CACHE{ grep { m{^\Q$storeid\E/} } keys %NS_CACHE };
}

# -- cluster-wide per-VM lock ------------------------------------------

# All consistency-group mutations (snapshot create/rollback/delete, membership
# changes, CG cleanup) are check-then-act sequences against a shared ONTAP
# object, racing the same code on other cluster nodes — or on another storage
# of the same SVM. Serialize them on a pmxcfs lock keyed by SVM + VMID.
# Like any pmxcfs write this needs cluster quorum, which PVE requires for VM
# operations anyway. The 60s timeout bounds the lock acquisition; pmxcfs also
# bounds the locked code's runtime (~60s) — fine here, ONTAP snapshot
# operations are metadata-level and fast — and a waiter behind a long holder
# fails loudly with a lock timeout instead of racing.
sub _cg_lock {
    my ($scfg, $vmid, $code) = @_;

    my $svm = $scfg->{vserver} // 'svm';
    $svm =~ s/[^A-Za-z0-9.-]/_/g;
    my $res = PVE::Cluster::cfs_lock_domain("ontapcg-${svm}-${vmid}", 60, $code);
    die $@ if $@;

    return $res;
}

# retry $check every $delay seconds up to $tries times; returns the first
# truthy result. Used to confirm ONTAP async operations whose job cannot be
# polled (SVM-scoped accounts get 202 with an unreadable /cluster/jobs).
sub _poll_for {
    my ($tries, $delay, $check) = @_;

    for (my $i = 0; $i < $tries; $i++) {
        sleep $delay if $i;
        my $res = eval { $check->() };
        return $res if $res;
    }

    return undef;
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
    $pve_name =~ s/^base_([0-9]+)_disk_([0-9]+)$/base-$1-disk-$2/;
    $pve_name =~ s/^vm_([0-9]+)_cloudinit$/vm-$1-cloudinit/;
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

    return ($1, 'cloudinit') if $name =~ m/^vm_([0-9]+)_cloudinit$/;
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

# ONTAP returns snapshot create_time as an RFC3339 string; PVE expects the
# snapshot timestamp as seconds since the epoch. Returns 0 on anything we
# cannot parse.
sub _snap_epoch {
    my ($ts) = @_;

    return 0 if !$ts;
    return int($ts) if $ts =~ /^[0-9]+$/; # already epoch (defensive)

    # ONTAP create_time is an RFC3339 string; let HTTP::Date (a libwww
    # dependency) do the parsing rather than rolling our own date math.
    my $epoch = str2time($ts);

    return defined($epoch) ? int($epoch) : 0;
}

# -- volume creation options -------------------------------------------

sub _vol_create_opts {
    my ($scfg) = @_;

    my $policy = $scfg->{snapshot_policy} || 'none';

    return (
        aggregate            => $scfg->{aggregate},
        # The scheduled-snapshot policy belongs to the VM's consistency group
        # (atomic across its disks); the member volume must carry 'none' or it
        # would be snapshotted twice — once by the CG, once by its own policy.
        # Create it with 'none' from the start so there is never a window, nor
        # a path, where both fire. schedule_active still sizes the snapshot
        # reserve because the CG's snapshots consume space on this volume.
        # (_apply_snapshot_schedule sets a per-volume policy only as the
        # ONTAP < 9.12.1 fallback, where the disk could not join the CG.)
        snapshot_policy      => 'none',
        schedule_active      => ($policy ne 'none') ? 1 : 0,
        encryption           => $scfg->{encryption},
        space_reserve        => $scfg->{space_reserve} || 'none',
        qos_policy           => $scfg->{qos_policy},
        adaptive_qos_policy  => $scfg->{adaptive_qos_policy},
        snapshot_reserve     => $scfg->{snapshot_reserve},
        tiering_policy       => $scfg->{tiering_policy},
        autosize             => $scfg->{autosize} // 1,
        autosize_max_percent => $scfg->{autosize_max_percent},
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

# resolve one portal (an IPv4/IPv6 literal or a FQDN) to one or more IP
# literals, preferring IPv6. A FQDN may carry A and/or AAAA records; literals
# pass through unchanged.
sub _resolve_portal {
    my ($host) = @_;

    return ($host)
        if $host =~ /\A[0-9.]+\z/          # IPv4 literal
        || $host =~ /\A[0-9a-fA-F:]+\z/;   # IPv6 literal

    my ($err, @res) = Socket::getaddrinfo(
        $host, '', { socktype => Socket::SOCK_STREAM() },
    );
    if ($err) {
        warn "cannot resolve NVMe/TCP portal '$host': $err\n";
        return ();
    }

    my (@v6, @v4);
    for my $ai (@res) {
        my ($e, $ip) = Socket::getnameinfo(
            $ai->{addr}, Socket::NI_NUMERICHOST(), Socket::NIx_NOSERV(),
        );
        next if $e;
        if ($ai->{family} == Socket::AF_INET6()) {
            push @v6, $ip;
        }
        else {
            push @v4, $ip;
        }
    }
    return (@v6, @v4); # IPv6 first
}

sub _get_portals {
    my ($scfg, $api) = @_;

    my @raw;
    if ($scfg->{ontap_portal}) {
        @raw = ($scfg->{ontap_portal});
        push @raw, $scfg->{ontap_portal2} if $scfg->{ontap_portal2};
    }
    else {
        eval {
            my $lifs = $api->get_nvme_lif_addresses();
            @raw = @$lifs if $lifs;
        };
        if ($@ || !@raw) {
            warn "unable to discover NVMe/TCP data LIFs: $@\n" if $@;
            die "no NVMe/TCP portals configured and auto-discovery"
                . " failed. Set 'ontap_portal' or ensure NVMe/TCP"
                . " data LIFs exist.\n";
        }
    }

    # a portal field may be a FQDN, IPv4 or IPv6; resolve FQDNs (preferring
    # IPv6), keep IPv6 ahead of IPv4 overall, and untaint each to an IP literal
    # for the nvme exec (pvedaemon -T) — a FQDN never reaches the command line.
    my (%seen, @clean);
    for my $ip (map { _resolve_portal($_) } @raw) {
        next if $ip !~ /\A([0-9a-fA-F.:]+)\z/;
        next if $seen{$1}++;
        push @clean, $1;
    }
    @clean = sort { ($b =~ /:/ ? 1 : 0) <=> ($a =~ /:/ ? 1 : 0) } @clean;

    die "no usable NVMe/TCP portal address\n" if !@clean;
    return \@clean;
}

# cached portal lookup for the hot activation path (it runs on every VM
# start): one successful LIF discovery per daemon lifetime is enough, and an
# explicit ontap_portal never needs the API at all. Recovery paths (path(),
# _nvme_rescan) keep using _get_portals directly so they always see fresh
# LIFs after a failover.
sub _get_portals_cached {
    my ($scfg, $api, $storeid) = @_;

    my $cached = $storeid ? $PORTAL_CACHE{$storeid} : undef;
    return $cached if $cached && @$cached;

    my $portals = _get_portals($scfg, $api);
    $PORTAL_CACHE{$storeid} = $portals
        if $storeid && $portals && @$portals;

    return $portals;
}

# -- NVMe/TCP connection management ------------------------------------

sub _untaint_nvme_key {
    my ($k) = @_;

    return undef if !defined($k);
    # DH-HMAC-CHAP (DHHC-1:...) and TLS (NVMeTLSkey-1:...) keys: base64 payload
    # plus structural chars only — no shell metacharacters, \z-anchored
    return $k =~ m{\A([A-Za-z0-9:+/=._-]+)\z} ? $1 : undef;
}

# redact NVMe secrets from a command/error string before it reaches a log
sub _redact {
    my ($m) = @_;
    $m //= '';
    $m =~ s/(--(?:dhchap-secret|dhchap-ctrl-secret|psk))\s+\S+/$1 <redacted>/g;
    return $m;
}

# resolve per-storage connect options (in-band auth + TLS) from the priv dir
sub _connect_opts {
    my ($storeid, $scfg) = @_;

    my $auth = _nvme_auth($storeid);
    return {
        dhchap_secret => $auth->{dhchap_secret},
        dhchap_ctrl   => $auth->{dhchap_ctrl},
        tls           => ($scfg->{nvme_tls} && $auth->{tls_psk}) ? 1 : 0,
    };
}

sub _nvme_connect_all {
    my ($portal, $copts) = @_;
    $copts //= {};

    my @cmd = ('nvme', 'connect-all', '-t', 'tcp', '-a', $portal);
    if ($copts->{dhchap_secret}) {
        my $s = _untaint_nvme_key($copts->{dhchap_secret})
            // die "invalid DH-HMAC-CHAP host secret format\n";
        push @cmd, '--dhchap-secret', $s;
        if ($copts->{dhchap_ctrl}) {
            my $c = _untaint_nvme_key($copts->{dhchap_ctrl})
                // die "invalid DH-HMAC-CHAP controller secret format\n";
            push @cmd, '--dhchap-ctrl-secret', $c;
        }
    }
    push @cmd, '--tls' if $copts->{tls};

    eval {
        run_command(
            \@cmd,
            outfunc => sub { },
            errfunc => sub { },
            timeout => 30,
        );
    };
    warn "nvme connect-all to $portal: " . _redact("$@") . "\n" if $@;
}

sub _nvme_ensure_connected {
    my ($scfg, $api, $copts, $storeid) = @_;

    # this storage's portal set, cached after the first successful discovery
    # so the common already-connected case costs no REST round-trip
    my $portals = eval { _get_portals_cached($scfg, $api, $storeid) };
    my $portal_err = $@;

    my $subsys_raw = '';
    eval {
        my @lines;
        run_command(
            ['nvme', 'list-subsys', '-o', 'json'],
            outfunc => sub { push @lines, shift; },
            errfunc => sub { },
            timeout => 5,
        );
        $subsys_raw = join('', @lines);
    };

    if ($portals) {
        # already connected? Only trust controllers whose traddr matches one
        # of THIS storage's portals — a leftover NVMe/TCP connection to some
        # other array/portal must not short-circuit the connect, or this
        # storage's namespaces silently stay unreachable on the node. The
        # regex covers both nvme-cli output forms: Address "traddr=IP,..."
        # and a dedicated "traddr":"IP" JSON field.
        my %want = map { lc($_) => 1 } @$portals;
        while ($subsys_raw =~ /traddr[="':\s]+([0-9a-fA-F.:]+)/g) {
            return if $want{ lc($1) };
        }
        _nvme_connect_all($_, $copts) for @$portals;
        return;
    }

    # portal discovery failed (management API unreachable): degrade to the
    # old behaviour — assume connected when any NVMe/TCP controller exists,
    # otherwise surface the discovery error.
    if ($subsys_raw =~ /tcp/i) {
        warn "cannot verify NVMe/TCP portals (portal discovery failed);"
            . " assuming existing connections are correct: $portal_err\n";
        return;
    }
    die $portal_err || "no NVMe/TCP portals available\n";
}

sub _nvme_rescan {
    my ($scfg, $api, $copts) = @_;

    my $portals = _get_portals($scfg, $api);
    _nvme_connect_all($_, $copts) for @$portals;
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

# -- consistency group management --------------------------------------

sub _cg_member {
    my ($cg, $vol_name) = @_;

    return 0 if !$cg;
    return (grep { ($_->{name} // '') eq $vol_name } @{$cg->{volumes} // []})
        ? 1
        : 0;
}

# delete all of our (pve_snap_*) snapshots on a CG. Used before deleting an
# empty CG (ONTAP refuses to delete a CG that still has snapshots) and when
# adopting a stale CG left behind by a previous owner of the same VMID — the
# new owner must not be able to list or restore the old tenant's snapshots.
sub _purge_cg_snapshots {
    my ($api, $cg) = @_;

    my $snaps = eval {
        $api->list_cg_snapshots($cg->{uuid}, "${SNAP_PREFIX}*");
    } // [];
    for my $s (@$snaps) {
        eval { $api->delete_cg_snapshot($cg->{uuid}, $s->{uuid}); };
        warn "could not delete stale CG snapshot '$s->{name}': $@\n" if $@;
    }
}

sub _ensure_cg {
    my ($api, $vmid, $vol_name, $prefix, $snap_policy) = @_;

    $prefix //= '';
    $snap_policy //= 'none';
    my $cgname = _cg_name($vmid, $prefix);
    my $cg = $api->get_consistency_group($cgname);

    if (!$cg) {
        eval {
            $api->create_consistency_group($cgname, [$vol_name], $snap_policy);
        };
        if (my $err = $@) {
            # another node may have created the CG concurrently (check-then-
            # create race): converge on the winner's CG instead of silently
            # leaving this disk outside it — fall through so membership and
            # policy are reconciled below
            $cg = $api->get_consistency_group($cgname);
            if (!$cg) {
                warn "failed to create CG $cgname — this disk falls back to"
                    . " per-volume (non-atomic) snapshots: $err\n";
                return undef;
            }
        }
        else {
            return $api->get_consistency_group($cgname);
        }
    }

    # adopting an existing CG with no member volumes: it was left behind by a
    # previous owner of this VMID (CG deletion fails while snapshots exist) —
    # purge its stale snapshots so they cannot leak to the new owner. Safe
    # against a concurrent creator: _ensure_cg always runs under the per-VM
    # lock, and a freshly created CG cannot carry pve_snap_* snapshots
    # (volume_snapshot only snapshots CGs the disk is a member of).
    if (!@{$cg->{volumes} // []}) {
        warn "adopting empty CG $cgname — purging its stale snapshots\n";
        _purge_cg_snapshots($api, $cg);
    }

    # keep the CG's scheduled-snapshot policy in sync with the storage config so
    # scheduled snapshots stay atomic across the VM's disks; this also upgrades a
    # CG created before the policy was applied at the CG level.
    my $have = $cg->{snapshot_policy}{name} // '';
    if ($have ne $snap_policy) {
        eval {
            $api->set_consistency_group_snapshot_policy(
                $cg->{uuid}, $snap_policy,
            );
        };
        warn "could not set snapshot policy '$snap_policy' on CG $cgname: $@\n"
            if $@;
    }

    if (!_cg_member($cg, $vol_name)) {
        eval {
            $api->add_volume_to_consistency_group(
                $cg->{uuid}, $vol_name,
            );
        };
        if ($@) {
            warn "failed to add $vol_name to CG $cgname"
                . " (modifying CG membership needs ONTAP 9.12.1+); this disk"
                . " will be excluded from atomic CG snapshots: $@\n";
        }
        elsif ($api->is_svm_scoped()) {
            # the membership PATCH may have returned 202 with a job this
            # account cannot poll: confirm the volume actually joined before
            # trusting CG snapshots to cover it
            my $joined = _poll_for(
                5, 2,
                sub {
                    _cg_member($api->get_consistency_group($cgname), $vol_name);
                },
            );
            warn "could not confirm that '$vol_name' joined CG $cgname —"
                . " CG snapshots may not cover this disk; verify the"
                . " membership on ONTAP\n"
                if !$joined;
        }
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
        # ONTAP refuses to delete a CG that still has snapshots; purge ours
        # first so the cleanup actually completes (a stale CG would otherwise
        # be adopted — snapshots included — by a future VM reusing this VMID)
        _purge_cg_snapshots($api, $cg);
        eval { $api->delete_consistency_group($cg->{uuid}); };
        warn "failed to delete empty CG $cgname: $@\n" if $@;
    }
}

# Apply (or remove) ONTAP snapshot autodelete on one of our volumes per the
# storage's snapshot_autodelete option. Best-effort: a disk must not fail to
# provision because its space-pressure valve could not be armed — but warn, the
# operator opted into the protection.
sub _apply_snapshot_autodelete {
    my ($api, $scfg, $vol_name) = @_;

    return if !$scfg->{snapshot_autodelete};
    eval {
        my $vuuid = $api->get_volume_uuid($vol_name);
        $api->set_volume_snapshot_autodelete($vuuid, 1, $SNAP_DEFER_PREFIX)
            if $vuuid;
    };
    warn "could not enable snapshot autodelete on '$vol_name': $@\n" if $@;
}

# Push the storage's snapshot_autodelete setting to all existing prefixed
# volumes at once, from the update hooks — so toggling the option protects (or
# un-protects) the fleet immediately, not just volumes created afterwards.
# Best-effort, same contract as _reconcile_snapshot_policy.
sub _reconcile_snapshot_autodelete {
    my ($storeid, $scfg) = @_;

    my $api = eval { _api($scfg, $storeid) };
    return if !$api;

    my $prefix = _prefix($scfg);
    my $enable = $scfg->{snapshot_autodelete} ? 1 : 0;

    my @failed;
    my $vols = eval {
        $api->list_volume_snapshot_policies("${prefix}*");
    } // [];
    for my $v (@$vols) {
        my $vn = $v->{name} // next;
        next if $vn !~ m/^\Q$prefix\E(?:vm|base)_[0-9]+_/;
        eval {
            $api->set_volume_snapshot_autodelete(
                $v->{uuid}, $enable, $SNAP_DEFER_PREFIX,
            );
        };
        if ($@) {
            warn "autodelete reconcile: volume '$vn': $@\n";
            push @failed, $vn;
        }
    }
    warn "snapshot autodelete reconcile for '$storeid': " . scalar(@failed)
        . " volume(s) not updated (" . join(', ', @failed) . ")\n"
        if @failed;
}

# Reconcile a member volume's own snapshot schedule with the configured policy.
# Scheduled snapshots are owned by the consistency group (atomic across the VM's
# disks), so a volume that is part of its CG must carry no schedule of its own
# ('none') or it would be snapshotted twice. A disk that could not join the CG
# (ONTAP < 9.12.1 cannot modify CG membership) keeps a per-volume schedule as a
# best-effort fallback, so it stays protected — just not crash-consistent with
# its siblings. The reconcile runs in both directions (it also clears a stale
# per-volume schedule, e.g. after the policy is lowered to 'none' or a disk is
# moved) but PATCHes only when the volume is not already at the wanted policy, so
# the common no-policy case costs no write. Best-effort: a failure here never
# fails the disk operation.
sub _apply_snapshot_schedule {
    my ($api, $scfg, $vmid, $vol_name, $prefix) = @_;

    my $policy = $scfg->{snapshot_policy} || 'none';

    my $cg = _get_cg_for_vm($api, $vmid, $prefix);

    my $want = _cg_member($cg, $vol_name) ? 'none' : $policy;

    my $info = $api->get_volume_snapshot_policy($vol_name);
    return if !$info || !$info->{uuid};
    return if $info->{name} eq $want; # already correct: avoid a redundant PATCH

    eval { $api->set_volume_snapshot_policy($info->{uuid}, $want); };
    warn "could not set snapshot policy '$want' on volume '$vol_name': $@\n"
        if $@;
}

# Push the storage's current snapshot_policy to all of its existing ONTAP objects
# at once. Called from the update hooks when the policy changes, so the new
# schedule takes effect immediately instead of only on the next disk operation.
# Every CG gets the policy; its member volumes are cleared to 'none' (the CG owns
# the schedule); an active disk not in any CG (ONTAP < 9.12.1 fallback) gets the
# policy per-volume; base templates carry none. Each object is re-read and
# patched under its VM's cluster lock (PATCH only on a real difference), and
# the sweep is best-effort (never dies — a storage-config update must not fail
# because ONTAP is briefly unreachable).
sub _reconcile_snapshot_policy {
    my ($storeid, $scfg) = @_;

    my $api = eval { _api($scfg, $storeid) };
    return if !$api;

    my $prefix = _prefix($scfg);
    my $policy = $scfg->{snapshot_policy} || 'none';

    my @failed;
    eval {
        # each CG is re-read and patched under its VM's lock so the sweep
        # cannot interleave with a concurrent disk operation on another node
        my $cgs = $api->list_consistency_groups("${prefix}${CG_PREFIX}*") // [];
        for my $cg (@$cgs) {
            my ($vmid) = (($cg->{name} // '') =~ m/\Q$CG_PREFIX\E([0-9]+)$/);
            next if !defined($vmid);
            eval {
                _cg_lock(
                    $scfg, $vmid,
                    sub {
                        my $fresh = $api->get_consistency_group($cg->{name});
                        return if !$fresh;
                        return
                            if ($fresh->{snapshot_policy}{name} // '')
                            eq $policy;
                        $api->set_consistency_group_snapshot_policy(
                            $fresh->{uuid}, $policy,
                        );
                    },
                );
            };
            if ($@) {
                warn "reconcile: CG '$cg->{name}': $@\n";
                push @failed, "cg:$cg->{name}";
            }
        }

        # member volumes go through _apply_snapshot_schedule under the same
        # per-VM lock — it re-reads CG membership itself, so the decision is
        # never based on a stale listing. Base images belong to no CG and are
        # simply kept schedule-free.
        my $vols = $api->list_volume_snapshot_policies("${prefix}*") // [];
        for my $v (@$vols) {
            my $vn = $v->{name} // next;
            if ($vn =~ m/^\Q$prefix\Ebase_[0-9]+_disk_[0-9]+$/) {
                next if ($v->{snapshot_policy}{name} // '') eq 'none';
                eval { $api->set_volume_snapshot_policy($v->{uuid}, 'none'); };
                if ($@) {
                    warn "reconcile: volume '$vn': $@\n";
                    push @failed, "vol:$vn";
                }
                next;
            }
            my ($vmid) = ($vn =~ m/^\Q$prefix\Evm_([0-9]+)_/);
            next if !defined($vmid);
            eval {
                _cg_lock(
                    $scfg, $vmid,
                    sub {
                        _apply_snapshot_schedule(
                            $api, $scfg, $vmid, $vn, $prefix,
                        );
                    },
                );
            };
            if ($@) {
                warn "reconcile: volume '$vn': $@\n";
                push @failed, "vol:$vn";
            }
        }
    };
    warn "snapshot policy reconcile for '$storeid' incomplete: $@\n" if $@;

    # one actionable summary instead of scattered per-object warnings: the
    # listed objects still run the previous schedule
    warn "snapshot policy reconcile for '$storeid': " . scalar(@failed)
        . " object(s) still on the previous policy (" . join(', ', @failed)
        . ") — fix connectivity and re-run 'pvesm set --snapshot_policy'\n"
        if @failed;
}

# best-effort full teardown of a volume (unmap + delete namespace, delete
# volume), used to roll back a partially provisioned disk. Retried once after
# a short pause — a transient ONTAP hiccup during cleanup would otherwise
# silently leave a mapped namespace and a space-leaking volume behind.
sub _teardown_volume {
    my ($api, $vol_name) = @_;

    for my $attempt (1, 2) {
        eval {
            my $ns = _find_ns_for_volume($api, $vol_name);
            if ($ns) {
                my $maps = $api->get_namespace_subsystem_map($ns->{uuid});
                for my $map (@$maps) {
                    my $sub_uuid = $map->{subsystem}{uuid} // next;
                    eval {
                        $api->unmap_namespace_from_subsystem(
                            $sub_uuid, $ns->{uuid},
                        );
                    };
                }
                eval { $api->delete_namespace($ns->{uuid}); };
            }
            my $vuuid = $api->get_volume_uuid($vol_name);
            # force: a seconds-old, half-provisioned volume holds no data
            # worth parking in the recovery queue
            eval { $api->delete_volume($vuuid, 1); } if $vuuid;
        };
        warn "rollback of volume '$vol_name' (attempt $attempt): $@\n" if $@;

        my $left = eval { $api->get_volume_uuid($vol_name) };
        return if !$left;

        if ($attempt == 1) {
            sleep 3;
            next;
        }
        warn "rollback of volume '$vol_name' incomplete — it still exists on"
            . " ONTAP (with its namespace/mapping) and must be cleaned up"
            . " manually\n";
    }
}

# remove a volume from the VM's consistency group if it is currently a member.
# No-op (with a warning) when the CG membership PATCH is unavailable
# (ONTAP < 9.12.1).
sub _detach_from_cg {
    my ($api, $vmid, $vol_name, $prefix) = @_;

    my $cg = _get_cg_for_vm($api, $vmid, $prefix);
    return if !_cg_member($cg, $vol_name);

    eval {
        $api->remove_volume_from_consistency_group(
            $cg->{uuid}, $vol_name,
        );
    };
    warn "failed to remove $vol_name from CG (ONTAP 9.12.1+ required"
        . " to modify CG membership): $@\n"
        if $@;
}

# -- subsystem registration --------------------------------------------

# best-effort: load the NVMe/TCP-TLS pre-shared key into the host kernel keyring
# so the local initiator can complete the TLS handshake. Requires nvme-cli with
# TLS support, a TLS-capable kernel and a running tlshd.
sub _nvme_tls_keyring_insert {
    my ($subsysnqn, $hostnqn, $psk) = @_;
    return if !$subsysnqn || !$hostnqn || !$psk;

    my $k = _untaint_nvme_key($psk);
    if (!$k) {
        warn "invalid NVMe/TCP TLS PSK format; skipping keyring insert\n";
        return;
    }
    my ($s) = $subsysnqn =~ m{\A([A-Za-z0-9:._-]+)\z};
    my ($h) = $hostnqn =~ m{\A([A-Za-z0-9:._-]+)\z};
    return if !$s || !$h;

    eval {
        run_command(
            [
                'nvme', 'gen-tls-key', '--insert', '--keyring', '.nvme',
                '--subsysnqn', $s, '--hostnqn', $h, '--psk', $k,
            ],
            outfunc => sub { },
            errfunc => sub { },
            timeout => 10,
        );
    };
    warn "NVMe/TCP TLS keyring provisioning failed (provision manually with"
        . " 'nvme gen-tls-key --insert'): " . _redact("$@") . "\n"
        if $@;
}

# Hard pre-flight for NVMe/TCP-TLS: a missing tlshd or an absent PSK in the
# kernel keyring does not fail `nvme connect` — it makes the TLS handshake
# (and the VM I/O behind it) hang with no visible cause. Fail activation
# loudly instead.
sub _nvme_tls_preflight {
    my ($storeid) = @_;

    my $rc = eval {
        run_command(
            ['systemctl', 'is-active', '--quiet', 'tlshd'],
            outfunc => sub { },
            errfunc => sub { },
            noerr => 1,
            timeout => 5,
        );
    };
    die "storage '$storeid': nvme_tls is enabled but the tlshd handshake"
        . " daemon is not running on this node — NVMe/TCP-TLS connections"
        . " would hang. Install/enable ktls-utils (tlshd) or disable"
        . " nvme_tls.\n"
        if !defined($rc) || $rc != 0;

    # the PSK may have been inserted by us (_nvme_tls_keyring_insert) or
    # manually; either way it must be present or connections hang
    my $keys = eval { PVE::Tools::file_get_contents('/proc/keys') } // '';
    die "storage '$storeid': nvme_tls is enabled but no NVMe TLS PSK is"
        . " present in the kernel keyring — connections would hang. Check"
        . " the keyring warning in the log, or insert the key manually with"
        . " 'nvme gen-tls-key --insert'.\n"
        if $keys !~ /\bpsk\b[^\n]*NVMe/;

    return;
}

sub _ensure_subsystem_and_host {
    my ($api, $subsystem_name, $auth) = @_;
    $auth //= {};

    my $subsys = $api->get_subsystem($subsystem_name);
    if (!$subsys) {
        eval { $api->create_subsystem($subsystem_name, 'linux'); };
        warn "failed to create subsystem: $@\n" if $@;
        $subsys = $api->get_subsystem($subsystem_name);
    }
    return $subsys if !$subsys;

    my $nqn = _get_host_nqn();
    my $want_chap = $auth->{dhchap_secret} ? 1 : 0;
    my $want_tls = $auth->{tls_psk} ? 1 : 0;

    my $host = $api->get_subsystem_host($subsys->{uuid}, $nqn);
    if (!$host) {
        $api->add_host_to_subsystem($subsys->{uuid}, $nqn, $auth);
    }
    elsif ($want_chap || $want_tls) {
        # in-band-auth / TLS secrets are create-only on the host entry: if the
        # host was registered without the wanted auth, re-register it once
        my $have_chap = (($host->{dh_hmac_chap}{mode} // 'none') ne 'none');
        my $have_tls = (($host->{tls}{key_type} // 'none') eq 'configured');
        if (($want_chap && !$have_chap) || ($want_tls && !$have_tls)) {
            # between the DELETE and the POST the host NQN is unregistered:
            # ONTAP rejects all I/O from this node to every namespace in the
            # subsystem for that window
            warn "re-registering host NQN on subsystem '$subsystem_name' to"
                . " apply new NVMe auth — access from this node is briefly"
                . " interrupted; apply auth changes in a maintenance window\n";
            eval { $api->remove_host_from_subsystem($subsys->{uuid}, $nqn); };
            $api->add_host_to_subsystem($subsys->{uuid}, $nqn, $auth);
        }
    }

    _nvme_tls_keyring_insert($subsys->{target_nqn}, $nqn, $auth->{tls_psk})
        if $want_tls;

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

# After a CG snapshot create on an SVM-scoped account, the operation may have
# returned 202 with a job that account cannot poll: confirm the snapshot
# actually exists before reporting success — a backup whose snapshot silently
# does not exist is worse than a failed one.
sub _verify_cg_snapshot {
    my ($api, $cg, $snap_name) = @_;

    return if !$api->is_svm_scoped();

    my $found = _poll_for(
        5, 2,
        sub { $api->get_cg_snapshot_by_name($cg->{uuid}, $snap_name) },
    );
    die "CG snapshot '$snap_name' was accepted by ONTAP but cannot be"
        . " verified — check it on ONTAP before trusting this snapshot\n"
        if !$found;
}

# Refuse a CG restore whose member set no longer matches the CG: ONTAP's CG
# restore is best-effort, reverts every member volume, and deletes all newer
# snapshots — restoring over a disk that was added after the snapshot would
# silently revert it to an unrelated state. The operator must resolve the
# topology change first.
sub _assert_cg_snapshot_restorable {
    my ($cg, $snap_obj, $snap) = @_;

    die "snapshot '$snap' is marked partial on ONTAP — it does not cover"
        . " every disk of the consistency group and cannot be restored as a"
        . " whole\n"
        if $snap_obj->{is_partial};

    my %covered = map { ($_->{volume}{name} // '') => 1 }
        @{$snap_obj->{snapshot_volumes} // []};
    return if !%covered; # member set not reported: nothing to validate

    my @uncovered = grep { !$covered{ $_->{name} // '' } }
        @{$cg->{volumes} // []};
    return if !@uncovered;

    my $list = join(', ', map { $_->{name} } @uncovered);
    die "CG snapshot '$snap' does not cover current member volume(s) $list"
        . " (added after the snapshot) — a CG restore would revert them to"
        . " an unrelated state and delete all newer snapshots. Detach those"
        . " disks from the VM first, or restore per-volume manually.\n";
}

# =====================================================================
# Plugin registration
# =====================================================================

sub type { return 'ontapnvme'; }

sub api {
    # This plugin targets the Proxmox VE 9 storage API:
    #   12: qemu_blockdev_options, volume_qemu_snapshot_method, get_formats
    #   13: $hints in activate_volume/map_volume, on_update_hook_full
    #   14: get_identity (optional, not implemented)
    #   15: volume_snapshot_info virtual-size, volume_resize $snapname
    # Report the running API version when it falls inside our tested range,
    # otherwise clamp to the maximum we support (still loadable while it stays
    # within PVE::Storage::APIAGE of the host's APIVER).
    my $supported_min = 12;
    my $supported_max = 15;

    # Reference APIVER at run time instead of 'use PVE::Storage'. PVE::Storage
    # is always loaded by the time api() is called (it is what loads the
    # plugin), and 'use'-ing it here would trigger a re-entrant plugin-
    # registration scan while this module is still compiling ("not derived
    # from PVE::Storage::Plugin").
    my $apiver = eval { PVE::Storage::APIVER() };
    return $supported_max if !defined($apiver);

    return $apiver
        if $apiver >= $supported_min && $apiver <= $supported_max;

    return $supported_max;
}

sub plugindata {
    return {
        content                => [{ images => 1 }, { images => 1 }],
        'sensitive-properties' => {
            password => 1,
            nvme_dhchap_secret => 1,
            nvme_dhchap_ctrl_secret => 1,
            nvme_tls_psk => 1,
        },
        shared                 => 1,
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
            description => "ONTAP scheduled-snapshot policy, applied to the VM's"
                . " consistency group so scheduled snapshots are atomic across"
                . " all its disks (default: none). On ONTAP < 9.12.1 a disk that"
                . " cannot join the CG falls back to a per-volume schedule.",
            type        => 'string',
            optional    => 1,
        },
        storage_prefix => {
            description => "Prefix for ONTAP object names.",
            type        => 'string',
            optional    => 1,
        },
        encryption => {
            description => "Volume encryption. Unset inherits the ONTAP/"
                . "aggregate default; true requests NVE when the aggregate "
                . "is not already NAE-encrypted; false disables it.",
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
            description => "Verify the ONTAP TLS certificate (default: 1, on)."
                . " For a private-CA certificate, trust the CA on the PVE node"
                . " (update-ca-certificates) instead of disabling this.",
            type        => 'boolean',
            optional    => 1,
        },
        nvme_dhchap_secret => {
            description => "NVMe in-band authentication (DH-HMAC-CHAP) host"
                . " secret, e.g. 'DHHC-1:00:...'. Generate with"
                . " 'nvme gen-dhchap-key'. Enables host authentication on the"
                . " NVMe/TCP connection.",
            type        => 'string',
            optional    => 1,
        },
        nvme_dhchap_ctrl_secret => {
            description => "Controller secret for bidirectional (mutual)"
                . " DH-HMAC-CHAP. Requires nvme_dhchap_secret.",
            type        => 'string',
            optional    => 1,
        },
        nvme_tls => {
            description => "Use NVMe/TCP-TLS (TLS 1.3) for the data path."
                . " Requires nvme_tls_psk, ONTAP 9.16+ and a TLS-capable node"
                . " (kernel NVMe/TCP-TLS, tlshd, nvme-cli with TLS support).",
            type        => 'boolean',
            optional    => 1,
        },
        nvme_tls_psk => {
            description => "NVMe/TCP-TLS pre-shared key, e.g."
                . " 'NVMeTLSkey-1:01:...'. Generate with 'nvme gen-tls-key'.",
            type        => 'string',
            optional    => 1,
        },
        snapshot_autodelete => {
            description => "Let ONTAP delete the oldest snapshots when a"
                . " FlexVol nears full despite autosize, instead of refusing"
                . " writes (VM I/O errors). Plugin-managed snapshots"
                . " (pve_snap_*, pve_base) are deferred to last resort, so"
                . " scheduled-policy snapshots are sacrificed first. Caveat:"
                . " if a pve_snap_* snapshot is ever reaped, the PVE snapshot"
                . " tree desynchronizes (rollback/delete of that snapshot"
                . " fails). Default 0.",
            type        => 'boolean',
            optional    => 1,
        },
        force_delete => {
            description => "Bypass the ONTAP volume recovery queue when"
                . " deleting disks (immediate, unrecoverable). Default 0:"
                . " deleted disks are parked in the recovery queue and remain"
                . " recoverable by the ONTAP admin for the retention period;"
                . " note a parked FlexClone pins its base image until purged"
                . " or expired.",
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
        autosize => {
            description => "Let the hosting FlexVol auto-grow so the thin "
                . "namespace never goes offline when snapshots fill its "
                . "container (default: true).",
            type        => 'boolean',
            optional    => 1,
        },
        autosize_max_percent => {
            description => "Max FlexVol auto-grow size as a percent of the "
                . "initial volume size (default: 300). Size it against churn:"
                . " each retained snapshot pins roughly the data rewritten"
                . " since the previous one.",
            type        => 'integer',
            minimum     => 105,
            maximum     => 1000,
            optional    => 1,
        },
        svm_scoped => {
            description => "Operate with an SVM-scoped ONTAP account: avoid "
                . "cluster-scoped REST calls (/cluster/jobs, /storage/"
                . "aggregates). status() then reports space from the SVM's "
                . "own volumes. Default: 0 (cluster-scoped).",
            type        => 'boolean',
            optional    => 1,
        },
        svm_capacity => {
            description => "Logical capacity in GiB reported by status() in "
                . "svm_scoped mode. Unset uses the sum of provisioned volume "
                . "sizes (reads 0 on an empty SVM).",
            type        => 'integer',
            minimum     => 1,
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
        autosize             => { optional => 1 },
        autosize_max_percent => { optional => 1 },
        svm_scoped           => { optional => 1 },
        svm_capacity         => { optional => 1 },
        snapshot_autodelete  => { optional => 1 },
        force_delete         => { optional => 1 },
        verify_ssl          => { optional => 1 },
        nvme_dhchap_secret      => { optional => 1 },
        nvme_dhchap_ctrl_secret => { optional => 1 },
        nvme_tls                => { optional => 1 },
        nvme_tls_psk            => { optional => 1 },
        debug               => { optional => 1 },
        shared              => { optional => 1 },
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

    # optional NVMe in-band-auth / TLS secrets (sensitive; stored like password)
    for my $s (
        ['nvme_dhchap_secret', 'dhchap'],
        ['nvme_dhchap_ctrl_secret', 'dhchapc'],
        ['nvme_tls_psk', 'tlspsk'],
    ) {
        my ($k, $kind) = @$s;
        _save_secret($storeid, $kind, $param{$k})
            if defined($param{$k}) && $param{$k} ne '';
    }

    # ONTAP NVMe/TCP is inherently shared storage, but the 'shared' flag in
    # plugindata() does not reach PVE's migration code (verified on PVE 9.1:
    # without 'shared 1' in storage.cfg, qm migrate treats the disks as local
    # and refuses --online). Persist the default at creation; an explicit
    # --shared 0 (single-node lab) is respected.
    $scfg->{shared} //= 1;

    my $mgmt_ip = $scfg->{mgmt_ip}
        || die "mgmt_ip is required\n";
    my $username = $scfg->{username} // $param{username}
        || die "username is required\n";
    my $vserver = $scfg->{vserver}
        || die "vserver is required\n";

    # an SVM-scoped account cannot see physical aggregate space; without an
    # explicit logical capacity, status() reads the sum of provisioned sizes
    # and can mask a full aggregate until namespaces go offline
    die "svm_scoped mode requires svm_capacity (set a conservative logical"
        . " capacity in GiB — leave headroom for snapshots and other SVMs)\n"
        if $scfg->{svm_scoped} && !$scfg->{svm_capacity};

    eval {
        my $api = PVE::Storage::OntapNvmeTcp::Api->new(
            mgmt_ip    => $mgmt_ip,
            username   => $username,
            password   => $password,
            vserver    => $vserver,
            verify_ssl => $scfg->{verify_ssl},
        );
        $api->get_svm_uuid();

        _ensure_subsystem_and_host(
            $api, $scfg->{subsystem}, _nvme_auth($storeid),
        ) if $scfg->{subsystem};
    };
    if (my $err = $@) {
        _delete_secret($storeid, $_) for qw(pw dhchap dhchapc tlspsk);
        die "ONTAP connection failed: $err\n";
    }

    return;
}

my sub _apply_sensitive_updates {
    my ($storeid, $sensitive, $delete) = @_;

    # Save new/updated sensitive properties
    _save_password($storeid, $sensitive->{password})
        if defined($sensitive->{password});

    for my $s (
        ['nvme_dhchap_secret',      'dhchap' ],
        ['nvme_dhchap_ctrl_secret', 'dhchapc'],
        ['nvme_tls_psk',            'tlspsk' ],
    ) {
        my ($k, $kind) = @$s;
        _save_secret($storeid, $kind, $sensitive->{$k})
            if defined($sensitive->{$k}) && $sensitive->{$k} ne '';
    }

    # Clean up secret files for deleted properties
    my %secret_map = (
        password                => 'pw',
        nvme_dhchap_secret      => 'dhchap',
        nvme_dhchap_ctrl_secret => 'dhchapc',
        nvme_tls_psk            => 'tlspsk',
    );
    for my $prop (@{$delete // []}) {
        my $kind = $secret_map{$prop} // next;
        _delete_secret($storeid, $kind);
    }
}

# Build the post-update view of $scfg for a reconcile: the hooks receive the
# PRE-update config (verified on PVE 9.1), so a changed key's new value must be
# taken from the update itself or the stale value would be pushed to ONTAP.
sub _effective_scfg {
    my ($scfg, $key, $value, $deleted) = @_;

    my $eff = { %$scfg };
    if ($deleted) {
        delete $eff->{$key};
    }
    else {
        $eff->{$key} = $value;
    }

    return $eff;
}

# Run the immediate reconciles for config keys that must take effect on
# existing ONTAP objects as soon as they change, not only on the next disk
# operation. $update holds the new values, $deleted_keys the removed ones.
sub _run_update_reconciles {
    my ($storeid, $scfg, $update, $deleted_keys) = @_;

    my %deleted = map { $_ => 1 } @{$deleted_keys // []};

    if (exists $update->{snapshot_policy} || $deleted{snapshot_policy}) {
        _reconcile_snapshot_policy(
            $storeid,
            _effective_scfg(
                $scfg, 'snapshot_policy', $update->{snapshot_policy},
                $deleted{snapshot_policy},
            ),
        );
    }
    if (exists $update->{snapshot_autodelete}
        || $deleted{snapshot_autodelete}) {
        _reconcile_snapshot_autodelete(
            $storeid,
            _effective_scfg(
                $scfg, 'snapshot_autodelete', $update->{snapshot_autodelete},
                $deleted{snapshot_autodelete},
            ),
        );
    }
}

sub on_update_hook {
    my ($class, $storeid, $scfg, %param) = @_;
    _apply_sensitive_updates($storeid, \%param, []);
    _invalidate_api_cache($storeid);

    my @deleted = defined($param{delete})
        ? PVE::Tools::split_list($param{delete})
        : ();
    _run_update_reconciles($storeid, $scfg, \%param, \@deleted);

    return;
}

sub on_update_hook_full {
    my ($class, $storeid, $scfg, $update, $delete, $sensitive) = @_;
    _apply_sensitive_updates($storeid, $sensitive, $delete);
    _invalidate_api_cache($storeid);

    _run_update_reconciles($storeid, $scfg, $update, $delete);

    return;
}

sub on_delete_hook {
    my ($class, $storeid, $scfg) = @_;

    # refuse to drop the credentials while volumes still exist: without the
    # password the plugin can no longer manage them and the data is stranded
    # on ONTAP. When the backend is unreachable the check is skipped, so a
    # dead storage definition can still be removed.
    my $vols = eval { $class->list_images($storeid, $scfg, undef, undef, {}) };
    if ($@) {
        warn "cannot verify storage '$storeid' is empty (ONTAP unreachable);"
            . " removing it anyway: $@\n";
    }
    elsif ($vols && @$vols) {
        die "storage '$storeid' still has " . scalar(@$vols)
            . " volume(s) on ONTAP — delete all disks before removing the"
            . " storage\n";
    }

    _delete_secret($storeid, $_) for qw(pw dhchap dhchapc tlspsk);

    _invalidate_api_cache($storeid);

    return;
}

# =====================================================================
# Volume operations
# =====================================================================

sub parse_volname {
    my ($class, $volname) = @_;

    # A regular disk (vm-N-disk-M), a base/template image (base-N-disk-M), or a
    # linked clone in PVE's compound form base-B-disk-J/vm-V-disk-I (the part
    # before '/' names the backing base image). Returns the *child* as $name so
    # all the ONTAP name mapping operates on the actual volume.
    if ($volname =~ m!^(?:(base-([0-9]+)-disk-[0-9]+)/)?((vm|base)-([0-9]+)-disk-([0-9]+))$!) {
        my $basename = $1;                        # base-B-disk-J or undef
        my $basevmid = $2;                        # B or undef
        my $name = $3;                            # the actual volume name
        my $isBase = ($4 eq 'base') ? 1 : undef;
        my $vmid = $5;
        return ('images', $name, $vmid, $basename, $basevmid, $isBase, 'raw');
    }
    if ($volname =~ m/^(vm-([0-9]+)-cloudinit)$/) {
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
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    # local cache first: a previously resolved namespace is matched to its
    # device purely via sysfs (by UUID), so VM starts and migrations keep
    # working while the ONTAP management API is unreachable — the NVMe data
    # path does not need it. A stale entry cannot mismatch (namespace UUIDs
    # are never reused); it just misses and falls through to the REST lookup.
    if (my $cached = $storeid ? $NS_CACHE{"$storeid/$ontap_name"} : undef) {
        my $dev = _find_nvme_device_for_namespace(
            $cached->{uuid}, $cached->{name},
        );
        if ($dev && $dev =~ m{\A(/dev/nvme[0-9]+n[0-9]+)\z}) {
            return wantarray ? ($1, $vmid, $vtype) : $1;
        }
    }

    my $api = _api($scfg, $storeid);

    my $ns = _find_ns_for_volume($api, $ontap_name);
    die "namespace not found in volume '$ontap_name'\n" if !$ns;

    # an ONTAP-side offline namespace (full volume/aggregate, admin action)
    # never produces a host device: name the actual cause instead of letting
    # QEMU fail later on a meaningless missing-device error
    my $state = $ns->{status}{state} // '';
    die "namespace '$ns->{name}' is $state on ONTAP — fix the cause (volume/"
        . "aggregate space, admin state) and bring its volume online there\n"
        if $state && $state ne 'online';

    $NS_CACHE{"$storeid/$ontap_name"} =
        { uuid => $ns->{uuid}, name => $ns->{name} }
        if $storeid;

    my $dev = _find_nvme_device_for_namespace(
        $ns->{uuid}, $ns->{name},
    );

    if (!$dev) {
        # not visible yet (typical on a live-migration target): connect, then
        # poll with backoff — LIF failover or kernel device registration can
        # easily exceed a fixed 2s wait under load
        my $copts = _connect_opts($storeid, $scfg);
        my $portals = _get_portals($scfg, $api);
        _nvme_connect_all($_, $copts) for @$portals;
        for my $wait (1, 2, 4, 8) {
            sleep $wait;
            $dev = _find_nvme_device_for_namespace(
                $ns->{uuid}, $ns->{name},
            );
            last if $dev;
        }
    }

    # failing here with the real problem beats returning a placeholder path
    # that QEMU later reports as an obscure open/ENOENT error
    die "NVMe device for namespace '$ns->{name}' (uuid=$ns->{uuid}) not"
        . " visible on this node after fabric rescan — check NVMe/TCP"
        . " connectivity to the ONTAP data LIFs\n"
        if !$dev;

    # safety: untaint device path (pvedaemon runs with -T). Strict, \z-anchored
    # whitelist — only a real NVMe namespace device, never a traversal (`..`)
    # or trailing-newline-bearing value.
    if ($dev =~ m{\A(/dev/nvme[0-9]+n[0-9]+)\z}) {
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
        if ($idx eq 'cloudinit') {
            $vol_name = $ontap; # already: ${prefix}vm_103_cloudinit
        }
        else {
            $vol_name = _ontap_name($vid, $idx, $prefix);
        }
        $pve_name = _ontap_to_pve($vol_name, $prefix);
    }
    else {
        $pve_name = $class->find_free_diskname($storeid, $scfg, $vmid, 'raw');
        $vol_name = _pve_to_ontap($pve_name, $prefix);
    }

    my $size_bytes = $size * 1024; # PVE passes KiB
    $size_bytes = $MIN_NS_BYTES if $size_bytes < $MIN_NS_BYTES;

    # step 1: create dedicated FlexVol. Best-effort headroom check first:
    # refuse an allocation that obviously cannot fit instead of letting it
    # succeed marginally and degrade later (a full container takes the
    # namespace offline)
    my $vol_size = int($size_bytes * $VOL_OVERHEAD);
    _check_alloc_headroom($api, $scfg, $vol_size);
    $api->create_volume($vol_name, $vol_size, _vol_create_opts($scfg));
    _apply_snapshot_autodelete($api, $scfg, $vol_name);

    # step 2: create NVMe namespace inside the volume
    my $result;
    eval {
        $result = $api->create_namespace(
            $vol_name, $vol_name, $size_bytes, 'linux',
        );
    };
    if ($@) {
        my $vuuid = $api->get_volume_uuid($vol_name);
        # force: brand-new empty volume, nothing to recover
        $api->delete_volume($vuuid, 1) if $vuuid;
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

    # steps 3-4: map namespace to subsystem and add the volume to the VM's
    # consistency group. Roll the whole volume back if mapping fails so we
    # never leave an orphaned namespace/volume behind.
    eval {
        my $subsys = $api->get_subsystem($scfg->{subsystem});
        die "subsystem '$scfg->{subsystem}' not found\n" if !$subsys;
        $api->map_namespace_to_subsystem($subsys->{uuid}, $ns_uuid);

        _cg_lock(
            $scfg, $vmid,
            sub {
                _ensure_cg(
                    $api, $vmid, $vol_name, $prefix,
                    $scfg->{snapshot_policy} || 'none',
                );
            },
        );
    };
    if (my $err = $@) {
        _teardown_volume($api, $vol_name);
        die "failed to provision namespace $vol_name: $err";
    }

    # scheduled snapshots are owned by the CG (atomic across the VM's disks);
    # clear this volume's own schedule, or keep one if it could not join the CG
    _cg_lock(
        $scfg, $vmid,
        sub { _apply_snapshot_schedule($api, $scfg, $vmid, $vol_name, $prefix) },
    );

    # step 5: discover new device on fabric
    _nvme_rescan($scfg, $api, _connect_opts($storeid, $scfg));

    return $pve_name;
}

sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase, $format) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    _debug($scfg, 1, "free_image($storeid, $volname)");
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $ontap_name = _pve_to_ontap($name, $prefix);

    delete $NS_CACHE{"$storeid/$ontap_name"};

    return _cg_lock($scfg, $vmid, sub {
        # detach from the consistency group before destroying the volume, so
        # the CG never keeps a reference to a deleted volume (which would
        # otherwise block the CG from ever being recognised as empty and
        # cleaned up)
        _detach_from_cg($api, $vmid, $ontap_name, $prefix);

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

        # delete volume — propagate failure so PVE does not drop its reference
        # and leave an orphaned volume behind (the namespace inside is removed
        # with it). Only force_delete bypasses the ONTAP recovery queue: by
        # default a deleted disk stays admin-recoverable for the retention
        # period.
        my $vol_uuid = $api->get_volume_uuid($ontap_name);
        if ($vol_uuid) {
            eval {
                $api->delete_volume($vol_uuid, $scfg->{force_delete} ? 1 : 0);
            };
            die "failed to delete volume '$ontap_name': $@" if $@;
        }

        _cleanup_cg_if_empty($api, $vmid, $prefix);

        return undef;
    });
}

sub list_images {
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;

    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $ckey = "ontapnvme_$storeid";

    if (!$cache->{$ckey}) {
        # match namespaces by their containing VOLUME name only (leaf '*'):
        # a namespace keeps its original name when its volume is renamed —
        # templates (vm_* -> base_*), and disks handed off from a storage
        # with a different prefix (ontapnvme-move). $re_vol below validates
        # the volume segment, which is the actual ownership filter.
        my $disk_ns = $api->list_namespaces(
            "/vol/${prefix}vm_*_disk_*/*",
        ) // [];
        my $state_ns = $api->list_namespaces(
            "/vol/${prefix}vm_*_state_*/*",
        ) // [];
        my $ci_ns = $api->list_namespaces(
            "/vol/${prefix}vm_*_cloudinit/*",
        ) // [];
        my $base_ns = $api->list_namespaces(
            "/vol/${prefix}base_*_disk_*/*",
        ) // [];
        $cache->{$ckey} = [@$disk_ns, @$state_ns, @$ci_ns, @$base_ns];

        # map FlexClone child volume -> backing base volume, so linked clones
        # are reported with PVE's compound volname (base-.../vm-...)
        my %cp;
        for my $v (@{$api->list_volume_clone_parents("${prefix}vm_*_disk_*") // []}) {
            my $parent = $v->{clone}{parent_volume}{name} // next;
            next if $parent !~ m/^\Q$prefix\Ebase_[0-9]+_disk_[0-9]+$/;
            $cp{$v->{name}} = $parent;
        }
        $cache->{"${ckey}_clone"} = \%cp;
    }
    my $clone_parent = $cache->{"${ckey}_clone"} // {};

    my $re_vol = qr{
        /vol/(\Q$prefix\E(?:
            vm_[0-9]+_(?:disk_[0-9]+|state_\S+|cloudinit)
            |base_[0-9]+_disk_[0-9]+
        ))/
    }x;

    my $res = [];
    for my $ns (@{$cache->{$ckey}}) {
        my $full_name = $ns->{name} // next;
        next if $full_name !~ $re_vol;
        my $ontap_vol = $1;

        next if $ontap_vol !~ m/\Q$prefix\E(?:vm|base)_([0-9]+)_/;
        my $vid = $1;
        next if defined($vmid) && $vid != $vmid;

        my $pve_name = _ontap_to_pve($ontap_vol, $prefix);
        # a FlexClone of a base image is a linked clone: present it as the PVE
        # compound volname base-.../vm-... so PVE tracks the backing base
        if (my $base = $clone_parent->{$ontap_vol}) {
            $pve_name = _ontap_to_pve($base, $prefix) . "/$pve_name";
        }
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

# Best-effort pre-allocation headroom check: refuse an allocation that
# obviously cannot fit. Skipped whenever space cannot be read — an allocation
# must not fail on a status-read hiccup.
sub _check_alloc_headroom {
    my ($api, $scfg, $need) = @_;

    my $free;
    if ($scfg->{svm_scoped}) {
        return if !$scfg->{svm_capacity};
        my $prefix = _prefix($scfg);
        my $sp = eval {
            $api->get_svm_volume_space($prefix ? "${prefix}*" : undef);
        };
        return if !$sp;
        $free = $scfg->{svm_capacity} * 1024 * 1024 * 1024 - $sp->{provisioned};
    }
    else {
        my $space = eval { $api->get_aggregate_space($scfg->{aggregate}) };
        return if !$space;
        $free = $space->{free};
    }

    die "not enough space on storage: need $need bytes, $free available\n"
        if defined($free) && $free < $need;
}

# Warn (once per volume, re-armed when it recovers) when a FlexVol's used
# space approaches its autosize ceiling: once the ceiling is reached and
# snapshots keep growing, ONTAP takes the namespace offline and the VM's I/O
# freezes — while space reporting still looks healthy. Swept from status() at
# most every 5 minutes per storage.
sub _check_autosize_headroom {
    my ($api, $scfg, $storeid) = @_;

    return if !$storeid;
    my $now = time();
    return if $now - ($CAPACITY_CHECK_TS{$storeid} // 0) < 300;
    $CAPACITY_CHECK_TS{$storeid} = $now;

    my $prefix = _prefix($scfg);
    my $vols = eval {
        $api->with_timeout(
            10,
            sub { $api->list_volume_autosize($prefix ? "${prefix}*" : undef) },
        );
    };
    return if !$vols;

    for my $v (@$vols) {
        my $vn = $v->{name} // next;
        my $max = $v->{autosize}{maximum} // next;
        my $used = $v->{space}{used} // next;
        my $key = "$storeid/$vn";
        if ($max && $used >= $max * 0.9) {
            next if $CAPACITY_WARNED{$key};
            $CAPACITY_WARNED{$key} = 1;
            my $pct = int(100 * $used / $max);
            warn "volume '$vn' uses ${pct}% of its autosize ceiling"
                . " ($used of $max bytes) — ONTAP will take its namespace"
                . " offline when full; grow the volume or free snapshot"
                . " space\n";
        }
        else {
            delete $CAPACITY_WARNED{$key};
        }
    }
}

sub status {
    my ($class, $storeid, $scfg, $cache) = @_;

    my $api = _api($scfg, $storeid);

    # capacity early warning (rate-limited): catches volumes closing in on
    # their autosize ceiling before ONTAP offlines their namespace
    eval { _check_autosize_headroom($api, $scfg, $storeid) };

    # SVM-scoped accounts cannot read the cluster-scoped aggregate endpoint;
    # report space from the SVM's own volumes instead.
    return _svm_scoped_status($api, $scfg) if $scfg->{svm_scoped};

    # short timeout: pvestatd polls every storage sequentially — a hung ONTAP
    # API must degrade this storage's status, not stall the whole poll loop
    my $space = $api->with_timeout(
        10,
        sub { $api->get_aggregate_space($scfg->{aggregate}) },
    );

    return $space
        ? ($space->{total}, $space->{free}, $space->{used}, 1)
        : (0, 0, 0, 0);
}

# status() for svm_scoped mode: total is the configured svm_capacity (GiB) if
# set, otherwise the sum of provisioned volume sizes; used/free come from the
# SVM's volumes. A logical view — physical aggregate capacity is governed on
# the ONTAP side, which an SVM-scoped account cannot (and should not) see.
sub _svm_scoped_status {
    my ($api, $scfg) = @_;

    my $prefix = _prefix($scfg);
    my $sp = eval {
        $api->with_timeout(
            10,
            sub { $api->get_svm_volume_space($prefix ? "${prefix}*" : undef) },
        );
    };
    return (0, 0, 0, 0) if $@ || !$sp;

    my $used = $sp->{used};
    my $total =
        $scfg->{svm_capacity}
        ? int($scfg->{svm_capacity}) * 1024 * 1024 * 1024
        : $sp->{provisioned};
    $total = $used if $total < $used;

    return ($total, $total - $used, $used, 1);
}

# Hourly, best-effort sweep for objects stranded by an interrupted operation
# (node crash or daemon restart mid-provisioning):
#  - a FlexVol without a namespace inside is the leftover of an allocation
#    that died between its steps; it is invisible to PVE (list_images lists
#    namespaces) and silently consumes space — warn with the remedy. Volumes
#    younger than an hour are skipped: another node's allocation is in flight
#    for seconds, not hours.
#  - a base volume without its pve_base snapshot (templating crashed between
#    the rename and the snapshot) breaks linked-clone creation — warn.
#  - an empty CG whose VM is gone is reaped outright, snapshots included; a
#    live VM's CG always has member volumes, and the reap re-checks under the
#    per-VM lock.
sub _check_stranded_objects {
    my ($api, $scfg, $storeid) = @_;

    return if !$storeid;
    my $now = time();
    return if $now - ($STRANDED_CHECK_TS{$storeid} // 0) < 3600;
    $STRANDED_CHECK_TS{$storeid} = $now;

    my $prefix = _prefix($scfg);

    eval {
        my %has_ns;
        my $nss = $api->list_namespaces("/vol/${prefix}*/*") // [];
        for my $ns (@$nss) {
            $has_ns{$1} = 1 if ($ns->{name} // '') =~ m{^/vol/([^/]+)/};
        }

        my $vols = $api->list_volumes_create_time("${prefix}*") // [];
        for my $v (@$vols) {
            my $vn = $v->{name} // next;
            next if $has_ns{$vn};
            # offline volumes are not stranded allocations: a fresh allocation
            # leftover is online, while a deleted volume parked in the
            # recovery queue (also namespace-less) was offlined first
            next if ($v->{state} // '') ne 'online';
            next if $vn
                !~ m/^\Q$prefix\Evm_[0-9]+_(?:disk_[0-9]+|cloudinit|state_\S+)$/;
            # unparseable/missing create_time skips the volume: for a
            # warn-only sweep a false negative beats a false positive
            my $ct = _snap_epoch($v->{create_time});
            next if !$ct || $now - $ct < 3600;
            my $pve = _ontap_to_pve($vn, $prefix);
            warn "stranded volume '$vn' (no namespace inside — likely an"
                . " interrupted allocation) consumes space invisibly; remove"
                . " it with 'pvesm free $storeid:$pve' or on ONTAP\n";
        }

        for my $v (@$vols) {
            my $vn = $v->{name} // next;
            next if ($v->{state} // '') ne 'online';
            next if $vn !~ m/^\Q$prefix\Ebase_[0-9]+_disk_[0-9]+$/;
            my $uuid = $v->{uuid} // next;
            next if $api->get_snapshot_by_name($uuid, $BASE_SNAP);
            warn "base volume '$vn' is missing its '$BASE_SNAP' snapshot"
                . " (templating was interrupted) — linked clones will fail;"
                . " create the snapshot on ONTAP or re-create the template\n";
        }

        # the unlocked emptiness test is only a pre-filter:
        # _cleanup_cg_if_empty re-fetches the CG and re-checks under the
        # per-VM lock, so a concurrent allocation cannot lose its fresh CG
        my $cgs = $api->list_consistency_groups("${prefix}${CG_PREFIX}*") // [];
        for my $cg (@$cgs) {
            next if @{$cg->{volumes} // []};
            my ($vmid) = (($cg->{name} // '') =~ m/\Q$CG_PREFIX\E([0-9]+)$/);
            next if !defined($vmid);
            eval {
                _cg_lock(
                    $scfg, $vmid,
                    sub { _cleanup_cg_if_empty($api, $vmid, $prefix) },
                );
            };
            warn "could not reap empty CG '$cg->{name}': $@\n" if $@;
        }
    };
    warn "stranded-object sweep for '$storeid' incomplete: $@\n" if $@;
}

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    die "nvme-cli not installed\n" if !-x '/usr/sbin/nvme';

    _debug($scfg, 1, "activate_storage($storeid)");

    warn "storage '$storeid': svm_scoped without svm_capacity — free-space"
        . " reporting is logical only and can mask a full aggregate; set"
        . " svm_capacity\n"
        if $scfg->{svm_scoped} && !$scfg->{svm_capacity};

    my $api = _api($scfg, $storeid);
    _ensure_subsystem_and_host($api, $scfg->{subsystem}, _nvme_auth($storeid));
    _nvme_tls_preflight($storeid) if $scfg->{nvme_tls};
    _nvme_ensure_connected($scfg, $api, _connect_opts($storeid, $scfg), $storeid);

    # best-effort hourly sweep for leftovers of interrupted operations
    eval { _check_stranded_objects($api, $scfg, $storeid) };

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
    _nvme_ensure_connected($scfg, $api, _connect_opts($storeid, $scfg), $storeid);

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
    my ($class, $scfg, $storeid, $volname, $size, $running, $snapname) = @_;

    # APIVER 15 may pass $snapname; only meaningful with snapshot-as-volume-
    # chain, which this plugin does not implement.
    die "resizing a snapshot is not supported by the ONTAP NVMe/TCP plugin\n"
        if $snapname;

    my ($vtype, $name) = $class->parse_volname($volname);
    _debug($scfg, 1, "volume_resize($volname, size=$size)");
    my $api = _api($scfg, $storeid);
    my $ontap_name = _pve_to_ontap($name, _prefix($scfg));

    # use the tolerant lookup so resizing also works for cloned volumes whose
    # namespace name differs from the volume name
    my $ns = _find_ns_for_volume($api, $ontap_name);
    die "namespace not found for '$ontap_name'\n" if !$ns;

    $api->resize_namespace($ns->{uuid}, $size);

    my $vol_uuid = $api->get_volume_uuid($ontap_name);
    if ($vol_uuid) {
        my $new_vol = int($size * $VOL_OVERHEAD);
        eval { $api->resize_volume($vol_uuid, $new_vol); };
        warn "volume resize for $ontap_name: $@\n" if $@;

        # keep the autosize grow ceiling tracking the new size
        if ($scfg->{autosize} // 1) {
            my $max_pct = $scfg->{autosize_max_percent} || 300;
            eval {
                $api->set_volume_autosize(
                    $vol_uuid, int($new_vol * $max_pct / 100),
                );
            };
            warn "autosize update for $ontap_name: $@\n" if $@;
        }
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

    return _cg_lock($scfg, $vmid, sub {
        my $ontap_name = _pve_to_ontap($name, $prefix);

        # CG-level snapshot first (atomic multi-disk) — but only when this
        # disk is actually a member: a CG snapshot taken for a non-member
        # would "succeed" while silently not covering this disk at all
        my $cg = _get_cg_for_vm($api, $vmid, $prefix);
        if (_cg_member($cg, $ontap_name)) {
            my $existing = $api->get_cg_snapshot_by_name(
                $cg->{uuid}, $snap_name,
            );
            return undef if $existing;
            eval {
                $api->create_cg_snapshot(
                    $cg->{uuid}, $snap_name, $comment,
                );
            };
            if (!$@) {
                _verify_cg_snapshot($api, $cg, $snap_name);
                return undef;
            }
            warn "CG snapshot failed, falling back to a per-volume snapshot"
                . " for '$ontap_name': $@\n";
        }
        elsif ($cg) {
            warn "volume '$ontap_name' is not a member of the VM's CG —"
                . " taking a per-volume snapshot (not atomic with the VM's"
                . " other disks)\n";
        }

        # fallback: per-volume snapshot
        my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
        die "volume '$name' not found\n" if !$vol_uuid;

        my $existing = $api->get_snapshot_by_name($vol_uuid, $snap_name);
        $api->create_snapshot($vol_uuid, $snap_name, $comment)
            if !$existing;

        return undef;
    });
}

sub volume_snapshot_rollback {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $snap_name = _snap_name($snap);

    return _cg_lock($scfg, $vmid, sub {
        my $ontap_name = _pve_to_ontap($name, $prefix);

        # CG-level rollback only for an actual member: triggered from a
        # non-member disk it would revert the OTHER disks instead of this one
        my $cg = _get_cg_for_vm($api, $vmid, $prefix);
        if (_cg_member($cg, $ontap_name)) {
            my $snap_obj = $api->get_cg_snapshot_detail(
                $cg->{uuid}, $snap_name,
            );
            if ($snap_obj) {
                _assert_cg_snapshot_restorable($cg, $snap_obj, $snap);
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
        die "snapshot '$snap' not found for '$name'"
            . " (neither CG-level nor per-volume)\n"
            if !$snap_obj;

        $api->restore_snapshot($vol_uuid, $snap_obj->{uuid});

        return undef;
    });
}

sub volume_snapshot_delete {
    my ($class, $scfg, $storeid, $volname, $snap, $running) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $snap_name = _snap_name($snap);

    return _cg_lock($scfg, $vmid, sub {
        # delete every same-named snapshot, CG-level and per-volume: a create
        # race can leave duplicates with one name, and the CG/per-volume
        # fallback can leave both kinds under one PVE snapshot name — leaving
        # any behind would make a later same-named create silently reuse a
        # stale point in time. Attempt all deletions before failing, so one
        # error does not strand the remaining copies.
        my @errors;

        my $cg = _get_cg_for_vm($api, $vmid, $prefix);
        if ($cg) {
            my $snaps = $api->list_cg_snapshots($cg->{uuid}, $snap_name) // [];
            for my $s (@$snaps) {
                eval { $api->delete_cg_snapshot($cg->{uuid}, $s->{uuid}); };
                push @errors, "cg: $@" if $@;
            }
        }

        my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
        if ($vol_uuid) {
            my $snaps = $api->list_snapshots($vol_uuid, $snap_name) // [];
            for my $s (@$snaps) {
                eval { $api->delete_snapshot($vol_uuid, $s->{uuid}); };
                push @errors, "volume: $@" if $@;
            }
        }

        die "failed to delete snapshot '$snap': " . join('; ', @errors)
            if @errors;

        return undef;
    });
}

sub volume_snapshot_info {
    my ($class, $scfg, $storeid, $volname) = @_;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $ontap_name = _pve_to_ontap($name, $prefix);

    # virtual size of the volume (APIVER 15); the namespace size is the
    # volume's virtual size for our raw block volumes
    my $ns = _find_ns_for_volume($api, $ontap_name);
    my $vsize = $ns ? ($ns->{space}{size} // 0) : 0;

    my %seen;
    my %result;
    my $snap_filter = "${SNAP_PREFIX}*";

    my $record = sub {
        my ($s) = @_;
        my $pve = _parse_snap_name($s->{name}) // return;
        return if $seen{$pve}++;
        $result{$pve} = {
            id             => $s->{uuid} // '',
            timestamp      => _snap_epoch($s->{create_time}),
            'virtual-size' => $vsize,
        };
    };

    # CG-level snapshots
    my $cg = _get_cg_for_vm($api, $vmid, $prefix);
    if ($cg) {
        $record->($_)
            for @{$api->list_cg_snapshots($cg->{uuid}, $snap_filter)};
    }

    # per-volume snapshots
    my $vol_uuid = _get_vol_uuid($api, $name, $prefix);
    if ($vol_uuid) {
        $record->($_)
            for @{$api->list_snapshots($vol_uuid, $snap_filter)};
    }

    return \%result;
}

# =====================================================================
# Infrastructure
# =====================================================================

sub check_connection {
    my ($class, $storeid, $scfg) = @_;

    my $mgmt_ip = $scfg->{mgmt_ip};
    return 0 if !$mgmt_ip;

    # probe the REST endpoint itself (unauthenticated, 5s cap): any real HTTP
    # answer proves the API service and its TLS are alive. A plain TCP probe
    # reports "connected" while the API service or certificate is broken.
    my $ok = eval {
        my $api = _api($scfg, $storeid);
        $api->probe();
    };
    return $ok ? 1 : 0 if !$@;

    # API client unbuildable (e.g. secret file not replicated yet): degrade to
    # the plain TCP probe rather than flagging the storage as disconnected
    $ok = eval {
        my $sock = IO::Socket::IP->new(
            PeerHost => $mgmt_ip,
            PeerPort => 443,
            Timeout  => 5,
            Type     => IO::Socket::IP::SOCK_STREAM(),
        );
        die "TCP connect failed\n" if !$sock;
        close($sock);
        1;
    };

    return $ok ? 1 : 0;
}

sub get_identity {
    my ($class, $scfg, $storeid) = @_;

    # the SVM UUID is a stable identifier of the backend, independent of how
    # this storage happens to be declared in storage.cfg
    my $api = _api($scfg, $storeid);

    return $api->get_svm_uuid();
}

# =====================================================================
# Templates and linked clones (ONTAP FlexClone)
# =====================================================================

sub create_base {
    my ($class, $storeid, $scfg, $volname) = @_;

    my ($vtype, $name, $vmid, undef, undef, $isBase) =
        $class->parse_volname($volname);

    die "create_base not possible with base image\n" if $isBase;
    die "create_base on wrong vtype '$vtype'\n" if $vtype ne 'images';
    die "can only create a base image from a regular disk ('$name')\n"
        if $name !~ m/^vm-[0-9]+-disk-[0-9]+$/;

    _debug($scfg, 1, "create_base($volname)");
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);

    my $src_vol = _pve_to_ontap($name, $prefix);
    (my $base_name = $name) =~ s/^vm-/base-/;
    my $base_vol = _pve_to_ontap($base_name, $prefix);

    my $vol_uuid = $api->get_volume_uuid($src_vol);
    die "volume '$src_vol' not found\n" if !$vol_uuid;
    die "base volume '$base_vol' already exists\n"
        if $api->get_volume_uuid($base_vol);

    # a template is no longer an active VM disk: detach it from the VM's
    # consistency group, then rename the FlexVol vm_* -> base_*. The contained
    # namespace path follows the rename and _find_ns_for_volume tolerates the
    # namespace keeping its original short name.
    delete $NS_CACHE{"$storeid/$src_vol"};
    _cg_lock(
        $scfg, $vmid,
        sub {
            _detach_from_cg($api, $vmid, $src_vol, $prefix);
            $api->set_volume_name($vol_uuid, $base_vol);
            _cleanup_cg_if_empty($api, $vmid, $prefix);
        },
    );

    # a template is immutable and belongs to no VM's CG: it carries no scheduled-
    # snapshot policy of its own (linked clones spawn from the base snapshot
    # below, not from a schedule). Clears a per-volume fallback policy a pre-9.12.1
    # disk may have kept so the template is not snapshotted on a stale schedule.
    eval { $api->set_volume_snapshot_policy($vol_uuid, 'none'); };
    warn "could not clear snapshot policy on base '$base_vol': $@\n" if $@;

    # create the snapshot that linked clones (FlexClone) spawn from. The volume
    # UUID is unchanged by the rename.
    eval { $api->create_snapshot($vol_uuid, $BASE_SNAP, "PVE base image"); };
    warn "could not create base snapshot on '$base_vol': $@\n" if $@;

    return $base_name;
}

sub clone_image {
    my ($class, $scfg, $storeid, $volname, $vmid, $snap) = @_;

    _debug($scfg, 1, "clone_image($volname -> vmid=$vmid)");

    # PVE invokes clone_image for a *linked* clone, always from a base image.
    my ($vtype, $name, undef, undef, undef, $isBase) =
        $class->parse_volname($volname);
    die "clone_image only works on base images (use full clone otherwise)\n"
        if !$isBase;

    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);
    my $base_pve = $name;                            # base-B-disk-J
    my $base_vol = _pve_to_ontap($base_pve, $prefix); # base_B_disk_J

    die "base volume '$base_vol' not found\n"
        if !$api->get_volume_uuid($base_vol);

    # destination (clone) volume name: next free disk on the target VM
    my $clone_pve = $class->find_free_diskname($storeid, $scfg, $vmid, 'raw');
    my $clone_vol = _pve_to_ontap($clone_pve, $prefix);

    # FlexClone the base from its base snapshot — instant and space-shared (a
    # true linked clone: no split, so it keeps sharing blocks with the base).
    # ONTAP clones the contained NVMe namespace as part of the volume.
    $api->clone_volume($clone_vol, $base_vol, (length($snap // '') ? $snap : $BASE_SNAP));
    _apply_snapshot_autodelete($api, $scfg, $clone_vol);

    eval {
        # locate the cloned namespace (name inherited from the base, so use the
        # tolerant per-volume lookup) and map it to the subsystem
        my $ns = _find_ns_for_volume($api, $clone_vol);
        die "cloned namespace not found in '$clone_vol'\n" if !$ns;

        my $subsys = $api->get_subsystem($scfg->{subsystem});
        die "subsystem '$scfg->{subsystem}' not found\n" if !$subsys;
        $api->map_namespace_to_subsystem($subsys->{uuid}, $ns->{uuid});

        _cg_lock(
            $scfg, $vmid,
            sub {
                _ensure_cg(
                    $api, $vmid, $clone_vol, $prefix,
                    $scfg->{snapshot_policy} || 'none',
                );
            },
        );
    };
    if (my $err = $@) {
        _teardown_volume($api, $clone_vol);
        die "clone of '$volname' failed: $err";
    }

    # the FlexClone inherits the base volume's schedule; reconcile it so the CG
    # owns the schedule (atomic) and the clone is not snapshotted twice
    _cg_lock(
        $scfg, $vmid,
        sub { _apply_snapshot_schedule($api, $scfg, $vmid, $clone_vol, $prefix) },
    );

    # make the new device visible on the fabric
    _nvme_rescan($scfg, $api, _connect_opts($storeid, $scfg));

    # PVE compound volname: <base>/<clone> so it tracks the backing base image
    return "$base_pve/$clone_pve";
}

sub rename_volume {
    my ($class, $scfg, $storeid, $source_volname, $target_vmid,
        $target_volname) = @_;

    _debug($scfg, 1, "rename_volume($source_volname -> vmid=$target_vmid)");

    my ($vtype, $source_name, $source_vmid) =
        $class->parse_volname($source_volname);
    my $api = _api($scfg, $storeid);
    my $prefix = _prefix($scfg);

    # allocate a free disk name on the target VM when none was requested
    if (!$target_volname) {
        $target_volname =
            $class->find_free_diskname($storeid, $scfg, $target_vmid, 'raw');
    }

    my $src_vol = _pve_to_ontap($source_name, $prefix);
    my $dst_vol = _pve_to_ontap($target_volname, $prefix);

    return "$storeid:$target_volname" if $src_vol eq $dst_vol;

    my $vol_uuid = $api->get_volume_uuid($src_vol);
    die "source volume '$src_vol' not found\n" if !$vol_uuid;
    die "target volume '$dst_vol' already exists\n"
        if $api->get_volume_uuid($dst_vol);

    my $moving = defined($target_vmid) && $target_vmid != $source_vmid;

    delete $NS_CACHE{"$storeid/$src_vol"};

    # detach from the source CG while the volume still carries its old name,
    # rename the FlexVol (the contained namespace path follows), then attach
    # to the target VM's CG
    my $do_rename = sub {
        _detach_from_cg($api, $source_vmid, $src_vol, $prefix) if $moving;

        $api->set_volume_name($vol_uuid, $dst_vol);

        if ($moving) {
            _ensure_cg(
                $api, $target_vmid, $dst_vol, $prefix,
                $scfg->{snapshot_policy} || 'none',
            );
            # the disk now belongs to the target VM's CG: hand its schedule to
            # that CG (clear the per-volume one) so snapshots stay atomic there
            _apply_snapshot_schedule(
                $api, $scfg, $target_vmid, $dst_vol, $prefix,
            );
            _cleanup_cg_if_empty($api, $source_vmid, $prefix);
        }
    };

    if ($moving) {
        # both VMs' CGs are mutated: take both locks, ordered by VMID so two
        # concurrent moves in opposite directions cannot deadlock
        my ($lo, $hi) = sort { $a <=> $b } ($source_vmid, $target_vmid);
        _cg_lock($scfg, $lo, sub { _cg_lock($scfg, $hi, $do_rename) });
    }
    else {
        $do_rename->();
    }

    return "$storeid:$target_volname";
}

sub volume_has_feature {
    my ($class, $scfg, $feature, $storeid, $volname, $snapname,
        $running, $opts) = @_;

    # 'template' converts a disk into a base image; 'clone' (from a base image)
    # is served by clone_image as an instant ONTAP FlexClone (space-shared
    # linked clone). 'copy' (full, independent clone) is handled by PVE itself
    # via qemu-img. Keys: 'base' for base images, 'snap' for snapshots,
    # otherwise 'current'.
    my $features = {
        clone      => { base => 1, snap => 1 },
        template   => { current => 1 },
        copy       => { base => 1, current => 1, snap => 1 },
        snapshot   => { current => 1, snap => 1 },
        sparseinit => { base => 1, current => 1 },
        rename     => { current => 1 },
    };

    my $isBase = ($class->parse_volname($volname))[5];
    my $key = $snapname ? 'snap' : ($isBase ? 'base' : 'current');

    return 1 if $features->{$feature} && $features->{$feature}{$key};
    return undef;
}

# =====================================================================
# Copy-less disk handoff between two storages of this plugin (same SVM)
# =====================================================================
# Not part of the PVE storage API — driven by the ontapnvme-move helper.
#
# Renames the FlexVol from the source storage's prefix to the target's,
# moves CG membership, reapplies the target's snapshot/QoS/autodelete
# settings, and optionally starts the ONTAP volume move to the target
# aggregate. Snapshots, FlexClone lineage and the namespace UUID (and
# with it the host device) are preserved — nothing is copied. Rewriting
# the VM config is the caller's job. Idempotent: re-running after an
# interruption resumes where it stopped (the rename is the only
# state-changing step; everything after re-applies cleanly).
sub ontap_handoff_volume {
    my ($class, $src_storeid, $src_scfg, $dst_storeid, $dst_scfg, $volname,
        $relocate)
        = @_;

    my ($vtype, $name, $vmid, $basename, undef, $isBase) =
        $class->parse_volname($volname);
    die "only regular VM disks can be handed off — base images and linked"
        . " clones must stay with their prefix family\n"
        if $isBase || $basename;

    my $src_api = _api($src_scfg, $src_storeid);
    my $dst_api = _api($dst_scfg, $dst_storeid);
    die "storages '$src_storeid' and '$dst_storeid' target different SVMs —"
        . " a copy-less handoff is only possible within one SVM\n"
        if $src_api->get_svm_uuid() ne $dst_api->get_svm_uuid();

    my ($sp, $dp) = (_prefix($src_scfg), _prefix($dst_scfg));
    die "both storages use the same storage_prefix ('$sp') — they already"
        . " share their volumes, nothing to hand off\n"
        if $sp eq $dp;

    my $src_vol = _pve_to_ontap($name, $sp);
    my $dst_vol = _pve_to_ontap($name, $dp);
    my $api = $src_api; # same SVM: one client serves both sides

    # the lock key is SVM+VMID, so source and target storages contend the
    # same lock — the whole handoff is one critical section cluster-wide
    return _cg_lock($src_scfg, $vmid, sub {
        my $src_uuid = $api->get_volume_uuid($src_vol);
        my $dst_uuid = $api->get_volume_uuid($dst_vol);
        die "both '$src_vol' and '$dst_vol' exist on the SVM — resolve the"
            . " collision manually before retrying\n"
            if $src_uuid && $dst_uuid;
        die "volume '$src_vol' not found (and no '$dst_vol' to resume)\n"
            if !$src_uuid && !$dst_uuid;

        if ($src_uuid) {
            _detach_from_cg($api, $vmid, $src_vol, $sp);
            $api->set_volume_name($src_uuid, $dst_vol);
            _cleanup_cg_if_empty($api, $vmid, $sp);
            $dst_uuid = $src_uuid;
        }
        delete $NS_CACHE{"$src_storeid/$src_vol"};

        _ensure_cg(
            $api, $vmid, $dst_vol, $dp,
            $dst_scfg->{snapshot_policy} || 'none',
        );
        _apply_snapshot_schedule($api, $dst_scfg, $vmid, $dst_vol, $dp);
        _apply_snapshot_autodelete($api, $dst_scfg, $dst_vol);
        if (my $qos =
            $dst_scfg->{qos_policy} || $dst_scfg->{adaptive_qos_policy}) {
            eval { $api->set_volume_qos_policy($dst_uuid, $qos); };
            warn "could not apply QoS policy '$qos' on '$dst_vol': $@\n"
                if $@;
        }

        my $relocating = 0;
        if ($relocate) {
            my $job = eval {
                $api->move_volume_aggregate(
                    $dst_uuid, $dst_scfg->{aggregate},
                );
            };
            if ($@) {
                warn "volume move could not be started — the disk now belongs"
                    . " to '$dst_storeid' but its data remains on the source"
                    . " aggregate: $@\n";
            }
            elsif ($job) {
                # catch an early authorization failure (SVM-scoped accounts
                # cannot move volumes); a healthy move continues in background
                sleep 2;
                my $j = eval { $api->get_job($job) } // {};
                if (($j->{state} // '') eq 'failure') {
                    warn "volume move failed ("
                        . ($j->{message} // 'unknown error')
                        . ") — the disk now belongs to '$dst_storeid' but its"
                        . " data remains on the source aggregate;"
                        . " cluster-scoped credentials are required to"
                        . " relocate it\n";
                }
                else {
                    $relocating = 1;
                }
            }
        }

        return {
            volname      => $name,
            ontap_volume => $dst_vol,
            relocating   => $relocating,
        };
    });
}

# =====================================================================
# QEMU integration (APIVER 12+)
# =====================================================================

sub qemu_blockdev_options {
    my ($class, $scfg, $storeid, $volname, $machine_version, $options) = @_;

    # ONTAP namespaces are plain local block devices: return backend access
    # only. qemu-server adds discard, detect-zeroes, cache and aio from the VM
    # disk configuration. For ONTAP thin reclaim, set discard=on,ssd=1 on each
    # VM disk.
    $options //= {};
    my $snapname = $options->{'snapshot-name'};

    return {
        driver   => 'host_device',
        filename => scalar $class->path(
            $scfg, $volname, $storeid, $snapname,
        ),
    };
}

sub volume_qemu_snapshot_method {
    my ($class, $storeid, $scfg, $volname) = @_;

    # ONTAP performs the snapshot transparently (CG/per-volume), so a running
    # VM does not need to do anything.
    return 'storage';
}

sub get_formats {
    my ($class, $scfg, $storeid) = @_;
    return {
        valid   => { raw => 1 },
        default => 'raw',
    };
}

1;
