package PVE::Storage::OntapNvmeTcp::Api;

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

use HTTP::Request;
use JSON;
use LWP::UserAgent;
use MIME::Base64;
use URI::Escape;

# ONTAP REST API client for NVMe/TCP storage plugin.
# Manages volumes, namespaces, subsystems, consistency groups,
# and snapshots via the ONTAP REST API (9.10.1+) over HTTPS.

my $DEFAULT_TIMEOUT = 30;
my $JOB_POLL_MAX = 120;

sub new {
    my ($class, %opts) = @_;

    for my $key (qw(mgmt_ip username password vserver)) {
        die "$key required\n"
            if !defined($opts{$key}) || $opts{$key} eq '';
    }

    my $self = {
        mgmt_ip    => $opts{mgmt_ip},
        username   => $opts{username},
        password   => $opts{password},
        vserver    => $opts{vserver},
        verify_ssl => ($opts{verify_ssl} // 1) ? 1 : 0,
        svm_scoped => $opts{svm_scoped} ? 1 : 0,
    };

    # max_redirect => 0: the ONTAP REST API never legitimately redirects, and
    # following a 3xx would let LWP resend the HTTP Basic credential to another
    # host (CVE-2026-8368, libwww-perl < 6.83). Treat any redirect as an error.
    # verify_hostname and SSL_verify_mode are driven by the same flag so they
    # cannot drift (CVE-2014-3230 class); verification is ON unless explicitly
    # disabled. For a private-CA ONTAP certificate, add the CA to the node's
    # trust store (update-ca-certificates) rather than setting verify_ssl 0.
    $self->{ua} = LWP::UserAgent->new(
        timeout      => $DEFAULT_TIMEOUT,
        max_redirect => 0,
        ssl_opts => {
            verify_hostname => $self->{verify_ssl},
            SSL_verify_mode => $self->{verify_ssl} ? 1 : 0,
        },
    );

    # bracket an IPv6 literal so the URL is well-formed (https://[::1]/api);
    # IPv4 and hostnames are left as-is
    my $host = $self->{mgmt_ip};
    $host = "[$host]" if $host =~ /:/ && $host !~ /\A\[/;
    $self->{base_url} = "https://$host/api";
    $self->{auth_header} = "Basic "
        . encode_base64(
            "$self->{username}:$self->{password}", "",
        );

    return bless $self, $class;
}

sub is_svm_scoped { return $_[0]->{svm_scoped}; }

# -- REST helpers ------------------------------------------------------

sub _request {
    my ($self, $method, $path, $body, $opts) = @_;

    # Ask ONTAP to finish async operations inline (120s = the max) instead of
    # returning a job to poll. This avoids the cluster-scoped /cluster/jobs
    # endpoint in the common case — which is what lets an SVM-scoped account
    # work — and saves a round-trip for everyone.
    if ($method ne 'GET') {
        my $sep = $path =~ /\?/ ? '&' : '?';
        $path .= "${sep}return_timeout=120";
    }

    # defence in depth: a path segment built from an ONTAP-supplied UUID or a
    # followed _links.next must never inject path traversal or control chars.
    # The host is already pinned to mgmt_ip; this guards the path itself.
    my $pathonly = $path;
    $pathonly =~ s/\?.*//s;
    die "refusing unsafe ONTAP API path\n"
        if $pathonly =~ m{\.\.} || $path =~ /[\x00-\x1f]/;

    my $url = "$self->{base_url}$path";
    my $req = HTTP::Request->new($method, $url);
    $req->header('Authorization' => $self->{auth_header});
    $req->header('Accept'        => 'application/json');
    $req->header('Content-Type'  => 'application/json');
    $req->content(encode_json($body)) if $body;

    my $resp = $self->{ua}->request($req);
    my $code = $resp->code;
    my $content = $resp->decoded_content // '';

    # LWP reports connect/TLS failures as a synthesized 5xx carrying the
    # Client-Warning header. Name the real problem — API unreachable or
    # certificate verification failing — instead of a generic ONTAP error, so
    # an expired certificate does not masquerade as a storage outage.
    if (($resp->header('Client-Warning') // '') eq 'Internal response') {
        my $reason = $content || $resp->status_line;
        $reason =~ s/\s+/ /g;
        my $hint = $reason =~ /certificate|\bssl\b|handshake/i
            ? ' (TLS verification failed: check the ONTAP certificate'
                . ' expiry/CA or the node trust store)'
            : '';
        die "cannot reach ONTAP API at https://$self->{mgmt_ip}:"
            . " ${reason}${hint}\n";
    }

    my $data = {};
    if ($content && $content =~ /^\s*[\{\[]/) {
        eval { $data = decode_json($content); };
        die "ONTAP API JSON parse error: $@\n" if $@;
    }

    die "ONTAP authentication failed for '$self->{username}'"
        . " at https://$self->{mgmt_ip}\n"
        if $code == 401;

    if ($code >= 400) {
        my $msg = "ONTAP API error ($code)";
        if ($data->{error}) {
            $msg .= ": $data->{error}{message}";
            $msg .= " (code $data->{error}{code})"
                if $data->{error}{code};
        }
        elsif ($content) {
            $msg .= ": " . substr($content, 0, 200);
        }
        die "$msg\n";
    }

    # async jobs return 202 Accepted
    if ($code == 202 && $data->{job}) {
        # some operations legitimately outlive any polling budget (volume
        # move): let the caller keep the job reference instead of following it
        return $data if $opts->{no_job_follow};
        if ($self->{svm_scoped}) {
            # an SVM-scoped account cannot read the cluster-scoped
            # /cluster/jobs endpoint; the operation exceeded return_timeout but
            # is still running. Proceed best-effort — callers re-verify the
            # resulting object (namespace/volume lookups).
            warn "ONTAP async job exceeded 120s and cannot be tracked with an"
                . " SVM-scoped account; assuming it is still in progress\n";
            return $data;
        }
        return $self->_wait_for_job($data->{job}{uuid});
    }

    return $data;
}

sub _wait_for_job {
    my ($self, $job_uuid) = @_;

    for (my $i = 0; $i < $JOB_POLL_MAX; $i++) {
        my $job = $self->_request('GET', "/cluster/jobs/$job_uuid");
        my $state = $job->{state} // '';

        return $job if $state eq 'success';

        if ($state eq 'failure' || $state eq 'error') {
            my $errmsg = $job->{message} // 'unknown error';
            die "ONTAP job $job_uuid failed: $errmsg\n";
        }

        sleep 1;
    }

    die "ONTAP job $job_uuid timed out after $JOB_POLL_MAX s\n";
}

sub _get    { return shift->_request('GET', @_); }
sub _post   { return shift->_request('POST', @_); }
sub _patch  { return shift->_request('PATCH', @_); }
sub _delete { return shift->_request('DELETE', @_); }

# helper: extract first record from a list query
sub _first_record {
    my ($self, $path) = @_;

    my $resp = $self->_get($path);
    my $records = $resp->{records} // [];

    return @$records ? $records->[0] : undef;
}

# helper: collect all records across paginated responses
sub _get_all_records {
    my ($self, $path) = @_;

    my @all;
    my $url = $path;

    while ($url) {
        my $resp = $self->_get($url);
        push @all, @{$resp->{records} // []};

        my $next = $resp->{_links}{next}{href} // '';
        if ($next) {
            # ONTAP returns absolute path starting with /api
            $next =~ s|^/api||;
            $url = $next;
        }
        else {
            $url = undef;
        }
    }

    return \@all;
}

# Run $code with a temporarily lowered HTTP timeout (seconds). Used on the
# pvestatd polling paths (status, check_connection) so a hung ONTAP API
# degrades one storage's poll instead of stalling the daemon for the full
# default timeout. LWP's timeout setter returns the previous value.
sub with_timeout {
    my ($self, $timeout, $code) = @_;

    my $old = $self->{ua}->timeout($timeout);
    my @res = eval { $code->() };
    my $err = $@;
    $self->{ua}->timeout($old);
    die $err if $err;

    return wantarray ? @res : $res[0];
}

# Lightweight reachability probe of the REST endpoint itself: any real HTTP
# answer (even 401/403 — no credentials are sent) proves the API service and
# its TLS are alive; an LWP-internal error (connection refused, timeout, TLS
# verification failure) means it is not. A plain TCP probe cannot tell these
# apart.
sub probe {
    my ($self) = @_;

    my $alive = 0;
    eval {
        $self->with_timeout(
            5,
            sub {
                my $req = HTTP::Request->new('GET', $self->{base_url});
                my $resp = $self->{ua}->request($req);
                $alive = 1
                    if ($resp->header('Client-Warning') // '')
                    ne 'Internal response';
            },
        );
    };

    return $alive;
}

# -- SVM ---------------------------------------------------------------

sub get_svm_uuid {
    my ($self) = @_;

    return $self->{_svm_uuid} if $self->{_svm_uuid};

    my $name = uri_escape($self->{vserver});
    my $svm = $self->_first_record(
        "/svm/svms?name=$name&fields=uuid",
    );
    die "SVM '$self->{vserver}' not found\n" if !$svm;

    $self->{_svm_uuid} = $svm->{uuid};

    return $self->{_svm_uuid};
}

# -- volume operations -------------------------------------------------

sub get_volume_uuid {
    my ($self, $vol_name) = @_;

    my $svm = uri_escape($self->{vserver});
    my $name = uri_escape($vol_name);
    my $vol = $self->_first_record(
        "/storage/volumes?name=$name"
            . "&svm.name=$svm&fields=uuid",
    );

    return $vol ? $vol->{uuid} : undef;
}

# Look up a volume's UUID and its current snapshot policy name in one call, so a
# caller reconciling the schedule can skip the PATCH when it is already correct.
# Returns { uuid, name } or undef when the volume does not exist.
sub get_volume_snapshot_policy {
    my ($self, $vol_name) = @_;

    my $svm = uri_escape($self->{vserver});
    my $name = uri_escape($vol_name);
    my $vol = $self->_first_record(
        "/storage/volumes?name=$name"
            . "&svm.name=$svm&fields=uuid,snapshot_policy.name",
    );
    return undef if !$vol;

    return {
        uuid => $vol->{uuid},
        name => $vol->{snapshot_policy}{name} // '',
    };
}

# List volumes (optionally by name pattern) with their creation time and
# state, used by the stranded-object sweep to skip allocations that may still
# be in flight and volumes parked offline (e.g. in the recovery queue).
sub list_volumes_create_time {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $q = "/storage/volumes?svm.name=$svm"
        . "&fields=uuid,name,create_time,state";
    $q .= "&name=" . uri_escape($pattern) if $pattern;

    return $self->_get_all_records($q);
}

# List volumes (optionally by name pattern) with their used space and autosize
# ceiling, used to warn before a volume fills up and ONTAP takes its namespace
# offline.
sub list_volume_autosize {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $q = "/storage/volumes?svm.name=$svm"
        . "&fields=name,space.used,autosize.maximum";
    $q .= "&name=" . uri_escape($pattern) if $pattern;

    return $self->_get_all_records($q);
}

# List volumes (optionally by name pattern) with their UUID and snapshot policy
# name. Used to reconcile per-volume schedules when the storage policy changes.
sub list_volume_snapshot_policies {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $q = "/storage/volumes?svm.name=$svm"
        . "&fields=uuid,name,snapshot_policy.name";
    $q .= "&name=" . uri_escape($pattern) if $pattern;

    return $self->_get_all_records($q);
}

sub create_volume {
    my ($self, $vol_name, $size_bytes, %opts) = @_;

    my $snap_policy = $opts{snapshot_policy} // 'none';
    my $reserve = $opts{space_reserve} // 'none';

    my $body = {
        name            => $vol_name,
        svm             => { name => $self->{vserver} },
        size            => int($size_bytes),
        guarantee       => { type => $reserve },
        snapshot_policy => { name => $snap_policy },
    };

    # snapshot reserve. A scheduled snapshot policy lives on the consistency
    # group, not on the member volume, so the volume's own policy can be 'none'
    # while snapshots still land on it — size the reserve from schedule_active
    # (whether any schedule is configured) rather than from this volume's own
    # policy. Falls back to the volume policy when the caller does not say.
    my $schedule_active =
        defined($opts{schedule_active})
        ? $opts{schedule_active}
        : ($snap_policy ne 'none');
    my $snap_pct = defined($opts{snapshot_reserve})
        ? int($opts{snapshot_reserve})
        : ($schedule_active ? 5 : 0);
    $body->{space} = {
        snapshot => { reserve_percent => $snap_pct },
    };

    if ($opts{aggregate}) {
        $body->{aggregates} = [{ name => $opts{aggregate} }];
    }

    # encryption (opt-in): only act when explicitly configured.
    #   unset -> inherit the ONTAP/aggregate default (send nothing), so volume
    #            creation never fails on clusters without a configured key
    #            manager; false -> explicitly disable; true -> rely on NAE
    #            (aggregate-level) when present, otherwise request NVE.
    if (defined($opts{encryption})) {
        if (!$opts{encryption}) {
            $body->{encryption} = { enabled => JSON::false };
        }
        else {
            my $nae = eval {
                $self->_is_aggregate_nae($opts{aggregate});
            } // 0;
            $body->{encryption} = { enabled => JSON::true } if !$nae;
        }
    }

    # QoS (mutually exclusive)
    if ($opts{qos_policy}) {
        $body->{qos} = {
            policy => { name => $opts{qos_policy} },
        };
    }
    elsif ($opts{adaptive_qos_policy}) {
        $body->{qos} = {
            policy => { name => $opts{adaptive_qos_policy} },
        };
    }

    # FabricPool tiering
    if ($opts{tiering_policy}) {
        $body->{tiering} = { policy => $opts{tiering_policy} };
    }

    # autosize: let the FlexVol grow to absorb snapshot/overwrite space so the
    # thin namespace it hosts never goes offline on a full container. The
    # namespace itself is fixed-size; this only enlarges its container.
    if ($opts{autosize}) {
        my $max_pct = int($opts{autosize_max_percent} || 300);
        $max_pct = 105 if $max_pct < 105;
        $body->{autosize} = {
            mode    => 'grow',
            maximum => int($size_bytes * $max_pct / 100),
        };
    }

    return $self->_post("/storage/volumes", $body);
}

# Adjust a volume's autosize ceiling (used after a resize so the grow limit
# keeps tracking the new size).
sub set_volume_autosize {
    my ($self, $vol_uuid, $max_bytes) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { autosize => { mode => 'grow', maximum => int($max_bytes) } },
    );
}

# Configure ONTAP snapshot autodelete on a FlexVol (PATCH-only — ONTAP rejects
# these fields at volume creation, error 262196). When the volume nears full,
# ONTAP deletes the oldest snapshots first; snapshots whose name starts with
# $defer_prefix are deferred to last resort. Autosize growth remains the first
# response — autodelete engages when growing no longer suffices.
sub set_volume_snapshot_autodelete {
    my ($self, $vol_uuid, $enabled, $defer_prefix) = @_;

    my $autodelete =
        $enabled
        ? {
            enabled           => JSON::true,
            trigger           => 'volume',
            delete_order      => 'oldest_first',
            defer_delete      => 'prefix',
            prefix            => $defer_prefix,
            commitment        => 'try',
            target_free_space => 20,
        }
        : { enabled => JSON::false };

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { space => { snapshot => { autodelete => $autodelete } } },
    );
}

# Set a FlexVol's own scheduled-snapshot policy. Used to clear a member
# volume's schedule ('none') once the consistency group carries it, or to set a
# per-volume schedule as a fallback for a disk that could not join the CG.
sub set_volume_snapshot_policy {
    my ($self, $vol_uuid, $policy) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { snapshot_policy => { name => $policy } },
    );
}

# Rename a FlexVol. The contained namespace path follows the new volume name.
sub set_volume_name {
    my ($self, $vol_uuid, $new_name) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { name => $new_name },
    );
}

sub delete_volume {
    my ($self, $vol_uuid, $force) = @_;

    eval {
        $self->_patch(
            "/storage/volumes/$vol_uuid",
            { state => "offline" },
        );
    };

    # Without $force the volume is parked in the ONTAP volume recovery queue
    # (recoverable by the cluster admin for the retention period) — the safe
    # default for disks that held real data. With $force it is removed
    # immediately and permanently; callers use that for rollback of half-
    # provisioned volumes, or when the storage sets force_delete (a parked
    # FlexClone pins its base image until purged, which blocks template
    # deletion for SVM-scoped accounts).
    my $q = $force ? '?force=true' : '';
    my $res = eval { $self->_delete("/storage/volumes/$vol_uuid$q"); };
    if (my $err = $@) {
        # never leave the volume stranded offline on a failed delete
        eval {
            $self->_patch(
                "/storage/volumes/$vol_uuid",
                { state => "online" },
            );
        };
        die $err;
    }

    return $res;
}

sub resize_volume {
    my ($self, $vol_uuid, $new_size) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { size => int($new_size) },
    );
}

# Read one job's state. Works for the caller's own jobs even on SVM-scoped
# accounts (verified live: vsadmin can read the job it just created, while the
# /cluster/jobs collection stays forbidden).
sub get_job {
    my ($self, $job_uuid) = @_;

    return $self->_get("/cluster/jobs/$job_uuid");
}

# Start relocating a FlexVol to another aggregate (ONTAP volume move) and
# return the job uuid. Non-disruptive and potentially hours-long, so the job
# is not followed — callers poll get_job() briefly to catch an early
# authorization failure (SVM-scoped accounts cannot move volumes).
sub move_volume_aggregate {
    my ($self, $vol_uuid, $aggr_name) = @_;

    my $res = $self->_request(
        'PATCH',
        "/storage/volumes/$vol_uuid",
        { movement => { destination_aggregate => { name => $aggr_name } } },
        { no_job_follow => 1 },
    );

    return $res->{job}{uuid};
}

# Apply a QoS policy group to a FlexVol (used when a disk is handed off to a
# storage configured with a different QoS class).
sub set_volume_qos_policy {
    my ($self, $vol_uuid, $policy) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { qos => { policy => { name => $policy } } },
    );
}

# Bring a FlexVol back online (e.g. after ONTAP offlined it on a full volume/
# aggregate and the operator has freed space). The contained namespace becomes
# reachable again once its volume is online.
sub set_volume_online {
    my ($self, $vol_uuid) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { state => "online" },
    );
}

# Create a FlexClone of $src_vol named $new_vol. The clone shares blocks with
# the parent until split. If $snapshot is given the clone is based on it,
# otherwise ONTAP creates a base snapshot automatically.
sub clone_volume {
    my ($self, $new_vol, $src_vol, $snapshot) = @_;

    my $clone = {
        parent_volume => { name => $src_vol },
        is_flexclone  => JSON::true,
    };
    $clone->{parent_snapshot} = { name => $snapshot } if $snapshot;

    return $self->_post(
        "/storage/volumes",
        {
            name  => $new_vol,
            svm   => { name => $self->{vserver} },
            clone => $clone,
        },
    );
}

# Start splitting a FlexClone from its parent so it becomes an independent
# volume. The split runs in the background on the controller.
sub split_volume_clone {
    my ($self, $vol_uuid) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { clone => { split_initiated => JSON::true } },
    );
}

# List volumes (optionally by name pattern) with their FlexClone parent volume,
# used to reconstruct PVE compound volnames for linked clones.
sub list_volume_clone_parents {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $q = "/storage/volumes?svm.name=$svm"
        . "&fields=name,clone.parent_volume.name";
    $q .= "&name=" . uri_escape($pattern) if $pattern;

    return $self->_get_all_records($q);
}

# -- NVMe namespace operations -----------------------------------------

sub create_namespace {
    my ($self, $vol_name, $ns_name, $size_bytes, $os_type) = @_;

    $os_type //= 'linux';

    return $self->_post(
        "/storage/namespaces?return_records=true",
        {
            svm     => { name => $self->{vserver} },
            name    => "/vol/$vol_name/$ns_name",
            os_type => $os_type,
            space   => {
                block_size => 4096,
                size       => int($size_bytes),
            },
        },
    );
}

sub delete_namespace {
    my ($self, $ns_uuid) = @_;

    return $self->_delete("/storage/namespaces/$ns_uuid");
}

sub get_namespace_by_name {
    my ($self, $ns_path) = @_;

    my $encoded = uri_escape($ns_path);
    my $svm = uri_escape($self->{vserver});

    return $self->_first_record(
        "/storage/namespaces?name=$encoded&svm.name=$svm"
            . "&fields=uuid,name,space,status,location",
    );
}

sub list_namespaces {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $query = "/storage/namespaces?svm.name=$svm"
        . "&fields=uuid,name,space,status,location";
    $query .= "&name=" . uri_escape($pattern) if $pattern;

    return $self->_get_all_records($query);
}

sub resize_namespace {
    my ($self, $ns_uuid, $new_size) = @_;

    return $self->_patch(
        "/storage/namespaces/$ns_uuid",
        { space => { size => int($new_size) } },
    );
}

# -- NVMe subsystem operations -----------------------------------------

sub get_subsystem {
    my ($self, $name) = @_;

    my $svm = uri_escape($self->{vserver});
    my $esc_name = uri_escape($name);

    return $self->_first_record(
        "/protocols/nvme/subsystems"
            . "?name=$esc_name&svm.name=$svm&fields=uuid,name,target_nqn",
    );
}

sub create_subsystem {
    my ($self, $name, $os_type) = @_;

    $os_type //= 'linux';

    return $self->_post(
        "/protocols/nvme/subsystems",
        {
            svm     => { name => $self->{vserver} },
            name    => $name,
            os_type => $os_type,
        },
    );
}

sub get_subsystem_host {
    my ($self, $subsys_uuid, $hostnqn) = @_;

    my $esc = uri_escape($hostnqn);
    return $self->_first_record(
        "/protocols/nvme/subsystems/$subsys_uuid/hosts"
            . "?nqn=$esc&fields=nqn,dh_hmac_chap.mode,tls.key_type",
    );
}

sub remove_host_from_subsystem {
    my ($self, $subsys_uuid, $hostnqn) = @_;

    my $esc = uri_escape($hostnqn);
    return $self->_delete(
        "/protocols/nvme/subsystems/$subsys_uuid/hosts/$esc",
    );
}

sub add_host_to_subsystem {
    my ($self, $subsys_uuid, $hostnqn, $auth) = @_;

    my $host = { nqn => $hostnqn };
    if ($auth && $auth->{dhchap_secret}) {
        # NVMe in-band authentication (DH-HMAC-CHAP); hash_function and
        # group_size default to sha_256 / 2048_bit on the ONTAP side
        $host->{dh_hmac_chap} = { host_secret_key => $auth->{dhchap_secret} };
        $host->{dh_hmac_chap}{controller_secret_key} = $auth->{dhchap_ctrl}
            if $auth->{dhchap_ctrl};
    }
    if ($auth && $auth->{tls_psk}) {
        # NVMe/TCP-TLS: configure the pre-shared key on the host entry
        $host->{tls} = {
            key_type       => 'configured',
            configured_psk => $auth->{tls_psk},
        };
    }

    eval {
        $self->_post(
            "/protocols/nvme/subsystems/$subsys_uuid/hosts", $host,
        );
    };
    if (my $err = $@) {
        return if $err =~ /already exists|duplicate/i;
        die $err;
    }
}

sub map_namespace_to_subsystem {
    my ($self, $subsys_uuid, $ns_uuid) = @_;

    return $self->_post(
        "/protocols/nvme/subsystem-maps",
        {
            svm       => { name => $self->{vserver} },
            subsystem => { uuid => $subsys_uuid },
            namespace => { uuid => $ns_uuid },
        },
    );
}

sub unmap_namespace_from_subsystem {
    my ($self, $subsys_uuid, $ns_uuid) = @_;

    eval {
        $self->_delete(
            "/protocols/nvme/subsystem-maps"
                . "/$subsys_uuid/$ns_uuid",
        );
    };
    return if $@ && $@ =~ /not found|not exist/i;
    die $@ if $@;
}

sub get_namespace_subsystem_map {
    my ($self, $ns_uuid) = @_;

    my $svm = uri_escape($self->{vserver});
    my $path = "/protocols/nvme/subsystem-maps"
        . "?namespace.uuid=$ns_uuid"
        . "&svm.name=$svm&fields=subsystem,namespace";

    return $self->_get_all_records($path);
}

# -- consistency group operations --------------------------------------

sub get_consistency_group {
    my ($self, $cg_name) = @_;

    my $svm = uri_escape($self->{vserver});
    my $name = uri_escape($cg_name);

    return $self->_first_record(
        "/application/consistency-groups"
            . "?svm.name=$svm&name=$name"
            . "&fields=uuid,name,volumes,snapshot_policy",
    );
}

# List consistency groups (optionally by name pattern) with their UUID, member
# volumes and snapshot policy. Used to reconcile CG schedules on a policy change.
sub list_consistency_groups {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $q = "/application/consistency-groups?svm.name=$svm"
        . "&fields=uuid,name,volumes,snapshot_policy";
    $q .= "&name=" . uri_escape($pattern) if $pattern;

    return $self->_get_all_records($q);
}

sub create_consistency_group {
    my ($self, $cg_name, $volume_names, $snap_policy) = @_;

    my @volumes = map {
        { name => $_, provisioning_options => { action => "add" } }
    } @{$volume_names // []};

    my $body = {
        svm  => { name => $self->{vserver} },
        name => $cg_name,
    };
    $body->{volumes} = \@volumes if @volumes;

    # Scheduled snapshots are taken at the CG level so they are atomic across
    # all member volumes (ONTAP fences I/O across the CG). The member FlexVols
    # therefore carry no schedule of their own. 'none' is a valid built-in
    # policy and is sent explicitly so the CG never inherits an unexpected
    # scheduled policy from the SVM default.
    $body->{snapshot_policy} = { name => $snap_policy }
        if defined($snap_policy);

    return $self->_post(
        "/application/consistency-groups?return_records=true",
        $body,
    );
}

# Set (or change) the consistency group's scheduled-snapshot policy. Scheduled
# CG snapshots are atomic across all member volumes, unlike independent
# per-volume snapshot policies. Used to keep the CG in sync with the storage
# config and to upgrade a CG created before a policy was set on it.
sub set_consistency_group_snapshot_policy {
    my ($self, $cg_uuid, $policy) = @_;

    return $self->_patch(
        "/application/consistency-groups/$cg_uuid",
        { snapshot_policy => { name => $policy } },
    );
}

sub add_volume_to_consistency_group {
    my ($self, $cg_uuid, $vol_name) = @_;

    return $self->_patch(
        "/application/consistency-groups/$cg_uuid",
        {
            volumes => [{
                name                 => $vol_name,
                provisioning_options => { action => "add" },
            }],
        },
    );
}

# Dissociate a volume from a consistency group (does not delete the volume).
# Requires ONTAP 9.12.1+ (CG membership PATCH). Mirror of the add operation.
sub remove_volume_from_consistency_group {
    my ($self, $cg_uuid, $vol_name) = @_;

    return $self->_patch(
        "/application/consistency-groups/$cg_uuid",
        {
            volumes => [{
                name                 => $vol_name,
                provisioning_options => { action => "remove" },
            }],
        },
    );
}

sub delete_consistency_group {
    my ($self, $cg_uuid) = @_;

    return $self->_delete(
        "/application/consistency-groups/$cg_uuid",
    );
}

# -- CG snapshot operations --------------------------------------------

sub create_cg_snapshot {
    my ($self, $cg_uuid, $snap_name, $comment) = @_;

    my $body = { name => $snap_name };
    $body->{comment} = $comment if $comment;

    return $self->_post(
        "/application/consistency-groups/$cg_uuid/snapshots",
        $body,
    );
}

sub list_cg_snapshots {
    my ($self, $cg_uuid, $filter) = @_;

    my $q = "/application/consistency-groups/$cg_uuid"
        . "/snapshots?fields=uuid,name,create_time,comment";
    $q .= "&name=" . uri_escape($filter) if $filter;

    return $self->_get_all_records($q);
}

sub get_cg_snapshot_by_name {
    my ($self, $cg_uuid, $snap_name) = @_;

    my $snaps = $self->list_cg_snapshots($cg_uuid, $snap_name);

    return @$snaps ? $snaps->[0] : undef;
}

# Fetch one CG snapshot by name including its member-volume set and partial
# flag — used to validate that a restore still matches the CG's current
# membership before reverting anything.
sub get_cg_snapshot_detail {
    my ($self, $cg_uuid, $snap_name) = @_;

    my $name = uri_escape($snap_name);

    return $self->_first_record(
        "/application/consistency-groups/$cg_uuid/snapshots"
            . "?name=$name&fields=uuid,name,create_time,is_partial,"
            . "snapshot_volumes.volume.name",
    );
}

sub delete_cg_snapshot {
    my ($self, $cg_uuid, $snap_uuid) = @_;

    return $self->_delete(
        "/application/consistency-groups/$cg_uuid"
            . "/snapshots/$snap_uuid",
    );
}

sub restore_cg_snapshot {
    my ($self, $cg_uuid, $snap_uuid) = @_;

    return $self->_patch(
        "/application/consistency-groups/$cg_uuid",
        { restore_to => { snapshot => { uuid => $snap_uuid } } },
    );
}

# -- volume-level snapshot operations ----------------------------------

sub create_snapshot {
    my ($self, $vol_uuid, $snap_name, $comment) = @_;

    my $body = { name => $snap_name };
    $body->{comment} = $comment if $comment;

    return $self->_post(
        "/storage/volumes/$vol_uuid/snapshots", $body,
    );
}

sub delete_snapshot {
    my ($self, $vol_uuid, $snap_uuid) = @_;

    return $self->_delete(
        "/storage/volumes/$vol_uuid/snapshots/$snap_uuid",
    );
}

sub list_snapshots {
    my ($self, $vol_uuid, $filter) = @_;

    my $q = "/storage/volumes/$vol_uuid/snapshots"
        . "?fields=name,create_time,comment";
    $q .= "&name=" . uri_escape($filter) if $filter;

    return $self->_get_all_records($q);
}

sub get_snapshot_by_name {
    my ($self, $vol_uuid, $snap_name) = @_;

    my $snaps = $self->list_snapshots($vol_uuid, $snap_name);

    return @$snaps ? $snaps->[0] : undef;
}

sub restore_snapshot {
    my ($self, $vol_uuid, $snap_uuid) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { restore_to => { snapshot => { uuid => $snap_uuid } } },
    );
}

# -- NVMe LIF discovery ------------------------------------------------

sub get_nvme_lif_addresses {
    my ($self) = @_;

    my $svm = uri_escape($self->{vserver});
    my $resp = $self->_get(
        "/network/ip/interfaces?svm.name=$svm"
            . "&services=data_nvme_tcp&fields=ip,name,enabled",
    );

    my @addrs;
    for my $lif (@{$resp->{records} // []}) {
        my $ip = $lif->{ip}{address} // next;
        next if defined($lif->{enabled}) && !$lif->{enabled};
        push @addrs, $ip;
    }

    return \@addrs;
}

# -- aggregate helpers -------------------------------------------------

sub _is_aggregate_nae {
    my ($self, $aggr_name) = @_;

    return 0 if !$aggr_name;
    return 0 if $self->{svm_scoped}; # /storage/aggregates is cluster-scoped

    my $name = uri_escape($aggr_name);
    my $aggr = eval {
        $self->_first_record(
            "/storage/aggregates"
                . "?name=$name&fields=data_encryption",
        );
    };
    return 0 if $@ || !$aggr;

    my $enc = $aggr->{data_encryption} // {};

    return $enc->{software_encryption_enabled} ? 1 : 0;
}

sub get_aggregate_space {
    my ($self, $aggr_name) = @_;

    my $q = "/storage/aggregates?fields=space";
    $q .= "&name=" . uri_escape($aggr_name) if $aggr_name;

    my $resp = $self->_get($q);
    my $records = $resp->{records} // [];
    return undef if !@$records;

    my $space = $records->[0]{space}{block_storage}
        // $records->[0]{space}
        // {};

    return {
        total => $space->{size}      // 0,
        used  => $space->{used}      // 0,
        free  => $space->{available} // 0,
    };
}

# Sum provisioned/used space across the SVM's volumes (optionally limited to a
# name pattern). SVM-scoped accessible — used by status() in svm_scoped mode,
# where the cluster-scoped aggregate endpoint is not available.
sub get_svm_volume_space {
    my ($self, $name_pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $q = "/storage/volumes?svm.name=$svm&fields=space.size,space.used";
    $q .= "&name=" . uri_escape($name_pattern) if $name_pattern;

    my $vols = $self->_get_all_records($q);
    my ($size, $used) = (0, 0);
    for my $v (@$vols) {
        $size += $v->{space}{size} // 0;
        $used += $v->{space}{used} // 0;
    }

    return { provisioned => $size, used => $used };
}

1;
