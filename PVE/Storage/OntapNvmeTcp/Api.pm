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
# and snapshots via the ONTAP 9.18+ REST API over HTTPS.

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
        verify_ssl => $opts{verify_ssl} // 0,
    };

    $self->{ua} = LWP::UserAgent->new(
        timeout  => $DEFAULT_TIMEOUT,
        ssl_opts => {
            verify_hostname => $self->{verify_ssl},
            SSL_verify_mode => $self->{verify_ssl} ? 1 : 0,
        },
    );

    $self->{base_url} = "https://$self->{mgmt_ip}/api";
    $self->{auth_header} = "Basic "
        . encode_base64(
            "$self->{username}:$self->{password}", "",
        );

    return bless $self, $class;
}

# -- REST helpers ------------------------------------------------------

sub _request {
    my ($self, $method, $path, $body) = @_;

    my $url = "$self->{base_url}$path";
    my $req = HTTP::Request->new($method, $url);
    $req->header('Authorization' => $self->{auth_header});
    $req->header('Accept'        => 'application/json');
    $req->header('Content-Type'  => 'application/json');
    $req->content(encode_json($body)) if $body;

    my $resp = $self->{ua}->request($req);
    my $code = $resp->code;
    my $content = $resp->decoded_content // '';

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

# -- SVM ---------------------------------------------------------------

sub get_svm_uuid {
    my ($self) = @_;

    return $self->{_svm_uuid} if $self->{_svm_uuid};

    my $svm = $self->_first_record(
        "/svm/svms?name=$self->{vserver}&fields=uuid",
    );
    die "SVM '$self->{vserver}' not found\n" if !$svm;

    $self->{_svm_uuid} = $svm->{uuid};

    return $self->{_svm_uuid};
}

# -- volume operations -------------------------------------------------

sub get_volume_uuid {
    my ($self, $vol_name) = @_;

    my $svm = uri_escape($self->{vserver});
    my $vol = $self->_first_record(
        "/storage/volumes?name=$vol_name"
            . "&svm.name=$svm&fields=uuid",
    );

    return $vol ? $vol->{uuid} : undef;
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

    # snapshot reserve
    my $snap_pct = defined($opts{snapshot_reserve})
        ? int($opts{snapshot_reserve})
        : ($snap_policy eq 'none' ? 0 : 5);
    $body->{space} = {
        snapshot => { reserve_percent => $snap_pct },
    };

    if ($opts{aggregate}) {
        $body->{aggregates} = [{ name => $opts{aggregate} }];
    }

    # encryption: prefer NAE, fallback to NVE
    if (defined($opts{encryption}) && !$opts{encryption}) {
        $body->{encryption} = { enabled => JSON::false };
    }
    elsif (!defined($opts{encryption}) || $opts{encryption}) {
        my $nae = eval {
            $self->_is_aggregate_nae($opts{aggregate});
        } // 0;
        $body->{encryption} = { enabled => JSON::true } if !$nae;
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

    return $self->_post("/storage/volumes", $body);
}

sub delete_volume {
    my ($self, $vol_uuid) = @_;

    eval {
        $self->_patch(
            "/storage/volumes/$vol_uuid",
            { state => "offline" },
        );
    };

    return $self->_delete("/storage/volumes/$vol_uuid");
}

sub resize_volume {
    my ($self, $vol_uuid, $new_size) = @_;

    return $self->_patch(
        "/storage/volumes/$vol_uuid",
        { size => int($new_size) },
    );
}

sub list_volumes_by_pattern {
    my ($self, $pattern) = @_;

    my $svm = uri_escape($self->{vserver});
    my $resp = $self->_get(
        "/storage/volumes?svm.name=$svm"
            . "&name=$pattern&fields=uuid,name,space",
    );

    return $resp->{records} // [];
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
    $query .= "&name=$pattern" if $pattern;

    my $resp = $self->_get($query);

    return $resp->{records} // [];
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

    return $self->_first_record(
        "/protocols/nvme/subsystems"
            . "?name=$name&svm.name=$svm&fields=uuid,name",
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

sub add_host_to_subsystem {
    my ($self, $subsys_uuid, $hostnqn) = @_;

    eval {
        $self->_post(
            "/protocols/nvme/subsystems/$subsys_uuid/hosts",
            { nqn => $hostnqn },
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
    my $resp = $self->_get(
        "/protocols/nvme/subsystem-maps"
            . "?namespace.uuid=$ns_uuid"
            . "&svm.name=$svm&fields=subsystem,namespace",
    );

    return $resp->{records} // [];
}

# -- consistency group operations --------------------------------------

sub get_consistency_group {
    my ($self, $cg_name) = @_;

    my $svm = uri_escape($self->{vserver});

    return $self->_first_record(
        "/application/consistency-groups"
            . "?svm.name=$svm&name=$cg_name"
            . "&fields=uuid,name,volumes",
    );
}

sub create_consistency_group {
    my ($self, $cg_name, $volume_names) = @_;

    my @volumes = map {
        { name => $_, provisioning_options => { action => "add" } }
    } @{$volume_names // []};

    my $body = {
        svm  => { name => $self->{vserver} },
        name => $cg_name,
    };
    $body->{volumes} = \@volumes if @volumes;

    return $self->_post(
        "/application/consistency-groups?return_records=true",
        $body,
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
        . "/snapshots?fields=name,create_time,comment";
    $q .= "&name=$filter" if $filter;

    my $resp = $self->_get($q);

    return $resp->{records} // [];
}

sub get_cg_snapshot_by_name {
    my ($self, $cg_uuid, $snap_name) = @_;

    my $snaps = $self->list_cg_snapshots($cg_uuid, $snap_name);

    return @$snaps ? $snaps->[0] : undef;
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
    $q .= "&name=$filter" if $filter;

    my $resp = $self->_get($q);

    return $resp->{records} // [];
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

    my $aggr = eval {
        $self->_first_record(
            "/storage/aggregates"
                . "?name=$aggr_name&fields=data_encryption",
        );
    };
    return 0 if $@ || !$aggr;

    my $enc = $aggr->{data_encryption} // {};

    return $enc->{software_encryption_enabled} ? 1 : 0;
}

sub get_aggregate_space {
    my ($self, $aggr_name) = @_;

    my $q = "/storage/aggregates?fields=space";
    $q .= "&name=$aggr_name" if $aggr_name;

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

1;
