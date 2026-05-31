# pve-storage-ontap-nvmetcp

Proxmox VE storage plugin for NetApp ONTAP NVMe/TCP.

> [!WARNING]
> **This plugin is experimental.** It has not yet been approved or endorsed by
> Proxmox or NetApp. Use at your own risk — test in non-production environments
> first. Feedback, bug reports, and testing results are greatly appreciated via
> [GitHub Issues](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/issues).

## Overview

This plugin exposes NetApp ONTAP NVMe namespaces as direct block devices for
Proxmox VE virtual machines over NVMe/TCP. It uses the ONTAP REST API to manage
the full lifecycle of VM disks: creation, deletion, resize, snapshots, and live
NVMe/TCP fabric discovery.

### Architecture

```
1 VM disk  =  1 NVMe namespace  =  1 FlexVol volume
```

Multi-disk VMs are grouped in an ONTAP consistency group (`pve_cg_vm_<vmid>`)
to enable atomic multi-disk snapshot operations.

### Features

- **Direct NVMe/TCP block access** — no iSCSI, no file layer, minimal latency
- **Shared storage with live migration** — all cluster nodes access the same
  namespaces via NVMe-oF/TCP fabric; `qm migrate` works out of the box
- **Cloud-init support** — `vm-<vmid>-cloudinit` disks for automated VM
  provisioning
- **Atomic multi-disk snapshots** via ONTAP consistency groups
- **Auto-discovery** of NVMe/TCP data LIFs (or manual portal override)
- **Three-strategy device resolution** — `nvme netapp ontapdevices`, sysfs UUID
  scan, `nvme list` + sysfs fallback
- **Volume encryption** — NAE (aggregate-level) preferred, NVE fallback
- **QoS policies** — fixed or adaptive, per-volume
- **FabricPool tiering** support
- **Sensitive properties** — password stored in `/etc/pve/priv/`, never in
  `storage.cfg`
- **Proxmox VE 9 storage API (APIVER 12–15)** — `qemu_blockdev_options`,
  `volume_qemu_snapshot_method`, `get_formats`
- **Templates + linked clones via ONTAP FlexClone** — `qm template` makes a
  base image; linked clones are instant, space-shared FlexClones of it (not
  host-side copies). Full clones use Proxmox's standard copy.
- **Disk reassignment** — `rename_volume` supports moving a disk to another VM

## Requirements

| Component             | Minimum                    | Recommended                |
|-----------------------|----------------------------|----------------------------|
| **NetApp ONTAP**      | 9.10.1 ¹                  | 9.12.1+ ²                 |
| **Proxmox VE**        | 9.x (storage APIVER 12)   | 9.x (storage APIVER 15)    |
| **nvme-cli**          | installed on each PVE node | latest from Debian repos   |
| **NVMe/TCP LIFs**     | configured on the SVM      |                            |
| **Perl dependencies** | `libjson-perl`, `libwww-perl`, `liburi-perl` |            |

> ¹ ONTAP 9.10.1 introduced NVMe/TCP and consistency groups REST API. Per-volume
> snapshots work. CG snapshots require 9.11.1.
>
> ² ONTAP 9.12.1 added the ability to modify consistency groups (add/remove
> volumes) via REST API — required for full CG lifecycle management and for
> atomic multi-disk snapshots. On earlier versions (9.10.1–9.12.0) CG
> membership cannot be changed via REST, so only a VM's first disk joins its
> CG (see Snapshots, below).

### ONTAP REST API features by version

| Feature                           | Introduced in  |
|-----------------------------------|----------------|
| NVMe namespace REST API           | ONTAP 9.6      |
| NVMe/TCP protocol support         | ONTAP 9.10.1   |
| Consistency groups REST API       | ONTAP 9.10.1   |
| CG snapshots via REST API         | ONTAP 9.11.1   |
| Add volumes to existing CG (PATCH)| ONTAP 9.12.1   |
| CG with NVMe namespaces (System Manager) | ONTAP 9.13.1 |

## Installation

### From .deb package

```bash
apt install nvme-cli
dpkg -i pve-storage-ontap-nvmetcp_1.1-1_all.deb
```

### From source

```bash
git clone https://github.com/McKay1717/pve-storage-ontap-nvmetcp.git
cd pve-storage-ontap-nvmetcp
make deb
dpkg -i pve-storage-ontap-nvmetcp_1.1-1_all.deb
```

## Configuration

> [!NOTE]
> **Adding this storage via the Proxmox web GUI is not supported.** Custom
> storage plugins can only be added from the command line with `pvesm add`.
> Once added, the storage is visible and usable in the GUI (disk creation,
> snapshots, resize, etc.).

### Add storage (CLI only)

```bash
pvesm add ontapnvme myontap \
    --mgmt_ip 10.0.0.1 \
    --username admin \
    --password '<password>' \
    --vserver svm-nvme \
    --subsystem pve-nvme-subsystem \
    --aggregate aggr1 \
    --content images
```

> [!NOTE]
> `mgmt_ip` and the data portals accept an **IPv4 literal, IPv6 literal, or a
> FQDN**. A FQDN resolves preferring IPv6 (AAAA over A); an IPv6 management
> address is bracketed automatically in the REST URL (`https://[…]/api`).

### Optional parameters

| Parameter            | Description                                          | Default  |
|----------------------|------------------------------------------------------|----------|
| `ontap_portal`       | NVMe/TCP target portal — IPv4, IPv6 or FQDN (overrides auto-discovery); a FQDN resolves preferring IPv6 | auto |
| `ontap_portal2`      | Secondary portal (IPv4/IPv6/FQDN) for multipath      | —        |
| `storage_prefix`     | Prefix for ONTAP object names (e.g. `pve_`)          | —        |
| `snapshot_policy`    | ONTAP snapshot policy                                 | `none`   |
| `encryption`         | Volume encryption (`1` NVE/NAE, `0` off)              | inherit  |
| `space_reserve`      | Space guarantee: `none` (thin) or `volume` (thick)    | `none`   |
| `qos_policy`         | QoS policy group                                      | —        |
| `adaptive_qos_policy`| Adaptive QoS policy group                             | —        |
| `snapshot_reserve`   | Snapshot reserve percent (0–90)                       | auto     |
| `tiering_policy`     | FabricPool tiering policy                             | —        |
| `autosize`           | Let the hosting FlexVol auto-grow (snapshot safety)   | `1`      |
| `autosize_max_percent`| Max FlexVol auto-grow, % of initial size             | `200`    |
| `svm_scoped`         | Use an SVM-scoped ONTAP account (no cluster API calls)| `0`      |
| `svm_capacity`       | Logical capacity (GiB) for `status()` in svm_scoped   | auto     |
| `verify_ssl`         | Verify ONTAP TLS certificate                          | `1`      |
| `nvme_dhchap_secret` | DH-HMAC-CHAP host secret — NVMe in-band auth (sensitive) | —     |
| `nvme_dhchap_ctrl_secret`| Controller secret for bidirectional DH-HMAC-CHAP (sensitive) | — |
| `nvme_tls`           | Use NVMe/TCP-TLS (TLS 1.3) for the data path           | `0`      |
| `nvme_tls_psk`       | NVMe/TCP-TLS pre-shared key (sensitive)                | —        |
| `debug`              | Debug logging level (0=off, 1=basic, 2=verbose)       | `0`      |
| `shared`             | Mark storage as shared across cluster nodes           | `1` ¹    |
| `nodes`              | Restrict storage to specific nodes                    | all      |

> ¹ ONTAP NVMe/TCP is inherently shared storage — all cluster nodes connect to
> the same namespaces via the NVMe-oF/TCP fabric. The plugin defaults to
> `shared=1`. Set `shared 0` only if testing single-node setups.

### ONTAP prerequisites

1. Create an SVM with NVMe protocol enabled
2. Create NVMe/TCP data LIFs on the SVM
3. Create an NVMe subsystem (or let the plugin create one on `pvesm add`)
4. Create an aggregate for volume placement. In `svm_scoped` mode (Mode B) the
   aggregate must also be **delegated to the SVM** (`vserver modify -vserver
   <svm> -aggr-list <aggr>`), or volume creation fails with *"Aggregate not
   found"*. Not required in Mode A — a cluster account sees every aggregate.
5. Ensure a management LIF is reachable from the PVE nodes over HTTPS (port
   443), with the `management-https` service enabled. **Mode B additionally
   requires a reachable _SVM_ management LIF** — an SVM-scoped user cannot
   authenticate through the cluster management LIF (it returns `401`).
6. Create a dedicated, least-privilege ONTAP user (see below) — do **not** use
   a cluster `admin` account

### Least-privilege ONTAP role (recommended)

The plugin authenticates with HTTP Basic on every request, so the configured
credentials should belong to a **dedicated REST user restricted to the API
paths the plugin actually uses** — never a cluster administrator. Two modes are
supported; choose one when creating the user.

The plugin uses these REST endpoints:

| API path                              | Access     | Scope   | Used for                                  |
|---------------------------------------|------------|---------|-------------------------------------------|
| `/api/storage/volumes`                | `all`      | SVM     | FlexVol create/resize/rename/clone/delete |
| `/api/storage/namespaces`             | `all`      | SVM     | NVMe namespace create/resize/delete       |
| `/api/protocols/nvme/subsystems`      | `all`      | SVM     | subsystem + host-NQN registration ¹       |
| `/api/protocols/nvme/subsystem-maps`  | `all`      | SVM     | map/unmap namespaces to the subsystem     |
| `/api/application/consistency-groups` | `all`      | SVM     | CG create/modify/delete + CG snapshots    |
| `/api/network/ip/interfaces`          | `readonly` | SVM     | NVMe/TCP data-LIF auto-discovery          |
| `/api/svm/svms`                       | `readonly` | SVM     | resolving the SVM UUID                    |
| `/api/storage/aggregates`             | `readonly` | cluster | free-space reporting + encryption check ² |
| `/api/cluster/jobs`                   | `readonly` | cluster | polling async operations to completion ²  |

#### Mode A — cluster-scoped role (default)

Grants all nine paths on the **cluster (admin) vserver**. Full functionality,
including accurate aggregate free space in `status()` — note this is the
**aggregate's** physical free space, so every storage backed by the same
aggregate reports the same figure (shared capacity, not a per-storage quota).
Still least-privilege — only these paths are exposed.

```text
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/storage/volumes                -access all
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/storage/namespaces             -access all
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/protocols/nvme/subsystems      -access all
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/protocols/nvme/subsystem-maps  -access all
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/application/consistency-groups -access all
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/storage/aggregates    -access readonly
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/network/ip/interfaces  -access readonly
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/cluster/jobs           -access readonly
security login rest-role create -vserver <cluster> -role pve-ontap-nvme -api /api/svm/svms               -access readonly
security login create -vserver <cluster> -user-or-group-name pve-ontap -application http -authentication-method password -role pve-ontap-nvme
```

#### Mode B — SVM-scoped role (set `svm_scoped 1`)

Maximum least-privilege: a role on the **data SVM** with only the seven
SVM-scoped paths — no `/storage/aggregates`, no `/cluster/jobs`. Set
`svm_scoped 1` on the storage so the plugin avoids those cluster-scoped calls:
async operations complete inline (via `return_timeout`) and `status()` reports
space from the SVM's own volumes. Point `mgmt_ip` at the **SVM's** management
LIF: an SVM-scoped user **cannot** authenticate through the cluster management
LIF (ONTAP returns `401`), so the SVM must expose a reachable management LIF
with the `management-https` service.

```text
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/storage/volumes                -access all
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/storage/namespaces             -access all
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/protocols/nvme/subsystems      -access all
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/protocols/nvme/subsystem-maps  -access all
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/application/consistency-groups -access all
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/network/ip/interfaces -access readonly
security login rest-role create -vserver <svm> -role pve-ontap-nvme -api /api/svm/svms              -access readonly
security login create -vserver <svm> -user-or-group-name pve-ontap -application http -authentication-method password -role pve-ontap-nvme
```

Then add `--svm_scoped 1` to `pvesm add` (and optionally `--svm_capacity <GiB>`
for a meaningful free-space gauge — without it, `status()` reports the sum of
provisioned volume sizes, which reads 0 on an empty SVM).

> ¹ If you pre-create the NVMe subsystem **and** register every PVE node's host
> NQN yourself, you can narrow `/api/protocols/nvme/subsystems` to `readonly`.
> Otherwise the plugin needs `all` to register host NQNs on `activate_storage`.
>
> ² Cluster-scoped — used only in Mode A. Not needed (and not called) with
> `svm_scoped 1`.

### Security hardening

The plugin runs as root inside `pvedaemon` and holds an ONTAP credential, so:

- **Keep TLS verification on** (`verify_ssl 1`, the default). If ONTAP presents
  a private-CA certificate, add that CA to the PVE node's trust store
  (`update-ca-certificates`) rather than setting `verify_ssl 0` — disabling
  verification exposes the management credential to a man-in-the-middle.
- **Use a dedicated, single-role ONTAP account** scoped to exactly the REST
  paths listed above. Prefer the SVM-scoped role (`svm_scoped 1`); never reuse a
  cluster `admin` account (privilege-escalation surface — NetApp CVE-2024-21985).
- **Isolate the NVMe/TCP fabric.** NVMe/TCP is unauthenticated and unencrypted
  on the wire and host NQNs are spoofable, so keep the data LIFs and PVE nodes
  on a dedicated, trusted storage VLAN; enable in-band auth (DH-HMAC-CHAP) if
  your ONTAP supports it.
- **The password is never written to `storage.cfg`** — it lives in
  `/etc/pve/priv/storage/<storeid>.pw` (mode 0600, root-only, replicated by
  pmxcfs). Don't pass it on a shared command line or commit it to scripts.
- The plugin's API client **refuses HTTP redirects**, so a redirected request
  can never leak the credential to another host regardless of the node's
  `libwww-perl` version; keep the node patched (kernel NVMe-oF, `libwww-perl`)
  as general hygiene.

### NVMe in-band authentication & TLS (optional)

NVMe/TCP is unauthenticated and cleartext by default. Two opt-in mechanisms
harden the data path. The plugin configures the ONTAP subsystem side
automatically (on add/activate) and stores each secret `0600` under
`/etc/pve/priv/storage/` as a sensitive property (never in `storage.cfg`, and
redacted from any log/error output). Both default **off** — unset means today's
behaviour, unchanged.

**DH-HMAC-CHAP in-band authentication** (ONTAP 9.14+) — the controller
authenticates the host before any I/O:

```bash
# host secret (unidirectional); generate with `nvme gen-dhchap-key`
pvesm set myontap --nvme_dhchap_secret 'DHHC-1:00:…:'
# optional controller secret for mutual (bidirectional) auth
pvesm set myontap --nvme_dhchap_ctrl_secret 'DHHC-1:00:…:'
```

Each node's host NQN is registered with the secret; `nvme connect` then
authenticates (verified: a connection without the secret is refused).
`--dhchap-ctrl-secret` on `nvme connect-all` needs a recent `nvme-cli`.

**NVMe/TCP-TLS (TLS 1.3)** (ONTAP 9.16+) — encrypts the data connection:

```bash
pvesm set myontap --nvme_tls 1 --nvme_tls_psk 'NVMeTLSkey-1:01:…:'
```

Each PVE node also needs a TLS-capable kernel, a running `tlshd`, and an
`nvme-cli` with TLS / `gen-tls-key` support. The plugin sets the PSK on the
ONTAP host entry and best-effort-loads it into the node keyring; on older
`nvme-cli` provision it manually (`nvme gen-tls-key --insert`).

> [!NOTE]
> TLS adds CPU cost. On **ONTAP 9.19.1+** with a supported NIC (CX6-Dx / CX7)
> enable the TLS data-phase crypto offload — `security config modify
> -is-offload-enabled true -interface SSL` (only post-handshake data is
> offloaded; existing connections must reconnect). See NetApp TR-4684 and the
> *Configure TLS offload* doc. On the PVE node, kernel TLS (ktls) + NIC offload
> similarly cut host CPU.

### Verify connectivity

```bash
pvesm status -storage myontap
nvme list
```

### Multi-tier / multi-aggregate setup

To back several aggregates of the **same SVM** with **different QoS and
snapshot policies**, define **one storage per aggregate** (the `aggregate`,
`qos_policy` and `snapshot_policy` options are all per-storage). This is the
usual Proxmox "one storage = one class of service" model (e.g. gold/silver).

```bash
# "gold" tier on aggr1
pvesm add ontapnvme ontap-gold \
    --mgmt_ip 10.0.0.1 --username admin --password '<password>' \
    --vserver svm-nvme --subsystem pve-nvme \
    --aggregate aggr1 \
    --storage_prefix gold_ \
    --qos_policy qos-gold --snapshot_policy snap-gold \
    --content images

# "silver" tier on aggr2 — same SVM, same subsystem
pvesm add ontapnvme ontap-silver \
    --mgmt_ip 10.0.0.1 --username admin --password '<password>' \
    --vserver svm-nvme --subsystem pve-nvme \
    --aggregate aggr2 \
    --storage_prefix silver_ \
    --qos_policy qos-silver --snapshot_policy snap-silver \
    --content images
```

> [!IMPORTANT]
> Give each storage a **distinct `storage_prefix`**. The plugin identifies its
> volumes by name within the SVM (`list_images` filters by name + prefix, not
> by aggregate). Two storages on the same SVM **without** distinct prefixes
> would see and claim each other's namespaces, corrupting per-storage listing
> and space reporting.

> [!NOTE]
> A single NVMe subsystem can be shared by both storages (common host access).
> QoS/snapshot policies are applied **per storage** (so per tier) and must
> already exist on ONTAP; `qos_policy` and `adaptive_qos_policy` are mutually
> exclusive. Atomic multi-disk snapshots are scoped to one storage: a VM with
> disks on both tiers gets one consistency group per tier, not a single
> cross-tier one. Moving a disk between tiers (`qm move-disk`) copies the data
> (it is not an ONTAP non-disruptive `volume move`).

## How it works

### Disk allocation (`alloc_image`)

1. Creates a dedicated FlexVol volume (sized at 105% for WAFL overhead)
2. Creates an NVMe namespace inside the volume
3. Maps the namespace to the configured NVMe subsystem
4. Adds the volume to the VM's consistency group
5. Triggers NVMe/TCP fabric rescan so the new device appears as `/dev/nvmeXnY`

### Snapshots

Snapshots are created at the ONTAP consistency group level for atomic multi-disk
consistency. If the CG is not available, the plugin falls back to per-volume
snapshots. All snapshot operations (create, rollback, delete) follow this
CG-first strategy.

> [!IMPORTANT]
> **Atomic multi-disk snapshots require ONTAP 9.12.1+.** Adding a disk to an
> existing consistency group uses the CG-membership PATCH API introduced in
> ONTAP 9.12.1. On **9.10.1–9.12.0** only the VM's *first* disk joins the CG;
> each additional disk is then snapshotted per-volume, so a multi-disk VM's
> snapshot is **not crash-consistent across its disks** (each disk is still
> individually consistent, just not coordinated to the same instant).
> Single-disk VMs are unaffected. On these earlier versions, freeing a disk can
> also leave its consistency group behind, since CG membership cannot be
> modified via REST.

> [!NOTE]
> These snapshots are **crash-consistent, not application-consistent**.
> `qm snapshot` does not quiesce the guest — PVE issues the guest-agent
> `fs-freeze`/`thaw` only during *backups*, not on snapshot. For application
> consistency, run a backup job with the QEMU Guest Agent enabled, snapshot a
> stopped VM, or include the VM memory state (`--vmstate`).

### Device resolution

When PVE requests a device path, the plugin resolves the ONTAP namespace UUID
to a local `/dev/nvmeXnY` using three strategies in order:

1. **`nvme netapp ontapdevices`** — namespace path match (survives live
   migration)
2. **sysfs UUID/NGUID scan** — direct kernel attribute lookup
3. **`nvme list` JSON + sysfs** — fallback for non-NetApp nvme-cli builds

### Live migration

Since the storage is shared (all nodes see the same NVMe/TCP namespaces), PVE
can live-migrate VMs without copying disk data:

```bash
qm migrate 100 target-node --online
```

**Requirements for live migration:**

1. The plugin must be installed on **all** cluster nodes
2. All nodes must have NVMe/TCP connectivity to the ONTAP data LIFs
3. The VM must not have snapshots with `vmstate` on local storage — delete them
   first or move vmstate to shared storage

During migration, the target node connects to the ONTAP namespaces via
`nvme connect-all` (triggered automatically by `path()` if the device is not
yet visible). No data is copied — only VM memory state is transferred between
nodes.

> [!NOTE]
> If migrating from a pre-1.0-4 installation, verify that `shared 1` is
> present in your storage configuration:
> ```bash
> grep -A5 'ontapnvme:' /etc/pve/storage.cfg
> # should show: shared 1
> ```
> New installations with 1.0-4+ get `shared 1` automatically.

## Troubleshooting

### Common errors

| Symptom (PVE / ONTAP error) | Cause | Fix |
|---|---|---|
| `Aggregate not found` on disk create (Mode B) | aggregate not delegated to the SVM | `vserver modify -vserver <svm> -aggr-list <aggr>` |
| `401 Unauthorized` (Mode B) | SVM-scoped user authenticating via the cluster LIF | point `mgmt_ip` at the SVM's management LIF |
| connection refused / timeout on port 443 | mgmt LIF without `management-https`, or wrong subnet/VLAN | enable the service; check the LIF's subnet/VLAN |
| `certificate verify failed` | `verify_ssl 1` (default) with a self-signed cert | install a trusted CA cert, or set `verify_ssl 0` (lab only) |
| `subsystem '<name>' not found` | insufficient NVMe privileges (Mode B role) | grant `/api/protocols/nvme/subsystems` = `all` |

### Debug logging

Enable debug output to syslog (visible via `journalctl -u pvedaemon`):

```bash
# basic (level 1): main operations (alloc, free, snapshot, resize)
pvesm set myontap --debug 1

# verbose (level 2): path resolution, device lookups
pvesm set myontap --debug 2

# disable
pvesm set myontap --debug 0
```

Filter debug messages:

```bash
journalctl -u pvedaemon -f | grep 'ontapnvme ::'
```

### TRIM / discard and SSD emulation

ONTAP namespaces are thin-provisioned on SSD-backed aggregates (AFF/ASA).
For optimal space reclaim, enable `discard=on` and `ssd=1` on each VM disk:

```bash
# CLI
qm set 100 --scsi0 myontap:vm-100-disk-0,ssd=1,discard=on
```

In the PVE web GUI: edit the disk → **Advanced** → check **Discard** and
**SSD emulation**.

> [!IMPORTANT]
> Without `discard=on`, deleted data inside the guest will not be reclaimed
> on ONTAP. This is the standard PVE behavior — the same setting is required
> for RBD, LVM-thin, and ZFS-thin storage.

> [!NOTE]
> `ssd=1` only applies to SCSI, IDE, and SATA controllers. VirtIO-blk
> does not expose SSD rotation hints. `discard=on` applies to all
> controller types.

The complete TRIM flow:

```
Guest TRIM → QEMU device (discard=on) → QEMU blockdev (discard=unmap) → /dev/nvmeXnY → ONTAP Deallocate
Guest zeros → QEMU blockdev (detect-zeroes=unmap) → ONTAP Deallocate
```

PVE propagates `discard=on` from the VM configuration to both the QEMU device
and blockdev layers automatically — including `detect-zeroes=unmap`.

### TLS certificate verification

Since 1.1-1, TLS certificate verification is **enabled by default**
(`verify_ssl 1`). This requires a valid certificate on the ONTAP management
LIF (signed by a CA trusted by the PVE node).

For lab environments using self-signed certificates, disable it explicitly:

```bash
pvesm set myontap --verify_ssl 0
```

## Development

### Code formatting

The code follows the
[Proxmox Perl Style Guide](https://pve.proxmox.com/wiki/Perl_Style_Guide).
A `.perltidyrc` is included for use with `proxmox-perltidy`:

```bash
# on a PVE 9 node with proxmox-perltidy installed:
make tidy
```

### Project structure

```
├── PVE/
│   └── Storage/
│       ├── Custom/
│       │   └── OntapNvmeTcpPlugin.pm   # PVE storage plugin
│       └── OntapNvmeTcp/
│           └── Api.pm                   # ONTAP REST API client
├── debian/                              # Debian packaging
│   ├── changelog
│   ├── control.in
│   ├── copyright
│   ├── postinst
│   └── triggers
├── .perltidyrc                          # Proxmox perltidy config
├── Makefile                             # Build system
├── run-perltidy.sh                      # Helper script
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE                              # AGPL-3.0-or-later
├── SECURITY.md
└── README.md
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

Since this plugin is experimental, **all forms of feedback are valuable**:

- **Bug reports** and unexpected behavior →
  [open an issue](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/issues)
- **Testing results** (ONTAP version, PVE version, workload type) →
  issue or discussion
- **Feature requests** → issue with `[feature]` prefix
- **Code contributions** → pull request against `main`

## License

This project is licensed under the **GNU Affero General Public License v3.0 or
later** (AGPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

## Author

**Nicolas I. (McKay1717)** —
[github.com/McKay1717](https://github.com/McKay1717)
