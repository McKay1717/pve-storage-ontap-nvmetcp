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
- **PVE APIVER 13** — full integration including `qemu_blockdev_options` and
  `volume_qemu_snapshot_method`

## Requirements

| Component             | Minimum                    | Recommended                |
|-----------------------|----------------------------|----------------------------|
| **NetApp ONTAP**      | 9.10.1 ¹                  | 9.12.1+ ²                 |
| **Proxmox VE**        | 8.x (APIVER ≥ 11)        | 9.x (APIVER 13)           |
| **nvme-cli**          | installed on each PVE node | latest from Debian repos   |
| **NVMe/TCP LIFs**     | configured on the SVM      |                            |
| **Perl dependencies** | `libjson-perl`, `libwww-perl`, `liburi-perl` |            |

> ¹ ONTAP 9.10.1 introduced NVMe/TCP and consistency groups REST API. Per-volume
> snapshots work. CG snapshots require 9.11.1.
>
> ² ONTAP 9.12.1 added the ability to modify consistency groups (add/remove
> volumes) via REST API — required for full CG lifecycle management. Earlier
> versions (9.10.1–9.11.1) require deleting and recreating CGs to change
> membership.

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
dpkg -i pve-storage-ontap-nvmetcp_1.0-6_all.deb
```

### From source

```bash
git clone https://github.com/McKay1717/pve-storage-ontap-nvmetcp.git
cd pve-storage-ontap-nvmetcp
make deb
dpkg -i pve-storage-ontap-nvmetcp_1.0-6_all.deb
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

### Optional parameters

| Parameter            | Description                                          | Default  |
|----------------------|------------------------------------------------------|----------|
| `ontap_portal`       | NVMe/TCP target portal IP (overrides auto-discovery) | auto     |
| `ontap_portal2`      | Secondary portal IP for multipath                    | —        |
| `storage_prefix`     | Prefix for ONTAP object names (e.g. `pve_`)          | —        |
| `snapshot_policy`    | ONTAP snapshot policy                                 | `none`   |
| `encryption`         | Volume encryption                                     | `true`   |
| `space_reserve`      | Space guarantee: `none` (thin) or `volume` (thick)    | `none`   |
| `qos_policy`         | QoS policy group                                      | —        |
| `adaptive_qos_policy`| Adaptive QoS policy group                             | —        |
| `snapshot_reserve`   | Snapshot reserve percent (0–90)                       | auto     |
| `tiering_policy`     | FabricPool tiering policy                             | —        |
| `verify_ssl`         | Verify ONTAP TLS certificate                          | `0`      |
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
4. Create an aggregate for volume placement
5. Ensure the management LIF is reachable from PVE nodes over HTTPS (port 443)

### Verify connectivity

```bash
pvesm status -storage myontap
nvme list
```

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

By default, TLS certificate verification is disabled for lab compatibility.
In production, enable it:

```bash
pvesm set myontap --verify_ssl 1
```

This requires a valid certificate on the ONTAP management LIF (signed by a
CA trusted by the PVE node).

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
├── .github/
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
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
