# pve-storage-ontap-nvmetcp

Proxmox VE storage plugin for NetApp ONTAP NVMe/TCP.

> [!WARNING]
> **This plugin is experimental.** Use at your own risk — test in non-production environments
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

| Component             | Recommended                |
|-----------------------|----------------------------|
| **NetApp ONTAP**      | 9.12.1+ ²                 |
| **Proxmox VE**        | 9.x (APIVER 13)           |

## Installation

### From .deb package

```bash
apt install nvme-cli
dpkg -i pve-storage-ontap-nvmetcp_1.0-1_all.deb
```

### From source

```bash
git clone https://github.com/McKay1717/pve-storage-ontap-nvmetcp.git
cd pve-storage-ontap-nvmetcp
make deb
dpkg -i pve-storage-ontap-nvmetcp_1.0-1_all.deb
```

## Configuration

### Add storage

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

