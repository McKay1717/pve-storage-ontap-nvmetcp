# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1-1] - 2026-05-31

First release since 1.0-6. Targets the **Proxmox VE 9** storage API and adds
templates and FlexClone linked clones, disk reassignment, snapshot-safety,
optional SVM-scoped operation, NVMe in-band authentication and TLS, IPv6/FQDN
support, and a full security-hardening pass.
**Requires Proxmox VE 9** — support for Proxmox VE 8 is dropped.

### Added

- **Proxmox VE 9 storage API (APIVER 12–15).** `api()` reports the host's
  `PVE::Storage::APIVER` clamped to the supported range; all method signatures
  match the current contract (`qemu_blockdev_options`,
  `volume_qemu_snapshot_method`, `free_image`, `get_formats`, `volume_resize`,
  `volume_has_feature`).
- **Templates and linked clones via ONTAP FlexClone.** `qm template` creates a
  base image with a `pve_base` snapshot; a linked clone is served by
  `clone_image` as an instant, space-shared FlexClone from that snapshot, using
  PVE's compound volname `base-X/vm-Y` (reconstructed in `list_images` from the
  FlexClone parent) so PVE tracks the backing base (e.g. refuses to delete a
  template still in use). Full clones use PVE's standard copy.
- **Disk reassignment / rename** (`rename_volume`) — `qm move-disk
  --target-vmid` and disk rename, moving consistency-group membership to the
  target VM.
- **FlexVol autosize** (`autosize`, `autosize_max_percent`) so the fixed-size
  thin namespace never goes offline when snapshots fill its container.
- **`get_identity`** — returns the ONTAP SVM UUID as a stable backend id.
- **Optional SVM-scoped operation** (`svm_scoped`, default off) for a
  least-privilege ONTAP account with no cluster privileges: the plugin avoids
  the cluster-scoped REST endpoints (async ops complete inline; `status()`
  reports SVM volume space, with `svm_capacity` for the gauge total).
- **NVMe in-band authentication (DH-HMAC-CHAP)** — `nvme_dhchap_secret` and
  optional `nvme_dhchap_ctrl_secret` (bidirectional). The host NQN is
  registered with the secret on the ONTAP subsystem and `nvme connect`
  authenticates. Requires ONTAP 9.14+.
- **NVMe/TCP-TLS (TLS 1.3)** — `nvme_tls` + `nvme_tls_psk` encrypt the data
  connection (ONTAP 9.16+; the PVE node needs a TLS-capable kernel, `tlshd`,
  and an `nvme-cli` with TLS support).
- **IPv6 and FQDN** for `mgmt_ip` and the data portals — an IPv6 management
  address is bracketed in the REST URL, and a FQDN portal is resolved
  preferring IPv6.

### Changed

- **`verify_ssl` defaults to `1`** (TLS verification on). For a private-CA
  ONTAP certificate, trust the CA on the node rather than disabling.
- **`encryption` is opt-in** — unset inherits the ONTAP/aggregate default
  instead of forcing NVE.
- All asynchronous ONTAP operations request `return_timeout=120` so they
  usually complete inline instead of returning a job to poll.
- **Volume deletion uses `force=true`** to bypass the ONTAP recovery queue, so
  a deleted FlexClone no longer pins its base image.

### Fixed

- `free_image` removes the volume from its consistency group before deleting
  it (no orphaned CGs) and propagates a delete failure instead of leaving an
  orphan; a failed delete re-onlines the volume rather than stranding it.
- `alloc_image` rolls back the namespace and volume if mapping fails.
- `volume_snapshot_info` returns `virtual-size` and epoch timestamps.

### Security

- The ONTAP API client **refuses HTTP redirects** (`max_redirect 0`), so the
  HTTP Basic credential cannot leak to another host on a 3xx redirect
  (CVE-2026-8368 class), independent of the node's `libwww-perl` version.
- Hardened taint untainting (`\z`-anchored, strict device/IP grammars) and a
  central REST path guard rejecting `..` / control characters.
- The password and the NVMe secrets are sensitive properties (never in
  `storage.cfg`), written `0600` atomically under `/etc/pve/priv/`, and
  **redacted from all log/error output**.
- All REST query-string parameters are URI-escaped; both a cluster-scoped and
  an SVM-scoped least-privilege ONTAP role are documented in the README.

### Performance

- The ONTAP API client and its resolved SVM UUID are cached per storage
  (invalidated on update/delete).
- `check_connection` is a lightweight TCP reachability probe.

## [1.0-6] - 2026-03-20

### Fixed

- **`qemu_blockdev_options`** — removed `discard=unmap` and
  `detect-zeroes=unmap` from blockdev return value. PVE validates plugin
  blockdev options against an allowed schema and silently dropped these,
  generating 4 warnings per VM start:

      WARN: volume '...' - dropping block device option 'discard'
      set by storage plugin - not currently part of allowed schema

  Per the PVE `qemu_blockdev_options` contract, plugins must return only
  backend access options (`driver` + `filename`). Discard and detect-zeroes
  are managed by qemu-server from the VM disk configuration (`discard=on`).
  The automatic TRIM feature introduced in 1.0-3 was never effective — the
  options were dropped before reaching QEMU.

### Changed

- TRIM/discard is now configured via VM disk options (standard PVE behavior):
  `qm set <vmid> --scsi0 myontap:vm-N-disk-0,discard=on,ssd=1`

## [1.0-5] - 2026-03-20

### Added

- **Cloud-init disk support** (`vm-<vmid>-cloudinit`). Cloud-init disks use a
  naming convention that differs from regular disks (`vm-N-cloudinit` vs
  `vm-N-disk-N`). Five functions now handle the cloudinit pattern:
  `parse_volname`, `_parse_ontap_disk_name`, `_ontap_to_pve`, `alloc_image`,
  and `list_images`. Cloud-init volumes are added to the VM's consistency group
  for atomic snapshots. ONTAP minimum namespace size (20 MiB) applies; real
  space consumption is near-zero on thin-provisioned aggregates.
  Fixes [#1](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/issues/1).
  Reported by [@PandemiK911](https://github.com/PandemiK911).

## [1.0-4] - 2026-03-13

### Fixed

- **CRITICAL** — Live migration failed with `storage type 'ontapnvme' not
  supported`. The plugin did not declare `shared` in `options()`, so PVE
  ignored `shared 1` in `storage.cfg` and treated the storage as node-local.
  PVE then attempted to copy disks to the target node — which is unnecessary
  for network-attached NVMe/TCP namespaces accessible from all cluster nodes.

### Added

- `shared` property in `options()` — PVE now recognizes the `shared`
  directive in `storage.cfg`.
- `shared => 1` default in `plugindata()` — ONTAP NVMe/TCP storage is
  inherently shared (all nodes connect to the same namespaces via NVMe-oF/TCP
  fabric). New storage entries are automatically configured as shared. Admin
  can still restrict per-node access via the `nodes` property.

## [1.0-3] - 2026-02-22

### Fixed

- **CRITICAL** — ONTAP REST API pagination: list operations now follow
  `_links.next` across all paginated responses. Previously, only the first
  page (20 records) was returned, causing volumes/namespaces to be invisible
  in PVE when a SVM contained more than 20 objects.
- **CRITICAL** — `volume_has_feature('copy')` returned true but no
  `clone_image` method existed, causing crashes on disk clone operations.
  Removed the `copy` feature declaration until FlexClone is implemented.
- ONTAP version requirement corrected from "9.18+" to "9.10.1+" in
  `debian/control.in` and `Api.pm` comment (9.18 does not exist).
- Missing `\n` on `die` message in `on_add_hook` error path.
- URI escaping applied consistently to all query string parameters in
  ONTAP REST API calls (`vol_name`, `cg_name`, `subsystem_name`, `pattern`).
- Removed unused Perl imports (`get_standard_option`, `trim`).

### Added

- **QEMU blockdev:** `discard=unmap` and `detect-zeroes=unmap` forced
  automatically on all VM disks — guest TRIM/zero-writes reclaim space
  on ONTAP thin-provisioned namespaces without user intervention.
- `verify_ssl` storage property — enables TLS certificate verification for
  ONTAP management API connections. Defaults to `0` (disabled) for lab
  compatibility. Recommended to enable in production.
- `debug` storage property — configurable debug logging (0=off, 1=basic,
  2=verbose). Output goes to syslog via `pvedaemon` journal.
- `SECURITY.md` — responsible disclosure policy.

## [1.0-2] - 2026-02-15

### Fixed

- `_ontap_to_pve()` — `$pve_name` was uninitialized when `storage_prefix` was
  empty, causing `alloc_image` to return an empty volume name. VM creation
  failed with `unable to parse volume ID 'store:'`. Root cause: Perl postfix
  `if` on `(my $var = $x) =~ s///` skips the entire statement including the
  `my` declaration when the condition is false.

## [1.0-1] - 2026-02-15

### Added

- Initial release.
- ONTAP REST API client (`Api.pm`) for NVMe namespace, volume, subsystem,
  consistency group, and snapshot management.
- PVE storage plugin (`OntapNvmeTcpPlugin.pm`) implementing APIVER 13:
  - `alloc_image` / `free_image` / `list_images` — full disk lifecycle
  - Volume snapshots via consistency groups (atomic multi-disk) with
    per-volume fallback
  - `volume_resize` / `volume_size_info`
  - `qemu_blockdev_options` (`host_device` driver)
  - `volume_qemu_snapshot_method` (`storage`-side snapshots)
  - `on_add_hook` / `on_update_hook` / `on_delete_hook`
  - `sensitive-properties` for password isolation in `/etc/pve/priv/`
- NVMe/TCP auto-discovery via ONTAP data LIFs.
- Three-strategy NVMe device resolution:
  1. `nvme netapp ontapdevices` (path match)
  2. sysfs UUID/NGUID scan
  3. `nvme list` JSON + sysfs fallback
- Volume encryption support (NAE preferred, NVE fallback).
- QoS policy support (fixed and adaptive).
- FabricPool tiering policy support.
- Debian packaging with `pvedaemon`/`pvestatd` restart on install.
- Code formatted per Proxmox Perl Style Guide with `.perltidyrc`.
