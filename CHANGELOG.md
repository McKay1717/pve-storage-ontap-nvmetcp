# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.3-1] - 2026-06-10

Hardening informed by the business-continuity threat

### Changed

- **Deleted disks now go through the ONTAP volume recovery queue by default**
  (admin-recoverable for the retention period) instead of being destroyed
  immediately. Set the new `force_delete 1` storage option to restore the old
  irreversible behaviour. Note: a recovery-queue-parked FlexClone pins its base
  image until purged/expired, which can delay template deletion.
- **`path()` fails loudly instead of returning a placeholder.** A namespace
  that is offline on ONTAP now produces an error naming the cause; a device
  not yet visible is awaited with backoff (1+2+4+8 s) after the fabric
  connect, then fails with a clear fabric error instead of handing QEMU a
  nonexistent `/dev/ontap-nvme-pending/...` path.
- **NVMe/TCP connection check matches portal addresses.** `activate_storage`/
  `activate_volume` no longer short-circuit on *any* NVMe/TCP controller: a
  leftover connection to another array no longer masks a missing connection to
  this storage's portals.
- `check_connection` probes the REST endpoint over HTTPS (service + TLS
  health) instead of a bare TCP connect, and `status()` runs with a 10 s
  timeout so a hung ONTAP API degrades one storage instead of stalling the
  pvestatd poll loop.
- New SVM-scoped storages (`svm_scoped 1`) require `svm_capacity` at
  `pvesm add` time; existing ones log a warning at activation.
- **Default `autosize_max_percent` raised from 200 to 300.** Live fill tests
  showed the 200% ceiling equals roughly a single fully-rewritten snapshot
  generation: with any snapshot retention and sustained writes it is reached
  quickly, and ONTAP then refuses writes (VM I/O errors). 300% gives headroom
  for about two pinned generations. Applies to newly created volumes and to
  ceilings recomputed on resize; explicitly configured values are unchanged.

### Added

- **Cluster-wide per-VM locking.** All consistency-group mutations (snapshot
  create/rollback/delete, membership changes, CG cleanup, cross-VM disk moves)
  are serialized on a pmxcfs lock keyed by SVM + VMID, closing the cross-node
  races that could lose a backup snapshot mid-delete, leave duplicate
  same-named snapshots, or strand a disk outside its CG.
- **Snapshot membership verification.** A CG snapshot is only taken/restored
  from a disk that is actually a CG member; a non-member disk gets a
  per-volume snapshot with a loud warning instead of being silently left out
  of a "successful" CG snapshot.
- **Restore topology guard.** A CG rollback is refused — with an explicit
  error — when the snapshot does not cover all current member volumes (a disk
  added after the snapshot) or is marked partial on ONTAP: restoring would
  revert those disks to an unrelated state and delete every newer snapshot.
- **VM start survives a management-API outage.** `path()` consults a local
  namespace→device cache (matched by UUID against live sysfs) before any REST
  call, so previously seen disks can start/migrate while the ONTAP management
  LIF is down; the NVMe data path does not need it.
- **SVM-scoped async verification.** Operations that ONTAP may complete
  asynchronously where the account cannot poll the job (202) are now confirmed
  by polling the object itself: CG snapshot creation fails loudly if it cannot
  be verified, CG membership warns when the join is unconfirmed.
- **Capacity awareness.** New allocations are refused when they obviously
  cannot fit (aggregate free space, or the `svm_capacity` budget); `status()`
  warns when a FlexVol passes 90% of its autosize ceiling — once per volume,
  swept at most every 5 minutes per storage — before ONTAP offlines its
  namespace.
- **Stale-CG hygiene.** Deleting a VM's last disk also purges the CG's
  `pve_snap_*` snapshots so the empty CG can actually be deleted; adopting an
  empty leftover CG (VMID reuse) purges the previous owner's snapshots so they
  cannot leak to the new VM.
- **Stranded-object sweep.** `activate_storage` scans hourly (best-effort) for
  leftovers of interrupted operations: FlexVols without a namespace inside
  (an allocation that died mid-provisioning — invisible to PVE, warned with
  the `pvesm free` remedy), base volumes missing their `pve_base` snapshot
  (templating crashed mid-way — linked clones would fail), and empty
  consistency groups, which are reaped outright under the per-VM lock.
- NVMe/TCP-TLS pre-flight in `activate_storage`: activation fails fast when
  `tlshd` is not running or no NVMe TLS PSK is present in the kernel keyring —
  either condition silently hangs TLS connections and the VM I/O behind them.
- `Api`: `set_volume_online` (recovery helper), `with_timeout`, `probe`,
  `get_cg_snapshot_detail`, `list_volume_autosize`, and discrimination of
  connect/TLS failures with actionable certificate diagnostics instead of a
  generic ONTAP error.
- **`ontapnvme-move` helper: copy-less disk moves between storages.** For two
  ontapnvme storages on the same SVM (distinct prefixes/aggregates), the
  bundled CLI renames the FlexVol to the target prefix, moves CG membership,
  reapplies the target's snapshot/QoS/autodelete settings, rewrites the VM
  config (snapshot sections included) and starts a non-disruptive ONTAP
  `volume move` to the target aggregate — ONTAP snapshots, FlexClone lineage
  and the namespace identity are preserved, nothing is copied (PVE's
  `qm move-disk` copies block by block and loses the snapshots). VM must be
  stopped; physical relocation requires cluster-scoped credentials (verified
  live: SVM-scoped accounts get the ownership handoff plus a warning);
  interrupted runs resume safely. New Api methods: `move_volume_aggregate`,
  `get_job`, `set_volume_qos_policy`. `list_images` now matches namespaces by
  their containing volume name only — a namespace keeps its original name when
  its volume is renamed, so a handed-off disk was invisible in the target
  storage's listing (found in live testing).
- **`snapshot_autodelete` option (default off).** When a FlexVol nears full
  despite autosize, ONTAP deletes the oldest snapshots instead of refusing
  writes (which the VM experiences as I/O errors — observed live with a 5-min
  snapshot policy under continuous rewrites). Plugin-managed snapshots
  (`pve_snap_*`, `pve_base`) are deferred to last resort via a name-prefix
  rule, so scheduled-policy snapshots are sacrificed first; if pressure ever
  reaches a `pve_snap_*`, the PVE snapshot tree desynchronizes for that
  snapshot — documented, with capacity-sizing guidance preferred
  (`autosize_max_percent ≥ 100 + churn% × retained copies`). Applied to new
  volumes and clones; toggling the option reconciles all existing volumes
  immediately from the update hook. New Api method

### Fixed

- Cross-node consistency-group create race: the losing node now converges on
  the winner's CG instead of silently leaving its disk outside the CG —
  excluded from atomic snapshots.
- `pvesm remove` refuses to delete the storage's secrets while volumes still
  exist on ONTAP (the credentials are the only way to keep managing them);
  removal still proceeds when the backend is unreachable.
- Changing NVMe auth secrets now logs a loud warning that host-NQN
  re-registration briefly interrupts the node's access to the whole subsystem.
- Deleting a PVE snapshot now removes **all** same-named ONTAP snapshots (CG
  and per-volume): duplicates from a create race or a CG/per-volume fallback
  mix no longer survive a delete and silently shadow a later same-named
  snapshot.
- Rollback of a half-provisioned disk retries once before giving up, and the
  final warning states explicitly that the volume remains on ONTAP.
- A failed `pvesm set --snapshot_policy` reconcile now ends with one summary
  warning listing exactly which CGs/volumes still run the previous schedule.
- The immediate snapshot-policy reconcile from the update hooks now derives
  the new policy from the update itself: the hooks receive the pre-update
  storage config, so the previous code pushed the stale value to ONTAP
  (found in integration testing on PVE 9.1).
- `pvesm add` now persists `shared 1` into `storage.cfg` (unless `--shared 0`
  is given): the plugin-level shared default declared in `plugindata()` is not
  honoured by PVE 9.1's migration volume scan, which treated the disks as
  local and refused live migration (found in integration testing; existing
  storages need a one-time `pvesm set <storeid> --shared 1`).

## [1.2-1] - 2026-06-09

### Changed

- **Scheduled snapshots are now atomic across a VM's disks.** The
  `snapshot_policy` is applied to the VM's ONTAP consistency group instead of to
  each FlexVol, so policy-driven snapshots are crash-consistent across all of the
  VM's disks (ONTAP fences I/O across the CG). Member FlexVols are kept at
  `snapshot_policy none` so they are not snapshotted twice. On ONTAP < 9.12.1, a
  disk that cannot join the CG falls back to a per-volume schedule (still
  protected, just not crash-consistent with its siblings). Base templates carry
  no schedule.
- **Changing `snapshot_policy` reconciles immediately.** `pvesm set <storage>
  --snapshot_policy …` now pushes the new schedule to all of the storage's
  existing consistency groups and volumes from the update hook, instead of
  waiting for the next disk operation on each VM. Bounded (one CG + one volume
  listing, writes only on a real difference) and best-effort (a config update
  never fails if ONTAP is briefly unreachable).

  New `Api` methods: `set_consistency_group_snapshot_policy`,
  `set_volume_snapshot_policy`, `get_volume_snapshot_policy`,
  `list_consistency_groups`, `list_volume_snapshot_policies`.

## [1.1-2] - 2026-06-01

Community contributions on top of 1.1-1 (thanks
[@PandemiK911](https://github.com/PandemiK911)): two bug fixes and a
secret-lifecycle improvement.

### Added

- **`on_update_hook_full()`** — deleting a sensitive property (e.g.
  `pvesm set <storage> --delete nvme_dhchap_secret`) now removes the
  corresponding secret file under `/etc/pve/priv/storage/` instead of leaving
  it orphaned. The save/delete logic is shared via `_apply_sensitive_updates`;
  `on_update_hook` is kept as the fallback for older Proxmox VE.
  ([#4](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/pull/4))

### Fixed

- **`get_formats()`** now returns the `valid` and `default` keys expected by
  `PVE::Storage::Plugin` (they were `formats` / `default_format`, which the
  base class silently ignored). No functional change for the raw-only backend.
  ([#2](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/pull/2))
- **`volume_snapshot_info()`** now reports a stable `id` for consistency-group
  snapshots: `list_cg_snapshots()` fetches the `uuid` field, which was
  previously empty (APIVER 15 contract).
  ([#3](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/pull/3))

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
