# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
