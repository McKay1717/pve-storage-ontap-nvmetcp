# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
