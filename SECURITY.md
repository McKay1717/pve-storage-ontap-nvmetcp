# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this plugin, **please do not open
a public issue.**

Instead, report it privately via one of these methods:

- **GitHub Security Advisory:**
  [Report a vulnerability](https://github.com/McKay1717/pve-storage-ontap-nvmetcp/security/advisories/new)
- **Email:** contact the maintainer directly via the GitHub profile

Please include:

- A description of the vulnerability
- Steps to reproduce
- The potential impact
- Your ONTAP and PVE versions

You should receive an initial response within **72 hours**. Security fixes
will be prioritized and released as soon as possible.

## Scope

This policy covers the plugin code itself:

- `PVE/Storage/Custom/OntapNvmeTcpPlugin.pm`
- `PVE/Storage/OntapNvmeTcp/Api.pm`

Issues in ONTAP, Proxmox VE, or Linux NVMe/TCP stack should be reported to
their respective vendors.

## Security Considerations

- **Password storage:** Passwords are stored in `/etc/pve/priv/storage/`
  with mode 0600, never in `storage.cfg`.
- **TLS verification:** Disabled by default for lab compatibility. Enable
  `verify_ssl` in production environments.
- **ONTAP credentials:** Use a dedicated SVM-scoped user with minimum
  privileges (volume, namespace, subsystem, consistency group operations).
  Avoid using the cluster admin account.
