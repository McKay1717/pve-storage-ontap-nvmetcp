# Contributing to pve-storage-ontap-nvmetcp

Thank you for your interest in contributing! This plugin is experimental and
community feedback is essential to making it production-ready.

## Reporting issues

Before opening a new issue, please check if a similar issue already exists.

When reporting a bug, include:

- **ONTAP version** (e.g. 9.12.1P8)
- **Proxmox VE version** (e.g. 8.3.2 or 9.0.1)
- **Plugin version** (`dpkg -l | grep ontap-nvmetcp`)
- **Steps to reproduce** the problem
- **Relevant log output** (`journalctl -u pvedaemon -u pvestatd --since "10 min ago"`)
- **Storage configuration** (sanitized `pvesm status` output)

For feature requests, prefix the issue title with `[feature]`.

## Testing

If you are testing the plugin, please share your results — even when everything
works as expected. Knowing which ONTAP versions, PVE versions, and workload
types work helps others.

## Code contributions

### Getting started

```bash
git clone https://github.com/McKay1717/pve-storage-ontap-nvmetcp.git
cd pve-storage-ontap-nvmetcp
```

### Code style

This project follows the
[Proxmox Perl Style Guide](https://pve.proxmox.com/wiki/Perl_Style_Guide):

- 4-space indentation, no tabs
- Maximum line length: 100 characters
- `for` instead of `foreach`
- `[0-9]` instead of `\d` in regular expressions
- Non-capturing groups `(?:)` when captures are not needed
- K&R brace style

Before submitting, format your code:

```bash
make tidy    # requires proxmox-perltidy on a PVE node
```

### Pull requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes following the code style above
4. Test on a PVE node with an ONTAP backend
5. Commit with a clear, descriptive message
6. Open a pull request against `main`

### Commit messages

Use clear, concise commit messages:

```
component: short description of the change

Optional longer explanation of what and why, not how.
```

Examples:

```
plugin: fix volume_size_info returning 0 for unmapped namespaces
api: add timeout parameter to _request method
debian: bump PKGREL for bugfix release
```

## License

By contributing, you agree that your contributions will be licensed under the
AGPL-3.0-or-later license.
