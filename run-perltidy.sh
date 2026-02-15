#!/bin/bash
# Format plugin sources with proxmox-perltidy.
# Run on a PVE 9 node:  apt install proxmox-perltidy && bash run-perltidy.sh

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v proxmox-perltidy &>/dev/null; then
    echo "ERROR: proxmox-perltidy not found."
    echo "Install: apt install proxmox-perltidy"
    exit 1
fi

FILES=(
    PVE/Storage/Custom/OntapNvmeTcpPlugin.pm
    PVE/Storage/OntapNvmeTcp/Api.pm
)

for f in "${FILES[@]}"; do
    [ -f "$f" ] && echo "tidying $f ..." && proxmox-perltidy "$f"
done

echo "done. Review with: git diff"
