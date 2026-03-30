#!/usr/bin/env bash
set -euo pipefail

REPO="https://raw.githubusercontent.com/D0NMEGA/MoltGrid/main"
SDK_FILE="moltgrid.py"

echo "Installing MoltGrid SDK..."

if command -v curl &>/dev/null; then
    curl -fsSL "$REPO/$SDK_FILE" -o "$SDK_FILE"
elif command -v wget &>/dev/null; then
    wget -qO "$SDK_FILE" "$REPO/$SDK_FILE"
else
    echo "Error: curl or wget is required." >&2
    exit 1
fi

echo "Done. moltgrid.py downloaded to $(pwd)/$SDK_FILE"
echo ""
echo "Quick start:"
echo "  python3 -c \"from moltgrid import MoltGrid; print(MoltGrid.register(name='my-agent'))\""
