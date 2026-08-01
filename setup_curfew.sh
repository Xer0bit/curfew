#!/usr/bin/env bash
# Installs Curfew without cloning the repo:
#   curl -fsSL https://raw.githubusercontent.com/Xer0bit/curfew/master/setup_curfew.sh | bash
set -euo pipefail

REPO="Xer0bit/curfew"
DEST="/usr/local/bin/curfew"

arch="$(uname -m)"
case "$arch" in
    x86_64) asset="curfew-linux-x86_64" ;;
    *)
        echo "No prebuilt binary for architecture '$arch' yet."
        echo "Build from source instead: https://github.com/$REPO#compatibility"
        exit 1
        ;;
esac

if [ "$(uname -s)" != "Linux" ]; then
    echo "Curfew is Linux-only (uses iproute2/tc, iw, procfs)."
    exit 1
fi

url="https://github.com/$REPO/releases/latest/download/$asset"
tmp="$(mktemp)"

echo "Downloading curfew ($asset)..."
curl -fL --progress-bar -o "$tmp" "$url"
chmod +x "$tmp"

echo "Installing to $DEST (needs sudo)..."
sudo install -m 755 "$tmp" "$DEST"
rm -f "$tmp"

echo
echo "Installed. Start it with:"
echo "  sudo curfew"
echo
echo "It'll check for required tools (nmap, arpspoof, etc.) on first run and"
echo "tell you what to install if anything's missing."
