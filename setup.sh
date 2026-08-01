#!/usr/bin/env bash
# Installs Curfew without cloning the repo:
#   curl -fsSL https://raw.githubusercontent.com/Xer0bit/curfew/master/setup.sh | bash
set -euo pipefail

REPO="Xer0bit/curfew"
DEST="/usr/local/bin/curfew"

BOLD=$'\033[1m'; CYAN=$'\033[36m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
info() { printf "%s\n" "${CYAN}$*${RESET}"; }
ok()   { printf "%s\n" "${GREEN}$*${RESET}"; }
fail() { printf "%s\n" "${RED}$*${RESET}" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || fail "Curfew is Linux-only (uses iproute2/tc, iw, procfs)."

arch="$(uname -m)"
case "$arch" in
    x86_64) asset="curfew-linux-x86_64" ;;
    *) fail "No prebuilt binary for '$arch' yet. Build from source: https://github.com/$REPO#compatibility" ;;
esac

printf "%s\n" "${BOLD}${CYAN}Curfew${RESET} — give your household's network a bedtime."
echo

url="https://github.com/$REPO/releases/latest/download/$asset"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

info "Downloading $asset..."
curl -fL --connect-timeout 10 --max-time 120 --progress-bar -o "$tmp" "$url" \
    || fail "Download failed — check your connection, or the repo has no release yet."
chmod +x "$tmp"

info "Installing to $DEST (needs sudo)..."
sudo install -m 755 "$tmp" "$DEST"

ok "Installed."
echo

# `curl | bash` means this script's own stdin is the download, not the
# keyboard — read the prompt (and later sudo's password) from the real
# terminal via /dev/tty instead, when one's available.
reply="n"
if [ -r /dev/tty ] 2>/dev/null; then
    read -r -p "Start Curfew now? [Y/n] " reply 2>/dev/null < /dev/tty || reply="n"
    reply="${reply:-Y}"
fi

if [[ "$reply" =~ ^[Yy] ]]; then
    exec sudo "$DEST" < /dev/tty
fi

printf "%s\n" "Run it anytime with: ${BOLD}sudo curfew${RESET}"
