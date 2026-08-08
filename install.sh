#!/bin/bash
# OmniTunnel installer - fetches the repo, drops the right prebuilt core binary
# for this CPU, and installs the manager. No compiler required.
#   curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/icmptun/main/install.sh | bash
set -euo pipefail
REPO="https://github.com/Free-Guy-IR/icmptun"
RAW="https://raw.githubusercontent.com/Free-Guy-IR/icmptun/main"
DEST="/opt/omnitunnel"
BINLINK="/usr/local/bin/omnitunnel"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64;;
    aarch64|arm64) ARCH=arm64;;
    *) echo "unsupported CPU: $(uname -m)"; exit 1;;
esac
echo "OmniTunnel installer - CPU arch: $ARCH"

# deps: iptables, iproute2, iperf3 (for benchmarking), openssh, sshpass (peer auto-setup)
if command -v apt-get >/dev/null; then
    apt-get update -qq || true
    apt-get install -y iproute2 iptables iperf3 openssh-client sshpass ca-certificates curl >/dev/null 2>&1 || true
elif command -v yum >/dev/null; then
    yum install -y iproute iptables iperf3 openssh-clients sshpass curl >/dev/null 2>&1 || true
fi

mkdir -p "$DEST/bin"
# prefer a local checkout (git clone), else download the needed files
if [[ -f "$(dirname "$0")/bin/omnitun-$ARCH" ]]; then
    SRC="$(cd "$(dirname "$0")" && pwd)"
    cp "$SRC/bin/omnitun-$ARCH" "$DEST/bin/omnitun-$ARCH"
    cp "$SRC/omnitunnel.sh" "$DEST/omnitunnel.sh"
else
    echo "downloading core + manager ..."
    curl -fsSL "$RAW/bin/omnitun-$ARCH" -o "$DEST/bin/omnitun-$ARCH"
    curl -fsSL "$RAW/omnitunnel.sh" -o "$DEST/omnitunnel.sh"
fi

chmod +x "$DEST/bin/omnitun-$ARCH" "$DEST/omnitunnel.sh"
install -m 0755 "$DEST/bin/omnitun-$ARCH" /usr/local/bin/omnitun
ln -sf "$DEST/omnitunnel.sh" "$BINLINK"

echo
echo "Installed. Core: /usr/local/bin/omnitun ($(/usr/local/bin/omnitun version))"
echo "Run it with:  omnitunnel"
