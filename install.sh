#!/bin/bash
# OmniTunnel installer / updater - fetches the repo, drops the right prebuilt
# binaries for this CPU, and installs the manager. No compiler required.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel/main/install.sh) && omnitunnel
#
# Re-running it is also the update path: it detects an existing install, refreshes
# the manager + binaries, and - if the version actually changed - restarts the
# running tunnels so they pick up the new core. Nothing is torn down when the
# version is unchanged.
set -euo pipefail
REPO="https://github.com/Free-Guy-IR/OmniTunnel"
RAW="https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel/main"
DEST="/opt/omnitunnel"
BINLINK="/usr/local/bin/omnitunnel"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64;;
    aarch64|arm64) ARCH=arm64;;
    *) echo "unsupported CPU: $(uname -m)"; exit 1;;
esac

ver_of() { grep -m1 -oE 'VERSION="[0-9.]+"' "$1" 2>/dev/null | grep -oE '[0-9.]+'; }
OLD_VER="$(ver_of "$DEST/omnitunnel.sh" 2>/dev/null || true)"
[[ -n "$OLD_VER" ]] && echo "OmniTunnel: found existing install v$OLD_VER ($ARCH), checking for updates..." \
                    || echo "OmniTunnel installer - CPU arch: $ARCH"

# deps: iptables, iproute2, iperf3 (benchmark), openssh, sshpass (peer auto-setup), python3 (hysteria relays)
# Only touch the package manager if something is actually missing - so a routine
# update (deps already present) never runs apt at all, and a broken *unrelated*
# third-party repo on the box can't spew "403 / no longer signed" errors into the
# output. When we do install, apt/yum noise is redirected away.
missing=0
for c in ip iptables iperf3 ssh sshpass curl python3; do
    command -v "$c" >/dev/null 2>&1 || { missing=1; break; }
done
if [[ $missing == 1 ]]; then
    echo "installing dependencies..."
    if command -v apt-get >/dev/null; then
        apt-get update -qq >/dev/null 2>&1 || true
        apt-get install -y iproute2 iptables iperf3 openssh-client sshpass ca-certificates curl python3 >/dev/null 2>&1 || true
    elif command -v yum >/dev/null; then
        yum install -y iproute iptables iperf3 openssh-clients sshpass curl python3 >/dev/null 2>&1 || true
    fi
fi

mkdir -p "$DEST/bin"
# prefer a local checkout (git clone), else download the needed files. The
# hysteria engine ships too (its own static binary), so the 'hysteria' transport
# works even where GitHub is unreachable at runtime.
if [[ -f "$(dirname "$0")/bin/omnitun-$ARCH" ]]; then
    SRC="$(cd "$(dirname "$0")" && pwd)"
    cp "$SRC/bin/omnitun-$ARCH" "$DEST/bin/omnitun-$ARCH"
    cp "$SRC/omnitunnel.sh" "$DEST/omnitunnel.sh"
    [[ -f "$SRC/bin/hysteria-$ARCH" ]] && cp "$SRC/bin/hysteria-$ARCH" "$DEST/bin/hysteria-$ARCH"
else
    echo "downloading core + manager ..."
    curl -fsSL "$RAW/bin/omnitun-$ARCH" -o "$DEST/bin/omnitun-$ARCH"
    curl -fsSL "$RAW/omnitunnel.sh"      -o "$DEST/omnitunnel.sh"
    curl -fsSL "$RAW/bin/hysteria-$ARCH" -o "$DEST/bin/hysteria-$ARCH" || true
fi

chmod +x "$DEST/bin/omnitun-$ARCH" "$DEST/omnitunnel.sh"
install -m 0755 "$DEST/bin/omnitun-$ARCH" /usr/local/bin/omnitun
[[ -f "$DEST/bin/hysteria-$ARCH" ]] && { chmod +x "$DEST/bin/hysteria-$ARCH"; install -m 0755 "$DEST/bin/hysteria-$ARCH" /usr/local/bin/hysteria; }
ln -sf "$DEST/omnitunnel.sh" "$BINLINK"

NEW_VER="$(ver_of "$DEST/omnitunnel.sh" || true)"

echo
if [[ -z "$OLD_VER" ]]; then
    echo "Installed OmniTunnel v${NEW_VER:-?} - core: $(/usr/local/bin/omnitun version 2>/dev/null)"
    [[ -x /usr/local/bin/hysteria ]] && echo "Hysteria engine: $(/usr/local/bin/hysteria version 2>/dev/null | awk -F'\t' '/Version/{print $2}')"
    echo "Run it with:  omnitunnel"
elif [[ "$OLD_VER" == "$NEW_VER" ]]; then
    echo "Already up to date (v$NEW_VER). Nothing changed; running tunnels left untouched."
else
    echo "Updated OmniTunnel  v$OLD_VER  ->  v$NEW_VER"
    # New core binaries are in place; restart the running tunnels so they pick
    # them up. (Port-forward relays don't use the core binary, so skip them.)
    changed=0
    for u in $(systemctl list-units 'omnitun-*.service' --state=active --no-legend 2>/dev/null | awk '{print $1}'); do
        case "$u" in *-pf-*.service) continue;; esac
        echo "  restarting $u"; systemctl restart "$u" 2>/dev/null || true; changed=1
    done
    [[ "$changed" == 1 ]] && echo "Running tunnels restarted on the new version." || echo "No running tunnels to restart."
fi
