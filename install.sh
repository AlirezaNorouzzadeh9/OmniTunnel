#!/bin/bash
# icmptun one-shot installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/icmptun/main/install.sh -o /tmp/icmptun-install.sh && sudo bash /tmp/icmptun-install.sh
#
# Downloads the real tool (icmptun-ctl.sh) to a stable path and hands
# control straight to it, so the one command above is the entire install -
# no manual file transfer needed. If raw.githubusercontent.com is itself
# filtered, add --socks5 host:port:
#
#   sudo bash /tmp/icmptun-install.sh --socks5 127.0.0.1:1080
set -euo pipefail

RAW_HOST="raw.githubusercontent.com"
RAW_PATH="/Free-Guy-IR/icmptun/main/icmptun-ctl.sh"
RAW_URL="https://${RAW_HOST}${RAW_PATH}"
INSTALL_PATH="/usr/local/bin/icmptun-ctl.sh"
CURL_OPTS=(-fsSL --connect-timeout 15 --retry 2)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --socks5) CURL_OPTS+=(--socks5 "$2"); shift 2 ;;
        *) echo "invalid option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "this script must be run as root: sudo bash $0"
    exit 1
fi

# The most common first-run failure on a filtered network is DNS, not the
# download itself: the box's configured resolver returns nothing for
# raw.githubusercontent.com and curl dies with "Could not resolve host"
# before a single byte moves. Detect that specific case and work around it
# by resolving through public resolvers and pinning the result, rather
# than making the user debug /etc/resolv.conf by hand.
resolve_raw_host() {
    local ip=""
    # Try the system resolver first - if it works, change nothing.
    if command -v getent >/dev/null 2>&1; then
        ip=$(getent ahostsv4 "$RAW_HOST" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [[ -z "$ip" ]]; then
        for resolver in 1.1.1.1 8.8.8.8 9.9.9.9; do
            if command -v dig >/dev/null 2>&1; then
                ip=$(dig +short +time=3 +tries=1 @"$resolver" "$RAW_HOST" A 2>/dev/null | grep -Eo '^[0-9.]+$' | head -1)
            elif command -v nslookup >/dev/null 2>&1; then
                ip=$(nslookup "$RAW_HOST" "$resolver" 2>/dev/null | awk '/^Address: /{print $2; exit}')
            fi
            [[ -n "$ip" ]] && break
        done
    fi
    printf '%s' "$ip"
}

if ! command -v gcc >/dev/null 2>&1; then
    echo "gcc not found - installing it..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq gcc iptables || {
            echo "package install failed - check this box's network/DNS and retry."
            exit 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q gcc iptables
    else
        echo "don't know how to install packages on this distro - install gcc yourself and re-run"
        exit 1
    fi
fi

echo "downloading icmptun-ctl.sh ..."
if ! curl "${CURL_OPTS[@]}" "$RAW_URL" -o "$INSTALL_PATH" 2>/dev/null; then
    echo "direct download failed - trying to resolve ${RAW_HOST} via public DNS..."
    RAW_IP=$(resolve_raw_host)
    if [[ -z "$RAW_IP" ]]; then
        echo
        echo "could not resolve ${RAW_HOST} at all."
        echo "this box's DNS is not answering for GitHub. Options:"
        echo "  1) fix DNS:    echo 'nameserver 1.1.1.1' >> /etc/resolv.conf   then re-run"
        echo "  2) via proxy:  sudo bash \$0 --socks5 127.0.0.1:1080"
        echo "  3) manual:     copy icmptun-ctl.sh to ${INSTALL_PATH} yourself, chmod +x it, and run it"
        exit 1
    fi
    echo "resolved ${RAW_HOST} -> ${RAW_IP}, retrying with that address pinned..."
    # --resolve keeps SNI/Host correct so TLS still validates properly.
    if ! curl "${CURL_OPTS[@]}" --resolve "${RAW_HOST}:443:${RAW_IP}" "$RAW_URL" -o "$INSTALL_PATH"; then
        echo
        echo "download still failed even with DNS resolved."
        echo "${RAW_HOST} is likely blocked on this network, not just unresolvable."
        echo "retry through a proxy:  sudo bash \$0 --socks5 127.0.0.1:1080"
        exit 1
    fi
fi

if [[ ! -s "$INSTALL_PATH" ]]; then
    echo "downloaded file is empty - aborting rather than installing a broken script."
    rm -f "$INSTALL_PATH"
    exit 1
fi

chmod +x "$INSTALL_PATH"
echo "installed: $INSTALL_PATH"
echo

exec "$INSTALL_PATH"
