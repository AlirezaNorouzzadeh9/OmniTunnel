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

RAW_URL="https://raw.githubusercontent.com/Free-Guy-IR/icmptun/main/icmptun-ctl.sh"
INSTALL_PATH="/usr/local/bin/icmptun-ctl.sh"
CURL_OPTS=(-fsSL)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --socks5) CURL_OPTS+=(--socks5 "$2"); shift 2 ;;
        *) echo "گزینه نامعتبر: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "این اسکریپت باید با root اجرا بشه: sudo bash $0"
    exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
    echo "gcc پیدا نشد - نصبش می‌کنم..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq gcc iptables
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q gcc iptables
    else
        echo "نمی‌دونم این توزیع چطور پکیج نصب می‌کنه - gcc رو خودت نصب کن و دوباره اجرا کن"
        exit 1
    fi
fi

echo "در حال دانلود icmptun-ctl.sh ..."
curl "${CURL_OPTS[@]}" "$RAW_URL" -o "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"
echo "نصب شد: $INSTALL_PATH"
echo

exec "$INSTALL_PATH"
