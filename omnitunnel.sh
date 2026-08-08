#!/bin/bash
# tunnelctl.sh - Multi-protocol obfuscated tunnel suite (part of the icmptun
# project). Drives ONE prebuilt static core binary ("tsuite") over an English
# TUI. No compiler needed on the box: the right binary for the CPU (amd64 or
# arm64) is shipped with the project.
#
#   gre      IP-over-GRE (kernel)  - often unpoliced / full line-rate
#   icmp     IP-over-ICMP          - blends in as ping (no key)
#   udp      IP-over-UDP AEAD      - fastest on open / UDP-friendly routes
#   tcp      IP-over-TCP AEAD      - one HTTPS-looking connection
#   mux      multi-connection TCP  - N parallel links; beats UDP-blocking DPI
#   ws       multi-connection WS   - looks like a browser/CDN WebSocket
#   hysteria Hysteria2 / QUIC      - Brutal CC beats UDP rate-policing; looks like HTTP/3
#
# One box runs many independent tunnels at once ("instances"), so any topology
# works: one Iran -> many foreign, one foreign -> many Iran, or many-to-many.
# Each instance has its own tun device, systemd unit, subnet and forward chain.
#
# State lives under /etc/omnitunnel, kept fully separate from any existing
# /etc/icmptun install (this tool never reads, edits or deletes that).
set -euo pipefail

VERSION="2.4.2"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

ROOT_DIR="/etc/omnitunnel"
INST_DIR="$ROOT_DIR/inst"
PEER_DIR="$ROOT_DIR/peers"
TSUITE_BIN="/usr/local/bin/omnitun"
BINLINK="/usr/local/bin/omnitunnel"   # the 'omnitunnel' command (symlink to this script)
# Hysteria2 is a separate Go engine (QUIC/UDP with the loss-agnostic "Brutal"
# congestion control). We ship its static binary alongside our C core and drive
# it through generated YAML - it is the stealthiest fast transport (looks like
# HTTP/3, with salamander obfs + website masquerade).
HYSTERIA_BIN="/usr/local/bin/hysteria"
HY_MASQ_HOST="www.bing.com"
# where the shipped per-arch binaries live (install.sh drops them here)
ASSET_DIR="${OMNITUN_ASSETS:-/opt/omnitunnel}"
RAW_BASE="https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel/main"

C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_ITAL=$'\033[3m'
C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
C_BLUE=$'\033[34m'; C_MAG=$'\033[35m'; C_WHITE=$'\033[97m'; C_GREY=$'\033[90m'
C_BGRN=$'\033[92m'; C_BCYN=$'\033[96m'; C_BYEL=$'\033[93m'; C_BRED=$'\033[91m'
# UI glyphs (fall back gracefully on dumb terminals - they are plain UTF-8)
G_DOT_ON="●"; G_DOT_OFF="○"; G_ARROW="→"; G_TL="╭"; G_TR="╮"; G_BL="╰"; G_BR="╯"; G_H="─"; G_V="│"

need_root() { [[ $EUID -eq 0 ]] || { printf '%b✗%b must be run as root\n' "$C_BRED$C_BOLD" "$C_RESET"; exit 1; }; }
die()  { printf '%b✗%b %s\n' "$C_BRED$C_BOLD" "$C_RESET" "$*" >&2; exit 1; }
ok()   { printf '%b✓%b %s\n' "$C_BGRN$C_BOLD" "$C_RESET" "$*"; }
info() { printf '%b›%b %s\n' "$C_BCYN$C_BOLD" "$C_RESET" "$*"; }
warn() { printf '%b!%b %s\n' "$C_BYEL$C_BOLD" "$C_RESET" "$*"; }
pause() { printf '\n  %bpress Enter to continue…%b' "$C_DIM" "$C_RESET"; read -r _ || true; }

arch_tag() { case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) echo unknown;; esac; }

# make sure /usr/local/bin/omnitun exists and matches this CPU
ensure_binary() {
    [[ -x "$TSUITE_BIN" ]] && return 0
    local a; a="$(arch_tag)"; [[ "$a" == unknown ]] && die "unsupported CPU: $(uname -m)"
    local cand=""
    for d in "$ASSET_DIR/bin" "$SCRIPT_DIR/bin"; do [[ -f "$d/omnitun-$a" ]] && cand="$d/omnitun-$a" && break; done
    [[ -n "$cand" ]] || die "core binary omnitun-$a not found (looked in $ASSET_DIR/bin and $SCRIPT_DIR/bin). Run install.sh."
    install -m 0755 "$cand" "$TSUITE_BIN"
}

# locate this box's hysteria binary (shipped in bin/, or downloadable)
hy_local_bin() {
    local a="$1" d
    for d in "$ASSET_DIR/bin" "$SCRIPT_DIR/bin"; do [[ -f "$d/hysteria-$a" ]] && { echo "$d/hysteria-$a"; return 0; }; done
    return 1
}
# make sure /usr/local/bin/hysteria exists for this CPU (ship-first, download-fallback)
ensure_hysteria() {
    [[ -x "$HYSTERIA_BIN" ]] && return 0
    local a; a="$(arch_tag)"; [[ "$a" == unknown ]] && die "unsupported CPU: $(uname -m)"
    local cand; cand="$(hy_local_bin "$a" || true)"
    if [[ -z "$cand" ]]; then
        info "  fetching hysteria core for $a ..."
        mkdir -p "$ASSET_DIR/bin"
        curl -fsSL -o "$ASSET_DIR/bin/hysteria-$a" \
            "https://github.com/apernet/hysteria/releases/download/app%2Fv2.12.0/hysteria-linux-$a" \
            || die "could not obtain hysteria-$a (no shipped copy and download failed)"
        chmod +x "$ASSET_DIR/bin/hysteria-$a"; cand="$ASSET_DIR/bin/hysteria-$a"
    fi
    install -m 0755 "$cand" "$HYSTERIA_BIN"
}

# ------------------------------------------------------------ type registry ---
ALL_TYPES="gre icmp udp mux ws hysteria tcp"
type_desc() {
    case "$1" in
        gre)      echo "IP-over-GRE  (kernel; often unpoliced & full line-rate)";;
        icmp)     echo "IP-over-ICMP  (blends in as ping; no key)";;
        udp)      echo "IP-over-UDP AEAD  (fastest where UDP is allowed)";;
        mux)      echo "multi-connection TCP  (N links; for UDP-blocking DPI)";;
        ws)       echo "multi-connection WebSocket  (looks like HTTPS; stealthy)";;
        hysteria) echo "Hysteria2/QUIC  (loss-agnostic; beats UDP rate-policing; looks like HTTP/3)";;
        tcp)      echo "single TCP AEAD  (looks like one HTTPS connection)";;
        *) echo "";;
    esac
}
# gre and icmp are kernel/plaintext carriers - no PSK
type_uses_key() { [[ "$1" != icmp && "$1" != gre ]]; }
# gre is a native kernel tunnel - no compiled core binary involved
type_is_kernel() { [[ "$1" == gre ]]; }
# hysteria is a separate engine: its own binary + YAML, no tun device, forwards
# ports natively (no iptables DNAT). It gets special-cased throughout.
type_is_hysteria() { [[ "$1" == hysteria ]]; }

# ------------------------------------------------------------ instance i/o ----
inst_path() { echo "$INST_DIR/$1"; }
inst_conf() { echo "$INST_DIR/$1/instance.conf"; }
inst_pf()   { echo "$INST_DIR/$1/pf.conf"; }
inst_exists() { [[ -f "$(inst_conf "$1")" ]]; }
list_instances() { [[ -d "$INST_DIR" ]] && ls -1 "$INST_DIR" 2>/dev/null | sort || true; }
svc_name() { echo "omnitun-$1.service"; }
dnat_chain() { echo "TSUITE_$(echo "$1" | tr '[:lower:]-' '[:upper:]_')"; }
gen_key() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
default_local_ip() { ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1; }

load_inst() {
    local n="$1"; inst_exists "$n" || die "no such instance: $n"
    TYPE=""; ROLE=""; LOCAL_IP=""; PEER_IP=""; TUN_ADDR=""; PEER_ADDR=""; PORT=""; KEY=""; DEV=""; MTU="1400"; NCONN="16"; SHAPE="none"
    # shellcheck disable=SC1090
    source "$(inst_conf "$n")"; INAME="$n"
}

# create NAME TYPE ROLE LOCAL PEER PORT KEY TUN_ADDR PEER_ADDR [SHAPE] [NCONN]
create_inst() {
    local n="$1" t="$2" role="$3" lip="$4" pip="$5" port="$6" key="$7" ta="$8" pa="$9" shape="${10:-none}" nc="${11:-16}"
    local dev="ts-$n"; [[ ${#dev} -gt 15 ]] && dev="ts$(echo "$n" | cksum | cut -c1-8)"
    mkdir -p "$(inst_path "$n")"; : > "$(inst_pf "$n")"
    cat > "$(inst_conf "$n")" <<EOF
TYPE=$t
ROLE=$role
LOCAL_IP=$lip
PEER_IP=$pip
TUN_ADDR=$ta
PEER_ADDR=$pa
PORT=$port
KEY=$key
DEV=$dev
MTU=1400
NCONN=$nc
SHAPE=$shape
EOF
}

# ------------------------------------------------------- execstart builder ----
build_execstart() {
    local sflag=""; [[ "$ROLE" == "server" ]] && sflag=" -s"
    case "$TYPE" in
        udp)  echo "$TSUITE_BIN udp -L $LOCAL_IP -R $PEER_IP -A $TUN_ADDR -P $PEER_ADDR -p $PORT -k $KEY -T $DEV -M $MTU";;
        tcp)  echo "$TSUITE_BIN tcp -L $LOCAL_IP -R $PEER_IP -A $TUN_ADDR -P $PEER_ADDR -p $PORT -k $KEY$sflag -T $DEV -M $MTU";;
        mux)  echo "$TSUITE_BIN mux -L $LOCAL_IP -R $PEER_IP -A $TUN_ADDR -P $PEER_ADDR -p $PORT -k $KEY$sflag -N $NCONN -T $DEV -M $MTU";;
        ws)   echo "$TSUITE_BIN ws -L $LOCAL_IP -R $PEER_IP -A $TUN_ADDR -P $PEER_ADDR -p $PORT -k $KEY$sflag -N $NCONN -T $DEV -M $MTU";;
        icmp) echo "$TSUITE_BIN icmp -L $LOCAL_IP -R $PEER_IP -A $TUN_ADDR -P $PEER_ADDR -I 4d54 -T $DEV -M $MTU$sflag";;
    esac
}

# ------------------------------------------------------- hysteria config ------
# One 64-hex KEY seeds both the auth password and the salamander obfs password,
# so the two ends stay in sync from the same secret.
hy_creds() { HY_AUTH="${KEY:0:32}"; HY_OBFS="${KEY:32:32}"; [[ -n "$HY_OBFS" ]] || HY_OBFS="$HY_AUTH"; }
hy_bw() { case "${1:-}" in ''|none|0) echo 200;; *) echo "${1%%[a-z]*}";; esac; }  # -> mbps number
# self-signed cert (masquerade CN) generated once per instance
hy_cert() {
    local d="$1"; [[ -f "$d/hy.crt" && -f "$d/hy.key" ]] && return 0
    openssl req -x509 -newkey rsa:2048 -keyout "$d/hy.key" -out "$d/hy.crt" \
        -days 3650 -nodes -subj "/CN=$HY_MASQ_HOST" >/dev/null 2>&1 || die "openssl needed for hysteria cert"
    chmod 600 "$d/hy.key"
}
# render the hysteria YAML for instance <n> into file <out>.
# The engine config holds only the transport + a localhost SOCKS5 (always on, so
# it stays connected before any forward is added) + any UDP forwards. TCP
# forwards deliberately live OUTSIDE the engine (see relays below) so that
# adding/removing one never restarts the engine or disturbs the QUIC session.
hy_render_config() {
    local n="$1" out="$2"; load_inst "$n"; local d; d="$(inst_path "$n")"; hy_creds
    if [[ "$ROLE" == server ]]; then
        hy_cert "$d"
        cat > "$out" <<EOF
listen: :$PORT
tls:
  cert: $d/hy.crt
  key: $d/hy.key
obfs:
  type: salamander
  salamander:
    password: $HY_OBFS
auth:
  type: password
  password: $HY_AUTH
masquerade:
  type: proxy
  proxy:
    url: https://$HY_MASQ_HOST/
    rewriteHost: true
EOF
    else
        local bw; bw="$(hy_bw "$SHAPE")"
        cat > "$out" <<EOF
server: $PEER_IP:$PORT
auth: $HY_AUTH
tls:
  insecure: true
  sni: $HY_MASQ_HOST
obfs:
  type: salamander
  salamander:
    password: $HY_OBFS
bandwidth:
  up: ${bw} mbps
  down: ${bw} mbps
socks5:
  listen: 127.0.0.1:$PORT
EOF
        # UDP forwards can't ride the SOCKS5 relay, so they stay in-config (adding
        # a UDP forward is the one case that still restarts the engine). TCP
        # forwards are normally handled by standalone relays and are NOT emitted
        # here; only the python3-less fallback sets HY_TCP_IN_CONFIG=1.
        local pf udp_e="" tcp_e="" proto port; pf="$(inst_pf "$n")"
        if [[ -s "$pf" ]]; then
            while IFS=: read -r proto port; do [[ -z "$proto" || -z "$port" ]] && continue
                local blk="  - listen: 0.0.0.0:$port"$'\n'"    remote: 127.0.0.1:$port"$'\n'
                [[ "$proto" == udp ]] && udp_e+="$blk"
                [[ "$proto" == tcp && "${HY_TCP_IN_CONFIG:-0}" == 1 ]] && tcp_e+="$blk"
            done < "$pf"
        fi
        [[ -n "$tcp_e" ]] && { echo "tcpForwarding:" >> "$out"; printf '%s' "$tcp_e" >> "$out"; }
        [[ -n "$udp_e" ]] && { echo "udpForwarding:" >> "$out"; printf '%s' "$udp_e" >> "$out"; }
    fi
    chmod 600 "$out" 2>/dev/null || true
}
hy_write_config() { hy_render_config "$1" "$(inst_path "$1")/hy.yaml"; }

# --- zero-disruption TCP forwards: one tiny relay per port, through the SOCKS5 --
# Each relay listens on 0.0.0.0:<port> and dials 127.0.0.1:<port> (resolved at the
# far end) via the client's local SOCKS5. It is its own systemd unit, so adding a
# port starts one relay and touches nothing else; the engine never restarts.
HY_RELAY="$ASSET_DIR/socksfwd.py"
hy_relay_unit() { echo "omnitun-$1-pf-$2.service"; }   # <inst> <port>
hy_write_relay_script() {
    [[ -f "$HY_RELAY" ]] && return 0
    mkdir -p "$(dirname "$HY_RELAY")"
    cat > "$HY_RELAY" <<'PYEOF'
import sys, socket, struct, threading
def s5(sh, sp, th, tp):
    s = socket.create_connection((sh, sp), timeout=10)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00": s.close(); raise IOError("no-auth refused")
    t = th.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(t)]) + t + struct.pack(">H", tp))
    r = s.recv(4)
    if len(r) < 2 or r[1] != 0: s.close(); raise IOError("connect refused")
    a = r[3]
    s.recv(4+2) if a == 1 else (s.recv(s.recv(1)[0]+2) if a == 3 else s.recv(16+2))
    return s
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except OSError: pass
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except OSError: pass
def handle(c, sh, sp, th, tp):
    try: u = s5(sh, sp, th, tp)
    except Exception: c.close(); return
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    pipe(u, c)
    for x in (c, u):
        try: x.close()
        except OSError: pass
def main():
    lh, lp, sh, sp, th, tp = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5], int(sys.argv[6])
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lh, lp)); srv.listen(256)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, sh, sp, th, tp), daemon=True).start()
main()
PYEOF
    chmod 755 "$HY_RELAY"
}
# reconcile the running per-port relays with pf.conf (client side only)
hy_reconcile_relays() {
    load_inst "$1"; local pf socksport="$PORT" changed=0; pf="$(inst_pf "$1")"
    local want=(); if [[ -s "$pf" ]]; then local pr po
        while IFS=: read -r pr po; do [[ "$pr" == tcp && -n "$po" ]] && want+=("$po"); done < "$pf"; fi
    hy_write_relay_script
    # stop relays whose port is no longer wanted
    local f base port u
    for f in /etc/systemd/system/omnitun-"$1"-pf-*.service; do
        [[ -e "$f" ]] || continue
        base="$(basename "$f")"; port="${base#omnitun-$1-pf-}"; port="${port%.service}"
        if ! printf '%s\n' "${want[@]:-}" | grep -qx "$port"; then
            systemctl disable --now "$base" >/dev/null 2>&1 || true; rm -f "$f"; changed=1
        fi
    done
    # write units for wanted ports
    for port in "${want[@]:-}"; do [[ -z "$port" ]] && continue
        u="$(hy_relay_unit "$1" "$port")"
        cat > "/etc/systemd/system/$u" <<EOF
[Unit]
Description=OmniTunnel hysteria forward $1 tcp/$port
After=network-online.target $(svc_name "$1")
Wants=$(svc_name "$1")

[Service]
Type=simple
ExecStart=/usr/bin/env python3 $HY_RELAY 0.0.0.0 $port 127.0.0.1 $socksport 127.0.0.1 $port
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
        changed=1
    done
    [[ "$changed" == 1 ]] && systemctl daemon-reload
    # start only the relays that are not already up (existing ones stay untouched)
    for port in "${want[@]:-}"; do [[ -z "$port" ]] && continue
        u="$(hy_relay_unit "$1" "$port")"
        systemctl enable "$u" >/dev/null 2>&1 || true
        systemctl is-active --quiet "$u" || systemctl start "$u" >/dev/null 2>&1 || true
    done
    return 0
}
# tear down all relays for an instance (used on remove)
hy_remove_relays() {
    local f base changed=0
    for f in /etc/systemd/system/omnitun-"$1"-pf-*.service; do
        [[ -e "$f" ]] || continue
        base="$(basename "$f")"; systemctl disable --now "$base" >/dev/null 2>&1 || true
        rm -f "$f"; changed=1
    done
    [[ "$changed" == 1 ]] && systemctl daemon-reload || true
    return 0
}
# apply pf.conf for a hysteria instance with the least possible disruption:
# rebuild the engine config and restart ONLY if it actually changed (i.e. a UDP
# forward was added/removed, or the python3-less TCP fallback is in play); TCP
# forwards are normally reconciled as standalone relays and never bounce engine.
hy_pf_reconcile() {
    load_inst "$1"
    local have_py=1; command -v python3 >/dev/null 2>&1 || have_py=0
    local d yaml tmp; d="$(inst_path "$1")"; yaml="$d/hy.yaml"; tmp="$d/hy.yaml.new"
    if [[ "$ROLE" != server && "$have_py" == 0 ]]; then
        warn "python3 not found: hysteria TCP forwards stay in-config (engine restarts on change)"
        HY_TCP_IN_CONFIG=1 hy_render_config "$1" "$tmp"
    else
        hy_render_config "$1" "$tmp"
    fi
    if ! cmp -s "$tmp" "$yaml" 2>/dev/null; then
        mv "$tmp" "$yaml"; chmod 600 "$yaml" 2>/dev/null || true
        inst_running "$1" && systemctl restart "$(svc_name "$1")" 2>/dev/null || true
    else rm -f "$tmp"; fi
    [[ "$ROLE" == server ]] && return 0
    [[ "$have_py" == 1 ]] && hy_reconcile_relays "$1"
    return 0
}

# ------------------------------------------------------------- tuning ---------
apply_tuning() {
    local dev="$1" shape="${2:-none}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.core.rmem_max=67108864 >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=67108864 >/dev/null 2>&1 || true
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    modprobe tcp_bbr 2>/dev/null || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    local i; for i in $(seq 1 40); do ip link show "$dev" >/dev/null 2>&1 && break; sleep 0.25; done
    ip link set "$dev" txqueuelen 1000 2>/dev/null || true
    if [[ "$shape" != none && -n "$shape" ]]; then
        tc qdisc replace dev "$dev" root tbf rate "$shape" burst 128kb latency 30ms 2>/dev/null || true
    else
        tc qdisc replace dev "$dev" root fq 2>/dev/null || true
    fi
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$dev" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$dev" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -i "$dev" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i "$dev" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}

# --------------------------------------------------- systemd unit + enable ----
write_service() {
    load_inst "$1"
    if type_is_hysteria "$TYPE"; then ensure_hysteria
    elif ! type_is_kernel "$TYPE"; then ensure_binary; fi
    local unit="/etc/systemd/system/$(svc_name "$1")"
    if type_is_hysteria "$TYPE"; then
        hy_write_config "$1"
        local mode=client; [[ "$ROLE" == server ]] && mode=server
        cat > "$unit" <<EOF
[Unit]
Description=OmniTunnel hysteria instance $1 ($ROLE $LOCAL_IP -> $PEER_IP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$HYSTERIA_BIN $mode -c $(inst_path "$1")/hy.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    elif type_is_kernel "$TYPE"; then
        # GRE (or other native kernel carrier): configured on start, removed on
        # stop. PORT doubles as the GRE key so several GRE tunnels can share an
        # endpoint pair without colliding. No compiled core binary involved.
        cat > "$unit" <<EOF
[Unit]
Description=OmniTunnel $TYPE instance $1 ($ROLE $LOCAL_IP -> $PEER_IP)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'modprobe ip_gre 2>/dev/null; ip link del $DEV 2>/dev/null; ip link add $DEV type gre local $LOCAL_IP remote $PEER_IP ttl 255 key $PORT; ip addr add $TUN_ADDR peer $PEER_ADDR dev $DEV; ip link set $DEV up mtu $MTU'
ExecStartPost=$SCRIPT_PATH _postup $1
ExecStop=-/sbin/ip link del $DEV
Restart=no

[Install]
WantedBy=multi-user.target
EOF
    else
        cat > "$unit" <<EOF
[Unit]
Description=OmniTunnel $TYPE instance $1 ($ROLE $LOCAL_IP -> $PEER_IP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/sbin/ip link del $DEV
ExecStart=$(build_execstart)
ExecStartPost=$SCRIPT_PATH _postup $1
Restart=always
RestartSec=3
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload
}
cmd_postup() { load_inst "$1"; apply_tuning "$DEV" "$SHAPE"; pf_apply_all "$1" || true; }

inst_enable() {
    need_root; load_inst "$1"; write_service "$1"
    systemctl enable "$(svc_name "$1")" >/dev/null 2>&1 || true
    systemctl restart "$(svc_name "$1")"; sleep 2; inst_status "$1"
}
inst_running() { systemctl is-active "$(svc_name "$1")" >/dev/null 2>&1; }
inst_status() {
    load_inst "$1"
    local running=0; inst_running "$1" && running=1
    local dot col; if [[ $running == 1 ]]; then dot="$G_DOT_ON"; col="$C_BGRN"; else dot="$G_DOT_OFF"; col="$C_GREY"; fi
    local port=""; [[ -n "$PORT" && "$TYPE" != icmp ]] && port=":$PORT"
    # identity line: ● name  type  role  local -> peer:port
    printf '  %b%s%b %b%-13s%b %b%-9s%b %b%-6s%b %s %b%s%b %s%s\n' \
        "$col" "$dot" "$C_RESET" "$C_BOLD$C_WHITE" "$1" "$C_RESET" \
        "$C_MAG" "$TYPE" "$C_RESET" "$C_DIM" "$ROLE" "$C_RESET" \
        "$LOCAL_IP" "$C_CYAN" "$G_ARROW" "$C_RESET" "$PEER_IP" "$port"
    # detail line: health
    local detail
    if [[ $running == 0 ]]; then
        detail="${C_GREY}stopped${C_RESET}"
    elif type_is_hysteria "$TYPE"; then
        local nf; nf=$(grep -c . "$(inst_pf "$1")" 2>/dev/null || echo 0)
        detail="${C_BGRN}connected${C_RESET}   ${C_DIM}forwards${C_RESET} ${C_WHITE}${nf}${C_RESET}   ${C_DIM}socks${C_RESET} 127.0.0.1:$PORT"
    elif ip link show "$DEV" >/dev/null 2>&1; then
        local out loss rtt; out=$(ping -c2 -W2 "$PEER_ADDR" 2>/dev/null || true)
        loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' || true)
        rtt=$(echo "$out" | awk -F'/' '/rtt|round-trip/{print $5}' || true)
        if [[ -n "$rtt" ]]; then
            local lc="$C_BGRN"; [[ -n "$loss" && "$loss" -gt 0 ]] && lc="$C_BYEL"
            detail="${C_BGRN}up${C_RESET}   ${C_DIM}rtt${C_RESET} ${C_WHITE}${rtt}${C_RESET}ms   ${lc}${loss:-?}% loss${C_RESET}"
            [[ "$TYPE" == tcp || "$TYPE" == mux ]] && detail="$detail   ${C_DIM}links${C_RESET} $(ss -tn state established 2>/dev/null | grep -c ":$PORT" || echo 0)"
        else detail="${C_GREEN}interface up${C_RESET}"; fi
    else detail="${C_BYEL}starting...${C_RESET}"; fi
    printf '     %b%s%b %s\n' "$C_GREY" "$G_V" "$C_RESET" "$detail"
}

# ------------------------------------------------------------- port fwd -------
pf_apply_all() {
    load_inst "$1"
    # hysteria forwards ports outside iptables: TCP via per-port relays (no engine
    # restart), UDP in-config (restart only if the UDP set changed).
    if type_is_hysteria "$TYPE"; then
        hy_pf_reconcile "$1"
        return 0
    fi
    local pf; pf="$(inst_pf "$1")"; [[ -f "$pf" ]] || return 0
    local ch; ch="$(dnat_chain "$1")"
    iptables -t nat -N "$ch" 2>/dev/null || true; iptables -t nat -F "$ch"
    iptables -t nat -C PREROUTING -j "$ch" 2>/dev/null || iptables -t nat -I PREROUTING 1 -j "$ch"
    iptables -t nat -C POSTROUTING -o "$DEV" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$DEV" -j MASQUERADE
    local proto port
    while IFS=: read -r proto port; do [[ -z "$proto" ]] && continue
        iptables -t nat -A "$ch" -p "$proto" --dport "$port" -j DNAT --to-destination "$PEER_ADDR:$port"; done < "$pf"
}
pf_add() {
    need_root; load_inst "$1"; local proto="$2" port="$3"
    [[ "$proto" =~ ^(tcp|udp|both)$ ]] || die "proto must be tcp|udp|both"
    local pf pr; pf="$(inst_pf "$1")"
    for pr in $([[ "$proto" == both ]] && echo "tcp udp" || echo "$proto"); do
        grep -qx "$pr:$port" "$pf" 2>/dev/null || echo "$pr:$port" >> "$pf"; done
    pf_apply_all "$1"; ok "forwarding $proto/$port through '$1' to $PEER_ADDR"
}
pf_del() {
    need_root; load_inst "$1"; local port="$2" pf; pf="$(inst_pf "$1")"
    [[ -f "$pf" ]] && { grep -v ":$port\$" "$pf" > "$pf.t" || true; mv "$pf.t" "$pf"; }
    pf_apply_all "$1"; ok "removed forward on port $port from '$1'"
}
pf_flush_chain() {
    load_inst "$1" 2>/dev/null || return 0; local ch; ch="$(dnat_chain "$1")"
    iptables -t nat -D PREROUTING -j "$ch" 2>/dev/null || true
    iptables -t nat -F "$ch" 2>/dev/null || true; iptables -t nat -X "$ch" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$DEV" -j MASQUERADE 2>/dev/null || true
}

# --------------------------------------------------------------- remove -------
# Removes ONLY the named instance this tool created. Never touches /etc/icmptun
# or any interface / unit it did not create.
inst_remove() {
    need_root; inst_exists "$1" || { warn "no such instance: $1"; return 0; }
    load_inst "$1"
    type_is_hysteria "$TYPE" && hy_remove_relays "$1"
    systemctl disable --now "$(svc_name "$1")" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$(svc_name "$1")"
    systemctl reset-failed "$(svc_name "$1")" 2>/dev/null || true   # no lingering 'not-found failed' ghost
    systemctl daemon-reload 2>/dev/null || true
    pf_flush_chain "$1"; ip link del "$DEV" 2>/dev/null || true
    rm -rf "$(inst_path "$1")"; ok "removed instance '$1'"
}

# allocation helpers (non-overlapping subnet + free udp/tcp port per box)
next_subnet_idx() {
    local i=0 n used
    for n in $(list_instances); do
        used=$(grep -oE 'TUN_ADDR=10\.201\.[0-9]+' "$(inst_conf "$n")" 2>/dev/null | grep -oE '[0-9]+$' || true)
        [[ -n "$used" && "$used" -ge "$i" ]] && i=$((used+1)); done
    echo "$i"
}
next_port() {
    local cand="${1:-51820}" used
    used=$(grep -hoE 'PORT=[0-9]+' "$INST_DIR"/*/instance.conf 2>/dev/null | grep -oE '[0-9]+' || true)
    while echo "$used" | grep -qx "$cand"; do cand=$((cand+1)); done; echo "$cand"
}

# ------------------------------------------------------------ peer SSH --------
peer_conf() { echo "$PEER_DIR/$1.conf"; }
save_peer() {
    mkdir -p "$PEER_DIR"; chmod 700 "$PEER_DIR"
    { printf 'PEER_USER=%s\nPEER_PASS=%s\n' "$2" "$3"; [[ -n "${4:-}" ]] && printf 'PEER_PROXY=%s\n' "$4"; } > "$(peer_conf "$1")"
    chmod 600 "$(peer_conf "$1")"
}
_peer_creds() { PEER_USER=root; PEER_PASS=""; PEER_PROXY=""; local f; f="$(peer_conf "$1")"; [[ -f "$f" ]] && source "$f"; return 0; }
# Provisioning SSH: don't let a stale/changed host key block automation
# (servers get reinstalled and their keys rotate). We authenticate with a
# password or an ssh key, not TOFU. An optional saved SOCKS5 proxy routes the
# provisioning SSH/SCP around an ISP that blocks the foreign box's port 22 -
# this only affects the outbound connection we make, never any server's sshd.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=15)
_proxy_opts() { PROXY_OPTS=(); [[ -n "${PEER_PROXY:-}" ]] && PROXY_OPTS=(-o "ProxyCommand=nc -X 5 -x $PEER_PROXY %h %p"); return 0; }
peer_ssh() { local h="$1"; shift; _peer_creds "$h"; _proxy_opts
    if [[ -n "$PEER_PASS" ]] && command -v sshpass >/dev/null; then
        sshpass -p "$PEER_PASS" ssh "${SSH_OPTS[@]}" ${PROXY_OPTS[@]+"${PROXY_OPTS[@]}"} "$PEER_USER@$h" "$@"
    else ssh "${SSH_OPTS[@]}" ${PROXY_OPTS[@]+"${PROXY_OPTS[@]}"} "$PEER_USER@$h" "$@"; fi
}
peer_scp() { local h="$1" s="$2" d="$3"; _peer_creds "$h"; _proxy_opts
    if [[ -n "$PEER_PASS" ]] && command -v sshpass >/dev/null; then
        sshpass -p "$PEER_PASS" scp "${SSH_OPTS[@]}" ${PROXY_OPTS[@]+"${PROXY_OPTS[@]}"} "$s" "$PEER_USER@$h:$d"
    else scp "${SSH_OPTS[@]}" ${PROXY_OPTS[@]+"${PROXY_OPTS[@]}"} "$s" "$PEER_USER@$h:$d"; fi
}

# push the manager + the peer's own-arch binary, then bring up the server side
provision_peer() {
    local h="$1" name="$2" t="$3" plip="$4" prip="$5" port="$6" key="$7" pta="$8" ppa="$9" shape="${10}" nc="${11}"
    local parch; parch=$(peer_ssh "$h" "uname -m" 2>/dev/null | tr -d '\r')
    case "$parch" in x86_64|amd64) parch=amd64;; aarch64|arm64) parch=arm64;; *) die "peer $h has unsupported CPU: $parch";; esac
    info "  far side is $parch; deploying engine + manager to $h ..."
    peer_ssh "$h" "mkdir -p /opt/omnitunnel/bin"
    peer_scp "$h" "$SCRIPT_PATH" "/opt/omnitunnel/omnitunnel.sh"
    peer_ssh "$h" "chmod +x /opt/omnitunnel/omnitunnel.sh"
    if type_is_hysteria "$t"; then
        local hbin; hbin="$(hy_local_bin "$parch" || true)"
        [[ -n "$hbin" ]] || die "no hysteria-$parch binary to send to peer"
        peer_scp "$h" "$hbin" "/opt/omnitunnel/bin/hysteria-$parch"
        peer_ssh "$h" "chmod +x /opt/omnitunnel/bin/hysteria-$parch; install -m0755 /opt/omnitunnel/bin/hysteria-$parch /usr/local/bin/hysteria"
    else
        local pbin=""
        for d in "$ASSET_DIR/bin" "$SCRIPT_DIR/bin"; do [[ -f "$d/omnitun-$parch" ]] && pbin="$d/omnitun-$parch" && break; done
        [[ -n "$pbin" ]] || die "no omnitun-$parch binary to send to peer"
        peer_scp "$h" "$pbin" "/opt/omnitunnel/bin/omnitun-$parch"
        peer_ssh "$h" "chmod +x /opt/omnitunnel/bin/omnitun-$parch; install -m0755 /opt/omnitunnel/bin/omnitun-$parch /usr/local/bin/omnitun"
    fi
    peer_ssh "$h" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _peercreate '$name' '$t' server '$plip' '$prip' '$port' '$key' '$pta' '$ppa' '$shape' '$nc'"
}
cmd_peercreate() {
    need_root
    if type_is_hysteria "$2"; then ensure_hysteria
    elif ! type_is_kernel "$2"; then ensure_binary; fi
    create_inst "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}"
    inst_enable "$1" >/dev/null 2>&1 || true; ok "peer instance '$1' up"
}

# Non-interactive add for scripting/automation.
# add-auto <type> <name> <foreign_ip> [nconn] [shape] [my_ip]
# Far-side SSH password comes from a saved peer file or $OMNITUN_PEER_PASS
# (+ optional $OMNITUN_PEER_USER, default root).
cmd_add_auto() {
    need_root; ensure_binary
    local t="$1" kn="$2" fhost="$3" nc="${4:-16}" shape="${5:-none}" mylip="${6:-$(default_local_ip)}"
    [[ -n "$t" && -n "$kn" && -n "$fhost" ]] || die "usage: add-auto <type> <name> <foreign_ip> [nconn] [shape] [my_ip]"
    inst_exists "$kn" && die "instance $kn exists"
    [[ -n "${OMNITUN_PEER_PASS:-}" ]] && save_peer "$fhost" "${OMNITUN_PEER_USER:-root}" "$OMNITUN_PEER_PASS"
    local sub port key ta pa; sub=$(next_subnet_idx); ta="10.201.$sub.1"; pa="10.201.$sub.2"
    port=$(next_port $((51820+sub))); key=$(gen_key); [[ "$t" == icmp || "$t" == gre ]] && key=""
    provision_peer "$fhost" "$kn" "$t" "$fhost" "$mylip" "$port" "$key" "$pa" "$ta" "$shape" "$nc"
    create_inst "$kn" "$t" client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" "$shape" "$nc"
    inst_enable "$kn"; ok "instance '$kn' ($t) up: $mylip -> $fhost"
}

# ---------------------------------------------------------- MANUAL mode --------
# For hostile ISPs where the near box cannot reach the foreign box's SSH at all
# (e.g. port 22 blocked). NO SSH between the boxes is used: this brings up the
# near (client) side and prints a single token to paste on the foreign box.
# It never touches any server's own sshd or port 22.
# add-manual <type> <name> <foreign_ip> [nconn] [shape] [my_ip]
cmd_add_manual() {
    need_root
    if type_is_hysteria "$1"; then ensure_hysteria
    elif ! type_is_kernel "$1"; then ensure_binary; fi
    local t="$1" kn="$2" fhost="$3" nc="${4:-16}" shape="${5:-none}" mylip="${6:-$(default_local_ip)}" want_port="${7:-}"
    [[ -n "$t" && -n "$kn" && -n "$fhost" ]] || die "usage: add-manual <type> <name> <foreign_ip> [nconn] [shape] [my_ip] [foreign_port]"
    inst_exists "$kn" && die "instance $kn exists"
    local sub port key ta pa; sub=$(next_subnet_idx); ta="10.201.$sub.1"; pa="10.201.$sub.2"
    port=$(next_port "${want_port:-$((51820+sub))}"); key=$(gen_key); [[ "$t" == icmp || "$t" == gre ]] && key=""
    create_inst "$kn" "$t" client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" "$shape" "$nc"
    inst_enable "$kn"
    # Server-side params (tun IPs swapped). Encoded so it is a single paste.
    local token; token=$(printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' "$kn" "$t" "$fhost" "$mylip" "$port" "$key" "$pa" "$ta" "$shape" "$nc" | base64 | tr -d '\n')
    echo
    echo "${C_GREEN}${C_BOLD}Near (Iran) side '$kn' is up.${C_RESET}"
    echo "${C_BOLD}Now run these TWO lines on the FOREIGN server ($fhost):${C_RESET}"
    echo
    echo "  ${C_CYAN}bash <(curl -fsSL $RAW_BASE/install.sh)${C_RESET}"
    echo "  ${C_CYAN}omnitunnel server-token $token${C_RESET}"
    echo
    echo "${C_DIM}No SSH is used between the servers, and nothing changes any server's"
    echo "own SSH login or port 22. The tunnel uses its own port ($port).${C_RESET}"
}
# Consume a token on the foreign box to bring up the matching server side.
cmd_server_token() {
    need_root
    local dec; dec=$(printf '%s' "$1" | base64 -d 2>/dev/null) || die "invalid token"
    local name t fhost mylip port key pta ppa shape nc
    IFS='|' read -r name t fhost mylip port key pta ppa shape nc <<< "$dec"
    [[ -n "$name" && -n "$t" ]] || die "invalid token"
    if type_is_hysteria "$t"; then ensure_hysteria
    elif ! type_is_kernel "$t"; then ensure_binary; fi
    inst_exists "$name" && die "instance $name already exists"
    create_inst "$name" "$t" server "$fhost" "$mylip" "$port" "$key" "$pta" "$ppa" "$shape" "$nc"
    inst_enable "$name"
    ok "foreign (server) side '$name' is up: $fhost <- $mylip"
}

# ------------------------------------------------------------ add wizard ------
wizard_add() {
    need_root; ensure_binary
    echo; echo "${C_BOLD}Add a tunnel  (this box = near side / client; far = foreign / server)${C_RESET}"
    local ci=1 types=() t
    for t in $ALL_TYPES; do printf "  %d) %-5s %s\n" "$ci" "$t" "$(type_desc "$t")"; types+=("$t"); ci=$((ci+1)); done
    read -rp "Tunnel type [1]: " ch; ch="${ch:-1}"; t="${types[$((ch-1))]:-}"; [[ -z "$t" ]] && { warn "invalid"; return; }
    local mylip; mylip="$(default_local_ip)"
    read -rp "This box public IP [$mylip]: " x; mylip="${x:-$mylip}"
    read -rp "Far (foreign) server IP: " fhost; [[ -z "$fhost" ]] && { warn "need a foreign IP"; return; }
    read -rp "Far SSH user [root]: " fu; fu="${fu:-root}"
    read -rsp "Far SSH password (blank = ssh key): " fp; echo; [[ -n "$fp" ]] && save_peer "$fhost" "$fu" "$fp"
    read -rp "Instance name [main]: " kn; kn="${kn:-main}"; inst_exists "$kn" && { warn "instance exists"; return; }
    local nc=16 shape=none
    if [[ "$t" == mux ]]; then
        read -rp "Parallel links N [16]: " nc; nc="${nc:-16}"
        read -rp "Download shaper rate to stabilise (e.g. 90mbit / none) [none]: " shape; shape="${shape:-none}"
    elif [[ "$t" == hysteria ]]; then
        read -rp "Brutal-CC target bandwidth in mbps (higher pushes harder through loss) [200]: " shape; shape="${shape:-200}"
    fi
    local sub port key ta pa; sub=$(next_subnet_idx); ta="10.201.$sub.1"; pa="10.201.$sub.2"
    port=$(next_port $((51820+sub))); key=$(gen_key)
    provision_peer "$fhost" "$kn" "$t" "$fhost" "$mylip" "$port" "$key" "$pa" "$ta" "$shape" "$nc"
    create_inst "$kn" "$t" client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" "$shape" "$nc"
    inst_enable "$kn"; ok "instance '$kn' ($t) is up on both sides."
}

# Manual add: brings up the near side and prints a token to paste on the
# foreign box. Use it when this box cannot reach the foreign box over SSH.
wizard_add_manual() {
    need_root; ensure_binary
    echo; echo "${C_BOLD}Add a tunnel - MANUAL${C_RESET} ${C_DIM}(no SSH to the foreign; nothing touches port 22)${C_RESET}"
    local ci=1 types=() t
    for t in $ALL_TYPES; do printf "  %d) %-5s %s\n" "$ci" "$t" "$(type_desc "$t")"; types+=("$t"); ci=$((ci+1)); done
    read -rp "Tunnel type [2]: " ch; ch="${ch:-2}"; t="${types[$((ch-1))]:-}"; [[ -z "$t" ]] && { warn "invalid"; return; }
    local mylip; mylip="$(default_local_ip)"
    read -rp "This box public IP [$mylip]: " x; mylip="${x:-$mylip}"
    read -rp "Far (foreign) server IP: " fhost; [[ -z "$fhost" ]] && { warn "need a foreign IP"; return; }
    read -rp "Instance name [main]: " kn; kn="${kn:-main}"; inst_exists "$kn" && { warn "instance exists"; return; }
    local nc=16 shape=none
    if [[ "$t" == mux ]]; then
        read -rp "Parallel links N [16]: " nc; nc="${nc:-16}"
        read -rp "Download shaper rate (e.g. 90mbit / none) [none]: " shape; shape="${shape:-none}"
    fi
    cmd_add_manual "$t" "$kn" "$fhost" "$nc" "$shape" "$mylip"
}

# ----------------------------------------------------------- benchmark --------
# The measurement server (iperf3) MUST be listening on :5599 on the foreign, or
# every tunnel measures nothing and the table is all-FAIL. Ensure it is up (or
# report clearly why it can't be) so the user isn't left guessing.
bench_ensure_iperf() {
    local h="$1" i
    for i in 1 2 3; do
        peer_ssh "$h" "ss -HlntuS 2>/dev/null | grep -q ':5599 ' || ss -lntu 2>/dev/null | grep -q ':5599 '" && return 0
        peer_ssh "$h" "command -v iperf3 >/dev/null 2>&1 || { apt-get install -y iperf3 >/dev/null 2>&1 || yum install -y iperf3 >/dev/null 2>&1 || true; }
            (systemctl reset-failed tsbench-iperf 2>/dev/null; systemd-run --unit=tsbench-iperf --collect iperf3 -s -p 5599 >/dev/null 2>&1) \
              || (setsid iperf3 -s -p 5599 >/dev/null 2>&1 </dev/null &); true" >/dev/null 2>&1 || true
        sleep 2
    done
    peer_ssh "$h" "ss -lntu 2>/dev/null | grep -q ':5599 '"
}
bench_run() {
    need_root; ensure_binary
    local fhost fu fp mylip x
    read -rp "Foreign server IP to benchmark against: " fhost; [[ -z "$fhost" ]] && { warn "need a foreign IP"; return; }
    read -rp "Foreign SSH user [root]: " fu; fu="${fu:-root}"
    read -rsp "Foreign SSH password (blank = ssh key): " fp; echo; [[ -n "$fp" ]] && save_peer "$fhost" "$fu" "$fp"
    mylip="$(default_local_ip)"; read -rp "This box public IP [$mylip]: " x; mylip="${x:-$mylip}"
    command -v iperf3 >/dev/null || { warn "installing iperf3..."; apt-get install -y iperf3 >/dev/null 2>&1 || yum install -y iperf3 >/dev/null 2>&1 || true; }

    # deploy core + iperf3 server on the far side
    local parch; parch=$(peer_ssh "$fhost" "uname -m" 2>/dev/null | tr -d '\r')
    case "$parch" in x86_64|amd64) parch=amd64;; aarch64|arm64) parch=arm64;; *) die "peer CPU $parch unsupported";; esac
    local pbin=""; for d in "$ASSET_DIR/bin" "$SCRIPT_DIR/bin"; do [[ -f "$d/omnitun-$parch" ]] && pbin="$d/omnitun-$parch"; done
    info "Deploying suite to $fhost ($parch)..."
    peer_ssh "$fhost" "mkdir -p /opt/omnitunnel/bin" || die "cannot reach $fhost"
    peer_scp "$fhost" "$pbin" "/opt/omnitunnel/bin/omnitun-$parch"
    peer_scp "$fhost" "$SCRIPT_PATH" "/opt/omnitunnel/omnitunnel.sh"
    peer_ssh "$fhost" "chmod +x /opt/omnitunnel/omnitunnel.sh; install -m0755 /opt/omnitunnel/bin/omnitun-$parch /usr/local/bin/omnitun" >/dev/null 2>&1 || true
    # hysteria engine for the far side too (so its bench server can come up)
    local hbin; hbin="$(hy_local_bin "$parch" || true)"
    [[ -n "$hbin" ]] && { peer_scp "$fhost" "$hbin" "/opt/omnitunnel/bin/hysteria-$parch"; peer_ssh "$fhost" "chmod +x /opt/omnitunnel/bin/hysteria-$parch; install -m0755 /opt/omnitunnel/bin/hysteria-$parch /usr/local/bin/hysteria" >/dev/null 2>&1 || true; }
    # bring up (and verify) the iperf3 measurement server on the foreign
    info "Starting measurement server on $fhost ..."
    if ! bench_ensure_iperf "$fhost"; then
        echo
        warn "Could not start iperf3 on $fhost - the benchmark can't measure without it."
        echo "  The foreign box needs the 'iperf3' package (it listens on port 5599 during"
        echo "  the test). Fix it one of these ways, then run the benchmark again:"
        echo "    - let it auto-install: make sure the foreign box can reach its apt/yum mirrors"
        echo "    - or install it by hand on the foreign:  ${C_CYAN}apt install -y iperf3${C_RESET}  (or ${C_CYAN}yum install -y iperf3${C_RESET})"
        die "measurement server unavailable on $fhost"
    fi
    sleep 1

    echo; printf "%b\n" "${C_BOLD}Raw path (no tunnel):${C_RESET}"
    local raw_dl raw_ping
    raw_ping=$(ping -c3 -W2 "$fhost" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}' || true)
    if nc -z -w4 "$fhost" 5599 2>/dev/null; then
        raw_dl=$(timeout 20 iperf3 -c "$fhost" -p 5599 -t 5 -P 8 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}' || true)
    else raw_dl="n/a (foreign 5599 not reachable directly)"; fi
    printf "  download %s   rtt %s ms\n" "${raw_dl:-n/a}" "${raw_ping:-n/a}"

    echo; printf "%b\n" "${C_BOLD}Benchmarking each tunnel (a few minutes)...${C_RESET}"
    local rows=() base; base=$(next_subnet_idx); local i=0 t
    # Best-effort measurement: one tunnel failing (a ping with no reply, an iperf
    # that times out, a far-side bring-up hiccup) must NOT abort the whole run
    # under 'set -e'. Relax it for the loop; each type just records FAIL instead.
    set +e
    for t in $ALL_TYPES; do
        local name="bench-$t" sub=$((base+i)); i=$((i+1))
        local ta="10.201.$sub.1" pa="10.201.$sub.2" port key nc=8 shape=none
        port=$(next_port $((51840+sub))); key=$(gen_key)
        [[ "$t" == icmp ]] && { key=""; }
        echo -n "  $t ... "
        # hysteria has no tun/ping: forward the iperf port through it and measure
        if type_is_hysteria "$t"; then
            peer_ssh "$fhost" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _peercreate '$name' hysteria server '$fhost' '$mylip' '$port' '$key' '$pa' '$ta' '200' '$nc'" >/dev/null 2>&1
            create_inst "$name" hysteria client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" 200 "$nc"
            inst_enable "$name" >/dev/null 2>&1
            echo "tcp:5599" > "$(inst_pf "$name")"; pf_apply_all "$name" >/dev/null 2>&1; sleep 6
            local hrtt hdl
            hrtt=$(ping -c3 -W2 "$fhost" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
            hdl=$(timeout 25 iperf3 -c 127.0.0.1 -p 5599 -t 6 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}')
            rows+=("$t|${hdl:-FAIL}|0%|${hrtt:-n/a}"); echo "${hdl:-FAIL}"
            inst_remove "$name" >/dev/null 2>&1
            peer_ssh "$fhost" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _remove '$name'" >/dev/null 2>&1 || true
            continue
        fi
        peer_ssh "$fhost" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _peercreate '$name' '$t' server '$fhost' '$mylip' '$port' '$key' '$pa' '$ta' '$shape' '$nc'" >/dev/null 2>&1
        create_inst "$name" "$t" client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" "$shape" "$nc"
        inst_enable "$name" >/dev/null 2>&1; sleep 6
        local out loss rtt dl
        out=$(ping -c5 -W2 "$pa" 2>/dev/null || true)
        rtt=$(echo "$out" | awk -F'/' '/rtt|round-trip/{print $5}')
        loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
        dl=$(timeout 20 iperf3 -c "$pa" -p 5599 -t 6 -P 8 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}')
        rows+=("$t|${dl:-FAIL}|${loss:-100}%|${rtt:-n/a}")
        echo "${dl:-FAIL}"
        inst_remove "$name" >/dev/null 2>&1
        peer_ssh "$fhost" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _remove '$name'" >/dev/null 2>&1 || true
    done
    # belt-and-braces: make sure no bench-* survived on either side
    for t in $ALL_TYPES; do
        inst_exists "bench-$t" && inst_remove "bench-$t" >/dev/null 2>&1 || true
        peer_ssh "$fhost" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _remove 'bench-$t'" >/dev/null 2>&1 || true
    done
    set -e

    echo; printf "%b\n" "${C_BOLD}${C_CYAN}==================== BENCHMARK RESULTS ====================${C_RESET}"
    printf "  raw path : download %s , rtt %s ms\n" "${raw_dl:-n/a}" "${raw_ping:-n/a}"
    printf "  %b%-6s %-18s %-7s %-9s%b\n" "$C_BOLD" "TYPE" "DOWNLOAD(tunnel)" "LOSS" "PING(ms)" "$C_RESET"
    local r; for r in "${rows[@]}"; do IFS='|' read -r t dl ls pg <<< "$r"
        printf "  %-6s %-18s %-7s %-9s\n" "$t" "$dl" "$ls" "$pg"; done
    printf "%b\n" "${C_CYAN}===========================================================${C_RESET}"; echo

    echo "All test tunnels have been removed from both sides."
    echo "Keep one as a permanent instance?"
    local ci=1; for t in $ALL_TYPES; do printf "  %d) %-5s %s\n" "$ci" "$t" "$(type_desc "$t")"; ci=$((ci+1)); done
    echo "  0) keep none"
    read -rp "Choice: " ch || true; [[ "$ch" == 0 || -z "$ch" ]] && { info "nothing kept."; return 0; }
    local keep; keep=$(echo $ALL_TYPES | cut -d' ' -f"$ch"); [[ -z "$keep" ]] && { warn "invalid"; return; }
    read -rp "Name for the kept instance [main]: " kn; kn="${kn:-main}"; inst_exists "$kn" && die "instance $kn exists"
    local nc=16 shape=none
    [[ "$keep" == mux ]] && { read -rp "mux links N [16]: " nc; nc="${nc:-16}"; read -rp "download shaper (e.g. 90mbit / none) [none]: " shape; shape="${shape:-none}"; }
    [[ "$keep" == hysteria ]] && { read -rp "Brutal-CC target bandwidth mbps [200]: " shape; shape="${shape:-200}"; }
    local sub port key ta pa; sub=$(next_subnet_idx); ta="10.201.$sub.1"; pa="10.201.$sub.2"; port=$(next_port $((51820+sub))); key=$(gen_key); [[ "$keep" == icmp || "$keep" == gre ]] && key=""
    provision_peer "$fhost" "$kn" "$keep" "$fhost" "$mylip" "$port" "$key" "$pa" "$ta" "$shape" "$nc"
    create_inst "$kn" "$keep" client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" "$shape" "$nc"
    inst_enable "$kn"; ok "kept '$keep' as instance '$kn' on both sides."
}

# --------------------------------------------------- MANUAL benchmark ----------
# Same benchmark, but with no SSH to the foreign box. The foreign side is
# brought up once from a single pasted token; this side measures all four
# tunnels, prints the table, and lets you keep one. Fixed bench subnets
# (10.201.100-103) / ports (51900-51903) so both sides match deterministically.
_bench_key_for() { case "$1" in udp) echo "$B_KUDP";; mux) echo "$B_KMUX";; tcp) echo "$B_KTCP";; *) echo "";; esac; }
cmd_bench_manual() {
    need_root; ensure_binary
    local fhost="$1" mylip="${2:-$(default_local_ip)}"
    [[ -n "$fhost" ]] || die "usage: bench-manual <foreign_ip> [my_ip]"
    command -v iperf3 >/dev/null || { warn "installing iperf3..."; apt-get install -y iperf3 >/dev/null 2>&1 || true; }
    local ku km kt; ku=$(gen_key); km=$(gen_key); kt=$(gen_key)
    B_KUDP=$ku B_KMUX=$km B_KTCP=$kt
    local token; token=$(printf 'bench|%s|%s|%s|%s|%s' "$fhost" "$mylip" "$ku" "$km" "$kt" | base64 | tr -d '\n')
    echo
    echo "${C_BOLD}Manual benchmark${C_RESET} ${C_DIM}(no SSH to the foreign box)${C_RESET}"
    echo "1) On the FOREIGN server ($fhost) run these two lines:"
    echo "   ${C_CYAN}bash <(curl -fsSL $RAW_BASE/install.sh)${C_RESET}"
    echo "   ${C_CYAN}omnitunnel bench-server $token${C_RESET}"
    read -rp "2) Press Enter here once it prints 'benchmark server ready'... " _
    local raw_dl raw_ping
    raw_ping=$(ping -c3 -W2 "$fhost" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}' || true)
    if nc -z -w4 "$fhost" 5599 2>/dev/null; then
        raw_dl=$(timeout 20 iperf3 -c "$fhost" -p 5599 -t 5 -P 8 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}' || true)
    else raw_dl="n/a (foreign 5599 not reachable directly)"; fi
    echo; printf "%b\n" "${C_BOLD}Measuring each tunnel...${C_RESET}"
    local rows=() i=0 t
    set +e   # best-effort measurement (see bench_run): never abort mid-run
    for t in $ALL_TYPES; do
        type_is_hysteria "$t" && { i=$((i+1)); continue; }  # manual bench (fixed keys) skips hysteria; use auto bench for it
        local name="bench-$t" sub=$((100+i)) port=$((51900+i)) key; key=$(_bench_key_for "$t")
        local ta="10.201.$sub.1" pa="10.201.$sub.2"
        echo -n "  $t ... "
        create_inst "$name" "$t" client "$mylip" "$fhost" "$port" "$key" "$ta" "$pa" none 8
        inst_enable "$name" >/dev/null 2>&1; sleep 6
        local out loss rtt dl
        out=$(ping -c5 -W2 "$pa" 2>/dev/null || true)
        rtt=$(echo "$out" | awk -F'/' '/rtt|round-trip/{print $5}')
        loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
        dl=$(timeout 20 iperf3 -c "$pa" -p 5599 -t 6 -P 8 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}')
        rows+=("$t|${dl:-FAIL}|${loss:-100}%|${rtt:-n/a}"); echo "${dl:-FAIL}"
        inst_remove "$name" >/dev/null 2>&1
        i=$((i+1))
    done
    set -e
    echo; printf "%b\n" "${C_BOLD}${C_CYAN}==================== BENCHMARK RESULTS ====================${C_RESET}"
    printf "  raw path : download %s , rtt %s ms\n" "${raw_dl:-n/a}" "${raw_ping:-n/a}"
    printf "  %b%-6s %-18s %-7s %-9s%b\n" "$C_BOLD" "TYPE" "DOWNLOAD(tunnel)" "LOSS" "PING(ms)" "$C_RESET"
    local r; for r in "${rows[@]}"; do IFS='|' read -r t dl ls pg <<< "$r"; printf "  %-6s %-18s %-7s %-9s\n" "$t" "$dl" "$ls" "$pg"; done
    printf "%b\n" "${C_CYAN}===========================================================${C_RESET}"; echo
    echo "${C_YELLOW}On the FOREIGN server, remove the test tunnels with:${C_RESET}  ${C_CYAN}omnitunnel bench-clean${C_RESET}"
    echo
    echo "Keep one as a permanent instance? (sets up its own fresh token)"
    local ci=1; for t in $ALL_TYPES; do printf "  %d) %-5s %s\n" "$ci" "$t" "$(type_desc "$t")"; ci=$((ci+1)); done
    echo "  0) keep none"
    read -rp "Choice: " ch || true; [[ "$ch" == 0 || -z "$ch" ]] && { info "nothing kept."; return 0; }
    local keep; keep=$(echo $ALL_TYPES | cut -d' ' -f"$ch"); [[ -z "$keep" ]] && { warn "invalid"; return; }
    read -rp "Name for the kept instance [main]: " kn; kn="${kn:-main}"
    local nc=16 shape=none
    [[ "$keep" == mux ]] && { read -rp "mux links N [16]: " nc; nc="${nc:-16}"; read -rp "download shaper (e.g. 90mbit / none) [none]: " shape; shape="${shape:-none}"; }
    cmd_add_manual "$keep" "$kn" "$fhost" "$nc" "$shape" "$mylip"
}
# Foreign side: bring up all four server tunnels + an iperf3 server, from a token.
cmd_bench_server() {
    need_root; ensure_binary
    local dec; dec=$(printf '%s' "$1" | base64 -d 2>/dev/null) || die "invalid token"
    local tag fhost mylip ku km kt; IFS='|' read -r tag fhost mylip ku km kt <<< "$dec"
    [[ "$tag" == bench ]] || die "not a benchmark token"
    B_KUDP=$ku B_KMUX=$km B_KTCP=$kt
    command -v iperf3 >/dev/null || { apt-get install -y iperf3 >/dev/null 2>&1 || yum install -y iperf3 >/dev/null 2>&1 || true; }
    systemctl reset-failed omnitun-bench-iperf 2>/dev/null || true
    systemd-run --unit=omnitun-bench-iperf --collect iperf3 -s -p 5599 >/dev/null 2>&1 || (setsid iperf3 -s -p 5599 >/dev/null 2>&1 &)
    local i=0 t
    set +e   # best-effort bring-up: don't abort if one type fails to come up
    for t in $ALL_TYPES; do
        type_is_hysteria "$t" && { i=$((i+1)); continue; }  # manual bench skips hysteria (fixed-key token path)
        local name="bench-$t" sub=$((100+i)) port=$((51900+i)) key; key=$(_bench_key_for "$t")
        local ta="10.201.$sub.1" pa="10.201.$sub.2"
        inst_exists "$name" && inst_remove "$name" >/dev/null 2>&1
        create_inst "$name" "$t" server "$fhost" "$mylip" "$port" "$key" "$pa" "$ta" none 8
        inst_enable "$name" >/dev/null 2>&1
        i=$((i+1))
    done
    set -e
    ok "benchmark server ready - now press Enter on the Iran side."
}
cmd_bench_clean() {
    need_root; local t
    for t in $ALL_TYPES; do inst_remove "bench-$t" >/dev/null 2>&1 || true; done
    systemctl stop omnitun-bench-iperf 2>/dev/null || true
    ok "benchmark test tunnels removed."
}

# ------------------------------------------------------------ self-update -----
# Re-run the canonical installer from GitHub. It is idempotent and version-aware:
# it refreshes the manager + core binaries and, only if the version changed,
# restarts the running tunnels. Returns non-zero (without aborting the menu) if
# GitHub can't be reached - e.g. a box with no direct egress, which you update by
# re-pushing the files the same way you first installed it.
cmd_update() {
    need_root
    command -v curl >/dev/null 2>&1 || { warn "curl is required to update"; return 1; }
    info "Checking GitHub for a newer OmniTunnel (current v$VERSION)..."
    local tmp; tmp="$(mktemp)"
    if ! curl -fsSL "$RAW_BASE/install.sh" -o "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        warn "Could not reach GitHub from this box."
        warn "If it has no direct internet egress, update it by re-pushing the files"
        warn "(run the installer on a box that can reach GitHub, or copy them over)."
        return 1
    fi
    bash "$tmp"; local rc=$?; rm -f "$tmp"
    [[ $rc -eq 0 ]] || { warn "update failed"; return 1; }
    return 0
}

# ----------------------------------------------------------- full uninstall ---
# Remove EVERYTHING this tool created: every instance (including any leftover
# bench-* ones) with its unit, relays, tun device and iptables chain; the core
# binaries; all state; and finally its own files and the 'omnitunnel' command.
# It never touches anything it did not create.
cmd_uninstall() {
    need_root
    echo
    warn "This completely removes OmniTunnel and everything it created:"
    echo "  - every tunnel/instance (including any 'bench-*'), its systemd unit,"
    echo "    port-forward relays, tun device and iptables chain"
    echo "  - the core binaries: $TSUITE_BIN and $HYSTERIA_BIN"
    echo "  - all state in $ROOT_DIR and the files in $ASSET_DIR"
    echo "  - the 'omnitunnel' command itself"
    echo "  ${C_DIM}(it does not touch anything OmniTunnel didn't create)${C_RESET}"
    echo
    local a; read -rp "Type 'DELETE' to remove everything: " a || true
    [[ "$a" == "DELETE" ]] || { info "aborted - nothing removed."; return 0; }
    echo
    # 1) clean removal of each instance the tool knows about
    local n
    for n in $(list_instances); do echo "  removing instance '$n'"; inst_remove "$n" >/dev/null 2>&1 || true; done
    # 2) sweep any stray omnitun-* units (relays, bench iperf, half-removed ones)
    local u
    for u in $(systemctl list-units 'omnitun-*' --all --no-legend 2>/dev/null | awk '{print $1}'); do
        systemctl disable --now "$u" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$u"
    done
    systemctl reset-failed 2>/dev/null || true; systemctl daemon-reload 2>/dev/null || true
    # 3) sweep any leftover TSUITE nat chains
    local ch
    for ch in $(iptables -t nat -S 2>/dev/null | grep -oE 'TSUITE_[A-Z0-9_]+' | sort -u); do
        iptables -t nat -D PREROUTING -j "$ch" 2>/dev/null || true
        iptables -t nat -F "$ch" 2>/dev/null || true
        iptables -t nat -X "$ch" 2>/dev/null || true
    done
    # 4) core binaries + relay helper
    rm -f "$TSUITE_BIN" "$HYSTERIA_BIN" "$HY_RELAY"
    # 5) state, the command symlink, then the install dir (this script lives there)
    rm -rf "$ROOT_DIR"
    rm -f "$BINLINK"
    ok "OmniTunnel removed. Deleting its own files now - goodbye."
    rm -rf "$ASSET_DIR"
    exit 0
}

# -------------------------------------------------------------------- menus ---
# count instances by state for the header strip
_state_counts() {
    RUN=0; STOP=0; local n
    for n in $(list_instances); do inst_running "$n" && RUN=$((RUN+1)) || STOP=$((STOP+1)); done
}
banner() {
    clear 2>/dev/null || true
    local myip; myip="$(default_local_ip 2>/dev/null)"
    printf '%b\n' "${C_BCYN}${C_BOLD}"
    cat <<'EOF'
   ___                 _ _____                       _
  / _ \ _ __ ___  _ __ (_)_   _|   _ _ __  _ __   ___| |
 | | | | '_ ` _ \| '_ \| | | || | | | '_ \| '_ \ / _ \ |
 | |_| | | | | | | | | | | | || |_| | | | | | | |  __/ |
  \___/|_| |_| |_|_| |_|_| |_| \__,_|_| |_|_| |_|\___|_|
EOF
    printf '%b' "${C_RESET}"
    printf '   %bmulti-protocol obfuscated tunnel suite%b   %bv%s%b %b(%s)%b\n' \
        "$C_DIM$C_ITAL" "$C_RESET" "$C_BOLD$C_WHITE" "$VERSION" "$C_RESET" "$C_GREY" "$(arch_tag)" "$C_RESET"
    _state_counts
    printf '   %b%s%b this box %b%s%b   %b%s running%b   %b%s stopped%b\n\n' \
        "$C_GREY" "$G_DOT_ON" "$C_RESET" "$C_WHITE" "${myip:-?}" "$C_RESET" \
        "$C_BGRN" "$RUN" "$C_RESET" "$([[ $STOP -gt 0 ]] && printf '%s' "$C_BRED" || printf '%s' "$C_GREY")" "$STOP" "$C_RESET"
}
# a section heading used inside the sub-screens
heading() { printf '%b%s %s%b\n' "$C_BOLD$C_BCYN" "$G_H$G_H" "$1" "$C_RESET"; }
# a numbered menu item:  key  label  [hint]  [key-colour]
mitem() {
    local kc="${4:-$C_BOLD$C_BCYN}"
    printf '   %b%s%b  %b%-27s%b %b%s%b\n' "$kc" "$1" "$C_RESET" "$C_WHITE" "$2" "$C_RESET" "$C_DIM$C_ITAL" "${3:-}" "$C_RESET"
}
prompt() { printf '\n  %b❯%b ' "$C_BCYN$C_BOLD" "$C_RESET"; }
menu_instances() {
    while true; do
        banner
        heading "Tunnels"
        local any=0 n
        for n in $(list_instances); do inst_status "$n"; any=1; done
        [[ "$any" == 0 ]] && printf '  %b%s none yet%b\n' "$C_GREY" "$G_DOT_OFF" "$C_RESET"
        echo
        heading "Manage"
        mitem 1 "Add a tunnel"        "auto - sets up the foreign over SSH"
        mitem 2 "Add a tunnel (MANUAL)" "no SSH - paste a token on the foreign"
        mitem 3 "Remove a tunnel"
        mitem 4 "Restart a tunnel"
        mitem 5 "Live logs"
        mitem 0 "Back"
        prompt; read -r c
        case "$c" in
            1) wizard_add; pause;;
            2) wizard_add_manual; pause;;
            3) read -rp "  instance to remove: " n; [[ -z "$n" ]] && continue; inst_remove "$n"
               read -rp "  also remove the far (foreign) side? [y/N]: " yn
               if [[ "$yn" =~ ^[Yy] ]]; then read -rp "  foreign IP: " fh; peer_ssh "$fh" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _remove '$n'" 2>/dev/null || true; fi; pause;;
            4) read -rp "  instance to restart: " n; [[ -n "$n" ]] && inst_enable "$n"; pause;;
            5) read -rp "  instance: " n; [[ -n "$n" ]] && journalctl -u "$(svc_name "$n")" -n 40 --no-pager 2>/dev/null || true; pause;;
            0) return;;
        esac
    done
}
menu_pf() {
    while true; do
        banner
        heading "Port forwarding  ${C_RESET}${C_DIM}${C_ITAL}(a port hit on this box is tunneled to the far side)${C_RESET}"
        local n pf any=0
        for n in $(list_instances); do
            pf="$(inst_pf "$n")"; any=1
            printf '  %b%s%b %b%s%b\n' "$C_MAG" "$G_V" "$C_RESET" "$C_BOLD$C_WHITE" "$n" "$C_RESET"
            if [[ -s "$pf" ]]; then
                local proto port
                while IFS=: read -r proto port; do [[ -z "$proto" ]] && continue
                    printf '       %b%s%b %b%-4s%b %s\n' "$C_GREEN" "$G_ARROW" "$C_RESET" "$C_CYAN" "$proto" "$C_RESET" "$port"; done < "$pf"
            else printf '       %b(no forwards)%b\n' "$C_DIM" "$C_RESET"; fi
        done
        [[ "$any" == 0 ]] && printf '  %b(add a tunnel first)%b\n' "$C_DIM" "$C_RESET"
        echo
        heading "Actions"
        mitem 1 "Add forward"
        mitem 2 "Remove forward"
        mitem 0 "Back"
        prompt; read -r c
        case "$c" in
            1) read -rp "  instance: " n; read -rp "  proto (tcp/udp/both): " p; read -rp "  port: " po; [[ -n "$n" && -n "$p" && -n "$po" ]] && pf_add "$n" "$p" "$po"; pause;;
            2) read -rp "  instance: " n; read -rp "  port: " po; [[ -n "$n" && -n "$po" ]] && pf_del "$n" "$po"; pause;;
            0) return;;
        esac
    done
}
menu_main() {
    while true; do
        banner
        heading "Tunnels"
        local any=0 n
        for n in $(list_instances); do inst_status "$n"; any=1; done
        [[ $any == 0 ]] && printf '  %b%s no tunnels yet%b %b- add one from "Manage tunnels"%b\n' "$C_GREY" "$G_DOT_OFF" "$C_RESET" "$C_DIM$C_ITAL" "$C_RESET"
        echo
        heading "Menu"
        mitem 1 "Benchmark & pick best"  "auto - SSH sets up the foreign"
        mitem 2 "Benchmark  (MANUAL)"    "no SSH - paste a token on the foreign"
        mitem 3 "Manage tunnels"         "add / remove / restart / logs"
        mitem 4 "Port forwarding"        "expose a port through a tunnel"
        mitem 5 "Status of everything"
        mitem 6 "Update OmniTunnel"      "pull the latest from GitHub"
        mitem 7 "Uninstall"              "remove every tunnel + all files" "$C_BOLD$C_BRED"
        mitem 0 "Exit"
        prompt; read -r c
        case "$c" in
            1) bench_run; pause;;
            2) local fh mip; read -rp "Foreign server IP: " fh; mip="$(default_local_ip)"; read -rp "This box public IP [$mip]: " x; mip="${x:-$mip}"; [[ -n "$fh" ]] && cmd_bench_manual "$fh" "$mip"; pause;;
            3) menu_instances;;
            4) menu_pf;;
            5) banner; heading "Status"; local a5=0; for n in $(list_instances); do inst_status "$n"; a5=1; done; [[ "$a5" == 0 ]] && printf '  %b%s no tunnels%b\n' "$C_GREY" "$G_DOT_OFF" "$C_RESET"; pause;;
            6) if cmd_update; then ok "Reloading the updated manager..."; sleep 1; exec "$SCRIPT_PATH" menu; else pause; fi;;
            7) cmd_uninstall; pause;;
            0) exit 0;;
        esac
    done
}

# ------------------------------------------------------------------- main -----
mkdir -p "$INST_DIR" "$PEER_DIR" 2>/dev/null || true
case "${1:-menu}" in
    menu|"")          need_root; ensure_binary; menu_main;;
    bench)            need_root; bench_run;;
    add)              need_root; wizard_add;;
    add-auto)         shift; cmd_add_auto "$@";;
    add-manual)       shift; cmd_add_manual "$@";;
    server-token)     need_root; cmd_server_token "${2:?token}";;
    bench-manual)     shift; cmd_bench_manual "$@";;
    bench-server)     need_root; cmd_bench_server "${2:?token}";;
    bench-clean)      need_root; cmd_bench_clean;;
    list)             for n in $(list_instances); do inst_status "$n"; done;;
    status)           inst_status "${2:?instance}";;
    enable)           inst_enable "${2:?instance}";;
    remove|_remove)   inst_remove "${2:?instance}";;
    pf-add)           pf_add "${2:?}" "${3:?}" "${4:?}";;
    pf-del)           pf_del "${2:?}" "${3:?}";;
    _postup)          cmd_postup "${2:?}";;
    _peercreate)      shift; cmd_peercreate "$@";;
    ensure-binary)    ensure_binary; ok "core ready at $TSUITE_BIN ($(arch_tag))";;
    update|upgrade)   need_root; cmd_update;;
    uninstall|purge)  need_root; cmd_uninstall;;
    version|-v|--version) echo "tunnelctl $VERSION (core: $($TSUITE_BIN version 2>/dev/null || echo n/a))";;
    *) echo "usage: $0 [menu|bench|add|list|status <n>|enable <n>|remove <n>|pf-add <n> <proto> <port>|pf-del <n> <port>|update|uninstall]";;
esac
