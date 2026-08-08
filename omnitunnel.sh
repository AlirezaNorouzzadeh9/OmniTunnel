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

VERSION="2.2.0"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

ROOT_DIR="/etc/omnitunnel"
INST_DIR="$ROOT_DIR/inst"
PEER_DIR="$ROOT_DIR/peers"
TSUITE_BIN="/usr/local/bin/omnitun"
# Hysteria2 is a separate Go engine (QUIC/UDP with the loss-agnostic "Brutal"
# congestion control). We ship its static binary alongside our C core and drive
# it through generated YAML - it is the stealthiest fast transport (looks like
# HTTP/3, with salamander obfs + website masquerade).
HYSTERIA_BIN="/usr/local/bin/hysteria"
HY_MASQ_HOST="www.bing.com"
# where the shipped per-arch binaries live (install.sh drops them here)
ASSET_DIR="${OMNITUN_ASSETS:-/opt/omnitunnel}"
RAW_BASE="https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel/main"

C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'

need_root() { [[ $EUID -eq 0 ]] || { echo "must be run as root"; exit 1; }; }
die() { echo "${C_RED}error:${C_RESET} $*" >&2; exit 1; }
ok() { echo "${C_GREEN}$*${C_RESET}"; }
info() { echo "${C_CYAN}$*${C_RESET}"; }
warn() { echo "${C_YELLOW}$*${C_RESET}"; }
pause() { echo; read -rp "Press Enter to continue..." _ || true; }

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
# render /etc/omnitunnel/inst/<n>/hy.yaml from instance.conf (+ pf.conf on client)
hy_write_config() {
    local n="$1"; load_inst "$n"; local d yaml; d="$(inst_path "$n")"; yaml="$d/hy.yaml"; hy_creds
    if [[ "$ROLE" == server ]]; then
        hy_cert "$d"
        cat > "$yaml" <<EOF
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
        cat > "$yaml" <<EOF
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
        # A localhost SOCKS5 is always present so the engine has a "mode" and
        # stays connected even before any port-forward is added (and it doubles
        # as a ready-to-use proxy through the tunnel). Port-forwards add on top.
        # forwarded ports become native hysteria forwards (server dials 127.0.0.1)
        local pf tcp_e="" udp_e="" proto port; pf="$(inst_pf "$n")"
        if [[ -s "$pf" ]]; then
            while IFS=: read -r proto port; do [[ -z "$proto" ]] && continue
                local blk="  - listen: 0.0.0.0:$port"$'\n'"    remote: 127.0.0.1:$port"$'\n'
                [[ "$proto" == tcp ]] && tcp_e+="$blk"
                [[ "$proto" == udp ]] && udp_e+="$blk"
            done < "$pf"
        fi
        [[ -n "$tcp_e" ]] && { echo "tcpForwarding:" >> "$yaml"; printf '%s' "$tcp_e" >> "$yaml"; }
        [[ -n "$udp_e" ]] && { echo "udpForwarding:" >> "$yaml"; printf '%s' "$udp_e" >> "$yaml"; }
    fi
    chmod 600 "$yaml"
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
    local st="stopped" col="$C_RED"; inst_running "$1" && { st="running"; col="$C_GREEN"; }
    printf "  %-14s %s%-8s%s type=%-4s role=%-6s %s -> %s%s  dev=%s\n" \
        "$1" "$col" "$st" "$C_RESET" "$TYPE" "$ROLE" "$LOCAL_IP" "$PEER_IP" \
        "$([[ -n "$PORT" && "$TYPE" != icmp ]] && echo ":$PORT")" "$DEV"
    if ip link show "$DEV" >/dev/null 2>&1; then
        local out loss rtt
        out=$(ping -c2 -W2 "$PEER_ADDR" 2>/dev/null || true)
        loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
        rtt=$(echo "$out" | awk -F'/' '/rtt|round-trip/{print $5}')
        [[ -n "$rtt" ]] && printf "                 up, peer rtt %s ms, loss %s%%\n" "$rtt" "${loss:-?}" || printf "                 interface up\n"
        if [[ "$TYPE" == tcp || "$TYPE" == mux ]]; then
            printf "                 established links: %s\n" "$(ss -tn state established 2>/dev/null | grep -c ":$PORT" || echo 0)"
        fi
    fi
}

# ------------------------------------------------------------- port fwd -------
pf_apply_all() {
    load_inst "$1"
    # hysteria forwards ports inside its own config, not via iptables: rewrite
    # the YAML from pf.conf and bounce the service.
    if type_is_hysteria "$TYPE"; then
        hy_write_config "$1"
        inst_running "$1" && systemctl restart "$(svc_name "$1")" 2>/dev/null || true
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
    systemctl disable --now "$(svc_name "$1")" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$(svc_name "$1")"; systemctl daemon-reload 2>/dev/null || true
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
    peer_ssh "$fhost" "chmod +x /opt/omnitunnel/omnitunnel.sh; install -m0755 /opt/omnitunnel/bin/omnitun-$parch /usr/local/bin/omnitun; command -v iperf3 >/dev/null || (apt-get install -y iperf3 || yum install -y iperf3) >/dev/null 2>&1; (systemctl reset-failed tsbench-iperf 2>/dev/null; systemd-run --unit=tsbench-iperf --collect iperf3 -s -p 5599 >/dev/null 2>&1) || (pkill -f 'iperf3 -s -p 5599'; setsid iperf3 -s -p 5599 >/dev/null 2>&1 &)" || true
    # hysteria engine for the far side too (so its bench server can come up)
    local hbin; hbin="$(hy_local_bin "$parch" || true)"
    [[ -n "$hbin" ]] && { peer_scp "$fhost" "$hbin" "/opt/omnitunnel/bin/hysteria-$parch"; peer_ssh "$fhost" "chmod +x /opt/omnitunnel/bin/hysteria-$parch; install -m0755 /opt/omnitunnel/bin/hysteria-$parch /usr/local/bin/hysteria" >/dev/null 2>&1 || true; }
    sleep 1

    echo; printf "%b\n" "${C_BOLD}Raw path (no tunnel):${C_RESET}"
    local raw_dl raw_ping
    raw_ping=$(ping -c3 -W2 "$fhost" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
    if nc -z -w4 "$fhost" 5599 2>/dev/null; then
        raw_dl=$(timeout 20 iperf3 -c "$fhost" -p 5599 -t 5 -P 8 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}')
    else raw_dl="n/a (foreign 5599 not reachable directly)"; fi
    printf "  download %s   rtt %s ms\n" "${raw_dl:-n/a}" "${raw_ping:-n/a}"

    echo; printf "%b\n" "${C_BOLD}Benchmarking each tunnel (a few minutes)...${C_RESET}"
    local rows=() base; base=$(next_subnet_idx); local i=0 t
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
            echo "tcp:5599" > "$(inst_pf "$name")"
            inst_enable "$name" >/dev/null 2>&1; sleep 6
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
    read -rp "Choice: " ch; [[ "$ch" == 0 || -z "$ch" ]] && { info "nothing kept."; return 0; }
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
    raw_ping=$(ping -c3 -W2 "$fhost" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
    if nc -z -w4 "$fhost" 5599 2>/dev/null; then
        raw_dl=$(timeout 20 iperf3 -c "$fhost" -p 5599 -t 5 -P 8 -R 2>/dev/null | grep -oE '[0-9.]+ [KMG]bits/sec +receiver' | tail -1 | awk '{print $1" "$2}')
    else raw_dl="n/a (foreign 5599 not reachable directly)"; fi
    echo; printf "%b\n" "${C_BOLD}Measuring each tunnel...${C_RESET}"
    local rows=() i=0 t
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
    read -rp "Choice: " ch; [[ "$ch" == 0 || -z "$ch" ]] && { info "nothing kept."; return 0; }
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
    for t in $ALL_TYPES; do
        type_is_hysteria "$t" && { i=$((i+1)); continue; }  # manual bench skips hysteria (fixed-key token path)
        local name="bench-$t" sub=$((100+i)) port=$((51900+i)) key; key=$(_bench_key_for "$t")
        local ta="10.201.$sub.1" pa="10.201.$sub.2"
        inst_exists "$name" && inst_remove "$name" >/dev/null 2>&1
        create_inst "$name" "$t" server "$fhost" "$mylip" "$port" "$key" "$pa" "$ta" none 8
        inst_enable "$name" >/dev/null 2>&1
        i=$((i+1))
    done
    ok "benchmark server ready - now press Enter on the Iran side."
}
cmd_bench_clean() {
    need_root; local t
    for t in $ALL_TYPES; do inst_remove "bench-$t" >/dev/null 2>&1 || true; done
    systemctl stop omnitun-bench-iperf 2>/dev/null || true
    ok "benchmark test tunnels removed."
}

# -------------------------------------------------------------------- menus ---
banner() {
    clear 2>/dev/null || true
    echo -e "${C_CYAN}${C_BOLD}"
    cat <<'EOF'
   ___                 _ _____                       _
  / _ \ _ __ ___  _ __ (_)_   _|   _ _ __  _ __   ___| |
 | | | | '_ ` _ \| '_ \| | | || | | | '_ \| '_ \ / _ \ |
 | |_| | | | | | | | | | | | || |_| | | | | | | |  __/ |
  \___/|_| |_| |_|_| |_|_| |_| \__,_|_| |_|_| |_|\___|_|
EOF
    echo -e "${C_RESET}${C_DIM}   OmniTunnel - multi-protocol obfuscated tunnel suite   v$VERSION   ($(arch_tag))${C_RESET}\n"
}
menu_instances() {
    while true; do
        banner; echo "${C_BOLD}Instances:${C_RESET}"; local any=0 n
        for n in $(list_instances); do inst_status "$n"; any=1; done
        [[ "$any" == 0 ]] && echo "  ${C_DIM}(none yet)${C_RESET}"
        echo; echo "  1) Add a tunnel  ${C_DIM}(auto: sets up the foreign side over SSH)${C_RESET}"
        echo "  2) Add a tunnel  ${C_YELLOW}MANUAL${C_RESET} ${C_DIM}(no SSH - for ISPs that block port 22; paste a token on the foreign)${C_RESET}"
        echo "  3) Remove a tunnel"; echo "  4) Restart a tunnel"; echo "  5) Live logs"; echo "  0) Back"
        read -rp "Choice: " c
        case "$c" in
            1) wizard_add; pause;;
            2) wizard_add_manual; pause;;
            3) read -rp "Instance to remove: " n; inst_remove "$n"
               read -rp "Also remove the far side? [y/N]: " yn
               if [[ "$yn" =~ ^[Yy] ]]; then read -rp "Foreign IP: " fh; peer_ssh "$fh" "OMNITUN_ASSETS=/opt/omnitunnel /opt/omnitunnel/omnitunnel.sh _remove '$n'" 2>/dev/null || true; fi; pause;;
            4) read -rp "Instance: " n; inst_enable "$n"; pause;;
            5) read -rp "Instance: " n; journalctl -u "$(svc_name "$n")" -n 40 --no-pager 2>/dev/null || true; pause;;
            0) return;;
        esac
    done
}
menu_pf() {
    while true; do
        banner; echo "${C_BOLD}Port forwarding${C_RESET}  (a port hit here is tunneled to the far side)"; local n pf
        for n in $(list_instances); do pf="$(inst_pf "$n")"; echo "  ${C_CYAN}$n${C_RESET}:"; [[ -s "$pf" ]] && sed 's/^/      /' "$pf" || echo "      (none)"; done
        echo; echo "  1) Add forward"; echo "  2) Remove forward"; echo "  0) Back"; read -rp "Choice: " c
        case "$c" in
            1) read -rp "Instance: " n; read -rp "Proto (tcp/udp/both): " p; read -rp "Port: " po; pf_add "$n" "$p" "$po"; pause;;
            2) read -rp "Instance: " n; read -rp "Port: " po; pf_del "$n" "$po"; pause;;
            0) return;;
        esac
    done
}
menu_main() {
    while true; do
        banner; local cnt; cnt=$(list_instances | grep -c . || true)
        echo "  ${C_DIM}active instances: $cnt${C_RESET}"; echo
        echo "  ${C_BOLD}1)${C_RESET} Benchmark all tunnels & pick the best  ${C_DIM}(auto: SSH to foreign)${C_RESET}"
        echo "  ${C_BOLD}2)${C_RESET} Benchmark - ${C_YELLOW}MANUAL${C_RESET} ${C_DIM}(no SSH; paste a token on the foreign)${C_RESET}"
        echo "  ${C_BOLD}3)${C_RESET} Manage tunnels (add / remove / restart)"
        echo "  ${C_BOLD}4)${C_RESET} Port forwarding"
        echo "  ${C_BOLD}5)${C_RESET} Show status of everything"
        echo "  ${C_BOLD}0)${C_RESET} Exit"
        read -rp "Choice: " c
        case "$c" in
            1) bench_run; pause;;
            2) local fh mip; read -rp "Foreign server IP: " fh; mip="$(default_local_ip)"; read -rp "This box public IP [$mip]: " x; mip="${x:-$mip}"; [[ -n "$fh" ]] && cmd_bench_manual "$fh" "$mip"; pause;;
            3) menu_instances;;
            4) menu_pf;;
            5) banner; for n in $(list_instances); do inst_status "$n"; done; pause;;
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
    version|-v|--version) echo "tunnelctl $VERSION (core: $($TSUITE_BIN version 2>/dev/null || echo n/a))";;
    *) echo "usage: $0 [menu|bench|add|list|status <n>|enable <n>|remove <n>|pf-add <n> <proto> <port>|pf-del <n> <port>]";;
esac
