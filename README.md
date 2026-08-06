# icmptun

**[free-guy-ir.github.io/icmptun](https://free-guy-ir.github.io/icmptun/)**

A point-to-point IP tunnel that disguises all traffic as ordinary ICMP echo request/reply packets, for links where most protocols are silently throttled or dropped but plain ICMP passes cleanly. Carries any IP traffic transparently (TCP, UDP, even ICMP itself) once the interface is up, so standard `iptables` DNAT port-forwarding works with zero protocol-specific code.

Single self-contained script: the C tunnel core is embedded in `icmptun-ctl.sh` and regenerated on every build, so there's only one file to deploy.

## Install

One command, on each box you're tunneling between:

```bash
curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/icmptun/main/install.sh -o /tmp/icmptun-install.sh && sudo bash /tmp/icmptun-install.sh
```

That's the entire install — it downloads `icmptun-ctl.sh` to `/usr/local/bin/` and drops you straight into the setup wizard. No manual file transfer, no separate build step. If `raw.githubusercontent.com` is itself filtered, fetch it through a SOCKS5 proxy instead:

```bash
sudo bash /tmp/icmptun-install.sh --socks5 127.0.0.1:1080
```

## Why

Some network paths apply protocol-blind traffic policing: TCP, UDP, GRE, and TLS relays all get an initial burst through and then go silent, with no RST or ICMP-unreachable — while bare ICMP keeps working under the same conditions. This tunnel wraps arbitrary IP packets inside genuine-looking ICMP echo request/reply pairs (the client always sends type-8, the server always replies with a real type-0 reply) to avoid a common failure mode: paths that apply direction-aware policy to ICMP, permitting traffic that looks like a reply to a locally-initiated request while treating an unsolicited inbound echo *request* as a fresh connection subject to stricter policy.

## Features

- **Self-contained**: brings its own interface up (address + point-to-point route) from inside the process itself — no external `ip addr`/`ip link` calls needed before or after starting it.
- **Per-flow reordering**: packet reordering on the underlying path is corrected per-flow (keyed by each inner packet's real 5-tuple), not with one shared buffer — so a reordering event on one TCP connection can never delay unrelated flows or a health-check ping.
- **TCP + UDP port forwarding**: add/remove/list forwarded ports through a proper `iptables` DNAT + MASQUERADE chain, fully isolated in its own custom chains.
- **Pre-flight conflict detection**: before adding a forward, warns if another DNAT rule or a local listener already claims that port, so a stale conflicting rule can't silently swallow your traffic.
- **Multi-instance**: run more than one independent tunnel on the same box at once (e.g. several Iran-side servers into one foreign box, or the reverse) — each instance gets its own config, binary, systemd unit, and iptables chains via `ICMPTUN_INSTANCE=<name>`.
- **Interactive menu by default**, direct CLI subcommands for scripting (`icmptun-ctl.sh pf add 8080 both`).
- **systemd-native**: `Type=simple`, no PID file — the binary is fully self-configuring, so systemd's own process tracking is always accurate.
- **BBR toggle** for the underlying TCP congestion control, since it tends to hold throughput better than cubic on a path with occasional loss/reordering.

## Quick start

After running the install command above on both boxes, you're already inside the interactive menu on each — it walks you through initial setup on first run. Re-launch it anytime with:

```bash
icmptun-ctl.sh
```

Or configure non-interactively on each end:

```bash
# foreign server (has the real public IP the client reaches)
icmptun-ctl.sh init --role server -L <this-box-real-ip> -R <other-box-real-ip>
icmptun-ctl.sh enable

# the other end
icmptun-ctl.sh init --role client -L <this-box-real-ip> -R <other-box-real-ip>
icmptun-ctl.sh enable
```

Then forward a port through the tunnel from whichever side should expose it publicly:

```bash
icmptun-ctl.sh pf add 8080 both      # tcp+udp, defaults to the tunnel's other end, same port
icmptun-ctl.sh pf add 443 tcp 10.0.0.5 8443   # or target a specific IP:port reachable from the far side
```

## Usage

```
icmptun-ctl.sh                 # interactive menu (status, start/stop, port forwards, BBR, ...)
icmptun-ctl.sh status           # tunnel health, ping to peer, active forwards
icmptun-ctl.sh pf add|del|list|flush ...
icmptun-ctl.sh start|stop|restart|enable
icmptun-ctl.sh bbr on|off|status
icmptun-ctl.sh logs [-f]
icmptun-ctl.sh remove [both]    # tear down locally, optionally also on the peer via saved SSH creds
```

Running a second, independent tunnel on the same box:

```bash
ICMPTUN_INSTANCE=second icmptun-ctl.sh init --role client -L <ip> -R <ip> -A 10.97.0.1 -P 10.97.0.2
ICMPTUN_INSTANCE=second icmptun-ctl.sh enable
ICMPTUN_INSTANCE=second icmptun-ctl.sh pf add 700 both
```

## Architecture

```
   client box                                          server box
 ┌───────────────┐        genuine ICMP echo          ┌───────────────┐
 │  local apps    │  ─── request (type 8) ──────►     │  local apps   │
 │      │         │                                    │      │        │
 │   tun0 (IP)    │  ◄── genuine ICMP echo             │   tun0 (IP)   │
 │      │         │      reply (type 0) ────           │      │        │
 │  icmptun core  │                                    │  icmptun core │
 └───────┬───────┘                                    └───────┬───────┘
         │                raw ICMP socket                      │
         └──────────────── public internet ───────────────────┘
```

Each side reads plain IP packets off its TUN device, wraps them in an ICMP packet addressed to the peer's real IP, and the far end unwraps and re-injects them into its own TUN device. Port forwards are plain `iptables` DNAT rules pointed at the tunnel's own point-to-point address, so any TCP/UDP service reachable from the far end can be exposed through either box.

## Requirements

- Linux, root (raw socket + `/dev/net/tun`)
- `gcc`, `iptables`, `systemd`
- OpenBSD `nc` if using the SOCKS5-proxy option for peer-to-peer management commands

## License

MIT
