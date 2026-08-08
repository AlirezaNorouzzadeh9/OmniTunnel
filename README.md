# OmniTunnel

**A multi-protocol, obfuscated tunnel suite for bypassing per-destination
traffic policing and DPI.** Prebuilt static binaries, one English
menu-driven manager, seven interchangeable tunnel transports, and any
many-to-many topology you need.

Built and hardened against real Iran ⇄ abroad conditions, where different ISPs
police, throttle, or block traffic very differently depending on the transport
and the destination datacenter. (Formerly the ICMP-only `icmptun` project —
ICMP is now just one of the seven transports.)

---

## Why seven transports?

No single tunnel wins everywhere. What an ISP lets through — and how fast — is
**per-route and per-transport**, and it changes. OmniTunnel ships all seven and
lets you **benchmark them and keep the winner**:

| Mode | What it is | Best when |
|------|------------|-----------|
| `gre`  | IP-over-GRE, native kernel tunnel (no key) | The ISP polices TCP/UDP but leaves protocol-47 alone — often **full line-rate** |
| `icmp` | IP-over-ICMP, blends in as ping (no key) | Only ICMP passes untouched — frequently unpoliced too |
| `udp`  | IP-over-UDP, XChaCha20-Poly1305, no header/handshake | UDP is allowed — usually the fastest of the encrypted carriers |
| `tcp`  | IP-over-TCP, one connection that looks like a long HTTPS session | UDP is blocked but a single TCP stream runs clean |
| `mux`  | **Multi-connection TCP** — N parallel links, each inner flow pinned to one link | Hostile DPI that blocks UDP *and* poisons long-lived TCP 5-tuples |
| `ws`   | **Multi-connection WebSocket** — real HTTP `Upgrade` handshake, AEAD payload inside masked WS frames | You need `mux`'s throughput but the carrier must be **indistinguishable from a browser/CDN WebSocket** on 443/80 |
| `hysteria` | **Hysteria2 / QUIC** — bundled engine with the loss-agnostic *Brutal* congestion control, salamander obfuscation and a real website masquerade | UDP passes but is **rate-policed or lossy**: Brutal ignores the induced loss and pushes at a fixed rate, so a policed UDP path that crawls at a few Mbit for `udp` runs an order of magnitude faster here — while looking exactly like HTTP/3 |

Many ISPs police only the *common* transports (TCP/UDP) and pass the "tunnel"
protocols — GRE (IP proto 47) and ICMP — at the link's real physical rate. On
one heavily-filtered Iran ISP tested, TCP/UDP were crushed to ~1 Mbit while
**GRE ran at ~650 Mbit and ICMP at ~350 Mbit** to the same foreign box. That is
exactly why you benchmark first and keep the winner. `gre`/`icmp` are plaintext
carriers (the inner proxy traffic is already encrypted); `udp`/`tcp`/`mux` add
their own XChaCha20-Poly1305.

The `mux` transport is the headline. On an ISP that blocks UDP and drops ~half
of new TCP handshakes, a naive single TCP tunnel melts down to a fraction of
the path. `mux` opens N links (each retried from a **fresh source port** until
one lands), spreads inner flows across them, and paces the aggregate just under
the raw rate so the links never overshoot — reaching **~90% of the raw path
speed** where a single tunnel managed under 15%.

All obfuscated transports are **unsignatured**: a random 24-byte nonce followed
by AEAD ciphertext, no magic bytes, no plaintext handshake — indistinguishable
from random traffic to a DPI box.

---

## Install

No compiler needed — the right static binary for your CPU (**amd64** or
**arm64**) ships with the project.

### Run this one line on your **Iran** server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel/main/install.sh) && omnitunnel
```

That's it. You run it **only on the Iran side**. When you add a tunnel (or run
the benchmark), the manager asks for the foreign server's IP and SSH login and
then **installs and configures the foreign side for you automatically over
SSH** — deploys the matching binary for the foreign box's CPU, brings up the
server end, and enables it on boot. You never have to log into the foreign box
by hand.

> Prefer to set the foreign side up yourself? Just run the same one-liner there
> too — the tool is symmetric.

From a checkout instead of the one-liner:

```bash
git clone https://github.com/Free-Guy-IR/OmniTunnel
cd OmniTunnel && sudo ./install.sh && omnitunnel
```

---

## First run: benchmark & pick the best

From the main menu choose **“Benchmark all tunnels & pick the best.”** Point it
at a foreign server (IP + SSH login) and it will:

1. measure the **raw** path (download + rtt),
2. bring up each of the seven tunnels in turn and measure **download, packet
   loss and ping** through it,
3. print a comparison table,
4. **remove every test tunnel from both sides**, then let you keep exactly one
   as a permanent instance.

Real numbers from a heavily-filtered Iran ISP (to one foreign box):

```
==================== BENCHMARK RESULTS ====================
  raw path : download 180 Mbits/sec (plain TCP - policed) , rtt 40 ms
  TYPE      DOWNLOAD(tunnel)   LOSS    PING(ms)
  gre       652 Mbits/sec      0%      40
  icmp      350 Mbits/sec      0%      40
  hysteria  100 Mbits/sec      0%      40
  mux       87  Mbits/sec      0%      40
  udp       3.8 Mbits/sec      23%     41
  tcp       1.2 Mbits/sec      0%      86
===========================================================
```

Here `gre` and `icmp` beat the "raw path" figure because that raw number is a
plain-TCP download, which this ISP **polices** — GRE and ICMP aren't policed, so
they expose the link's real line rate. TCP is 5-tuple-poisoned and plain UDP is
rate-crushed, so a single `tcp` or `udp` tunnel is nearly useless here. The
interesting result is `hysteria`: the same policed UDP path that limits the
plaintext `udp` tunnel to **3.8 Mbit** carries **~100 Mbit** under Hysteria's
Brutal congestion control — the fastest of the *fully obfuscated* transports on
this ISP, and indistinguishable from HTTP/3. `gre`/`icmp` are faster still but
are recognisable protocols; when stealth matters, `hysteria` is the sweet spot.
On a *different* ISP the winner might be `udp` or `mux` — which is the whole
point of benchmarking. Re-run it from the menu any time conditions change.

> These are real measurements taken end-to-end through the manager on two
> different Iran servers (one auto-provisioned over SSH, one set up with the
> no-SSH paste token) to the same foreign box.

---

## When the foreign box can't be reached over SSH

Some Iran ISPs block **outbound port 22** (and DNS to GitHub) entirely, so the
automatic "set up the far side over SSH" step can't run. Two built-in ways
around it — **neither touches any server's own SSH or port 22:**

**1. Manual mode (no SSH at all).** From the manage menu pick *“Add a tunnel —
MANUAL”*, or:

```bash
omnitunnel add-manual mux main <foreign_ip> 16 90mbit
```

It brings up the near (Iran) side and prints two lines to paste on the foreign
box (which abroad can reach GitHub fine):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Free-Guy-IR/OmniTunnel/main/install.sh)
omnitunnel server-token <token>
```

The `<token>` carries the key, port and addresses — the tunnel comes straight
up. No SSH between the two boxes is ever used.

**2. SOCKS5 proxy for provisioning.** If you already have a working SOCKS5 proxy
on the Iran box, the auto setup can tunnel its SSH/SCP through it (as the
original icmptun did) — save a peer with a proxy and the manager adds
`ProxyCommand=nc -X 5 -x host:port` to every provisioning connection.

> The tunnel always uses **its own port** (e.g. 51820), never 22. Installing or
> running OmniTunnel never changes any server's SSH login or SSH port.

---

## Topologies (many-to-many)

Each tunnel is an **instance** with its own tun device, systemd unit, subnet,
port and port-forward chain, so any shape works and instances never collide:

- **one Iran → many foreign** — add several instances on one box
- **many Iran → one foreign** — the foreign box hosts one server instance per
  Iran box
- **many → many** — any combination of the above

The manager auto-allocates a non-overlapping subnet and a free port for every
new instance, and (given an SSH login to the far side) brings up both ends.

---

## Port forwarding

Expose a port on one side and have it tunneled to the other:

```bash
omnitunnel pf-add <instance> both 443     # tcp+udp 443 -> peer over the tunnel
omnitunnel pf-add <instance> tcp  8080
omnitunnel pf-del <instance> 443
```

or use the **Port forwarding** menu.

---

## CLI (for scripting)

```bash
omnitunnel add                       # interactive add wizard
omnitunnel add-auto <type> <name> <foreign_ip> [nconn] [shape] [my_ip]
omnitunnel list
omnitunnel status  <instance>
omnitunnel remove  <instance>        # removes ONLY that instance (both-side safe)
omnitunnel pf-add  <instance> <tcp|udp|both> <port>
omnitunnel bench
```

The core binary can also be driven directly:

```bash
omnitun mux -L <local-ip> -R <peer-ip> -A <local-tun-ip> -P <peer-tun-ip> \
            -p <port> -k <64-hex-key> -N 16 [-s] -T <dev> -M 1400
omnitun udp  ...     omnitun tcp  ...     omnitun icmp ...
```

`-s` marks the server (listening) side; the client omits it.

---

## Architecture

- **One static core binary** (`omnitun`) — a busybox-style multi-call program
  that dispatches to `udp` / `tcp` / `mux` / `ws` / `icmp`. No shared-library
  dependencies: crypto is vendored ([Monocypher](https://monocypher.org),
  XChaCha20-Poly1305), so it builds and cross-compiles trivially and runs on
  any modern Linux kernel.
- **Bundled `hysteria` engine** — the `hysteria` transport is powered by the
  upstream [Hysteria2](https://github.com/apernet/hysteria) static binary,
  shipped in [`bin/`](bin/) for both CPUs. The manager generates its YAML
  (salamander obfs + website masquerade + self-signed TLS) and runs it under
  systemd. The engine keeps an always-on localhost SOCKS5, and each **TCP
  port-forward is a tiny standalone relay** that dials through that SOCKS5 as
  its own systemd unit — so adding or removing a forward starts/stops one relay
  and **never restarts the engine or disturbs the live QUIC session or other
  forwards** (UDP forwards are the one exception and still live in-config). No
  tun device or iptables DNAT is used for this type.
- Prebuilt for **amd64** and **arm64** under [`bin/`](bin/), also attached to
  each release.
- **`omnitunnel.sh`** — the English TUI manager: benchmark, instance
  add/remove/restart, port forwarding, systemd persistence, BBR + fq/tbf
  tuning, and automatic far-side provisioning over SSH.
- State lives under `/etc/omnitunnel` and never touches an existing
  `/etc/icmptun` install.

Build from source (any Linux with gcc):

```bash
cd src
gcc -O2 -Wall -o omnitun main.c obsctun.c obsctcp.c obscmux.c icmptun.c monocypher.c -lpthread -static
# arm64:
aarch64-linux-gnu-gcc -O2 -Wall -o omnitun-arm64 main.c obsctun.c obsctcp.c obscmux.c icmptun.c monocypher.c -lpthread -static
```

---

## Notes on performance

- Throughput is **per-route and time-variable**; benchmark on your own pair of
  servers, and re-benchmark whenever conditions change.
- No tunnel exceeds the raw path — obfuscation defeats *recognition/policing*,
  not physics. If the raw route to a given foreign datacenter is capped, pick a
  different foreign IP/datacenter.
- `mux` performs best with a shaper set a touch under the raw rate (the add
  wizard asks); use the sustainable, not the burst, path capacity.

---

## License

MIT — see [LICENSE](LICENSE).
