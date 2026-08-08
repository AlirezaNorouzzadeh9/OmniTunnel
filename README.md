# OmniTunnel

**A multi-protocol, obfuscated tunnel suite for bypassing per-destination
traffic policing and DPI.** One prebuilt static core binary, one English
menu-driven manager, four interchangeable tunnel transports, and any
many-to-many topology you need.

Built and hardened against real Iran ⇄ abroad conditions, where different ISPs
police, throttle, or block traffic very differently depending on the transport
and the destination datacenter. (Formerly the ICMP-only `icmptun` project —
ICMP is now just one of the four transports.)

---

## Why four transports?

No single tunnel wins everywhere. What an ISP lets through — and how fast — is
**per-route and per-transport**, and it changes. OmniTunnel ships all four and
lets you **benchmark them and keep the winner**:

| Mode | What it is | Best when |
|------|------------|-----------|
| `udp`  | IP-over-UDP, XChaCha20-Poly1305, no header/handshake | UDP is allowed — usually the fastest, closest to raw |
| `tcp`  | IP-over-TCP, one connection that looks like a long HTTPS session | UDP is blocked but a single TCP stream runs clean |
| `mux`  | **Multi-connection TCP** — N parallel links, each inner flow pinned to one link | Hostile DPI that blocks UDP *and* poisons long-lived TCP 5-tuples |
| `icmp` | IP-over-ICMP, blends in as ping (no key) | Only ICMP passes untouched |

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
2. bring up each of the four tunnels in turn and measure **download, packet
   loss and ping** through it,
3. print a comparison table,
4. **remove every test tunnel from both sides**, then let you keep exactly one
   as a permanent instance.

```
==================== BENCHMARK RESULTS ====================
  raw path : download 180 Mbits/sec , rtt 38 ms
  TYPE   DOWNLOAD(tunnel)   LOSS    PING(ms)
  udp    9.2 Mbits/sec      23%     41
  mux    88  Mbits/sec      0%      40
  tcp    11  Mbits/sec      0%      39
  icmp   6.4 Mbits/sec      1%      44
===========================================================
```

You can re-run the benchmark from the menu any time conditions change.

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
  that dispatches to `udp` / `tcp` / `mux` / `icmp`. No shared-library
  dependencies: crypto is vendored ([Monocypher](https://monocypher.org),
  XChaCha20-Poly1305), so it builds and cross-compiles trivially and runs on
  any modern Linux kernel.
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
