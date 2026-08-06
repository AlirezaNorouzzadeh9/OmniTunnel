#!/bin/bash
# icmptun-ctl.sh - install/manage the ICMPTUN core + TCP/UDP port-forwarding.
#
# Runs the SAME on both tunnel endpoints; role (client/server) and the two
# real IPs are set once via `init`. Deploy this one file to each box, run
# `init` + `start` on each, then use `pf add/del/list` on whichever side
# should expose a public port.
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"

# A box can run more than one independent tunnel at once (e.g. two Iran
# servers both tunneling to the same foreign box, or one Iran server
# tunneling to several foreign boxes) - each such tunnel is an "instance"
# with its own config dir, binary, systemd unit, and iptables chains, so
# they can never step on each other. Select which instance a given
# invocation manages with ICMPTUN_INSTANCE=<name>; unset/empty means the
# original single-tunnel layout (fully backward compatible - an existing
# install never has to move or rename anything to keep working).
INSTANCE="${ICMPTUN_INSTANCE:-}"
SUFFIX=""
CHAIN_SUFFIX=""
if [[ -n "$INSTANCE" ]]; then
    if ! [[ "$INSTANCE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "instance name may only contain letters/digits/hyphen/underscore: $INSTANCE"
        exit 1
    fi
    SUFFIX="-$INSTANCE"
    CHAIN_SUFFIX="_$(echo "$INSTANCE" | tr '[:lower:]-' '[:upper:]_')"
fi

CONF_DIR="/etc/icmptun${SUFFIX}"
CONF_FILE="$CONF_DIR/icmptun.conf"
PF_FILE="$CONF_DIR/portforwards.conf"
PEER_CONF_FILE="$CONF_DIR/peer_ssh.conf"
SRC_FILE="$CONF_DIR/icmptun.c"
BIN="/usr/local/bin/icmptun${SUFFIX}"
LOG_FILE="/var/log/icmptun${SUFFIX}.log"
SERVICE_FILE="/etc/systemd/system/icmptun${SUFFIX}.service"
SERVICE_NAME="icmptun${SUFFIX}.service"
DNAT_CHAIN="ICMPTUN_DNAT${CHAIN_SUFFIX}"
FWD_CHAIN="ICMPTUN_FWD${CHAIN_SUFFIX}"

# ---------------------------------------------------------------- helpers --

need_root() {
    [[ $EUID -eq 0 ]] || { echo "must be run as root"; exit 1; }
}

load_conf() {
    [[ -f "$CONF_FILE" ]] || { echo "not configured yet."; exit 1; }
    # shellcheck disable=SC1090
    source "$CONF_FILE"
}

# ------------------------------------------------------------- C source ----

write_source() {
    mkdir -p "$CONF_DIR"
    cat > "$SRC_FILE" <<'EOF_ICMPTUN_C'
/*
 * ICMPTUN - Symmetric IP-over-ICMP tunnel for bypassing destination-IP
 * traffic policing that leaves ICMP untouched.
 *
 * Both peers run the SAME binary. Each end reads plain IP packets from
 * a TUN device and wraps them inside ICMP Echo Request (type 8) packets
 * sent directly to the other peer's real IP. The other end unwraps and
 * injects them back into its own TUN device. Since the payload is a
 * full IP packet, ordinary TCP and UDP traffic (and therefore iptables
 * DNAT port-forwarding) works transparently once the interface is up -
 * no protocol-specific code needed here at all.
 *
 * Compile: gcc -O2 -Wall -o icmptun icmptun.c
 * Must run as root (raw socket + TUN device).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <time.h>

#define DEFAULT_MTU    1400
#define DEFAULT_IDENT  0x4D54      /* "MT" - MyTunnel */
#define QUEUE_SIZE     4096
#define MAX_PKT        2048
#define MAX_INNER      1500

static char *tun_name = "tun0";
static int mtu = DEFAULT_MTU;
static uint16_t ident = DEFAULT_IDENT;
static int is_server = 0;
static int verbose = 0;
static uint16_t local_ident, remote_ident;
static struct in_addr local_ip, peer_ip;
static struct sockaddr_in peer_addr;
static int tun_fd = -1, icmp_fd = -1, epoll_fd = -1;

typedef struct {
    unsigned char data[MAX_PKT];
    ssize_t len;
    struct sockaddr_in dest;
} out_pkt_t;

static out_pkt_t *send_queue;
static int sq_head = 0, sq_tail = 0, sq_count = 0;

static inline int next_idx(int i) { return (i + 1) % QUEUE_SIZE; }

#define DBG(...) do { if (verbose) fprintf(stderr, __VA_ARGS__); } while (0)

static uint16_t cksum(const void *buf, int len) {
    uint32_t sum = 0;
    const uint16_t *p = buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t*)p;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static int encapsulate(const void *inner, int inner_len, uint16_t seq, out_pkt_t *out) {
    if (inner_len > mtu) {
        fprintf(stderr, "drop oversized inner packet: %d > mtu %d\n", inner_len, mtu);
        return -1;
    }
    int total = (int)sizeof(struct icmphdr) + inner_len;
    if (total > (int)sizeof(out->data)) return -1;

    struct icmphdr *icmp = (struct icmphdr*)out->data;
    memset(icmp, 0, sizeof(*icmp));
    /* Client always sends genuine-looking Echo Request (type 8); server
       always answers with genuine-looking Echo Reply (type 0), using a
       distinct id per direction. This isn't cosmetic: some paths apply
       direction-aware policy to ICMP, permitting traffic that looks like
       a reply to a locally-initiated request while treating an inbound
       Echo Request as a fresh unsolicited connection subject to a
       stricter policy. Mirroring genuine request/reply semantics avoids
       that distinction entirely. */
    icmp->type = is_server ? ICMP_ECHOREPLY : ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(local_ident);
    /* seq is scoped PER FLOW (see flow_key_t below), not a single tunnel-
       wide counter - assigned by the caller from that flow's own tx
       counter, so reordering in one flow can never affect another. */
    icmp->un.echo.sequence = htons(seq);
    memcpy(out->data + sizeof(*icmp), inner, inner_len);
    icmp->checksum = cksum(icmp, total);
    out->len = total;
    out->dest = peer_addr;
    return 0;
}

static int decapsulate(const unsigned char *buf, int len,
                        unsigned char *inner, int *inner_len, uint16_t *out_seq,
                        const struct sockaddr_in *from) {
    if (from->sin_addr.s_addr != peer_ip.s_addr) return -1;
    /* recvfrom() on a SOCK_RAW/IPPROTO_ICMP socket includes the outer IP
       header in the received bytes (unlike sendto(), which does NOT want
       one - the kernel builds it for us there). Skip it using its real
       IHL field rather than assuming a fixed 20 bytes. */
    if (len < (int)sizeof(struct iphdr)) return -1;
    const struct iphdr *iph = (const struct iphdr*)buf;
    int ip_hlen = iph->ihl * 4;
    if (ip_hlen < 20 || len < ip_hlen + (int)sizeof(struct icmphdr)) return -1;
    buf += ip_hlen;
    len -= ip_hlen;
    const struct icmphdr *icmp = (const struct icmphdr*)buf;
    /* Client expects genuine Echo Reply (type 0) from the server, tagged
       with the server's own id; server expects genuine Echo Request
       (type 8) from the client, tagged with the client's id. The local
       kernel may also try to auto-answer an inbound client request with
       its own ICMP_ECHOREPLY mirroring the CLIENT's id verbatim (since
       icmp_echo_ignore_all=0 is required for real inner-tunnel pings) -
       that's a same-host loopback artifact, not a message from the peer's
       icmptun process. Because it carries the client's id rather than the
       server's own dedicated reply id, it fails this check on its own;
       it is additionally suppressed at the iptables raw/OUTPUT layer
       (see deploy notes) so it never even reaches the wire. */
    int want_type = is_server ? ICMP_ECHO : ICMP_ECHOREPLY;
    if (icmp->type != want_type ||
        icmp->code != 0 || ntohs(icmp->un.echo.id) != remote_ident)
        return -1;
    int payload = len - (int)sizeof(*icmp);
    if (payload < 0 || payload > mtu) return -1;
    memcpy(inner, buf + sizeof(*icmp), payload);
    *inner_len = payload;
    *out_seq = ntohs(icmp->un.echo.sequence);
    return 0;
}

/*
 * Per-flow reorder buffer.
 *
 * This path occasionally delivers our outer ICMP packets out of order
 * (confirmed - TCP through the tunnel needed tcp_reordering raised to
 * tolerate it). An earlier version of this fix used ONE global sequence
 * space shared by all tunneled traffic, which caused head-of-line
 * blocking: a reordering event on one TCP connection delayed delivery of
 * every OTHER flow's packets too - including a bare ICMP ping used just
 * to measure tunnel health, which has nothing to do with any TCP
 * connection's reordering. Measured impact: ping through the tunnel was
 * a steady ~39.3ms, but spiked to 42-47ms whenever some unrelated flow
 * triggered the shared buffer.
 *
 * The fix: derive a flow key from each INNER packet's own headers (5-
 * tuple for TCP/UDP, id+type for ICMP) so reordering is scoped per flow.
 * Both peers compute the same key from the same decapsulated packet, so
 * no wire-format change is needed - the per-flow sequence still rides in
 * the existing 16-bit ICMP echo sequence field, just scoped differently.
 * A reordering event in one flow can now only ever delay that flow's own
 * packets.
 *
 * Flows are tracked in a bounded, self-cleaning 4-way set-associative
 * table (256 buckets x 4 ways = 1024 flows) with LRU eviction, so a long
 *-running tunnel handling many short connections doesn't grow unbounded.
 * A lazily-cleaned min-heap of per-flow give-up deadlines gives the main
 * loop a single epoll_wait() timeout - the minimum across every flow
 * currently waiting on a missing packet - without scanning the table.
 */
#define FLOW_TABLE_BUCKETS  256   /* power of two */
#define FLOW_TABLE_WAYS     4
#define FLOW_TABLE_SIZE     (FLOW_TABLE_BUCKETS * FLOW_TABLE_WAYS)
#define REORDER_WINDOW      32    /* power of two - per-flow reorder window */
#define REORDER_TIMEOUT_MS  12    /* max wait for a missing packet in one flow */
#define TIMER_HEAP_CAP      (FLOW_TABLE_SIZE * 4)

#define FLOW_KEY_FRAG  0x01
#define FLOW_ROLE_TX   1
#define FLOW_ROLE_RX   2

typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;   /* TCP/UDP src port, or inner ICMP id, or 0 */
    uint16_t dport;   /* TCP/UDP dst port, or inner ICMP type<<8|code, or 0 */
    uint16_t ip_id;   /* only meaningful for non-first fragments */
    uint8_t  proto;
    uint8_t  flags;
} flow_key_t;

typedef struct {
    unsigned char *pkt;   /* heap-allocated, owned by the slot while buffered */
    uint16_t len;
    uint16_t seq;
} rslot_t;

typedef struct {
    flow_key_t key;
    uint32_t   last_seen_ms;
    uint16_t   rx_next_seq;
    uint16_t   tx_next_seq;
    uint16_t   generation;    /* invalidates stale timer-heap entries after evict/reuse */
    uint8_t    role;
    uint8_t    valid;
    uint32_t   timer_deadline; /* 0 = no pending reorder timeout for this flow */
    rslot_t    rbuf[REORDER_WINDOW];
} flow_entry_t;

typedef struct {
    flow_entry_t slots[FLOW_TABLE_WAYS];
} flow_bucket_t;

static flow_bucket_t flow_table[FLOW_TABLE_BUCKETS];

typedef struct {
    uint32_t deadline;
    flow_entry_t *flow;
    uint16_t generation;
} timer_event_t;

static timer_event_t timer_heap[TIMER_HEAP_CAP];
static int timer_heap_size = 0;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Parses the raw inner IP packet (as read from/written to the TUN
   device) into a flow key. Both peers run this on the same decapsulated
   bytes, so they always agree on the key without exchanging it. */
static int flow_key_from_inner(const unsigned char *pkt, int len, flow_key_t *key) {
    if (len < 20 || (pkt[0] >> 4) != 4) return 0;
    unsigned ihl = (pkt[0] & 0x0f) * 4;
    if (ihl < 20 || (int)ihl > len) return 0;

    memset(key, 0, sizeof(*key));
    memcpy(&key->src_ip, pkt + 12, 4);
    memcpy(&key->dst_ip, pkt + 16, 4);
    key->proto = pkt[9];

    uint16_t frag_off_net;
    memcpy(&frag_off_net, pkt + 6, 2);
    uint16_t frag_off = ntohs(frag_off_net) & 0x1fff;

    if (frag_off != 0) {
        /* non-first fragment: no L4 header available, group by IP id so
           all fragments of one datagram share a flow */
        uint16_t id_net;
        memcpy(&id_net, pkt + 4, 2);
        key->ip_id = ntohs(id_net);
        key->flags |= FLOW_KEY_FRAG;
        return 1;
    }

    const unsigned char *l4 = pkt + ihl;
    int l4len = len - (int)ihl;

    if (key->proto == IPPROTO_TCP || key->proto == IPPROTO_UDP) {
        if (l4len < 4) return 0;
        uint16_t sport_net, dport_net;
        memcpy(&sport_net, l4, 2);
        memcpy(&dport_net, l4 + 2, 2);
        key->sport = ntohs(sport_net);
        key->dport = ntohs(dport_net);
    } else if (key->proto == IPPROTO_ICMP) {
        if (l4len < 8) return 0;
        uint8_t type = l4[0], code = l4[1];
        uint16_t id_net;
        memcpy(&id_net, l4 + 4, 2);
        key->sport = ntohs(id_net);
        key->dport = ((uint16_t)type << 8) | code;
    }
    /* other protocols: no ports - every packet between this src/dst pair
       for that protocol shares one flow, which is fine, they're rare */
    return 1;
}

static inline uint32_t flow_key_hash(const flow_key_t *k) {
    const uint8_t *p = (const uint8_t*)k;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < sizeof(*k); i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static inline int flow_key_eq(const flow_key_t *a, const flow_key_t *b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

static flow_entry_t *flow_table_lookup(const flow_key_t *key, uint32_t hash) {
    flow_bucket_t *b = &flow_table[hash & (FLOW_TABLE_BUCKETS - 1)];
    for (int i = 0; i < FLOW_TABLE_WAYS; i++) {
        flow_entry_t *f = &b->slots[i];
        if (f->valid && flow_key_eq(&f->key, key)) {
            f->last_seen_ms = (uint32_t)now_ms();
            return f;
        }
    }
    return NULL;
}

static void flow_evict(flow_entry_t *f) {
    if (!f->valid) return;
    f->generation++;
    f->valid = 0;
    f->timer_deadline = 0;
    for (int i = 0; i < REORDER_WINDOW; i++) {
        if (f->rbuf[i].pkt) { free(f->rbuf[i].pkt); f->rbuf[i].pkt = NULL; }
    }
}

static flow_entry_t *flow_table_insert(const flow_key_t *key, uint32_t hash, uint8_t role) {
    flow_bucket_t *b = &flow_table[hash & (FLOW_TABLE_BUCKETS - 1)];
    flow_entry_t *victim = NULL;

    /* prefer an empty slot, then the LRU slot with no pending timer */
    for (int i = 0; i < FLOW_TABLE_WAYS; i++) {
        flow_entry_t *f = &b->slots[i];
        if (!f->valid) { victim = f; break; }
        if (f->timer_deadline != 0) continue;
        if (!victim || f->last_seen_ms < victim->last_seen_ms) victim = f;
    }
    if (!victim) {
        /* every slot has a pending timer - just take the LRU one anyway */
        for (int i = 0; i < FLOW_TABLE_WAYS; i++) {
            flow_entry_t *f = &b->slots[i];
            if (!victim || f->last_seen_ms < victim->last_seen_ms) victim = f;
        }
    }

    if (victim->valid) flow_evict(victim);

    victim->key = *key;
    victim->valid = 1;
    victim->role = role;
    victim->last_seen_ms = (uint32_t)now_ms();
    victim->rx_next_seq = 0;
    victim->tx_next_seq = 0;
    victim->timer_deadline = 0;
    victim->generation++;
    for (int i = 0; i < REORDER_WINDOW; i++) victim->rbuf[i].pkt = NULL;
    return victim;
}

static flow_entry_t *flow_get_or_create(const flow_key_t *key, uint32_t hash, uint8_t role) {
    flow_entry_t *f = flow_table_lookup(key, hash);
    return f ? f : flow_table_insert(key, hash, role);
}

static void timer_heap_sift_up(int i) {
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (timer_heap[parent].deadline <= timer_heap[i].deadline) break;
        timer_event_t tmp = timer_heap[parent];
        timer_heap[parent] = timer_heap[i];
        timer_heap[i] = tmp;
        i = parent;
    }
}

static void timer_heap_sift_down(int i) {
    while (1) {
        int l = 2 * i + 1, r = l + 1, smallest = i;
        if (l < timer_heap_size && timer_heap[l].deadline < timer_heap[smallest].deadline) smallest = l;
        if (r < timer_heap_size && timer_heap[r].deadline < timer_heap[smallest].deadline) smallest = r;
        if (smallest == i) break;
        timer_event_t tmp = timer_heap[i];
        timer_heap[i] = timer_heap[smallest];
        timer_heap[smallest] = tmp;
        i = smallest;
    }
}

static void timer_heap_push(flow_entry_t *f) {
    if (timer_heap_size >= TIMER_HEAP_CAP) {
        /* Shouldn't happen (bounded by flow table size), but never
           overflow the array - the deadline still fires via the flow's
           own timer_deadline check during periodic flush sweeps if this
           ever gets hit; drop the heap-acceleration for this one event. */
        return;
    }
    timer_heap[timer_heap_size].deadline = f->timer_deadline;
    timer_heap[timer_heap_size].flow = f;
    timer_heap[timer_heap_size].generation = f->generation;
    int i = timer_heap_size++;
    timer_heap_sift_up(i);
}

/* drop stale heap entries (flow evicted/reused, or timer already cleared) */
static void timer_heap_clean(void) {
    while (timer_heap_size > 0) {
        timer_event_t *e = &timer_heap[0];
        if (e->flow->valid && e->flow->generation == e->generation &&
            e->flow->timer_deadline == e->deadline && e->deadline != 0)
            break;
        timer_heap[0] = timer_heap[--timer_heap_size];
        timer_heap_sift_down(0);
    }
}

static uint32_t timer_heap_min_deadline(void) {
    timer_heap_clean();
    return timer_heap_size ? timer_heap[0].deadline : 0;
}

static void flow_flush(flow_entry_t *f) {
    uint16_t start = f->rx_next_seq;
    uint16_t max_delivered = f->rx_next_seq;
    int any = 0;

    for (int i = 0; i < REORDER_WINDOW; i++) {
        uint16_t seq = (uint16_t)(start + i);
        int idx = seq & (REORDER_WINDOW - 1);
        rslot_t *slot = &f->rbuf[idx];
        if (slot->pkt && slot->seq == seq) {
            ssize_t w = write(tun_fd, slot->pkt, slot->len);
            DBG("DBG reorder: timeout-flush seq=%u wrote %zd to tun\n", seq, w);
            free(slot->pkt);
            slot->pkt = NULL;
            max_delivered = seq;
            any = 1;
        }
    }
    if (any) f->rx_next_seq = (uint16_t)(max_delivered + 1);
    f->timer_deadline = 0;
}

static void timer_heap_process_expired(uint32_t now) {
    timer_heap_clean();
    while (timer_heap_size > 0 && timer_heap[0].deadline <= now) {
        timer_event_t e = timer_heap[0];
        timer_heap[0] = timer_heap[--timer_heap_size];
        timer_heap_sift_down(0);
        if (e.flow->valid && e.flow->generation == e.generation && e.flow->timer_deadline == e.deadline)
            flow_flush(e.flow);
        timer_heap_clean();
    }
}

static int reorder_gap_pending(const flow_entry_t *f) {
    for (int i = 0; i < REORDER_WINDOW; i++) if (f->rbuf[i].pkt) return 1;
    return 0;
}

/* inner/inner_len must be a heap buffer the caller is handing off
   ownership of - flow_rx_packet either writes+frees it immediately or
   stores it in the flow's own reorder slot until delivered or timed out. */
static void flow_rx_packet(flow_entry_t *f, unsigned char *inner, uint16_t inner_len, uint16_t seq) {
    uint16_t expected = f->rx_next_seq;
    uint16_t delta = (uint16_t)(seq - expected);

    if (delta == 0) {
        ssize_t w = write(tun_fd, inner, inner_len);
        DBG("DBG reorder: in-order seq=%u wrote %zd to tun\n", seq, w);
        free(inner);
        f->rx_next_seq++;
        while (1) {
            int idx = f->rx_next_seq & (REORDER_WINDOW - 1);
            rslot_t *slot = &f->rbuf[idx];
            if (slot->pkt && slot->seq == f->rx_next_seq) {
                ssize_t dw = write(tun_fd, slot->pkt, slot->len);
                DBG("DBG reorder: drained seq=%u wrote %zd to tun\n", slot->seq, dw);
                free(slot->pkt);
                slot->pkt = NULL;
                f->rx_next_seq++;
            } else break;
        }
        if (!reorder_gap_pending(f)) f->timer_deadline = 0;
    } else if (delta < REORDER_WINDOW) {
        int idx = seq & (REORDER_WINDOW - 1);
        if (f->rbuf[idx].pkt && f->rbuf[idx].seq == seq) { free(inner); return; } /* duplicate */
        if (f->rbuf[idx].pkt) free(f->rbuf[idx].pkt); /* stale leftover, shouldn't happen */
        f->rbuf[idx].pkt = inner;
        f->rbuf[idx].len = inner_len;
        f->rbuf[idx].seq = seq;
        DBG("DBG reorder: buffered seq=%u (expected %u)\n", seq, expected);
        if (f->timer_deadline == 0) {
            f->timer_deadline = (uint32_t)now_ms() + REORDER_TIMEOUT_MS;
            timer_heap_push(f);
        }
    } else {
        /* Far outside the window: most likely the sender's per-flow
           counter restarted (its flow entry was evicted/recreated) while
           we still remember a much higher expected sequence. Treat this
           packet as a fresh synchronization point rather than dropping
           it - flush whatever was buffered under the old expectation
           first. */
        DBG("DBG reorder: seq=%u far outside window (expected %u), resyncing\n", seq, expected);
        flow_flush(f);
        ssize_t w = write(tun_fd, inner, inner_len);
        DBG("DBG reorder: resync wrote %zd to tun\n", w);
        free(inner);
        f->rx_next_seq = (uint16_t)(seq + 1);
    }
}

/* epoll_wait timeout: the minimum remaining time across every flow
   currently waiting on a missing packet, or the normal idle timeout */
static int flow_epoll_timeout(void) {
    uint32_t now = (uint32_t)now_ms();
    uint32_t deadline = timer_heap_min_deadline();
    if (!deadline) return 1000;
    return deadline > now ? (int)(deadline - now) : 0;
}

static void send_flush(void) {
    while (sq_count) {
        out_pkt_t *pkt = &send_queue[sq_head];
        ssize_t n = sendto(icmp_fd, pkt->data, pkt->len, MSG_DONTWAIT,
                           (struct sockaddr*)&pkt->dest, sizeof(pkt->dest));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            fprintf(stderr, "sendto failed (len=%zd): %s\n", pkt->len, strerror(errno));
        } else {
            DBG("DBG sendto ok, sent %zd bytes to %s\n", n, inet_ntoa(pkt->dest.sin_addr));
        }
        sq_head = next_idx(sq_head);
        sq_count--;
    }
}

static int tun_create(const char *dev, int mtu_) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("/dev/net/tun"); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF"); close(fd); return -1;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifreq ifr2;
        memset(&ifr2, 0, sizeof(ifr2));
        strncpy(ifr2.ifr_name, dev, IFNAMSIZ - 1);
        ifr2.ifr_mtu = mtu_;
        if (ioctl(s, SIOCSIFMTU, &ifr2) < 0) perror("SIOCSIFMTU (ignored)");
        close(s);
    }
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

/*
 * Bring the interface up and assign its point-to-point addresses from
 * inside the process itself, instead of relying on a wrapper script to
 * run `ip addr`/`ip link set up` after the fact. This is what lets the
 * systemd unit be a plain Type=simple with no PIDFile: the binary is
 * fully self-contained from the moment it starts, so systemd's own
 * process tracking (via the real PID it launched) is always accurate -
 * no window where an external script's stale bookkeeping could delete
 * this interface out from under a still-running instance.
 */
static int tun_configure(const char *dev, struct in_addr local_tun, struct in_addr peer_tun) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket(SOCK_DGRAM) for tun_configure"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr = local_tun;
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) { perror("SIOCSIFADDR"); close(s); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    sin = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    sin->sin_family = AF_INET;
    sin->sin_addr = peer_tun;
    if (ioctl(s, SIOCSIFDSTADDR, &ifr) < 0) { perror("SIOCSIFDSTADDR"); close(s); return -1; }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { perror("SIOCGIFFLAGS"); close(s); return -1; }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { perror("SIOCSIFFLAGS"); close(s); return -1; }

    close(s);
    return 0;
}

static int icmp_sock_create(struct in_addr local) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) { perror("raw ICMP socket"); return -1; }

    int buf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr = local;
    if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
        perror("bind raw ICMP"); close(fd); return -1;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

static volatile int running = 1;
static void int_handler(int sig) { (void)sig; running = 0; }

static void usage(const char *arg0) {
    fprintf(stderr,
        "Usage: %s -L <local-real-ip> -R <peer-real-ip> -A <local-tun-ip> -P <peer-tun-ip>\n"
        "          [-M mtu] [-I ident-hex] [-T tun-name] [-s] [-v]\n"
        "  -L  this server's real public IP (mandatory)\n"
        "  -R  the OTHER server's real public IP (mandatory)\n"
        "  -A  this end's point-to-point tunnel IP, e.g. 10.99.0.1 (mandatory)\n"
        "  -P  the OTHER end's point-to-point tunnel IP, e.g. 10.99.0.2 (mandatory)\n"
        "  -M  inner MTU, default %d\n"
        "  -I  base ICMP identifier in hex, default 0x%04x (must match on both ends)\n"
        "  -T  TUN device name, default tun0\n"
        "  -s  server mode: answer with genuine Echo Reply (id+1) instead of\n"
        "      Echo Request (id). Run with -s on exactly one end; the other\n"
        "      end (client) is the default with no -s.\n"
        "  -v  verbose: log every packet (debug only, hurts throughput)\n"
        "\n"
        "The process brings its own interface up and assigns -A/-P itself - no\n"
        "external `ip addr`/`ip link` calls needed before or after starting it.\n",
        arg0, DEFAULT_MTU, DEFAULT_IDENT);
    exit(1);
}

int main(int argc, char **argv) {
    int got_local = 0, got_peer = 0, got_tun_local = 0, got_tun_peer = 0;
    int opt;
    unsigned tmp;
    struct in_addr tun_local_ip, tun_peer_ip;

    while ((opt = getopt(argc, argv, "L:R:A:P:M:I:T:svh")) != -1) {
        switch (opt) {
        case 'L':
            if (!inet_aton(optarg, &local_ip)) usage(argv[0]);
            got_local = 1; break;
        case 'R':
            if (!inet_aton(optarg, &peer_ip)) usage(argv[0]);
            got_peer = 1; break;
        case 'A':
            if (!inet_aton(optarg, &tun_local_ip)) usage(argv[0]);
            got_tun_local = 1; break;
        case 'P':
            if (!inet_aton(optarg, &tun_peer_ip)) usage(argv[0]);
            got_tun_peer = 1; break;
        case 'M':
            mtu = atoi(optarg);
            if (mtu < 576 || mtu > 1472) usage(argv[0]);
            break;
        case 'I':
            if (sscanf(optarg, "%x", &tmp) != 1 || tmp > 0xFFFF) usage(argv[0]);
            ident = (uint16_t)tmp; break;
        case 'T':
            tun_name = optarg; break;
        case 's':
            is_server = 1; break;
        case 'v':
            verbose = 1; break;
        default:
            usage(argv[0]);
        }
    }
    if (!got_local || !got_peer || !got_tun_local || !got_tun_peer) usage(argv[0]);

    /* Client owns id=ident (used on its Echo Request); server owns
       id=ident+1 (used on its Echo Reply). Each side's decapsulate()
       expects the OTHER side's id on the OTHER side's type. */
    if (is_server) { local_ident = (uint16_t)(ident + 1); remote_ident = ident; }
    else           { local_ident = ident; remote_ident = (uint16_t)(ident + 1); }

    send_queue = calloc(QUEUE_SIZE, sizeof(out_pkt_t));
    if (!send_queue) { perror("calloc"); return 1; }

    char local_str[16];
    strncpy(local_str, inet_ntoa(local_ip), sizeof(local_str) - 1);
    local_str[sizeof(local_str) - 1] = '\0';
    printf("ICMPTUN: local %s <-> peer %s, MTU %d, role=%s, local_id 0x%04x, remote_id 0x%04x, dev %s\n",
           local_str, inet_ntoa(peer_ip), mtu, is_server ? "server" : "client",
           local_ident, remote_ident, tun_name);

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr = peer_ip;

    icmp_fd = icmp_sock_create(local_ip);
    if (icmp_fd < 0) return 1;

    tun_fd = tun_create(tun_name, mtu);
    if (tun_fd < 0) return 1;

    if (tun_configure(tun_name, tun_local_ip, tun_peer_ip) < 0) {
        fprintf(stderr, "failed to configure %s (address/up) - exiting\n", tun_name);
        return 1;
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); return 1; }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = tun_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev);
    ev.data.fd = icmp_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, icmp_fd, &ev);

    signal(SIGINT, int_handler);
    signal(SIGTERM, int_handler);
    signal(SIGPIPE, SIG_IGN);

    char tun_local_str[16];
    strncpy(tun_local_str, inet_ntoa(tun_local_ip), sizeof(tun_local_str) - 1);
    tun_local_str[sizeof(tun_local_str) - 1] = '\0';
    printf("Tunnel running. %s is up: %s peer %s\n",
           tun_name, tun_local_str, inet_ntoa(tun_peer_ip));
    fflush(stdout);

    unsigned char inner[MAX_INNER], rawbuf[MAX_PKT];
    struct sockaddr_in from;
    socklen_t fromlen;

    while (running) {
        struct epoll_event events[2];
        int nfds = epoll_wait(epoll_fd, events, 2, flow_epoll_timeout());
        if (nfds < 0) { if (errno == EINTR) continue; break; }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == tun_fd) {
                while (1) {
                    ssize_t n = read(tun_fd, inner, sizeof(inner));
                    if (n < 0) {
                        if (errno != EAGAIN) fprintf(stderr, "tun read error: %s\n", strerror(errno));
                        break;
                    }
                    if (n == 0) break;
                    DBG("DBG tun_read n=%zd\n", n);
                    if (sq_count >= QUEUE_SIZE) { fprintf(stderr, "queue full, dropping packet\n"); continue; }

                    flow_key_t key;
                    uint16_t seq = 0;
                    if (flow_key_from_inner(inner, (int)n, &key)) {
                        flow_entry_t *f = flow_get_or_create(&key, flow_key_hash(&key), FLOW_ROLE_TX);
                        seq = f->tx_next_seq++;
                    }
                    /* unparseable inner packet (shouldn't happen from a
                       real TUN device): still tunnel it, seq=0 is fine
                       since it won't collide with a real flow's buffer
                       for more than one packet */

                    out_pkt_t *slot = &send_queue[sq_tail];
                    if (encapsulate(inner, (int)n, seq, slot) == 0) {
                        sq_tail = next_idx(sq_tail);
                        sq_count++;
                        DBG("DBG queued for send, sq_count=%d dest=%s\n", sq_count, inet_ntoa(slot->dest.sin_addr));
                    } else {
                        DBG("DBG encapsulate failed\n");
                    }
                }
            } else if (events[i].data.fd == icmp_fd) {
                while (1) {
                    fromlen = sizeof(from);
                    ssize_t n = recvfrom(icmp_fd, rawbuf, sizeof(rawbuf),
                                         MSG_DONTWAIT,
                                         (struct sockaddr*)&from, &fromlen);
                    if (n < 0) {
                        if (errno != EAGAIN) fprintf(stderr, "icmp recv error: %s\n", strerror(errno));
                        break;
                    }
                    DBG("DBG icmp_recv n=%zd from=%s\n", n, inet_ntoa(from.sin_addr));
                    int inlen;
                    uint16_t seq;
                    if (decapsulate(rawbuf, (int)n, inner, &inlen, &seq, &from) == 0) {
                        DBG("DBG decap ok, len=%d seq=%u\n", inlen, seq);
                        flow_key_t key;
                        flow_entry_t *f;
                        if (flow_key_from_inner(inner, inlen, &key)) {
                            f = flow_get_or_create(&key, flow_key_hash(&key), FLOW_ROLE_RX);
                        } else {
                            /* fallback: shouldn't happen for anything we
                               ourselves encapsulated, but keep a single
                               shared flow for it rather than dropping */
                            memset(&key, 0, sizeof(key));
                            f = flow_get_or_create(&key, flow_key_hash(&key), FLOW_ROLE_RX);
                        }
                        unsigned char *copy = malloc(inlen);
                        if (copy) {
                            memcpy(copy, inner, inlen);
                            flow_rx_packet(f, copy, (uint16_t)inlen, seq);
                        }
                    } else {
                        DBG("DBG decapsulate rejected packet\n");
                    }
                }
            }
        }
        timer_heap_process_expired((uint32_t)now_ms());
        send_flush();
    }

    fprintf(stderr, "shutting down\n");
    close(tun_fd); close(icmp_fd); close(epoll_fd);
    free(send_queue);
    return 0;
}
EOF_ICMPTUN_C
}

# ------------------------------------------------------------------ init ---

cmd_init() {
    need_root
    local role="" local_ip="" peer_ip="" ident="4d54" mtu="1400" tun="tun0"
    local tun_local="" tun_peer=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role) role="$2"; shift 2 ;;
            -L) local_ip="$2"; shift 2 ;;
            -R) peer_ip="$2"; shift 2 ;;
            -I) ident="$2"; shift 2 ;;
            -M) mtu="$2"; shift 2 ;;
            -T) tun="$2"; shift 2 ;;
            -A) tun_local="$2"; shift 2 ;;
            -P) tun_peer="$2"; shift 2 ;;
            *) echo "invalid option: $1"; exit 1 ;;
        esac
    done
    [[ "$role" == "client" || "$role" == "server" ]] || { echo "--role must be client or server"; exit 1; }
    [[ -n "$local_ip" && -n "$peer_ip" ]] || { echo "both -L and -R are required"; exit 1; }

    # -A/-P let you pick the tunnel's own point-to-point IPs explicitly -
    # required once more than one tunnel exists on the same box (e.g. one
    # Iran server tunneling to several foreign boxes, or several Iran
    # servers into one foreign box - see ICMPTUN_INSTANCE): each needs
    # its own non-overlapping range. Falls back to the original fixed
    # convention (client=.1, server=.2 on 10.99.0.0/30) when not given,
    # for backward compatibility with a single-tunnel setup.
    if [[ -z "$tun_local" || -z "$tun_peer" ]]; then
        if [[ "$role" == "server" ]]; then tun_local="10.99.0.2"; tun_peer="10.99.0.1"
        else                               tun_local="10.99.0.1"; tun_peer="10.99.0.2"; fi
    fi

    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
ROLE=$role
LOCAL_IP=$local_ip
PEER_IP=$peer_ip
IDENT=$ident
MTU=$mtu
TUN_NAME=$tun
TUN_LOCAL=$tun_local
TUN_PEER=$tun_peer
EOF
    touch "$PF_FILE"
    write_source
    echo "config written: $CONF_FILE"
    echo "role=$role local=$local_ip peer=$peer_ip tun=$tun_local<->$tun_peer"
    echo "next: pick 'Enable auto-start' from the menu"
}

# ----------------------------------------------------------------- build ---

cmd_build() {
    need_root
    # Always regenerate from the source embedded in THIS copy of the
    # script, never trust whatever .c happens to already be on disk - an
    # older deploy's leftover source silently recompiling into "the new
    # binary" is exactly how a stale build ships without anyone noticing.
    write_source
    gcc -O2 -Wall -o "$BIN" "$SRC_FILE"
    echo "built: $BIN"
}

# ------------------------------------------------------------ nat scaffold -

_ident_hex_upper() {
    # normalizes IDENT to 4 uppercase hex digits, e.g. 4d54 -> 4D54
    printf '%04X' "0x$1"
}

setup_nat_scaffolding() {
    load_conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    iptables -t nat -N "$DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -C PREROUTING -j "$DNAT_CHAIN" 2>/dev/null || \
        iptables -t nat -A PREROUTING -j "$DNAT_CHAIN"
    iptables -t nat -C POSTROUTING -o "$TUN_NAME" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$TUN_NAME" -j MASQUERADE

    iptables -N "$FWD_CHAIN" 2>/dev/null || true
    iptables -C FORWARD -j "$FWD_CHAIN" 2>/dev/null || \
        iptables -A FORWARD -j "$FWD_CHAIN"
    iptables -C "$FWD_CHAIN" -i "$TUN_NAME" -j ACCEPT 2>/dev/null || \
        iptables -A "$FWD_CHAIN" -i "$TUN_NAME" -j ACCEPT
    iptables -C "$FWD_CHAIN" -o "$TUN_NAME" -j ACCEPT 2>/dev/null || \
        iptables -A "$FWD_CHAIN" -o "$TUN_NAME" -j ACCEPT

    # Suppress the local kernel's own auto-reply to an inbound client
    # envelope (icmp_echo_ignore_all=0 is required for real inner-tunnel
    # pings, but that means the kernel also answers our own outer client
    # packets with a spurious Echo Reply carrying the CLIENT's id - see
    # icmptun.c's decapsulate() comment for why this matters). Harmless to
    # install on both ends: the client never emits an outbound echo-reply
    # with this id in the first place.
    local hex; hex=$(_ident_hex_upper "$IDENT")
    iptables -t raw -C OUTPUT -p icmp --icmp-type echo-reply \
        -m u32 --u32 "24&0xFFFF0000=0x${hex}0000" -j DROP 2>/dev/null || \
        iptables -t raw -A OUTPUT -p icmp --icmp-type echo-reply \
            -m u32 --u32 "24&0xFFFF0000=0x${hex}0000" -j DROP
}

# ----------------------------------------------------------------- start ---

_pgrep_pattern() { echo "$BIN -L $LOCAL_IP -R $PEER_IP"; }

# Tracks the running process by matching its actual command line (pgrep)
# rather than a PID file. A PID file needs external bookkeeping to stay
# correct; a stale one caused a real bug here once already (systemd's
# Type=forking + PIDFile path normalization desynced from this script's
# own view of "is it running", leading to a second instance deleting the
# first one's still-live interface). pgrep has no state to go stale.
_is_running() { pgrep -f "$(_pgrep_pattern)" >/dev/null 2>&1; }

# True once `enable` has installed the unit: from then on, systemd owns
# starting/stopping the actual process (it runs the binary directly, no
# wrapper), and this script's start/stop just delegate to systemctl. This
# is what prevents a manual start/stop from ever running a second,
# independent instance alongside the systemd-managed one - the exact
# collision that once caused a live instance's tun0 to get deleted out
# from under it.
_systemd_owns_it() { systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; }

cmd_start() {
    need_root
    load_conf
    [[ -x "$BIN" ]] || cmd_build

    if _is_running; then
        echo "already running"
        return 0
    fi

    if _systemd_owns_it; then
        systemctl start "$SERVICE_NAME"
        echo "tunnel started (via systemd). role=$ROLE tun=$TUN_LOCAL<->$TUN_PEER"
        return 0
    fi

    ip link del "$TUN_NAME" 2>/dev/null || true

    local sflag=""
    [[ "$ROLE" == "server" ]] && sflag="-s"
    # shellcheck disable=SC2086
    setsid "$BIN" -L "$LOCAL_IP" -R "$PEER_IP" -A "$TUN_LOCAL" -P "$TUN_PEER" \
        -M "$MTU" -I "$IDENT" -T "$TUN_NAME" $sflag \
        >> "$LOG_FILE" 2>&1 < /dev/null &
    disown
    sleep 1

    cmd_postup
    echo "tunnel started. role=$ROLE tun=$TUN_LOCAL<->$TUN_PEER"
}

cmd_stop() {
    need_root
    load_conf 2>/dev/null || true
    if _systemd_owns_it; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi
    pkill -f "$(_pgrep_pattern)" 2>/dev/null || true
    sleep 0.3
    [[ -n "${TUN_NAME:-}" ]] && ip link del "$TUN_NAME" 2>/dev/null || true
    echo "tunnel stopped"
}

cmd_restart() { cmd_stop; sleep 1; cmd_start; }

# ---------------------------------------------------------------- status ---

_row() { printf "  %-16s %s\n" "$1" "$2"; }

cmd_status() {
    load_conf
    echo "┌─ tunnel ──────────────────────────────────────────────────"
    _row "role"     "$ROLE$([ -n "$INSTANCE" ] && echo "  (instance: $INSTANCE)")"
    _row "local"     "$LOCAL_IP"
    _row "peer"      "$PEER_IP"
    _row "interface" "$TUN_NAME  ($TUN_LOCAL <-> $TUN_PEER)"
    _row "ident/mtu" "0x$IDENT / $MTU"

    local pid
    pid=$(pgrep -f "$(_pgrep_pattern)" | head -1)
    if [[ -n "$pid" ]]; then
        _row "process" "${C_GREEN}running${C_RESET} (pid $pid)"
    else
        _row "process" "${C_RED}stopped${C_RESET}"
    fi
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        _row "systemd" "enabled ($(systemctl is-active "$SERVICE_NAME" 2>/dev/null))"
    fi

    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        _row "$TUN_NAME" "${C_GREEN}up${C_RESET}"
        if ping -c 3 -W 2 -i 0.3 "$TUN_PEER" >/tmp/.icmptun_ping.$$ 2>&1; then
            loss=$(grep -oP '\d+(?=% packet loss)' /tmp/.icmptun_ping.$$ || true)
            rtt=$(grep -oP 'rtt.*= \K[0-9.]+(?=/)' /tmp/.icmptun_ping.$$ || true)
            local loss_c="$C_GREEN"; [[ "${loss:-100}" != "0" ]] && loss_c="$C_YELLOW"
            _row "ping to peer" "${loss_c}loss=${loss}%${C_RESET}  rtt=${rtt}ms"
        else
            _row "ping to peer" "${C_RED}failed${C_RESET}"
        fi
        rm -f /tmp/.icmptun_ping.$$
    else
        _row "$TUN_NAME" "${C_RED}down${C_RESET}"
    fi
    echo "└───────────────────────────────────────────────────────────"
    echo
    echo "  port forwards:"
    pf_list | sed 's/^/  /'
}

# Applied after the binary is confirmed up (tcp_reordering + NAT/port-
# forward rules) - shared by both the manual start path and systemd's
# ExecStartPost. Safe to run even if tun0 hasn't finished appearing yet:
# iptables accepts rules naming an interface by string before it exists,
# they simply take effect the moment it does.
cmd_postup() {
    load_conf
    # The in-tunnel reorder buffer's window was shortened (see
    # REORDER_TIMEOUT_MS in icmptun.c) to bound head-of-line-blocking
    # latency under real multi-connection load, which means more
    # residual reordering now reaches TCP directly - bumped a bit from
    # the previous value to compensate so genuine reordering still
    # doesn't trigger spurious fast-retransmits.
    sysctl -w net.ipv4.tcp_reordering=16 >/dev/null
    setup_nat_scaffolding
    pf_apply_all
}

cmd_enable() {
    need_root
    load_conf
    [[ -x "$BIN" ]] || cmd_build
    # Avoid a manually-started instance sticking around once systemd also
    # starts owning this service - see _systemd_owns_it.
    cmd_stop 2>/dev/null || true

    local sflag=""
    [[ "$ROLE" == "server" ]] && sflag="-s"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ICMPTUN tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/sbin/ip link del $TUN_NAME
ExecStart=$BIN -L $LOCAL_IP -R $PEER_IP -A $TUN_LOCAL -P $TUN_PEER -M $MTU -I $IDENT -T $TUN_NAME $sflag
ExecStartPost=$SCRIPT_PATH postup
ExecStopPost=-/sbin/ip link del $TUN_NAME
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME"
    echo "systemd service enabled: $SERVICE_NAME"
}

cmd_logs() {
    if [[ "${1:-}" == "-f" ]]; then
        tail -f "$LOG_FILE"
    else
        tail -100 "$LOG_FILE"
    fi
}

# ------------------------------------------------------- port forwarding ---

_pf_validate_proto() {
    case "$1" in
        tcp|udp) echo "$1" ;;
        both) echo "tcp udp" ;;
        *) echo "invalid protocol: $1 (must be tcp/udp/both)" >&2; exit 1 ;;
    esac
}

_pf_dnat_rule() {
    local action="$1" proto="$2" port="$3" tip="$4" tport="$5"
    iptables -t nat "$action" "$DNAT_CHAIN" -p "$proto" --dport "$port" \
        -j DNAT --to-destination "$tip:$tport"
}

# Surfaces exactly the class of bug that once silently broke a port
# forward here: a pre-existing DNAT rule elsewhere in the nat table (from
# an older/unrelated setup) sitting BEFORE our chain and matching the
# same port, or a local process already bound to it. Neither is fatal by
# itself, but both mean this forward may never actually reach the
# tunnel - warn loudly so it's a deliberate call, not a silent failure
# discovered hours later.
_pf_check_conflicts() {
    local port="$1" proto="$2"
    local hits
    hits=$(iptables-save -t nat 2>/dev/null | \
        grep -E "^-A (PREROUTING|OUTPUT) .*-p ${proto} .*--dport ${port}( |$)" || true)
    if [[ -n "$hits" ]]; then
        echo "${C_YELLOW}warning: another DNAT rule already claims port $port/$proto (outside our chain) - it may catch traffic before it ever reaches the tunnel:${C_RESET}"
        echo "$hits" | sed 's/^/    /'
    fi
    if ss -H -"${proto:0:1}"ln 2>/dev/null | awk '{print $4}' | grep -qE ":${port}\$"; then
        echo "${C_YELLOW}warning: a local process is already listening on port $port ($proto) on this box${C_RESET}"
    fi
}

cmd_pf_add() {
    need_root
    load_conf
    local port="${1:?port required}" proto="${2:?tcp/udp/both required}"
    local tip="${3:-$TUN_PEER}" tport="${4:-$port}"
    local plist; plist=$(_pf_validate_proto "$proto")

    for p in $plist; do
        if grep -qE "^${port} ${p} " "$PF_FILE" 2>/dev/null; then
            echo "already exists: $port/$p - skipped"
            continue
        fi
        _pf_check_conflicts "$port" "$p"
        echo "$port $p $tip $tport" >> "$PF_FILE"
        _pf_dnat_rule -A "$p" "$port" "$tip" "$tport"
        echo "added: $port/$p -> $tip:$tport"
    done
}

cmd_pf_del() {
    need_root
    load_conf
    local port="${1:?port required}" proto="${2:?tcp/udp/both required}"
    local plist; plist=$(_pf_validate_proto "$proto")

    for p in $plist; do
        local line; line=$(grep -E "^${port} ${p} " "$PF_FILE" 2>/dev/null || true)
        if [[ -z "$line" ]]; then
            echo "not found: $port/$p"
            continue
        fi
        local tip tport
        tip=$(awk '{print $3}' <<<"$line")
        tport=$(awk '{print $4}' <<<"$line")
        _pf_dnat_rule -D "$p" "$port" "$tip" "$tport" 2>/dev/null || true
        # grep -v legitimately exits 1 when it filters out the file's only
        # remaining line (zero output = "no lines selected") - under set -e
        # that must NOT skip the mv, or the "deleted" entry silently stays
        # in the file while this function still reports success.
        grep -vE "^${port} ${p} " "$PF_FILE" > "$PF_FILE.tmp" || true
        mv "$PF_FILE.tmp" "$PF_FILE"
        echo "removed: $port/$p"
    done
}

cmd_pf_list() { pf_list; }

pf_list() {
    load_conf 2>/dev/null || return 0
    [[ -s "$PF_FILE" ]] || { echo "(no port forwards defined)"; return 0; }
    printf "%-8s %-6s %-20s %-8s\n" "PORT" "PROTO" "TARGET" "TPORT"
    while read -r port proto tip tport; do
        [[ -z "$port" ]] && continue
        printf "%-8s %-6s %-20s %-8s\n" "$port" "$proto" "$tip" "$tport"
    done < "$PF_FILE"
}

pf_apply_all() {
    load_conf
    iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
    [[ -s "$PF_FILE" ]] || return 0
    while read -r port proto tip tport; do
        [[ -z "$port" ]] && continue
        _pf_dnat_rule -A "$proto" "$port" "$tip" "$tport"
    done < "$PF_FILE"
}

cmd_pf_flush() {
    need_root
    load_conf
    iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
    : > "$PF_FILE"
    echo "all port forwards cleared"
}

# ------------------------------------------------------------------ test ---

cmd_test() {
    load_conf
    echo "--- ping ---"
    ping -c 8 -i 0.3 -W 3 "$TUN_PEER" || true
    if command -v iperf3 >/dev/null 2>&1; then
        echo "--- iperf3 (needs iperf3 -s running on the peer) ---"
        timeout 10 iperf3 -c "$TUN_PEER" -t 5 -B "$TUN_LOCAL" || \
            echo "(iperf3 is not running on the peer - start it there with iperf3 -s -D)"
    else
        echo "iperf3 not installed, speed test skipped"
    fi
}

# ------------------------------------------------------------------- BBR ---
#
# System-wide TCP congestion control, independent of the tunnel itself -
# applies to any TCP this box originates or forwards. Worth offering on
# both ends: BBR tends to hold throughput better than the default cubic
# on paths with occasional loss/reordering, which is exactly this path's
# profile even with the reorder buffer catching most of it.

cmd_bbr_status() {
    local cur avail qdisc
    cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
    avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "?")
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
    echo "current algorithm: $cur   qdisc: $qdisc"
    echo "kernel-available algorithms: $avail"
    if [[ "$cur" == "bbr" ]]; then
        echo "status: ${C_GREEN}enabled${C_RESET}"
    else
        echo "status: ${C_RED}disabled${C_RESET}"
    fi
}

cmd_bbr_enable() {
    need_root
    modprobe tcp_bbr 2>/dev/null || true
    local avail; avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
    if [[ "$avail" != *bbr* ]]; then
        echo "this kernel doesn't support BBR (available: $avail)"
        return 1
    fi
    sysctl -w net.core.default_qdisc=fq >/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-icmptun-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    echo "BBR enabled and made persistent (survives reboot too)."
}

cmd_bbr_disable() {
    need_root
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null
    rm -f /etc/sysctl.d/99-icmptun-bbr.conf
    echo "BBR disabled, back to cubic."
}

# ------------------------------------------------- peer SSH (remote mgmt) --
#
# Used only by "remove tunnel from both servers". Entered once, saved to a
# root-only file, never required again. Purely a management convenience -
# the tunnel core (icmptun itself) has zero SSH dependency, and a failed
# or unreachable peer connection here must never touch local tunnel state.

load_peer_conf() {
    [[ -f "$PEER_CONF_FILE" ]] || return 1
    # shellcheck disable=SC1090
    source "$PEER_CONF_FILE"
    [[ -n "${PEER_SSH_HOST:-}" ]]
}

wizard_peer_conf() {
    load_conf
    header
    echo "--- SSH connection details for the peer server ---"
    echo "Saved once (file $PEER_CONF_FILE, root-readable only) - you won't need to enter it again."
    echo
    read -rp "Peer IP/host [default: $PEER_IP]: " h; h="${h:-$PEER_IP}"
    read -rp "SSH port [22]: " prt; prt="${prt:-22}"
    read -rp "User [root]: " usr; usr="${usr:-root}"
    read -rsp "Password: " pass; echo
    read -rp "SOCKS5 proxy to reach that server (optional, host:port format - Enter to skip): " proxy
    mkdir -p "$CONF_DIR"
    cat > "$PEER_CONF_FILE" <<EOF
PEER_SSH_HOST=$h
PEER_SSH_PORT=$prt
PEER_SSH_USER=$usr
PEER_SSH_PASS=$pass
PEER_SSH_PROXY=$proxy
EOF
    chmod 600 "$PEER_CONF_FILE"
    echo "saved."
}

# Runs one command on the peer over SSH (password auth via a throwaway
# SSH_ASKPASS helper, optionally through a SOCKS5 proxy). Never touches
# local state; callers must treat a non-zero return as "remote step
# skipped", not as a reason to unwind anything already done locally.
_peer_ssh() {
    local remote_cmd="$1"
    load_peer_conf || return 1
    local ap; ap=$(mktemp)
    cat > "$ap" <<'EOF'
#!/bin/sh
printf '%s\n' "$ICMPTUN_PEER_PASS"
EOF
    chmod 700 "$ap"
    local proxy_opts=()
    if [[ -n "${PEER_SSH_PROXY:-}" ]]; then
        proxy_opts=(-o "ProxyCommand=nc -X 5 -x $PEER_SSH_PROXY %h %p")
    fi
    ICMPTUN_PEER_PASS="$PEER_SSH_PASS" SSH_ASKPASS="$ap" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
            -o LogLevel=ERROR -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 "${proxy_opts[@]}" \
            -p "${PEER_SSH_PORT:-22}" "${PEER_SSH_USER:-root}@${PEER_SSH_HOST}" "$remote_cmd"
    local rc=$?
    rm -f "$ap"
    return $rc
}

# --------------------------------------------------------------- remove ---

# Full local teardown: stop process, disable/remove the systemd unit,
# remove our iptables rules (targeted removal, never a blanket flush of
# chains we don't own), drop tun0. Config files are kept so the tunnel
# can be brought back with just "start" later. Always completes fully
# regardless of any later remote step's outcome.
cmd_remove_local() {
    need_root
    load_conf 2>/dev/null || { echo "nothing to remove (not configured)"; return 0; }

    systemctl disable --now icmptun.service 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true

    cmd_stop 2>/dev/null || true

    iptables -t nat -F "$DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D PREROUTING -j "$DNAT_CHAIN" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "$TUN_NAME" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -X "$DNAT_CHAIN" 2>/dev/null || true
    iptables -D FORWARD -j "$FWD_CHAIN" 2>/dev/null || true
    iptables -F "$FWD_CHAIN" 2>/dev/null || true
    iptables -X "$FWD_CHAIN" 2>/dev/null || true
    local hex; hex=$(_ident_hex_upper "$IDENT")
    iptables -t raw -D OUTPUT -p icmp --icmp-type echo-reply \
        -m u32 --u32 "24&0xFFFF0000=0x${hex}0000" -j DROP 2>/dev/null || true

    echo "tunnel fully removed from this box (config kept, 'start' brings it back)."
}

# Local removal always runs first and unconditionally; the remote attempt
# is strictly best-effort afterward and never allowed to affect the
# already-completed local result.
cmd_remove_both() {
    need_root
    cmd_remove_local

    echo
    echo "attempting to remove the tunnel from the peer server too..."
    if ! load_peer_conf; then
        echo "no saved connection details for the peer server."
        read -rp "enter them now? (Y/n): " yn
        if [[ "${yn:-Y}" == "n" || "${yn:-Y}" == "N" ]]; then
            echo "skipped - the peer will need manual removal."
            return 0
        fi
        wizard_peer_conf
    fi

    local remote_cmd='systemctl disable --now icmptun.service 2>/dev/null; rm -f /etc/systemd/system/icmptun.service; systemctl daemon-reload 2>/dev/null; pkill -f "icmptun -L" 2>/dev/null; ip link del tun0 2>/dev/null; iptables -t nat -F ICMPTUN_DNAT 2>/dev/null; iptables -t nat -X ICMPTUN_DNAT 2>/dev/null; iptables -F ICMPTUN_FWD 2>/dev/null; iptables -X ICMPTUN_FWD 2>/dev/null; echo REMOTE_REMOVE_OK'

    if _peer_ssh "$remote_cmd"; then
        echo "removal from the peer server succeeded too."
    else
        echo "SSH to the peer server failed - this box is fully removed and healthy, but the peer needs manual removal."
    fi
}

# ---------------------------------------------------------------- UI/menu --

C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'

pause() { echo; read -rp "Press Enter to continue..." _ || true; }

header() {
    clear
    local title="ICMPTUN"
    [[ -n "$INSTANCE" ]] && title="ICMPTUN [$INSTANCE]"
    # Note: lines below deliberately don't close the box with a right-hand
    # border - printf's field-width padding counts ANSI color bytes as
    # visible characters, so a colored value inside a fixed-width field
    # throws off the padding and misaligns a right border. Left-aligned,
    # no right border, is the option that can't silently drift.
    echo -e "${C_CYAN}${C_BOLD}╔══════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  $title"
    echo -e "${C_CYAN}${C_BOLD}╠══════════════════════════════════════════════════════════${C_RESET}"
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CONF_FILE"
        local proc_state tun_state
        if _is_running; then
            proc_state="${C_GREEN}●${C_RESET} running"
        else
            proc_state="${C_RED}●${C_RESET} stopped"
        fi
        if ip link show "$TUN_NAME" >/dev/null 2>&1; then
            tun_state="${C_GREEN}up${C_RESET}"
        else
            tun_state="${C_RED}down${C_RESET}"
        fi
        echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  role: ${C_YELLOW}$ROLE${C_RESET}   local: $LOCAL_IP   peer: $PEER_IP"
        echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  process: $proc_state   $TUN_NAME: $tun_state"
    else
        echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  ${C_RED}not configured yet${C_RESET}"
    fi
    echo -e "${C_CYAN}${C_BOLD}╚══════════════════════════════════════════════════════════${C_RESET}"
    echo
}

wizard_init() {
    header
    echo "--- Initial setup ---"
    echo "What is this server's role?"
    echo "  1) client  (initiates the connection)"
    echo "  2) server  (answers - typically the box with the reachable public IP)"
    read -rp "Choice: " rchoice
    local role=""
    case "$rchoice" in
        1) role=client ;;
        2) role=server ;;
        *) echo "invalid choice"; pause; return 1 ;;
    esac
    read -rp "This server's real IP: " local_ip
    read -rp "Peer server's real IP: " peer_ip
    if [[ -z "$local_ip" || -z "$peer_ip" ]]; then
        echo "both IPs are required"; pause; return 1
    fi
    read -rp "ICMP identifier, hex [default 4d54]: " ident; ident="${ident:-4d54}"
    read -rp "MTU [default 1400]: " mtu; mtu="${mtu:-1400}"

    local def_local def_peer
    if [[ "$role" == "server" ]]; then def_local="10.99.0.2"; def_peer="10.99.0.1"
    else                               def_local="10.99.0.1"; def_peer="10.99.0.2"; fi
    echo
    echo "Tunnel's internal IP (used only between the two tunnel ends, not a real IP)."
    echo "If this is the only tunnel running on this box, the default is fine."
    echo "If you're running several tunnels on this box at once (e.g. several Iran servers into one foreign box), each needs its own separate range."
    read -rp "This end's tunnel IP [default $def_local]: " tun_local; tun_local="${tun_local:-$def_local}"
    read -rp "Peer's tunnel IP [default $def_peer]: " tun_peer; tun_peer="${tun_peer:-$def_peer}"

    cmd_init --role "$role" -L "$local_ip" -R "$peer_ip" -I "$ident" -M "$mtu" -A "$tun_local" -P "$tun_peer"
    cmd_build

    read -rp "Start and enable the systemd service (auto-start) now too? (Y/n): " yn
    if [[ "${yn:-Y}" != "n" && "${yn:-Y}" != "N" ]]; then
        cmd_enable
    fi
    pause
}

declare -a PF_IDX_PORT PF_IDX_PROTO

pf_list_numbered() {
    load_conf 2>/dev/null || { echo "(not configured)"; return 0; }
    PF_IDX_PORT=(); PF_IDX_PROTO=()
    if [[ ! -s "$PF_FILE" ]]; then
        echo "(no port forwards defined)"
        return 0
    fi
    printf "%-4s %-8s %-6s %-20s %-8s\n" "#" "PORT" "PROTO" "TARGET" "TPORT"
    local i=1
    while read -r port proto tip tport; do
        [[ -z "$port" ]] && continue
        printf "%-4s %-8s %-6s %-20s %-8s\n" "$i" "$port" "$proto" "$tip" "$tport"
        PF_IDX_PORT+=("$port"); PF_IDX_PROTO+=("$proto")
        i=$((i + 1))
    done < "$PF_FILE"
}

wizard_pf_add() {
    load_conf
    read -rp "Public port: " port
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then echo "invalid port"; return 1; fi
    echo "Protocol?  1) tcp   2) udp   3) both together (tcp+udp)"
    read -rp "Choice [3]: " pchoice
    local proto
    case "${pchoice:-3}" in
        1) proto=tcp ;;
        2) proto=udp ;;
        *) proto=both ;;
    esac
    read -rp "Target IP [default: tunnel peer - $TUN_PEER]: " tip; tip="${tip:-$TUN_PEER}"
    read -rp "Target port [default: same as $port]: " tport; tport="${tport:-$port}"
    cmd_pf_add "$port" "$proto" "$tip" "$tport"
}

wizard_pf_del() {
    pf_list_numbered
    [[ ${#PF_IDX_PORT[@]} -eq 0 ]] && return 0
    read -rp "Row number to remove (0 = cancel): " idx
    [[ -z "$idx" || "$idx" == "0" ]] && return 0
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#PF_IDX_PORT[@]} )); then
        echo "invalid number"; return 1
    fi
    cmd_pf_del "${PF_IDX_PORT[$((idx - 1))]}" "${PF_IDX_PROTO[$((idx - 1))]}"
}

menu_portforward() {
    while true; do
        header
        echo -e "${C_DIM}── port forwarding (tcp/udp) ─────────────────────────────${C_RESET}"
        echo
        pf_list_numbered
        echo
        cat <<MENU
  ${C_BOLD}1)${C_RESET} Add a port forward
  ${C_BOLD}2)${C_RESET} Remove a port forward
  ${C_BOLD}3)${C_RESET} Clear all
  ${C_BOLD}0)${C_RESET} Back to main menu
MENU
        read -rp "Choice: " choice
        case "$choice" in
            1) wizard_pf_add; pause ;;
            2) wizard_pf_del; pause ;;
            3) read -rp "Sure? This clears every port forward (y/N): " c
               [[ "$c" == "y" || "$c" == "Y" ]] && cmd_pf_flush
               pause ;;
            0) return 0 ;;
            *) echo "invalid choice"; sleep 1 ;;
        esac
    done
}

menu_main() {
    while true; do
        header
        cat <<MENU
  ${C_DIM}tunnel${C_RESET}
   ${C_BOLD}1)${C_RESET} Status
   ${C_BOLD}2)${C_RESET} Start
   ${C_BOLD}3)${C_RESET} Stop
   ${C_BOLD}4)${C_RESET} Restart
   ${C_BOLD}5)${C_RESET} Port forwarding (add/remove/list)
   ${C_BOLD}6)${C_RESET} Ping + speed test

  ${C_DIM}system${C_RESET}
   ${C_BOLD}7)${C_RESET} Enable auto-start (systemd)
   ${C_BOLD}8)${C_RESET} Remove tunnel completely (this box + peer)
   ${C_BOLD}9)${C_RESET} Set peer SSH connection details
  ${C_BOLD}10)${C_RESET} Reconfigure (re-init)
  ${C_BOLD}11)${C_RESET} Enable/disable BBR (this box)

   ${C_BOLD}0)${C_RESET} Exit
MENU
        read -rp "Choice: " choice
        case "$choice" in
            1) header; cmd_status; pause ;;
            2) header; cmd_start; pause ;;
            3) header; cmd_stop; pause ;;
            4) header; cmd_restart; pause ;;
            5) menu_portforward ;;
            6) header; cmd_test; pause ;;
            7) header; cmd_enable; pause ;;
            8) header
               read -rp "Sure? This removes the tunnel completely from this box AND the peer (y/N): " c
               [[ "$c" == "y" || "$c" == "Y" ]] && cmd_remove_both
               pause ;;
            9) wizard_peer_conf; pause ;;
            10) wizard_init ;;
            11) menu_bbr ;;
            0) echo "goodbye"; exit 0 ;;
            *) echo "invalid choice"; sleep 1 ;;
        esac
    done
}

menu_bbr() {
    header
    echo "--- BBR (TCP congestion control) ---"
    echo
    cmd_bbr_status
    echo
    echo "  1) Enable BBR"
    echo "  2) Disable BBR (back to cubic)"
    echo "  0) Back"
    read -rp "Choice: " c
    case "$c" in
        1) cmd_bbr_enable ;;
        2) cmd_bbr_disable ;;
    esac
    pause
}

# ------------------------------------------------------------------- CLI ---
#
# Running with no arguments opens the interactive menu - the normal way to
# use this script day to day. Direct subcommands still work too, for quick
# one-off calls and scripting (e.g. `./icmptun-ctl.sh pf add 400 both`).

main() {
    need_root
    if [[ $# -gt 0 ]]; then
        case "$1" in
            start)    cmd_start; exit 0 ;;
            stop)     cmd_stop; exit 0 ;;
            restart)  cmd_restart; exit 0 ;;
            postup)   cmd_postup; exit 0 ;;
            status)   cmd_status; exit 0 ;;
            enable)   cmd_enable; exit 0 ;;
            build)    cmd_build; exit 0 ;;
            test)     cmd_test; exit 0 ;;
            logs)     shift; cmd_logs "$@"; exit 0 ;;
            bbr)
                case "${2:-status}" in
                    on|enable)   cmd_bbr_enable ;;
                    off|disable) cmd_bbr_disable ;;
                    *)           cmd_bbr_status ;;
                esac
                exit 0 ;;
            pf)
                shift
                case "${1:-}" in
                    add)   shift; cmd_pf_add "$@"; exit 0 ;;
                    del)   shift; cmd_pf_del "$@"; exit 0 ;;
                    list)  cmd_pf_list; exit 0 ;;
                    flush) cmd_pf_flush; exit 0 ;;
                    *) echo "usage: $SCRIPT_PATH pf add|del|list|flush ..."; exit 1 ;;
                esac
                ;;
            remove)
                case "${2:-}" in
                    both)  cmd_remove_both; exit 0 ;;
                    *)     cmd_remove_local; exit 0 ;;
                esac
                ;;
        esac
    fi
    if [[ ! -f "$CONF_FILE" ]]; then
        header
        echo "Welcome to the ICMPTUN management panel."
        echo "Not configured yet - let's set it up first."
        pause
        wizard_init
    fi
    menu_main
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
