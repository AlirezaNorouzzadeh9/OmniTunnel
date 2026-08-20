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
#define MIN_ICMP_PAYLOAD 56        /* Linux `ping` default payload size - pad
                                       up to this so small tunneled packets
                                       (TCP ACKs, DNS, etc) don't stand out by
                                       size alone. Packets already >= this
                                       (bulk data) are NOT disguised by this -
                                       there is no way to make a 1400-byte
                                       packet look like a 56-byte ping; that
                                       needs fragmenting into many ping-sized
                                       pieces, which this build does not do. */

static char *tun_name = "tun0";
static int mtu = DEFAULT_MTU;
static uint16_t ident = DEFAULT_IDENT;
static int is_server = 0;
/* Which ICMP type THIS end emits for its outbound tunnel data. -1 = derive from
   role (server->Echo Reply, client->Echo Request), the classic behaviour. An
   explicit -r reply|request overrides it, decoupling the ICMP type from the
   client/server role so a box can emit Echo REPLY (type 0) even as the tunnel
   initiator - needed on paths that drop inbound Echo Requests (type 8) but pass
   Echo Replies. The far side accepts either ICMP type; the per-direction id is
   the real tag (see decapsulate). */
static int tx_type = -1;
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
    /* Pad the ICMP payload up to a normal ping size when the real inner
       packet is smaller, so small tunneled packets aren't trivially
       distinguishable from genuine pings by size alone. The receiver
       recovers the true length from the inner IP header's own Total
       Length field (see decapsulate()), so this needs no wire-format
       change and no length prefix. */
    int payload_len = inner_len < MIN_ICMP_PAYLOAD ? MIN_ICMP_PAYLOAD : inner_len;
    int total = (int)sizeof(struct icmphdr) + payload_len;
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
    /* Default type follows the role (server=reply, client=request); -r overrides. */
    icmp->type = (tx_type >= 0) ? (uint8_t)tx_type
                                : (is_server ? ICMP_ECHOREPLY : ICMP_ECHO);
    icmp->code = 0;
    icmp->un.echo.id = htons(local_ident);
    /* seq is scoped PER FLOW (see flow_key_t below), not a single tunnel-
       wide counter - assigned by the caller from that flow's own tx
       counter, so reordering in one flow can never affect another. */
    icmp->un.echo.sequence = htons(seq);
    memcpy(out->data + sizeof(*icmp), inner, inner_len);
    if (payload_len > inner_len) {
        /* Fill the pad region with the classic incrementing byte pattern
           real `ping` implementations use, rather than zeros, so it also
           passes a casual look at the payload bytes themselves. */
        unsigned char *pad = out->data + sizeof(*icmp) + inner_len;
        for (int i = 0; i < payload_len - inner_len; i++) pad[i] = (unsigned char)(0x10 + (i & 0x3f));
    }
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
    /* Accept EITHER Echo Request (8) or Echo Reply (0) from the peer: with the
       -r flag each end may emit either type, so the type alone no longer tells
       us the role. The per-direction id (remote_ident) is the real tag - and it
       also rejects the kernel's own auto-reply to an inbound Echo Request, which
       mirrors the SENDER's id (never our remote_ident) rather than the peer's. */
    if ((icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY) ||
        icmp->code != 0 || ntohs(icmp->un.echo.id) != remote_ident)
        return -1;
    int payload = len - (int)sizeof(*icmp);
    if (payload < 0 || payload > mtu) return -1;
    /* Small packets are padded up to MIN_ICMP_PAYLOAD by the sender (see
       encapsulate()) with no separate length field - the true length is
       whatever the inner IP header itself declares. Trust that over the
       padded wire length whenever it's smaller and structurally valid. */
    if (payload >= (int)sizeof(struct iphdr)) {
        const struct iphdr *inner_iph = (const struct iphdr*)(buf + sizeof(*icmp));
        if (inner_iph->version == 4) {
            int declared = ntohs(inner_iph->tot_len);
            if (declared >= (int)sizeof(struct iphdr) && declared <= payload)
                payload = declared;
        }
    }
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
#define REORDER_WINDOW      256   /* power of two - per-flow reorder window */
#define REORDER_TIMEOUT_MS  45    /* max wait for a missing packet in one flow */
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
        "  -r  force emitted ICMP type: 'reply' (Echo Reply, type 0) or 'request'\n"
        "      (Echo Request, type 8), independent of role. Use on the end that\n"
        "      must reach a peer whose ingress drops one echo type. Default: by\n"
        "      role (server=reply, client=request). The far side accepts either.\n"
        "  -v  verbose: log every packet (debug only, hurts throughput)\n"
        "\n"
        "The process brings its own interface up and assigns -A/-P itself - no\n"
        "external `ip addr`/`ip link` calls needed before or after starting it.\n",
        arg0, DEFAULT_MTU, DEFAULT_IDENT);
    exit(1);
}

int tun_main_icmp(int argc, char **argv) {
    int got_local = 0, got_peer = 0, got_tun_local = 0, got_tun_peer = 0;
    int opt;
    unsigned tmp;
    struct in_addr tun_local_ip, tun_peer_ip;

    while ((opt = getopt(argc, argv, "L:R:A:P:M:I:T:r:svh")) != -1) {
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
        case 'r':
            /* Force the emitted ICMP type independently of role, for paths that
               drop one echo type in one direction. */
            if (!strcmp(optarg, "reply"))        tx_type = ICMP_ECHOREPLY;
            else if (!strcmp(optarg, "request")) tx_type = ICMP_ECHO;
            else usage(argv[0]);
            break;
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
    int eff_type = (tx_type >= 0) ? tx_type : (is_server ? ICMP_ECHOREPLY : ICMP_ECHO);
    printf("ICMPTUN: local %s <-> peer %s, MTU %d, role=%s, tx=%s%s, local_id 0x%04x, remote_id 0x%04x, dev %s\n",
           local_str, inet_ntoa(peer_ip), mtu, is_server ? "server" : "client",
           eff_type == ICMP_ECHOREPLY ? "reply(0)" : "request(8)",
           tx_type >= 0 ? " [forced]" : "",
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
