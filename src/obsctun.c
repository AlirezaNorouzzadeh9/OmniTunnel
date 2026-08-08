/*
 * obsctun - an unsignatured IP-over-UDP tunnel.
 *
 * A custom point-to-point tunnel built to beat aggressive traffic policing
 * that throttles recognizable protocols (raw TCP, WireGuard, bare QUIC) but
 * leaves generic UDP far less touched. Every byte on the wire is
 * indistinguishable from random: there is NO magic constant, NO fixed
 * header, NO handshake, NO sequence number, NO constant-length control
 * packet. A passive classifier has nothing to fingerprint - the design
 * philosophy is obfs4's "look like nothing", applied to a plain IP tunnel.
 *
 * Wire format (one UDP datagram = one inner IP packet):
 *     [0 .. 11]   12-byte random nonce (looks random, because it is)
 *     [12 .. end] ChaCha20-Poly1305 AEAD ciphertext of the inner IP packet
 *                 (Poly1305 tag is the trailing 16 bytes)
 * No length field: UDP frames the datagram, and the inner IP header's own
 * total-length field bounds the real packet after decryption. No sequence
 * number: each datagram is a whole inner IP packet, so the inner TCP/IP
 * stack handles any reordering itself - a tunnel-level reorder buffer would
 * add both latency and a fingerprint for nothing.
 *
 * Crypto is libsodium's audited ChaCha20-Poly1305 (IETF). Rolling our own
 * Poly1305 would be irresponsible; the novelty here is the framing and the
 * transport, not the cipher.
 *
 * Symmetric: both peers run the same binary with the same pre-shared key,
 * each pointing -R at the other. No client/server distinction.
 *
 * Build: gcc -O2 -Wall -o obsctun obsctun.c -lsodium
 * Root only (TUN device).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/random.h>
#include <stdint.h>
#include "tcrypto.h"

#define MAX_INNER 1500
#define MAX_PKT   2048

static unsigned char key[KEY_LEN];
static int tun_fd, udp_fd;
static struct sockaddr_in peer_addr;
static char *tun_name = "obsc0";
static int mtu = 1400;
static volatile int running = 1;

static void die(const char *m) { perror(m); exit(1); }

/* ---- batched nonce pool: avoid a getrandom() syscall per packet ---- */
static _Thread_local unsigned char nonce_pool[NONCE_LEN * 2048];
static _Thread_local size_t nonce_off = sizeof(nonce_pool);
static void next_nonce(unsigned char out[NONCE_LEN]) {
    if (nonce_off + NONCE_LEN > sizeof(nonce_pool)) {
        ts_random(nonce_pool, sizeof(nonce_pool));
        nonce_off = 0;
    }
    memcpy(out, nonce_pool + nonce_off, NONCE_LEN);
    nonce_off += NONCE_LEN;
}

/* Length of the inner IP packet from its own header, so trailing padding
 * (if any) is dropped and we never write junk to the TUN. */
static int inner_ip_len(const unsigned char *p, size_t n) {
    if (n < 20) return -1;
    unsigned v = p[0] >> 4;
    if (v == 4) {
        int tot = (p[2] << 8) | p[3];
        if (tot < 20 || (size_t)tot > n) return -1;
        return tot;
    } else if (v == 6) {
        if (n < 40) return -1;
        int plen = (p[4] << 8) | p[5];
        int tot = 40 + plen;
        if ((size_t)tot > n) return -1;
        return tot;
    }
    return -1;
}

static int tun_alloc(const char *dev, int mtu_) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) die("/dev/net/tun");
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) die("TUNSETIFF");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifreq m; memset(&m, 0, sizeof(m));
        strncpy(m.ifr_name, dev, IFNAMSIZ - 1);
        m.ifr_mtu = mtu_;
        if (ioctl(s, SIOCSIFMTU, &m) < 0) perror("SIOCSIFMTU");
        struct ifreq q; memset(&q, 0, sizeof(q));
        strncpy(q.ifr_name, dev, IFNAMSIZ - 1);
        q.ifr_qlen = 100000;
        if (ioctl(s, SIOCSIFTXQLEN, &q) < 0) perror("SIOCSIFTXQLEN");
        close(s);
    }
    return fd;
}

static int tun_configure(const char *dev, struct in_addr lt, struct in_addr pt) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr; struct sockaddr_in *sin;
    memset(&ifr, 0, sizeof(ifr)); strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    sin = (struct sockaddr_in *)&ifr.ifr_addr; sin->sin_family = AF_INET; sin->sin_addr = lt;
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) { perror("SIOCSIFADDR"); close(s); return -1; }
    memset(&ifr, 0, sizeof(ifr)); strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    sin = (struct sockaddr_in *)&ifr.ifr_dstaddr; sin->sin_family = AF_INET; sin->sin_addr = pt;
    if (ioctl(s, SIOCSIFDSTADDR, &ifr) < 0) { perror("SIOCSIFDSTADDR"); close(s); return -1; }
    memset(&ifr, 0, sizeof(ifr)); strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { close(s); return -1; }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { perror("SIOCSIFFLAGS"); close(s); return -1; }
    close(s);
    return 0;
}

/* tun -> encrypt -> udp */
static void *uplink(void *arg) {
    (void)arg;
    unsigned char in[MAX_INNER];
    unsigned char out[MAX_PKT];
    while (running) {
        ssize_t n = read(tun_fd, in, sizeof(in));
        if (n <= 0) {
            /* Never let a transient error kill the thread. read(tun) can
               return EINTR; treat anything non-fatal as "try again". */
            if (errno == EINTR || errno == EAGAIN) continue;
            usleep(1000); continue;
        }
        unsigned char *nonce = out;
        next_nonce(nonce);
        unsigned long long clen = 0;
        aead_enc(
            out + NONCE_LEN, &clen,
            in, (unsigned long long)n,
            NULL, 0, NULL, nonce, key);
        ssize_t olen = NONCE_LEN + (ssize_t)clen;
        if (send(udp_fd, out, olen, 0) < 0 && errno != EAGAIN && errno != ENOBUFS)
            /* transient send errors are ignored - inner TCP retransmits */ ;
    }
    return NULL;
}

/* udp -> decrypt -> tun */
static void *downlink(void *arg) {
    (void)arg;
    unsigned char in[MAX_PKT];
    unsigned char out[MAX_INNER + TAG_LEN];
    while (running) {
        ssize_t n = recv(udp_fd, in, sizeof(in), 0);
        if (n <= 0) {
            /* On a connected UDP socket, recv() surfaces ICMP errors from
               the peer (e.g. ECONNREFUSED / port-unreachable while the peer
               is still starting up). Those are transient - keep looping, do
               NOT tear the tunnel down. Earlier this break killed the whole
               receive path the moment the peer wasn't ready first. */
            if (errno == EINTR || errno == EAGAIN) continue;
            usleep(1000); continue;
        }
        if (n < (ssize_t)(NONCE_LEN + TAG_LEN)) continue;
        unsigned char *nonce = in;
        unsigned long long mlen = 0;
        if (aead_dec(
                out, &mlen, NULL,
                in + NONCE_LEN, (unsigned long long)(n - NONCE_LEN),
                NULL, 0, nonce, key) != 0)
            continue;                       /* forged/corrupt - drop silently */
        int ilen = inner_ip_len(out, mlen);
        if (ilen < 0) continue;
        if (write(tun_fd, out, ilen) < 0 && errno != EAGAIN)
            /* TUN write error - drop, inner stack recovers */ ;
    }
    return NULL;
}

static void sigh(int s) { (void)s; running = 0; }

static int parse_hexkey(const char *hex) {
    if (strlen(hex) != KEY_LEN * 2) return -1;
    for (int i = 0; i < KEY_LEN; i++) {
        unsigned b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        key[i] = (unsigned char)b;
    }
    return 0;
}

static void usage(const char *a) {
    fprintf(stderr,
      "Usage: %s -L <local-ip> -R <peer-ip> -A <local-tun-ip> -P <peer-tun-ip>\n"
      "          -p <udp-port> -k <64-hex-char key> [-T tun-name] [-M mtu]\n"
      "  Both peers run this with the SAME key, each -R pointing at the other.\n"
      "  Generate a key with:  openssl rand -hex 32\n", a);
    exit(1);
}

int tun_main_udp(int argc, char **argv) {

    struct in_addr local_ip = {0}, peer_ip = {0}, tun_local = {0}, tun_peer = {0};
    int port = 0, opt;
    int gL=0,gR=0,gA=0,gP=0,gk=0;
    char *keyhex = NULL;
    while ((opt = getopt(argc, argv, "L:R:A:P:p:k:T:M:h")) != -1) {
        switch (opt) {
        case 'L': if (!inet_aton(optarg,&local_ip)) usage(argv[0]); gL=1; break;
        case 'R': if (!inet_aton(optarg,&peer_ip)) usage(argv[0]); gR=1; break;
        case 'A': if (!inet_aton(optarg,&tun_local)) usage(argv[0]); gA=1; break;
        case 'P': if (!inet_aton(optarg,&tun_peer)) usage(argv[0]); gP=1; break;
        case 'p': port = atoi(optarg); break;
        case 'k': keyhex = optarg; gk=1; break;
        case 'T': tun_name = optarg; break;
        case 'M': mtu = atoi(optarg); break;
        default: usage(argv[0]);
        }
    }
    if (!gL||!gR||!gA||!gP||!gk||port<=0) usage(argv[0]);
    if (parse_hexkey(keyhex) < 0) { fprintf(stderr,"key must be exactly 64 hex chars (32 bytes)\n"); return 1; }

    tun_fd = tun_alloc(tun_name, mtu);
    if (tun_configure(tun_name, tun_local, tun_peer) < 0) return 1;

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) die("udp socket");
    int buf = 16 * 1024 * 1024;
    setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET; la.sin_addr = local_ip; la.sin_port = htons(port);
    if (bind(udp_fd, (struct sockaddr*)&la, sizeof(la)) < 0) die("bind");
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET; peer_addr.sin_addr = peer_ip; peer_addr.sin_port = htons(port);
    if (connect(udp_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) die("connect");

    signal(SIGINT, sigh); signal(SIGTERM, sigh); signal(SIGPIPE, SIG_IGN);

    { char a[16], b[16];
      snprintf(a,sizeof(a),"%s",inet_ntoa(local_ip));
      snprintf(b,sizeof(b),"%s",inet_ntoa(peer_ip));
      fprintf(stderr,"obsctun up: %s <-> %s udp/%d, dev %s mtu %d\n", a, b, port, tun_name, mtu);
      fprintf(stderr,"wire: 12B nonce + ChaCha20-Poly1305, no header/handshake/seq\n"); }

    pthread_t up, down;
    pthread_create(&up, NULL, uplink, NULL);
    pthread_create(&down, NULL, downlink, NULL);
    pthread_join(up, NULL);
    pthread_join(down, NULL);
    close(udp_fd); close(tun_fd);
    return 0;
}
