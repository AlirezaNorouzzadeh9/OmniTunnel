/*
 * obscmux - multi-connection IP-over-TCP tunnel, obfuscated.
 *
 * Built for hostile ISPs that (a) block UDP outright and (b) poison a
 * long-lived TCP 5-tuple / drop ~half of new SYNs, yet let an *established*
 * connection run clean at line rate. A single-connection TCP tunnel melts
 * down there (TCP-over-TCP head-of-line blocking) to a fraction of the path.
 *
 * obscmux opens N parallel TCP connections and pins each inner flow to one
 * connection by hashing its 5-tuple, so:
 *   - per-flow ordering is preserved (no spurious inner retransmits),
 *   - many inner flows spread across N links -> aggregate approaches raw,
 *   - each link carries less -> the meltdown never dominates.
 *
 * Connection setup is non-blocking with a short timeout: a poisoned 5-tuple
 * is abandoned in ~3s and retried from a *fresh source port*, which is how a
 * plain client (fresh port each try) gets through ~50% SYN loss.
 *
 * Stream framing per packet (same as obsctcp):
 *     [2-byte big-endian L][ 12-byte nonce + ChaCha20-Poly1305(inner IP) ]
 * No magic, no plaintext header beyond the length. libsodium AEAD, PSK.
 *
 * Build: gcc -O2 -Wall -o obscmux obscmux.c -lpthread /usr/lib/x86_64-linux-gnu/libsodium.a
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
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <time.h>
#include "tcrypto.h"

#define MAX_INNER 1500
#define MAX_FRAME (NONCE_LEN + MAX_INNER + TAG_LEN)
#define MAXCONN 32
#define QDEPTH 2048          /* per-link outbound queue, in packets */

static unsigned char key[KEY_LEN];
static int tun_fd;
static char *tun_name = "obscm0";
static int mtu = 1400;
static int is_server = 0, port = 443, Nconn = 8;
static struct in_addr local_ip, peer_ip;
static volatile int running = 1;

/* One slot per parallel link. Each link has its own outbound queue drained by
 * its own writer thread, so a stalled link never blocks the TUN reader or the
 * other links (that thread-level head-of-line blocking was capping aggregate
 * throughput to a fraction of the path). fd<0 means the link is down. */
struct pkt { int len; unsigned char buf[2 + MAX_FRAME]; };
struct conn {
    volatile int fd;
    pthread_mutex_t qlock;
    pthread_cond_t  qcond;
    struct pkt *q;                    /* QDEPTH ring */
    int head, tail, count;
};
static struct conn conns[MAXCONN];

struct wr_arg { int idx; int fd; };

static void die(const char *m) { perror(m); exit(1); }

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

static int inner_ip_len(const unsigned char *p, size_t n) {
    if (n < 20) return -1;
    unsigned v = p[0] >> 4;
    if (v == 4) { int t = (p[2] << 8) | p[3]; return (t >= 20 && (size_t)t <= n) ? t : -1; }
    if (v == 6) { if (n < 40) return -1; int t = 40 + ((p[4] << 8) | p[5]); return ((size_t)t <= n) ? t : -1; }
    return -1;
}

/* FNV-1a over the inner flow key (src ip, dst ip, proto, src/dst ports) */
static uint32_t flow_hash(const unsigned char *p, int len) {
    uint32_t h = 2166136261u;
    if (len >= 20 && (p[0] >> 4) == 4) {
        for (int i = 12; i < 20; i++) { h ^= p[i]; h *= 16777619u; }   /* src+dst */
        unsigned proto = p[9];
        h ^= proto; h *= 16777619u;
        int ihl = (p[0] & 0x0f) * 4;
        if ((proto == 6 || proto == 17) && len >= ihl + 4)
            for (int i = ihl; i < ihl + 4; i++) { h ^= p[i]; h *= 16777619u; }  /* ports */
        return h;
    }
    int m = len < 40 ? len : 40;
    for (int i = 0; i < m; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

static int tun_alloc(const char *dev, int mtu_) {
    struct ifreq ifr; int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) die("/dev/net/tun");
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) die("TUNSETIFF");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifreq m; memset(&m, 0, sizeof(m)); strncpy(m.ifr_name, dev, IFNAMSIZ-1);
        m.ifr_mtu = mtu_; ioctl(s, SIOCSIFMTU, &m);
        struct ifreq q; memset(&q, 0, sizeof(q)); strncpy(q.ifr_name, dev, IFNAMSIZ-1);
        q.ifr_qlen = 100000; ioctl(s, SIOCSIFTXQLEN, &q);
        close(s);
    }
    return fd;
}

static int tun_configure(const char *dev, struct in_addr lt, struct in_addr pt) {
    int s = socket(AF_INET, SOCK_DGRAM, 0); if (s < 0) return -1;
    struct ifreq ifr; struct sockaddr_in *sin;
    memset(&ifr,0,sizeof(ifr)); strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
    sin=(struct sockaddr_in*)&ifr.ifr_addr; sin->sin_family=AF_INET; sin->sin_addr=lt;
    if (ioctl(s,SIOCSIFADDR,&ifr)<0){perror("SIOCSIFADDR");close(s);return -1;}
    memset(&ifr,0,sizeof(ifr)); strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
    sin=(struct sockaddr_in*)&ifr.ifr_dstaddr; sin->sin_family=AF_INET; sin->sin_addr=pt;
    if (ioctl(s,SIOCSIFDSTADDR,&ifr)<0){perror("SIOCSIFDSTADDR");close(s);return -1;}
    memset(&ifr,0,sizeof(ifr)); strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
    if (ioctl(s,SIOCGIFFLAGS,&ifr)<0){close(s);return -1;}
    ifr.ifr_flags |= (IFF_UP|IFF_RUNNING|IFF_POINTOPOINT);
    if (ioctl(s,SIOCSIFFLAGS,&ifr)<0){perror("SIOCSIFFLAGS");close(s);return -1;}
    close(s); return 0;
}

static int readn(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        got += r;
    }
    return 0;
}
static int writen(int fd, const unsigned char *buf, size_t n) {
    size_t put = 0;
    while (put < n) {
        ssize_t w = write(fd, buf + put, n - put);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return -1; }
        put += w;
    }
    return 0;
}

static void set_sockopts(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* No SO_SNDBUF/SO_RCVBUF: pinning either one disables Linux TCP autotuning,
     * which then pins the receive window near its initial ~64 KiB and rwnd-limits
     * each link to ~20 Mbit on a high-BDP path. Autotuning grows it to the BDP. */
}

/* append a framed packet to a link's queue; drop if full (inner TCP will
 * retransmit). Never blocks the caller on the socket. */
static void enqueue(int idx, const unsigned char *buf, int len) {
    struct conn *c = &conns[idx];
    pthread_mutex_lock(&c->qlock);
    if (c->fd >= 0 && c->count < QDEPTH) {
        struct pkt *p = &c->q[c->tail];
        p->len = len; memcpy(p->buf, buf, len);
        c->tail = (c->tail + 1) % QDEPTH;
        c->count++;
        pthread_cond_signal(&c->qcond);
    }
    pthread_mutex_unlock(&c->qlock);
}

/* one writer thread per live link: drains its queue to its socket. Blocking
 * writes here only ever stall this one link. Exits when its fd is replaced. */
static void *writer(void *arg) {
    struct wr_arg *wa = (struct wr_arg*)arg;
    int idx = wa->idx, fd = wa->fd; free(wa);
    struct conn *c = &conns[idx];
    for (;;) {
        pthread_mutex_lock(&c->qlock);
        while (c->count == 0 && running && c->fd == fd) {
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 1;
            pthread_cond_timedwait(&c->qcond, &c->qlock, &ts);
        }
        if (!running || c->fd != fd) { pthread_mutex_unlock(&c->qlock); break; }
        struct pkt p = c->q[c->head];
        c->head = (c->head + 1) % QDEPTH;
        c->count--;
        pthread_mutex_unlock(&c->qlock);
        if (writen(fd, p.buf, p.len) != 0) { shutdown(fd, SHUT_RDWR); break; }
    }
    return NULL;
}

/* single reader of the TUN: encrypt, then enqueue on the inner flow's pinned
 * link (fall back to any live link only while that one is reconnecting). */
static void *uplink(void *arg) {
    (void)arg;
    unsigned char in[MAX_INNER];
    unsigned char frame[2 + MAX_FRAME];
    while (running) {
        ssize_t n = read(tun_fd, in, sizeof(in));
        if (n <= 0) { if (errno == EINTR) continue; usleep(1000); continue; }
        unsigned char *nonce = frame + 2;
        next_nonce(nonce);
        unsigned long long clen = 0;
        aead_enc(
            frame + 2 + NONCE_LEN, &clen, in, (unsigned long long)n,
            NULL, 0, NULL, nonce, key);
        size_t L = NONCE_LEN + clen;
        frame[0] = (unsigned char)(L >> 8);
        frame[1] = (unsigned char)(L & 0xff);
        int start = (int)(flow_hash(in, (int)n) % (uint32_t)Nconn);
        int idx = -1;
        if (conns[start].fd >= 0) idx = start;
        else for (int k = 1; k < Nconn; k++) { int j = (start + k) % Nconn; if (conns[j].fd >= 0) { idx = j; break; } }
        if (idx >= 0) enqueue(idx, frame, (int)(2 + L));
    }
    return NULL;
}

/* stream -> decrypt -> TUN; returns when this link breaks */
static void downlink_once(int fd) {
    unsigned char hdr[2];
    unsigned char cbuf[MAX_FRAME];
    unsigned char out[MAX_INNER + TAG_LEN];
    while (running) {
        if (readn(fd, hdr, 2) < 0) return;
        size_t L = (hdr[0] << 8) | hdr[1];
        if (L < NONCE_LEN + TAG_LEN || L > MAX_FRAME) return;
        if (readn(fd, cbuf, L) < 0) return;
        unsigned long long mlen = 0;
        if (aead_dec(
                out, &mlen, NULL, cbuf + NONCE_LEN, (unsigned long long)(L - NONCE_LEN),
                NULL, 0, cbuf, key) != 0)
            return;
        int ilen = inner_ip_len(out, mlen);
        if (ilen < 0) continue;
        if (write(tun_fd, out, ilen) < 0 && errno != EAGAIN) { /* drop */ }
    }
}

static int connect_timeout(int fd, struct sockaddr_in *ra, int ms) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (struct sockaddr*)ra, sizeof(*ra));
    if (r != 0) {
        if (errno != EINPROGRESS) return -1;
        fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
        struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
        r = select(fd + 1, NULL, &wf, NULL, &tv);
        if (r <= 0) return -1;                       /* timeout/err -> abandon this 5-tuple */
        int err = 0; socklen_t el = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err) return -1;
    }
    fcntl(fd, F_SETFL, fl);
    return 0;
}

/* bring a freshly-connected link into service: reset its queue, publish the
 * fd, spawn its writer, run the reader until the link breaks, then tear down. */
static void run_link(int idx, int fd) {
    struct conn *c = &conns[idx];
    set_sockopts(fd);
    pthread_mutex_lock(&c->qlock); c->head = c->tail = c->count = 0; pthread_mutex_unlock(&c->qlock);
    c->fd = fd;
    struct wr_arg *wa = malloc(sizeof(*wa)); wa->idx = idx; wa->fd = fd;
    pthread_t wt; pthread_create(&wt, NULL, writer, wa);
    downlink_once(fd);                 /* blocks until the link breaks */
    c->fd = -1;
    pthread_cond_signal(&c->qcond);    /* wake the writer so it can exit */
    pthread_join(wt, NULL);
    close(fd);
}

/* client: one thread per slot, keeps a fresh-source-port link alive */
static void *client_slot(void *arg) {
    int idx = (int)(long)arg;
    while (running) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { sleep(1); continue; }
        struct sockaddr_in la; memset(&la, 0, sizeof(la));
        la.sin_family = AF_INET; la.sin_addr = local_ip;   /* port 0 -> new ephemeral each try */
        bind(fd, (struct sockaddr*)&la, sizeof(la));
        struct sockaddr_in ra; memset(&ra, 0, sizeof(ra));
        ra.sin_family = AF_INET; ra.sin_addr = peer_ip; ra.sin_port = htons(port);
        if (connect_timeout(fd, &ra, 3000) < 0) { close(fd); continue; }  /* retry, new port */
        run_link(idx, fd);
    }
    return NULL;
}

/* server: per-accepted-connection thread that owns one slot */
struct srv_arg { int fd; int idx; };
static void *server_conn(void *arg) {
    struct srv_arg *sa = (struct srv_arg*)arg;
    int fd = sa->fd, idx = sa->idx;
    free(sa);
    run_link(idx, fd);
    return NULL;
}

static void sigh(int s){
    (void)s; running = 0;
    for (int i = 0; i < Nconn; i++) { int fd = conns[i].fd; if (fd >= 0) shutdown(fd, SHUT_RDWR); }
}

static int parse_hexkey(const char *hex) {
    if (strlen(hex) != KEY_LEN * 2) return -1;
    for (int i = 0; i < KEY_LEN; i++){ unsigned b; if (sscanf(hex+i*2,"%2x",&b)!=1) return -1; key[i]=(unsigned char)b; }
    return 0;
}

static void usage(const char *a){
    fprintf(stderr,"Usage: %s -L <local-ip> -R <peer-ip> -A <local-tun> -P <peer-tun> "
                   "-p <tcp-port> -k <64hex> [-s] [-N conns] [-T tun] [-M mtu]\n"
                   "  -s = server (listen). client omits -s and connects to -R.\n"
                   "  -N = number of parallel TCP links (default 8, max %d).\n", a, MAXCONN);
    exit(1);
}

int tun_main_mux(int argc, char **argv){
    struct in_addr tun_local={0}, tun_peer={0};
    int gL=0,gR=0,gA=0,gP=0,gk=0, opt; char *keyhex=NULL;
    while ((opt=getopt(argc,argv,"L:R:A:P:p:k:T:M:N:sh"))!=-1){
        switch(opt){
        case 'L': if(!inet_aton(optarg,&local_ip))usage(argv[0]); gL=1; break;
        case 'R': if(!inet_aton(optarg,&peer_ip))usage(argv[0]); gR=1; break;
        case 'A': if(!inet_aton(optarg,&tun_local))usage(argv[0]); gA=1; break;
        case 'P': if(!inet_aton(optarg,&tun_peer))usage(argv[0]); gP=1; break;
        case 'p': port=atoi(optarg); break;
        case 'k': keyhex=optarg; gk=1; break;
        case 'T': tun_name=optarg; break;
        case 'M': mtu=atoi(optarg); break;
        case 'N': Nconn=atoi(optarg); break;
        case 's': is_server=1; break;
        default: usage(argv[0]);
        }
    }
    if(!gL||!gR||!gA||!gP||!gk) usage(argv[0]);
    if(Nconn<1||Nconn>MAXCONN){fprintf(stderr,"N must be 1..%d\n",MAXCONN);return 1;}
    if(parse_hexkey(keyhex)<0){fprintf(stderr,"key must be 64 hex chars\n");return 1;}

    for (int i=0;i<MAXCONN;i++){
        conns[i].fd=-1;
        pthread_mutex_init(&conns[i].qlock,NULL);
        pthread_cond_init(&conns[i].qcond,NULL);
        conns[i].head=conns[i].tail=conns[i].count=0;
        conns[i].q = (i < Nconn) ? calloc(QDEPTH, sizeof(struct pkt)) : NULL;
        if (i < Nconn && !conns[i].q) { fprintf(stderr,"queue alloc failed\n"); return 1; }
    }

    tun_fd = tun_alloc(tun_name, mtu);
    if (tun_configure(tun_name, tun_local, tun_peer) < 0) return 1;
    signal(SIGINT,sigh); signal(SIGTERM,sigh); signal(SIGPIPE,SIG_IGN);

    fprintf(stderr,"obscmux up: %s, %s tcp/%d x%d links dev %s mtu %d (multi-conn IP-over-TCP, ChaCha20-Poly1305)\n",
            is_server?"server":"client", is_server?"listen":"connect", port, Nconn, tun_name, mtu);

    pthread_t up;
    pthread_create(&up, NULL, uplink, NULL);

    if (is_server) {
        int ls = socket(AF_INET, SOCK_STREAM, 0); if (ls<0) die("socket");
        int one=1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a; memset(&a,0,sizeof(a));
        a.sin_family=AF_INET; a.sin_addr=local_ip; a.sin_port=htons(port);
        if (bind(ls,(struct sockaddr*)&a,sizeof(a))<0) die("bind");
        if (listen(ls, MAXCONN) < 0) die("listen");
        while (running) {
            struct sockaddr_in ca; socklen_t cl=sizeof(ca);
            int fd = accept(ls, (struct sockaddr*)&ca, &cl);
            if (fd < 0) { if (errno==EINTR) continue; usleep(100000); continue; }
            if (ca.sin_addr.s_addr != peer_ip.s_addr) { close(fd); continue; }
            int idx=-1;
            for (int i=0;i<Nconn;i++) if (conns[i].fd<0){ idx=i; break; }
            if (idx<0) { close(fd); continue; }                 /* pool full */
            struct srv_arg *sa=malloc(sizeof(*sa)); sa->fd=fd; sa->idx=idx;
            pthread_t t; pthread_create(&t,NULL,server_conn,sa); pthread_detach(t);
        }
    } else {
        pthread_t th[MAXCONN];
        for (int i=0;i<Nconn;i++) pthread_create(&th[i], NULL, client_slot, (void*)(long)i);
        for (int i=0;i<Nconn;i++) pthread_join(th[i], NULL);
    }
    running = 0; pthread_join(up, NULL);
    close(tun_fd);
    return 0;
}
