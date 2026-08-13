/*
 * obsctcp - IP-over-TCP tunnel (the "ipx tcp" architecture), obfuscated.
 *
 * Built to test whether a professional, unsignatured TCP tunnel on port 443
 * (looking like an ordinary long-lived HTTPS connection) evades per-route
 * rate policing that crushes raw/recognizable tunnels.
 *
 * One persistent TCP connection carries all tunneled IP packets. Framing on
 * the stream:
 *     [2-byte big-endian frame length L]
 *     [L bytes: 12-byte random nonce + ChaCha20-Poly1305 AEAD ciphertext of
 *               the inner IP packet]
 * No magic, no plaintext protocol header beyond the length prefix. libsodium
 * AEAD. Both peers share a pre-shared key. Server listens, client connects
 * (and auto-reconnects if the connection drops).
 *
 * Build: gcc -O2 -Wall -o obsctcp obsctcp.c -lpthread /usr/lib/x86_64-linux-gnu/libsodium.a
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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include "tcrypto.h"

#define MAX_INNER 1500
#define MAX_FRAME (NONCE_LEN + MAX_INNER + TAG_LEN)

static unsigned char key[KEY_LEN];
static int tun_fd;
static int conn_fd = -1;              /* current TCP connection */
static pthread_mutex_t wlock = PTHREAD_MUTEX_INITIALIZER;
static char *tun_name = "obsct0";
static int mtu = 1400;
static int is_server = 0, port = 443;
static struct in_addr local_ip, peer_ip;
static volatile int running = 1;

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

/* read exactly n bytes from a stream fd */
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

/* tun -> encrypt -> TCP framed. Coalesces a burst of tun packets into ONE
 * socket write (framing is self-delimiting, so concatenation is transparent to
 * the peer): far fewer write syscalls and smooth, large TCP sends instead of a
 * tiny segment per packet. */
#define UP_BATCH 64
static void *uplink(void *arg) {
    (void)arg;
    unsigned char in[MAX_INNER];
    unsigned char sbuf[UP_BATCH * (2 + MAX_FRAME)];
    while (running) {
        size_t used = 0; int cnt = 0;
        for (;;) {
            ssize_t n = read(tun_fd, in, sizeof(in));
            if (n <= 0) { if (errno == EINTR) continue; break; }
            unsigned char *fr = sbuf + used;
            unsigned char *nonce = fr + 2;
            next_nonce(nonce);
            unsigned long long clen = 0;
            aead_enc(fr + 2 + NONCE_LEN, &clen, in, (unsigned long long)n,
                     NULL, 0, NULL, nonce, key);
            size_t L = NONCE_LEN + clen;
            fr[0] = (unsigned char)(L >> 8);
            fr[1] = (unsigned char)(L & 0xff);
            used += 2 + L; cnt++;
            if (cnt >= UP_BATCH || used + (2 + MAX_FRAME) > sizeof(sbuf)) break;
            struct pollfd pfd = { .fd = tun_fd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 0) <= 0) break;     /* nothing more queued - flush */
        }
        if (used == 0) { usleep(500); continue; }
        int fd = conn_fd;
        if (fd < 0) continue;                     /* not connected yet - drop */
        pthread_mutex_lock(&wlock);
        int ok = (writen(fd, sbuf, used) == 0);
        pthread_mutex_unlock(&wlock);
        if (!ok) { if (conn_fd == fd) { shutdown(fd, SHUT_RDWR); } }
    }
    return NULL;
}

/* TCP framed -> decrypt -> tun. Drains the socket in large 256 KiB reads and
 * decodes every complete frame in the buffer per read. The old code read 2
 * bytes then L bytes per packet, so the app drained the socket one small packet
 * at a time and the receive window kept collapsing (rwnd-limited the sender to a
 * fraction of the link). Returns when the connection breaks. */
#define DL_BUF (1 << 18)
static void downlink_once(int fd) {
    unsigned char *buf = malloc(DL_BUF);
    unsigned char out[MAX_INNER + TAG_LEN];
    if (!buf) return;
    size_t have = 0;
    while (running) {
        size_t off = 0;
        while (have - off >= 2) {
            size_t L = (buf[off] << 8) | buf[off + 1];
            if (L < NONCE_LEN + TAG_LEN || L > MAX_FRAME) { free(buf); return; } /* desync */
            if (have - off < 2 + L) break;          /* frame not fully arrived yet */
            unsigned long long mlen = 0;
            if (aead_dec(out, &mlen, NULL, buf + off + 2 + NONCE_LEN,
                         (unsigned long long)(L - NONCE_LEN),
                         NULL, 0, buf + off + 2, key) != 0) { free(buf); return; }
            int ilen = inner_ip_len(out, mlen);
            if (ilen > 0) { if (write(tun_fd, out, ilen) < 0 && errno != EAGAIN) { /* drop */ } }
            off += 2 + L;
        }
        if (off > 0) { if (have > off) memmove(buf, buf + off, have - off); have -= off; }
        if (have == DL_BUF) { free(buf); return; }  /* single frame > buffer: impossible, bail */
        ssize_t r = read(fd, buf + have, DL_BUF - have);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; free(buf); return; }
        have += (size_t)r;
    }
    free(buf);
}

static void set_sockopts(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* Deliberately do NOT pin SO_SNDBUF/SO_RCVBUF. Setting either one disables
     * Linux TCP buffer autotuning; the receive window then stays pinned near its
     * initial ~64 KiB (rcv_ssthresh) and rwnd-limits the flow to ~20 Mbit on a
     * 40 ms / high-BDP path (measured). Autotuning grows both to the BDP by
     * itself and lets a single tunnel connection reach line rate. */
}

static void sigh(int s){ (void)s; running = 0; if (conn_fd >= 0) shutdown(conn_fd, SHUT_RDWR); }

static int parse_hexkey(const char *hex) {
    if (strlen(hex) != KEY_LEN * 2) return -1;
    for (int i = 0; i < KEY_LEN; i++){ unsigned b; if (sscanf(hex+i*2,"%2x",&b)!=1) return -1; key[i]=(unsigned char)b; }
    return 0;
}

static void usage(const char *a){
    fprintf(stderr,"Usage: %s -L <local-ip> -R <peer-ip> -A <local-tun> -P <peer-tun> -p <tcp-port> -k <64hex> [-s] [-T tun] [-M mtu]\n"
                   "  -s = server (listen). client omits -s and connects to -R.\n", a);
    exit(1);
}

int tun_main_tcp(int argc, char **argv){
    struct in_addr tun_local={0}, tun_peer={0};
    int gL=0,gR=0,gA=0,gP=0,gk=0, opt; char *keyhex=NULL;
    while ((opt=getopt(argc,argv,"L:R:A:P:p:k:T:M:sh"))!=-1){
        switch(opt){
        case 'L': if(!inet_aton(optarg,&local_ip))usage(argv[0]); gL=1; break;
        case 'R': if(!inet_aton(optarg,&peer_ip))usage(argv[0]); gR=1; break;
        case 'A': if(!inet_aton(optarg,&tun_local))usage(argv[0]); gA=1; break;
        case 'P': if(!inet_aton(optarg,&tun_peer))usage(argv[0]); gP=1; break;
        case 'p': port=atoi(optarg); break;
        case 'k': keyhex=optarg; gk=1; break;
        case 'T': tun_name=optarg; break;
        case 'M': mtu=atoi(optarg); break;
        case 's': is_server=1; break;
        default: usage(argv[0]);
        }
    }
    if(!gL||!gR||!gA||!gP||!gk) usage(argv[0]);
    if(parse_hexkey(keyhex)<0){fprintf(stderr,"key must be 64 hex chars\n");return 1;}

    tun_fd = tun_alloc(tun_name, mtu);
    if (tun_configure(tun_name, tun_local, tun_peer) < 0) return 1;
    signal(SIGINT,sigh); signal(SIGTERM,sigh); signal(SIGPIPE,SIG_IGN);

    fprintf(stderr,"obsctcp up: %s, %s tcp/%d dev %s mtu %d (IP-over-TCP, ChaCha20-Poly1305)\n",
            is_server?"server":"client", is_server?"listen":"connect", port, tun_name, mtu);

    pthread_t up;
    pthread_create(&up, NULL, uplink, NULL);   /* reads conn_fd live */

    if (is_server) {
        int ls = socket(AF_INET, SOCK_STREAM, 0); if (ls<0) die("socket");
        int one=1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a; memset(&a,0,sizeof(a));
        a.sin_family=AF_INET; a.sin_addr=local_ip; a.sin_port=htons(port);
        if (bind(ls,(struct sockaddr*)&a,sizeof(a))<0) die("bind");
        if (listen(ls, 4) < 0) die("listen");
        while (running) {
            struct sockaddr_in ca; socklen_t cl=sizeof(ca);
            int fd = accept(ls, (struct sockaddr*)&ca, &cl);
            if (fd < 0) { if (errno==EINTR) continue; usleep(100000); continue; }
            if (ca.sin_addr.s_addr != peer_ip.s_addr) { close(fd); continue; }
            set_sockopts(fd);
            conn_fd = fd;
            downlink_once(fd);
            conn_fd = -1; close(fd);
        }
    } else {
        while (running) {
            int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd<0) die("socket");
            struct sockaddr_in la; memset(&la,0,sizeof(la));
            la.sin_family=AF_INET; la.sin_addr=local_ip;
            bind(fd,(struct sockaddr*)&la,sizeof(la));
            struct sockaddr_in ra; memset(&ra,0,sizeof(ra));
            ra.sin_family=AF_INET; ra.sin_addr=peer_ip; ra.sin_port=htons(port);
            if (connect(fd,(struct sockaddr*)&ra,sizeof(ra))<0) { close(fd); sleep(1); continue; }
            set_sockopts(fd);
            conn_fd = fd;
            downlink_once(fd);
            conn_fd = -1; close(fd);
            if (running) sleep(1);            /* reconnect */
        }
    }
    running = 0; pthread_join(up, NULL);
    close(tun_fd);
    return 0;
}
