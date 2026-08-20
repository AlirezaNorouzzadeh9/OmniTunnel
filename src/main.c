/* tsuite - multi-protocol obfuscated tunnel core. One static binary that
 * dispatches to the requested transport; the bash manager drives it. */
#include <stdio.h>
#include <string.h>

int tun_main_udp(int, char **);
int tun_main_tcp(int, char **);
int tun_main_mux(int, char **);
int tun_main_icmp(int, char **);
int tun_main_ws(int, char **);

#define TSUITE_VERSION "2.3.0"

static void usage(const char *a) {
    fprintf(stderr,
        "omnitun " TSUITE_VERSION " - multi-protocol tunnel core\n"
        "usage: %s <mode> [options]\n"
        "  modes:\n"
        "    udp    IP-over-UDP AEAD (obsctun)\n"
        "    tcp    IP-over-TCP AEAD (obsctcp)\n"
        "    mux    multi-connection TCP (obscmux)\n"
        "    ws     multi-connection WebSocket, looks like HTTPS/WS (obscws)\n"
        "    icmp   IP-over-ICMP (icmptun)\n"
        "run '%s <mode> -h' for that mode's options.\n", a, a);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    const char *m = argv[1];
    if (!strcmp(m, "udp"))  return tun_main_udp(argc - 1, argv + 1);
    if (!strcmp(m, "tcp"))  return tun_main_tcp(argc - 1, argv + 1);
    if (!strcmp(m, "mux"))  return tun_main_mux(argc - 1, argv + 1);
    if (!strcmp(m, "ws"))   return tun_main_ws(argc - 1, argv + 1);
    if (!strcmp(m, "icmp")) return tun_main_icmp(argc - 1, argv + 1);
    if (!strcmp(m, "version") || !strcmp(m, "-v") || !strcmp(m, "--version")) {
        printf("omnitun %s\n", TSUITE_VERSION); return 0;
    }
    usage(argv[0]); return 1;
}
