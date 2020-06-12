

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>


#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "pcap_handler.h"
#include "ja3_parser.h"

static volatile sig_atomic_t shutdown_request = 0;

/* Datalink types that we know about */
static struct PCAP_CONFIG pcap_conf = {
    .bufsize = 1000000,
    .snaplen = 640,
    .promisc_mode = 1,
    .timeout = 1000,
    .bpf_filter = NULL,
    .max_packet = 1000
};

/* Context for libpcap callback functions */
struct CB_CTXT {
    int linktype;
    int fatal;
    int want_v6;
};

static int
process_packet(const u_int8_t *cap_pkt, int dl_len, int af, const u_int32_t cap_len, const u_int32_t len, const struct timeval *rcv_time)
{
    int ret, frag, filtered;
    const u_int8_t *pkt = cap_pkt;
    int pkt_len = cap_len;

    // L2
    pkt += dl_len;
    pkt_len -= dl_len;

    // L3
    const struct ip *ip = (const struct ip *)pkt;
    if (pkt_len < 20 || pkt_len < ip->ip_hl * 4)
        return -1;
    if (ip->ip_v != 4)
        return -1;

    pkt += ip->ip_hl * 4;
    pkt_len -= ip->ip_hl * 4;

    // L4
    const struct tcphdr *tcp = (const struct tcphdr *)pkt;
    const struct udphdr *udp = (const struct udphdr *)pkt;
    const struct icmp *icmp = (const struct icmp *)pkt;

    // L5
    char srcaddr[64], dstaddr[64];
    inet_ntop(af, &ip->ip_src, srcaddr, sizeof(srcaddr));
    inet_ntop(af, &ip->ip_dst, dstaddr, sizeof(dstaddr));

    switch(ip->ip_p) {
    case IPPROTO_TCP:
        /* Check for runt packet, but don't error out on short frags */
        if (pkt_len < sizeof(*tcp))
            return -1;
        
        pkt += tcp->th_off * 4;
        pkt_len -= tcp->th_off * 4;

        char* ja3 = clienthello_parse_ja3(pkt, pkt_len, pkt_len);
        if(ja3){
            printf("[JA3] %s:%d ---> %s:%d (%s)\n", srcaddr, ntohs(tcp->th_sport), dstaddr, ntohs(tcp->th_dport), ja3);
            free(ja3);
        }
        ja3 = serverhello_parse_ja3s(pkt, pkt_len, pkt_len);
        if(ja3){
            printf("[JA3S] %s:%d ---> %s:%d (%s)\n", srcaddr, ntohs(tcp->th_sport), dstaddr, ntohs(tcp->th_dport), ja3);
            free(ja3);
        }
        break;
    case IPPROTO_UDP:
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        break;
    }

    return 0;
}

/*
 * Per-packet callback function from libpcap. Pass the packet (if it is IP)
 * sans datalink headers to process_packet.
 */
static void
pcap_cb(u_char *user_data, const struct pcap_pkthdr* phdr, const u_char *pkt)
{
    struct CB_CTXT *cb_ctxt = (struct CB_CTXT *)user_data;
    struct timeval tv;
    int s, af;

    s = datalink_check(cb_ctxt->linktype, pkt, phdr->caplen, &af);
    if (s < 0 || af == AF_INET6 ) {
        // non_ip packet
    }
    else {
        tv.tv_sec = phdr->ts.tv_sec;
        tv.tv_usec = phdr->ts.tv_usec;
        process_packet(pkt, s, af, phdr->caplen, phdr->len-s, &tv);
    }
    
}

/* Display commandline usage information */
static void
usage(void)
{
    printf("Usage: ja3_parser [-i INTERFACE] [-r pcap] [OPTIONS]\n");
}

int main(int argc, char **argv)
{
    char *iface = NULL, *capfile = NULL;
    extern char *optarg;
    extern int optind;

    pcap_t *pcap = NULL;
    struct CB_CTXT cb_ctxt;

    int ch, r;
    while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
        switch (ch) {
        case 'h':
            usage();
            return (0);
        case 'i':
            iface = strdup(optarg);
            break;
        case 'r':
            capfile = strdup(optarg);
            break;
        default:
            fprintf(stderr, "Invalid commandline option.\n");
            usage();
            return 0;
        }
    }

    printf("iface: %s, capfile: %s\n", iface, capfile);

    /* Will exit on failure */
    setup_packet_capture(&pcap, &pcap_conf, &cb_ctxt.linktype, iface, capfile);

    r = 0;
    while(r == 0 && shutdown_request == 0)
    {
        /* If we have data, run it through libpcap */
        r = pcap_dispatch(pcap, pcap_conf.max_packet, pcap_cb, (u_char*) &cb_ctxt);
        if (r == -1) {
            printf("pcap_dispatch() failed: %s", pcap_geterr(pcap));
            //break;
        }
        else if (r == 0 && capfile != NULL) {
            printf("shutting down after pcap EOF");
            break;
        }
    }

    pcap_close(pcap);

    return 0;
}
