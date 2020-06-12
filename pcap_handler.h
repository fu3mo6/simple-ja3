#ifndef PCAP_HANDLER_H
#define PCAP_HANDLER_H

#include <pcap.h>

typedef struct PCAP_CONFIG {
    int bufsize;
    int snaplen;
    int promisc_mode;
    int timeout;
    int max_packet;
    char* bpf_filter;
} pcap_c;

/* Describes a datalink header and how to extract v4/v6 frames from it */
struct DATALINK {
    int dlt;        /* BPF datalink type */
    int skiplen;        /* Number of bytes to skip datalink header */
    int ft_off;     /* Datalink frametype offset */
    int ft_len;     /* Datalink frametype length */
    int ft_is_be;       /* Set if frametype is big-endian */
    u_int32_t ft_mask;  /* Mask applied to frametype */
    u_int32_t ft_v4;    /* IPv4 frametype */
    u_int32_t ft_v6;    /* IPv6 frametype */
};

void setup_packet_capture(pcap_t **pcap, pcap_c *conf, int *linktype, char *dev, char *capfile);
int datalink_check(int linktype, const u_int8_t *pkt, u_int32_t caplen, int *af);

#endif