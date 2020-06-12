

#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h> /* memset */
#include <stdlib.h>
#include <unistd.h> /* close */

#include "pcap_handler.h"

/* Datalink types that we know about */
static const struct DATALINK lt[] = {
    { DLT_EN10MB,   14, 12,  2,  1, 0xffffffff,  0x0800,   0x86dd },
    { DLT_PPP,   5,  3,  2,  1, 0xffffffff,  0x0021,   0x0057 },
#ifdef DLT_LINUX_SLL
    { DLT_LINUX_SLL,16, 14,  2,  1, 0xffffffff,  0x0800,   0x86dd },
#endif
    { DLT_RAW,   0,  0,  1,  1, 0x000000f0,  0x0040,   0x0060 },
    { DLT_NULL,  4,  0,  4,  0, 0xffffffff, AF_INET, AF_INET6 },
#ifdef DLT_LOOP
    { DLT_LOOP,  4,  0,  4,  1, 0xffffffff, AF_INET, AF_INET6 },
#endif
    { -1,       -1, -1, -1, -1, 0x00000000,  0xffff,   0xffff },
};

/*
 * Figure out how many bytes to skip from front of packet to get past
 * datalink headers. If pkt is specified, also check whether determine
 * whether or not it is one that we are interested in (IPv4 or IPv6 for now)
 *
 * Returns number of bytes to skip or -1 to indicate that entire
 * packet should be skipped
 */
int
datalink_check(int linktype, const u_int8_t *pkt, u_int32_t caplen, int *af)
{
    int i, j;
    u_int32_t frametype;
    static const struct DATALINK *dl = NULL;

    /* Try to cache last used linktype */
    if (dl == NULL || dl->dlt != linktype) {
        for (i = 0; lt[i].dlt != linktype && lt[i].dlt != -1; i++)
            ;
        dl = &lt[i];
    }
    if (dl->dlt == -1 || pkt == NULL)
        return (dl->dlt);
    if (caplen <= dl->skiplen)
        return (-1);

    /* Suck out the frametype */
    frametype = 0;
    if (dl->ft_is_be) {
        for (j = 0; j < dl->ft_len; j++) {
            frametype <<= 8;
            frametype |= pkt[j + dl->ft_off];
        }
    } else {
        for (j = dl->ft_len - 1; j >= 0 ; j--) {
            frametype <<= 8;
            frametype |= pkt[j + dl->ft_off];
        }
    }
    frametype &= dl->ft_mask;

    if (frametype == dl->ft_v4)
        *af = AF_INET;
    else if (frametype == dl->ft_v6)
        *af = AF_INET6;
    else
        return (-1);

    return (dl->skiplen);
}

/* Initialization setups */
void
setup_packet_capture(pcap_t **pcap, pcap_c *conf, int *linktype, char *dev, char *capfile)
{
    char ebuf[PCAP_ERRBUF_SIZE];
    struct bpf_program prog_c;
    u_int32_t bpf_mask, bpf_net;

    memset(&ebuf, '\0', sizeof(char)*PCAP_ERRBUF_SIZE);

    /* Open pcap */
    if (capfile == NULL) {
        memset(&ebuf, '\0', sizeof(char)*PCAP_ERRBUF_SIZE);
        if ((*pcap = pcap_create(dev, ebuf)) == NULL) {
            fprintf(stderr, "pcap_create: %s\n", ebuf);
            exit(1);
        }
        if (pcap_set_snaplen(*pcap, conf->snaplen) != 0 ||
            pcap_set_promisc(*pcap, conf->promisc_mode) != 0 ||
            pcap_set_timeout(*pcap, conf->timeout > 1 ? conf->timeout*1000 : 1000) != 0 ||
            pcap_set_buffer_size(*pcap, conf->bufsize) != 0) {
            fprintf(stderr, "pcap_set_*: handle cannot be activated\n");
            exit(1);
        }
        if (pcap_activate(*pcap) < 0) {
            fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(*pcap));
            exit(1);
        }
        if (pcap_lookupnet(dev, &bpf_net, &bpf_mask, ebuf) == -1)
            bpf_net = bpf_mask = 0;
    }
    else {
        if ((*pcap = pcap_open_offline(capfile, ebuf)) == NULL) {
            fprintf(stderr, "pcap_open_offline(%s): %s\n", capfile, ebuf);
            exit(1);
        }
        bpf_net = bpf_mask = 0;
    }

    *linktype = pcap_datalink(*pcap);
    if (datalink_check(*linktype, NULL, 0, NULL) == -1) {
        fprintf(stderr, "Unsupported datalink type %d\n", *linktype);
        exit(1);
    }

    /* Attach BPF filter, if specified */
    if (conf->bpf_filter != NULL) {
        if (pcap_compile(*pcap, &prog_c, conf->bpf_filter, 1, bpf_mask) == -1) {

            fprintf(stderr, "pcap_compile(\"%s\"): %s\n", conf->bpf_filter, pcap_geterr(*pcap));
            exit(1);
        }
        if (pcap_setfilter(*pcap, &prog_c) == -1) {
            fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(*pcap));
            exit(1);
        }
    }
}
