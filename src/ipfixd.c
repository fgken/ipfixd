#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <pthread.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <pcap.h>

#include "log.h"
#include "ipfixd.h"
#include "circular_buffer.h"

struct ipfix_stat stat;

void
usage()
{
    struct base_tuple asdf;
	fatal_exit("Usage: ipfixd [-i interface]");
}

uint32_t
parse_packet(struct base_tuple *tuple, const uint8_t *data, size_t len)
{
    size_t i = 0;

    /* L2 */
    if (len < ETH_HLEN) {
        log_err("packet too short: %zu bytes", len);
        return -1;
    }
    struct ether_header *eth = (struct ether_header *)data;
    tuple->ether_type = eth->ether_type;

    // TODO: VLAN
    i += ETH_HLEN;

    /* L3 */
    switch(ntohs(tuple->ether_type)) {
        case ETHERTYPE_IP:
            #define IPV4_HEADER_MIN_LEN     20
            if (len - i < IPV4_HEADER_MIN_LEN) {
                log_err("packet too short: %zu bytes", len);
                return -1;
            }
            struct iphdr *ipv4 = (struct iphdr *)(data + i);
            tuple->protocol = ipv4->protocol;
            memcpy(&tuple->src_ip.v4, &ipv4->saddr, sizeof(struct in_addr));
            memcpy(&tuple->dst_ip.v4, &ipv4->daddr, sizeof(struct in_addr));
            i += IPV4_HEADER_MIN_LEN;
            // TODO: ipv4 option
            break;
        case ETHERTYPE_IPV6:
            #define IPV6_HEADER_LEN     40
            if (len - i < IPV6_HEADER_LEN) {
                log_err("packet too short: %zu bytes", len);
                return -1;
            }
            struct ip6_hdr *ipv6 = (struct ip6_hdr *)(data + i);
            tuple->protocol = ipv6->ip6_nxt;
            memcpy(&tuple->src_ip.v6, &ipv6->ip6_src, sizeof(struct in6_addr));
            memcpy(&tuple->dst_ip.v6, &ipv6->ip6_dst, sizeof(struct in6_addr));
            i += IPV6_HEADER_LEN;
            // TODO: extension header
            break;
        default:
            log_err("unknown ether type: %u", ntohs(eth->ether_type));
            return -1;
    }

    /* L4 */
    switch(tuple->protocol) {
        case IPPROTO_UDP:
            #define UDP_HEADER_LEN  8
            if (len - i < UDP_HEADER_LEN) {
                log_err("packet too short: %zu bytes", len);
                return -1;
            }
            struct udphdr *udp = (struct udphdr *)(data + i);
            tuple->src_port = udp->uh_sport;
            tuple->dst_port = udp->uh_dport;
            i += UDP_HEADER_LEN;
            break;
        case IPPROTO_TCP:
            #define TCP_HEADER_MIN_LEN  20
            if (len - i < TCP_HEADER_MIN_LEN) {
                log_err("packet too short: %zu bytes", len);
                return -1;
            }
            struct tcphdr *tcp = (struct tcphdr *)(data + i);
            tuple->src_port = tcp->th_sport;
            tuple->dst_port = tcp->th_dport;
            i + TCP_HEADER_MIN_LEN;
            break;
        default:
            log_err("unknown protocol: %u", tuple->protocol);
            return -1;
    }

    return 0;
}

void
print_tuple(const struct base_tuple *tuple)
{
    uint16_t af;

    switch(ntohs(tuple->ether_type)) {
        case ETHERTYPE_IP:
            af = AF_INET;
            break;
        case ETHERTYPE_IPV6:
            af = AF_INET6;
            break;
        default:
            return;
    }

    char srcip[INET6_ADDRSTRLEN] = {0};
    char dstip[INET6_ADDRSTRLEN] = {0};
    inet_ntop(af, &tuple->src_ip, srcip, sizeof(srcip));
    inet_ntop(af, &tuple->dst_ip, dstip, sizeof(dstip));

    char proto[] = "Unknown";
    if (tuple->protocol == IPPROTO_UDP) strncpy(proto, "UDP", sizeof(proto));
    if (tuple->protocol == IPPROTO_TCP) strncpy(proto, "TCP", sizeof(proto));

    printf("%s:%u -> %s:%u - %s\n",
        srcip, tuple->src_port, dstip, tuple->dst_port, proto);
}

static void
pcap_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    struct circular_buffer *cbuf = (struct circular_buffer *)user;
    struct base_tuple *tuple = calloc(1, sizeof(struct base_tuple));

    if (tuple == NULL) {
        stat.drop_alloc_failed++;
        stat.drop_octet += hdr->len;
        log_warn("Ignore a packet: " LOG_ALLOC_FAILED);
        return;
    }

    if (cbuf_is_full(cbuf)) {
        goto ignore;
    }

    parse_packet(tuple, bytes, hdr->caplen);

    if (cbuf_push(cbuf, tuple) == 0) {
        return;
    }

ignore:
        free(tuple);
        stat.drop_no_buffer++;
        stat.drop_octet += hdr->len;
        log_warn("Ignore a packet: " LOG_NO_BUFFER);
}

void
start_capture(char *device, struct circular_buffer *cbuf)
{
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Get a default network device */
	if (device == NULL) {
		device = pcap_lookupdev(errbuf);
		if (device == NULL) {
			fatal_exit("cannot find default target device: %s", errbuf);
		}
	}
	log_info("target device: %s", device);

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(device, 2048, 1, 1000, errbuf);
	if (handle == NULL) {
		fatal_exit("cannot open device '%s': %s", device, errbuf);
	}
	log_info("open the session in promiscuous mode");

	/* Start capture */
	log_info("start caputuring");
	if (pcap_loop(handle, -1, pcap_cb, (u_char *)cbuf) < 0) {
		fatal_exit("error in pcap_loop");
	}
	pcap_close(handle);
}

void *
thread_print_tuple(void *p)
{
    struct circular_buffer *cbuf = (struct circular_buffer *)p;

    while (1) {
        struct base_tuple *tuple = cbuf_pop(cbuf);
        if (tuple != NULL) {
            print_tuple(tuple);
            free(tuple);
        }
    }
}

int
main(int argc, char *argv[])
{
	char *device = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "i:")) != -1) {
		switch (ch) {
			case 'i':
				device = optarg;
				break;
			default:
				break;
		}
	}

    struct circular_buffer *cbuf;
    cbuf = cbuf_create(1024);

    pthread_t pthread;
    pthread_create(&pthread, NULL, &thread_print_tuple, (void *)cbuf);

    start_capture(device, cbuf);

    pthread_join(pthread, NULL);

	return 0;
}
