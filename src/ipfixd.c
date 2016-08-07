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

#include "log.h"
#include "ipfixd.h"
#include "capture.h"
#include "circular_buffer.h"

void
usage()
{
    struct base_tuple asdf;
	fatal_exit("Usage: ipfixd [-i interface]");
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

void
merge_flow(struct ipfix_flow *dst, struct ipfix_flow *src)
{
    dst->octet += src->octet;
    dst->count += src->count;
}

uint32_t
flowdb_add(struct ipfix_flow **flowdb, size_t size, struct ipfix_flow *flow)
{
    for (size_t i=0; i < size; i++) {
        if (flowdb[i] != NULL && flowdb[i]->hash == flow->hash) {
            merge_flow(flowdb[i], flow);
            return 1;
        }
    }

    for (size_t i=0; i < size; i++) {
        if (flowdb[i] == NULL) {
            flowdb[i] = flow;
            return 0;
        }
    }

    return -1;
}

void
print_flowdb(struct ipfix_flow **flowdb, size_t size)
{
    for (size_t i=0; i < size; i++) {
        if (flowdb[i] != NULL) {
            printf("flowdb[%4zu]:\n", i);
            printf("  ");
            print_tuple(&flowdb[i]->tuple);
            printf("  octet: %zu\n", flowdb[i]->octet);
            printf("  count: %zu\n", flowdb[i]->count);
        }
    }
    puts("");
}

void *
thread_print_tuple(void *p)
{
    struct circular_buffer *cbuf = (struct circular_buffer *)p;
    #define FLOWDB_SIZE    1024
    size_t flowdb_size = FLOWDB_SIZE;
    struct ipfix_flow **flowdb = calloc(1, sizeof(struct ipfix_flow *)*flowdb_size);

    while (1) {
        struct ipfix_flow *flow = cbuf_pop(cbuf);
        if (flow != NULL) {
            // FIXME
            flow->hash = *(uint64_t *)&flow->tuple;

            if (flowdb_add(flowdb, flowdb_size, flow) != 0) {
                free(flow);
            }
            print_flowdb(flowdb, flowdb_size);
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
    cbuf = cbuf_create(128*1024);

    pthread_t pthread;
    pthread_create(&pthread, NULL, &thread_print_tuple, (void *)cbuf);

    start_capture(device, cbuf);

    pthread_join(pthread, NULL);

	return 0;
}
