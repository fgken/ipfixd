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
    cbuf = cbuf_create(128*1024);

    pthread_t pthread;
    pthread_create(&pthread, NULL, &thread_print_tuple, (void *)cbuf);

    start_capture(device, cbuf);

    pthread_join(pthread, NULL);

	return 0;
}
