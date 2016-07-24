#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>

#include "log.h"

void
usage()
{
	fatal_exit("Usage: ipfixd [-i interface]");
}

void
pcap_cb(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
	puts("capture");
}

int
main(int argc, char *argv[])
{
	char *device = NULL;
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
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

	/* Get a default network device */
	if (device == NULL) {
		device = pcap_lookupdev(errbuf);
		if (device == NULL) {
			fatal_exit("cannot find default target device: %s", errbuf);
		}
	}
	log_info("target device: %s", device);

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(device, 1024, 1, 1000, errbuf);
	if (handle == NULL) {
		fatal_exit("cannot open device '%s': %s", device, errbuf);
	}
	log_info("open the session in promiscuous mode");

	/* Start capture */
	log_info("start caputuring");
	if (pcap_loop(handle, -1, pcap_cb, NULL) < 0) {
		fatal_exit("error in pcap_loop");
	}
	pcap_close(handle);

	return 0;
}
