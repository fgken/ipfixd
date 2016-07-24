#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap.h>

#include "log.h"
#include "metering_process.h"
#include "observation_domain.h"
#include "observation_point.h"

void
usage()
{
	fatal_exit("Usage: ipfixd [-i interface]");
}

void
pcap_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
	puts("capture");
}

struct metering_process *
setup_metering_process(char *ifname)
{
	log_step();

	struct observation_point *point = observation_point_create(ifname);
	struct observation_domain *domain = observation_domain_create();
	observation_domain_add(domain, point);

    enum flow_key flow_definitions[2] = {sourceIPv4Address, destinationIPv4Address};
    enum flow_key metering_targets[2] = {octetDeltaCount, packetDeltaCount};
	struct metering_process *process = metering_process_create(domain, flow_definitions, 2, metering_targets, 2);

	return process;
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

	struct metering_process *process = setup_metering_process(device);
	metering_process_start(process);

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
