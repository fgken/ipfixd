#include <stdlib.h>
#include <pcap.h>
#include "metering_process.h"
#include "log.h"


struct metering_process *
metering_process_create(struct observation_domain *obsv_domain)
{
	if (obsv_domain == NULL) {
		return NULL;
	}

	struct metering_process *process = (struct metering_process *)calloc(1, sizeof(struct metering_process));
	if (process == NULL) {
		fatal_exit("cannnot allocate memory");
	}

	process->domain = obsv_domain;
	process->flow_definition[0] = sourceIPv4Address;
	process->flow_definition[1] = destinationIPv4Address;
	process->num_flow_definition = 2;

	process->metering_target[0] = octetDeltaCount;
	process->metering_target[1] = packetDeltaCount;
	process->num_metering_target = 2;

	return process;
}

void
metering_process_delete(struct metering_process *mtr_process)
{
}

static void
pcap_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
	struct metering_process *process = (struct metering_process *)user;

	if (1) {
	}

	uint8_t srcIPv4[4] = {0};
	uint8_t dstIPv4[4] = {0};

	for (size_t i; i<process->num_flow_definition; i++) {
		switch(process->flow_definition[i]) {
			case sourceIPv4Address:
				break;
			case destinationIPv4Address:
				break;
			default:
				break;
		}
	}

	enum flow_key metering_target[8];
	size_t num_metering_target;
	struct flow_record records[128];
}

void
metering_process_start(struct metering_process *mtr_process)
{
	pcap_t *handles[8];
	size_t num_handles = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	for (size_t i=0; i<mtr_process->domain->num_points; i++) {
		char *ifname = mtr_process->domain->obsv_points[i]->ifname;
		pcap_t *handle = pcap_open_live(ifname, 1024, 1, 1000, errbuf);
		if (handle == NULL) {
			fatal_exit("cannot open device '%s': %s", ifname, errbuf);
		}
		log_info("open the session in promiscuous mode");
	
		handles[i] = handle;	
		num_handles++;
	}

	/* Start capture */
	log_info("start caputuring");
	if (pcap_loop(handles[0], -1, pcap_cb, NULL) < 0) {
		fatal_exit("error in pcap_loop");
	}

	for (size_t i=0; i<num_handles; i++) {
		pcap_close(handles[i]);
	}
}
