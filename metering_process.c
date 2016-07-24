#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "metering_process.h"
#include "log.h"


struct metering_process *
metering_process_create(struct observation_domain *obsv_domain, enum flow_key *flow_definitions, size_t num_flow_definitions, enum flow_key *metering_targets, size_t num_metering_targets)
{
	if (obsv_domain == NULL) {
		return NULL;
	}

	struct metering_process *process = (struct metering_process *)calloc(1, sizeof(struct metering_process));
	if (process == NULL) {
		fatal_exit("cannnot allocate memory");
	}

	process->domain = obsv_domain;

	process->num_flow_definitions = num_flow_definitions;
	for (size_t i=0; i < num_flow_definitions; i++) {
		process->flow_definitions[i] = flow_definitions[i];
	}

	process->num_metering_targets = num_metering_targets;
	for (size_t i=0; i < num_metering_targets; i++) {
		process->metering_targets[i] = metering_targets[i];
	}

	return process;
}

uint32_t
get_flow_data(const struct pcap_pkthdr *hdr, const u_char *bytes, struct flow_data *flow_data, enum flow_key key)
{
	if (bytes[6+6] != 0x08 || bytes[6+6+1] != 0x00) {
		return -1;
	}

	const struct ip *ip = (const struct ip *)&bytes[6+6+2];
	flow_data->key = key;
	
	switch(key) {
		case sourceIPv4Address:
			flow_data->size = 4;
			memcpy(flow_data->data, &ip->ip_src, 4);
			break;
		case destinationIPv4Address:
			flow_data->size = 4;
			memcpy(flow_data->data, &ip->ip_dst, 4);
			break;
		case octetDeltaCount:
			flow_data->size = 8;
			*(uint64_t *)flow_data->data = (uint64_t)hdr->len;
			break;
		case packetDeltaCount:
			flow_data->size = 8;
			*(uint64_t *)flow_data->data = (uint64_t)1;
			break;
		default:
			break;
	}

	return 0;
}

static void
pcap_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
	struct metering_process *process = (struct metering_process *)user;
	struct flow_record record;

	for (size_t i=0; i < process->num_flow_definitions; i++) {
		get_flow_data(hdr, bytes, &record.definition_entity[i], process->flow_definitions[i]);
	}

	for (size_t i=0; i < process->num_metering_targets; i++) {
		get_flow_data(hdr, bytes, &record.metering_entity[i], process->metering_targets[i]);
	}

    printf("hdr->len = %u, hdr->caplen = %u\n", hdr->len, hdr->caplen);
	printf("capture packet: srcIP=%u.%u.%u.%u dstIP=%u.%u.%u.%u, octeteDeltaCount=%lu, packetDeltaCount=%lu\n",
		record.definition_entity[0].data[0],
		record.definition_entity[0].data[1],
		record.definition_entity[0].data[2],
		record.definition_entity[0].data[3],
		record.definition_entity[1].data[0],
		record.definition_entity[1].data[1],
		record.definition_entity[1].data[2],
		record.definition_entity[1].data[3],
		*(uint64_t *)record.metering_entity[0].data,
		*(uint64_t *)record.metering_entity[1].data);
}

void
metering_process_start(struct metering_process *mtr_process)
{
	pcap_t *handles[8];
	size_t num_handles = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	for (size_t i=0; i<mtr_process->domain->num_points; i++) {
		char *ifname = mtr_process->domain->obsv_points[i]->ifname;
		pcap_t *handle = pcap_open_live(ifname, 128, 1, 1000, errbuf);
		if (handle == NULL) {
			fatal_exit("cannot open device '%s': %s", ifname, errbuf);
		}
		log_info("open the session in promiscuous mode");
	
		handles[i] = handle;	
		num_handles++;
	}

	/* Start capture */
	log_info("start caputuring");
	if (pcap_loop(handles[0], -1, pcap_cb, (u_char *)mtr_process) < 0) {
		fatal_exit("error in pcap_loop");
	}

	for (size_t i=0; i<num_handles; i++) {
		pcap_close(handles[i]);
	}
}
