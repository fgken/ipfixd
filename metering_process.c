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

uint32_t
insert_flow_record(struct metering_process *process, struct flow_record *record)
{
	for (size_t i=0; i < sizeof(process->records)/sizeof(process->records[0]); i++) {
		if (process->records[i] != NULL) {
			if (memcmp(process->records[i]->definition_entity[0].data,
					record->definition_entity[0].data,
					process->records[i]->definition_entity[0].size
					) == 0 &&
				memcmp(process->records[i]->definition_entity[1].data,
					record->definition_entity[1].data,
					process->records[i]->definition_entity[1].size
					) == 0)
			{
				*(uint64_t *)process->records[i]->metering_entity[0].data += *(uint64_t *)record->metering_entity[0].data;
				*(uint64_t *)process->records[i]->metering_entity[1].data += *(uint64_t *)record->metering_entity[1].data;
				break;
			}
		} else {
			process->records[i] = calloc(1, sizeof(struct flow_record));
			memcpy(process->records[i], record, sizeof(struct flow_record));
			break;
		}
	}
	return 0;
}

void
dump_flow_records(struct metering_process *process)
{
	printf("--- dump flow records -------------------\n");	
	for (size_t i=0; i < sizeof(process->records)/sizeof(process->records[0]); i++) {
		if (process->records[i] != NULL) {
			struct flow_record *record = process->records[i];
			printf("capture packet: srcIP=%u.%u.%u.%u dstIP=%u.%u.%u.%u, octeteDeltaCount=%llu, packetDeltaCount=%llu\n",
				record->definition_entity[0].data[0],
				record->definition_entity[0].data[1],
				record->definition_entity[0].data[2],
				record->definition_entity[0].data[3],
				record->definition_entity[1].data[0],
				record->definition_entity[1].data[1],
				record->definition_entity[1].data[2],
				record->definition_entity[1].data[3],
				*(uint64_t *)record->metering_entity[0].data,
				*(uint64_t *)record->metering_entity[1].data);
				}
	}
	printf("-----------------------------------------\n");	
}

void nbufwrite8(uint8_t **dst, uint8_t val)
{
	**dst = val;
	*dst += 1;
}
void nbufwrite16(uint8_t **dst, uint16_t val)
{
	**dst = val;
	*dst += 1;
}
void nbufwrite32(uint8_t **dst, uint32_t val)
{
	**dst = val;
	*dst += 1;
}

void
send_flow_records(struct metering_process *process)
{
	for (size_t i=0; i < sizeof(process->records)/sizeof(process->records[0]); i++) {
		struct flow_record *record = process->records[i];
		if (record != NULL &&
			*(uint64_t *)record->metering_entity[1].data > 100)
		{
			static uint32_t seq = 0;
			uint8_t *nbuf = calloc(1, 1024*1024);

			printf("send a flow record\n");
			uint8_t *p = nbuf;

			/* Message Header */
			nbufwrite16(&p, 0x0009);		// Version Number
			nbufwrite16(&p, 100);		// Length
			nbufwrite32(&p, 0x0000ffff);	// Export Time
			nbufwrite32(&p, seq++);			// Sequence Number
			nbufwrite32(&p, 1);				// Observation Domain ID

			/* Set Header */
			nbufwrite16(&p, 1);				// Set ID
			nbufwrite16(&p, 100);			// Length

			/* Template Record */
			nbufwrite16(&p, 256);			// Template ID
			nbufwrite16(&p, 4);				// Field Count
			nbufwrite16(&p, 0x0000 | sourceIPv4Address);		// E | Information Element identifier
			nbufwrite16(&p, 4);				// Field Length
			nbufwrite32(&p, 0);				// Enterpprise Number
			nbufwrite16(&p, 0x0000 | destinationIPv4Address);	// E | Information Element identifier
			nbufwrite16(&p, 4);				// Field Length
			nbufwrite32(&p, 0);				// Enterpprise Number
			nbufwrite16(&p, 0x0000 | octetDeltaCount);			// E | Information Element identifier
			nbufwrite16(&p, 8);				// Field Length
			nbufwrite32(&p, 0);				// Enterpprise Number
			nbufwrite16(&p, 0x0000 | packetDeltaCount);			// E | Information Element identifier
			nbufwrite16(&p, 8);				// Field Length
			nbufwrite32(&p, 0);				// Enterpprise Number

			/* Set Header */
			nbufwrite16(&p, 256);			// Set ID (= Template ID)
			nbufwrite16(&p, 100);			// Length

			/* Data Record */
			nbufwrite32(&p, *(uint32_t *)record->definition_entity[0].data);
			nbufwrite32(&p, *(uint32_t *)record->definition_entity[1].data);
			nbufwrite32(&p, *(uint64_t *)record->metering_entity[0].data);
			nbufwrite32(&p, *(uint64_t *)record->metering_entity[1].data);

			free(nbuf);
			free(process->records[i]);
			process->records[i] = NULL;
		}
	}
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

//    printf("hdr->len = %u, hdr->caplen = %u\n", hdr->len, hdr->caplen);
//	printf("capture packet: srcIP=%u.%u.%u.%u dstIP=%u.%u.%u.%u, octeteDeltaCount=%llu, packetDeltaCount=%llu\n",
//		record.definition_entity[0].data[0],
//		record.definition_entity[0].data[1],
//		record.definition_entity[0].data[2],
//		record.definition_entity[0].data[3],
//		record.definition_entity[1].data[0],
//		record.definition_entity[1].data[1],
//		record.definition_entity[1].data[2],
//		record.definition_entity[1].data[3],
//		*(uint64_t *)record.metering_entity[0].data,
//		*(uint64_t *)record.metering_entity[1].data);

	insert_flow_record(process, &record);

	dump_flow_records(process);

	send_flow_records(process);
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
