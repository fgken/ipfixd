#ifndef __METERING_PROCESS_H__
#define __METERING_PROCESS_H__

#include <pcap.h>
#include "ipfixd.h"
#include "observation_domain.h"

struct flow_data {
    enum flow_key key;
    uint8_t data[8];
    size_t size;
};

struct flow_record {
    struct flow_data definition_entity[8];
    struct flow_data metering_entity[8];
};

struct metering_process {
	struct observation_domain *domain;
	pcap_t *handles;

	enum flow_key flow_definitions[8];
	size_t num_flow_definitions;
	enum flow_key metering_targets[8];
	size_t num_metering_targets;
	struct flow_record records[128];
    size_t num_records;
};

struct metering_process *
metering_process_create(struct observation_domain *obsv_domain, enum flow_key *flow_definitions, size_t num_flow_definitions, enum flow_key *metering_targets, size_t num_metering_targets);

void
metering_process_delete(struct metering_process *mtr_process);

void
metering_process_start(struct metering_process *mtr_process);

#endif /* __METERING_PROCESS_H__*/
