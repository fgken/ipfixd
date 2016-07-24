#ifndef __METERING_PROCESS_H__
#define __METERING_PROCESS_H__

#include <pcap.h>
#include "ipfixd.h"
#include "observation_domain.h"

struct metering_process {
	struct observation_domain *domain;
	pcap_t *handles;

	enum flow_key flow_definition[8];
	size_t num_flow_definition;
	enum flow_key metering_target[8];
	size_t num_metering_target;
	struct flow_record records[128];
};

struct metering_process *
metering_process_create(struct observation_domain *obsv_domain);

void
metering_process_delete(struct metering_process *mtr_process);

void
metering_process_start(struct metering_process *mtr_process);

#endif /* __METERING_PROCESS_H__*/
