#ifndef __OBSERVATION_DOMAIN_H__
#define __OBSERVATION_DOMAIN_H__

#include <stdint.h>
#include "observation_point.h"

struct observation_domain {
	struct observation_point *obsv_points[8];
	size_t num_points;
};

struct observation_domain *
observation_domain_create();

void
observation_domain_delete(struct observation_domain *obsv_domain);

uint32_t
observation_domain_add(struct observation_domain *obsv_domain, struct observation_point *obsv_point);

uint32_t
observation_domain_del(struct observation_domain *obsv_domain, struct observation_point *obsv_point);

#endif /* __OBSERVATION_DOMAIN_H__ */
