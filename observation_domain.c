#include <stdlib.h>

#include "observation_domain.h"

struct observation_domain *
observation_domain_create()
{
	struct observation_domain *domain = (struct observation_domain *)calloc(1, sizeof(struct observation_domain));
	return domain;
}

uint32_t
observation_domain_add(struct observation_domain *obsv_domain, struct observation_point *obsv_point)
{
	obsv_domain->obsv_points[obsv_domain->num_points++] = obsv_point;
	return 0;
}
