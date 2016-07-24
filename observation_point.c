#include <stdlib.h>
#include <string.h>

#include "observation_point.h"

struct observation_point *
observation_point_create(char *ifname)
{
	struct observation_point *point = (struct observation_point *)calloc(1, sizeof(struct observation_point));
	strncpy(point->ifname, ifname, sizeof(point->ifname)-1);
	return point;
}
