#ifndef __OBSERVATION_POINT_H__
#define __OBSERVATION_POINT_H__

#include <net/if.h>

struct observation_point {
	char ifname[IF_NAMESIZE];
};

struct observation_point *
observation_point_create(char *ifname);

void
observation_point_delete(struct observation_point *obsv_point);

#endif /* __OBSERVATION_POINT_H__ */
