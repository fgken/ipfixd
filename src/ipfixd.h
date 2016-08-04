#ifndef __IPFIXD_H__
#define __IPFIXD_H__

#include <stdint.h>
#include <netinet/in.h>

union ip_addr {
    struct in_addr v4;
    struct in6_addr v6;
};

struct full_tuple {
    /* L2 */
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ether_type;

    /* L3 */
    union ip_addr src_ip;
    union ip_addr dst_ip;

    /* L4 */
    uint16_t src_port;
    uint16_t dst_port;
};

struct base_tuple {
    /* L2 */
    uint16_t ether_type;

    /* L3 */
    union ip_addr src_ip;
    union ip_addr dst_ip;
    uint8_t protocol;

    /* L4 */
    uint16_t src_port;
    uint16_t dst_port;
};

struct http_tuple {
    int req;
};

struct dns_tuple {
    int qname;
};

#endif /* __IPFIXD_H__ */
