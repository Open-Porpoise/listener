#ifndef _UTILS_H_
#define _UTILS_H_
#include <stdlib.h>
#include <netinet/in.h>

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_devargs.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_alarm.h>
#include <rte_cycles.h>

#define HASH_L4_PORTS(h) ((h)->src_port ^ (h)->dst_port)

void dump_mbuf(const struct rte_mbuf *m);
uint32_t xmit_l34_hash32(struct rte_mbuf *buf);
size_t get_vlan_offset(struct ether_hdr *eth_hdr, uint16_t *proto);

static inline uint32_t ipv4_hash(struct ipv4_hdr *ipv4_hdr) {
	return (ipv4_hdr->src_addr ^ ipv4_hdr->dst_addr);
}

static inline uint32_t ipv6_hash(struct ipv6_hdr *ipv6_hdr) {
	uint32_t *word_src_addr = (uint32_t *)&(ipv6_hdr->src_addr[0]);
	uint32_t *word_dst_addr = (uint32_t *)&(ipv6_hdr->dst_addr[0]);

	return (word_src_addr[0] ^ word_dst_addr[0]) ^
			(word_src_addr[1] ^ word_dst_addr[1]) ^
			(word_src_addr[2] ^ word_dst_addr[2]) ^
			(word_src_addr[3] ^ word_dst_addr[3]);
}



#endif
