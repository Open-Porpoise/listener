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

#ifndef TAILQ_FOREACH_SAFE
/*
 * TAILQ_FOREACH_SAFE() provides a traversal where the current iterated element
 * may be freed or unlinked.
 * It does not allow freeing or modifying any other element in the list,
 * at least not the next element.
 */
#define TAILQ_FOREACH_SAFE(elm,head,field,tmpelm)			\
	for ((elm) = TAILQ_FIRST(head) ;				\
	     (elm) && ((tmpelm) = TAILQ_NEXT((elm), field), 1) ;	\
	     (elm) = (tmpelm))
#endif


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

static inline int
before(u_int seq1, u_int seq2)
{
  return ((int)(seq1 - seq2) < 0);
}

static inline int
after(u_int seq1, u_int seq2)
{
  return ((int)(seq2 - seq1) < 0);
}




#endif
