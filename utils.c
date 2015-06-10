#include "utils.h"


size_t get_vlan_offset(struct ether_hdr *eth_hdr, uint16_t *proto) {
	size_t vlan_offset = 0;

	if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
		struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);

		vlan_offset = sizeof(struct vlan_hdr);
		*proto = vlan_hdr->eth_proto;

		if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
			vlan_hdr = vlan_hdr + 1;
			*proto = vlan_hdr->eth_proto;
			vlan_offset += sizeof(struct vlan_hdr);
		}
	}
	return vlan_offset;
}

uint32_t xmit_l34_hash32(const struct rte_mbuf *buf) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);
	uint16_t proto = eth_hdr->ether_type;
	size_t vlan_offset = get_vlan_offset(eth_hdr, &proto);

	struct udp_hdr *udp_hdr = NULL;
	struct tcp_hdr *tcp_hdr = NULL;
	uint32_t hash, l3hash = 0, l4hash = 0;

	if (rte_cpu_to_be_16(ETHER_TYPE_IPv4) == proto) {
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)
				((char *)(eth_hdr + 1) + vlan_offset);
		size_t ip_hdr_offset;

		l3hash = ipv4_hash(ipv4_hdr);

		ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
			tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			l4hash = HASH_L4_PORTS(tcp_hdr);
		} else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			l4hash = HASH_L4_PORTS(udp_hdr);
		}
	} else if  (rte_cpu_to_be_16(ETHER_TYPE_IPv6) == proto) {
		struct ipv6_hdr *ipv6_hdr = (struct ipv6_hdr *)
				((char *)(eth_hdr + 1) + vlan_offset);
		l3hash = ipv6_hash(ipv6_hdr);

		if (ipv6_hdr->proto == IPPROTO_TCP) {
			tcp_hdr = (struct tcp_hdr *)(ipv6_hdr + 1);
			l4hash = HASH_L4_PORTS(tcp_hdr);
		} else if (ipv6_hdr->proto == IPPROTO_UDP) {
			udp_hdr = (struct udp_hdr *)(ipv6_hdr + 1);
			l4hash = HASH_L4_PORTS(udp_hdr);
		}
	}

	hash = l3hash ^ l4hash;
	hash ^= hash >> 16;
	hash ^= hash >> 8;

	return hash;
}
