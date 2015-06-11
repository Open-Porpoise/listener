#include "main.h"
#include "utils.h"

void deal_pkt(struct app_lcore_params_worker *lp,
		struct rte_mbuf *pkt){
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	uint16_t proto = eth_hdr->ether_type;
	size_t vlan_offset = get_vlan_offset(eth_hdr, &proto);

	struct udp_hdr *udp_hdr = NULL;
	struct tcp_hdr *tcp_hdr = NULL;
	uint32_t hash, l3hash = 0, l4hash = 0;
	//struct app_protocol *pp;
	//struct app_conn *cp;

	if (lp && rte_cpu_to_be_16(ETHER_TYPE_IPv4) == proto) {
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((char *)(eth_hdr + 1) + vlan_offset);
		size_t ip_hdr_offset;

		l3hash = ipv4_hash(ipv4_hdr);
		ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;

		//pp = app_proto_get(ipv4_hdr->next_proto_id);
		//if (unlikely(!pp))
		//	 goto out;

		//cp = pp->conn_get(af, skb, pp, &iph, iph.len, 0);

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
			tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			l4hash = HASH_L4_PORTS(tcp_hdr);
			hash = l3hash ^ l4hash;
			hash ^= hash >> 16;
			hash ^= hash >> 8;
			hash &= APP_CONN_TAB_SIZE - 1;
			if(!lp->app_conn_tab[hash]){
				lp->app_conn_count++;
				lp->app_conn_tab[hash] = 1;
			}
		} else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			l4hash = HASH_L4_PORTS(udp_hdr);
			hash = l3hash ^ l4hash;
			hash ^= hash >> 16;
			hash ^= hash >> 8;
			hash &= APP_CONN_TAB_SIZE - 1;
			if(!lp->app_conn_tab[hash]){
				lp->app_conn_count++;
				lp->app_conn_tab[hash] = 1;
			}
		}
/*
	}else if  (rte_cpu_to_be_16(ETHER_TYPE_IPv6) == proto) {
		goto out;
	}else{
		goto out;
*/
	}

	rte_pktmbuf_free(pkt);
}


void app_worker_counter_reset(uint32_t lcore_id, 
		struct app_lcore_params_worker *lp_worker){
	memset(lp_worker->app_conn_tab, 0, 
			APP_CONN_TAB_SIZE * sizeof(*lp_worker->app_conn_tab));
	printf("lcore(%u) hash element count: %u\n", lcore_id, lp_worker->app_conn_count);
	lp_worker->app_conn_count = 0;
}

