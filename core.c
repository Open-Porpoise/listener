#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>

#include "main.h"
#include "utils.h"

#define	PRIME_VALUE	0xeaad8405

#if 0
static uint32_t app_conn_hashkey(uint32_t s_addr, uint16_t s_port, 
		uint32_t d_addr, uint16_t d_port){
	return rte_jhash_3words(s_addr, d_addr, s_port << 16 | d_port, PRIME_VALUE);
}
#endif

void process_mbuf(struct app_lcore_params_worker *lp,
		struct rte_mbuf *m, uint64_t tms){
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	uint16_t proto = eth_hdr->ether_type;
	size_t vlan_offset = get_vlan_offset(eth_hdr, &proto);
	size_t ip_hdr_offset;

	//struct udp_hdr *udp_hdr = NULL;
	//uint32_t hash;
	uint32_t from_client = 0;
	struct app_protocol *pp;
	struct app_conn *cp;
	if(vlan_offset){
		lp->app_vlan_count++;
	}

	if (lp && rte_cpu_to_be_16(ETHER_TYPE_IPv4) == proto) {
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((char *)(eth_hdr + 1) + vlan_offset);
		ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;


		 /* if it is a fragmented packet, then try to reassemble. */
		if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr)) {
			struct rte_mbuf *mo;

			/* prepare mbuf: setup l2_len/l3_len. */
			m->l2_len = sizeof(*eth_hdr);
			m->l3_len = sizeof(*ipv4_hdr);

			/* process this fragment. */
			mo = rte_ipv4_frag_reassemble_packet(lp->frag_tbl, &lp->frag_dr, m, tms, ipv4_hdr);
			if (mo == NULL)
				/* no packet to send out. */
				return;

			/* we have our packet reassembled. */
			if (mo != m) {
				m = mo;
				eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
#if 1
				if(get_vlan_offset(eth_hdr, &proto)){
					dump_mbuf(m);
					rte_panic("find vlan in reassembled mbuf\n");
				}
#endif 
				ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
			}
			lp->app_frag_count++;
		}
		eth_hdr->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);


		pp = app_proto_get(ipv4_hdr->next_proto_id);
		if (unlikely(!pp))
			 goto out;

		if((cp = pp->conn_get(pp, lp->conn_tbl, m, tms, ipv4_hdr, ip_hdr_offset, &from_client)) == NULL){
			goto out;
		}

		pp->process_handle(pp, cp, m, tms, ipv4_hdr, ip_hdr_offset, from_client);
		
#if 0
		if (ipv4_hdr->next_proto_id == IPPROTO_TCP){
			tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			//v = rte_jhash_3words(p[0], p[1], key->id, PRIME_VALUE);
			hash = app_conn_hashkey(ipv4_hdr->src_addr, tcp_hdr->src_port, 
					ipv4_hdr->dst_addr, tcp_hdr->dst_port);
			hash &= APP_CONN_TAB_SIZE - 1;
			if(!lp->app_conn_tab[hash]){
				lp->app_conn_count[0]++;
				lp->app_conn_tab[hash] = 1;
			}
			lp->app_bytes_count += rte_be_to_cpu_16(ipv4_hdr->total_length);
			lp->app_pkt_count++; 
		} else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr +
					ip_hdr_offset);
			hash = app_conn_hashkey(ipv4_hdr->src_addr, udp_hdr->src_port, 
					ipv4_hdr->dst_addr, udp_hdr->dst_port);
			hash &= APP_CONN_TAB_SIZE - 1;
			if(!lp->app_conn_tab[hash]){
				lp->app_conn_count[0]++;
				lp->app_conn_tab[hash] = 1;
			}
			lp->app_bytes_count += rte_be_to_cpu_16(ipv4_hdr->total_length);
			lp->app_pkt_count++; 
		}
#endif
/*
	}else if  (rte_cpu_to_be_16(ETHER_TYPE_IPv6) == proto) {
		goto out;
*/
	}else{
		lp->app_unknow_count++;
	}

out:
	rte_pktmbuf_free(m);
	m = NULL;
}


void app_worker_counter_reset(uint32_t lcore_id, 
		struct app_lcore_params_worker *lp_worker){
	//memset(lp_worker->app_conn_tab, 0, 
	//		APP_CONN_TAB_SIZE * sizeof(*lp_worker->app_conn_tab));
	printf("lcore(%2u) pkt:%8u,\tbytes:%8lu/%lf(Mb/s),\thash_count:%8u,\tfrag:%8u,\tvlan:%8u,\tunknow proto:%u\n", lcore_id, 
			lp_worker->app_pkt_count,
			lp_worker->app_bytes_count,
			((double)lp_worker->app_bytes_count * 8)/ (60 *  (1<<20)),
			lp_worker->app_conn_count[0] - lp_worker->app_conn_count[1], 
			lp_worker->app_frag_count,
			lp_worker->app_vlan_count,
			lp_worker->app_unknow_count);
	lp_worker->app_conn_count[1] = lp_worker->app_conn_count[0];
	lp_worker->app_frag_count = 0;
	lp_worker->app_unknow_count = 0;
	lp_worker->app_vlan_count = 0;
	lp_worker->app_pkt_count = 0;
	lp_worker->app_bytes_count = 0;
}


