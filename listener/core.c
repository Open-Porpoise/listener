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
		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, vlan, 1);
	}

	if (lp && rte_cpu_to_be_16(ETHER_TYPE_IPv4) == proto) {
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((char *)(eth_hdr + 1) + vlan_offset);
		ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;

		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, total_pkts, 1);
		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, total_bytes,
				rte_be_to_cpu_16(ipv4_hdr->total_length));

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
#if 0
				if(get_vlan_offset(eth_hdr, &proto)){
					dump_mbuf(m);
					rte_panic("find vlan in reassembled mbuf\n");
				}
#endif 
				ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
			}
			APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, frag, 1);
		}
		eth_hdr->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPv4);


		pp = app_proto_get(ipv4_hdr->next_proto_id);
		if (unlikely(!pp))
			 goto out;

		if((cp = pp->conn_get(pp, lp->conn_tbl, m, tms, ipv4_hdr, ip_hdr_offset, &from_client)) == NULL){
			APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, conn_miss, 1);
			goto out;
		}

		pp->process_handle(lp->conn_tbl, cp, m, tms, ipv4_hdr, ip_hdr_offset, from_client);
	/*
	}else if  (rte_cpu_to_be_16(ETHER_TYPE_IPv6) == proto) {
		goto out;
	*/
	}else{
		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, unknow, 1);
	}

out:
	rte_pktmbuf_free(m);
	m = NULL;
}


void app_worker_counter_reset(uint32_t lcore_id, 
		struct app_lcore_params_worker *lp){
	uint64_t fail_total, fail_nospace;
	struct app_conn_tbl *tbl = lp->conn_tbl;
	struct conn_tbl_stat *stat = &tbl->stat;

	fail_total = stat->fail_total;
	fail_nospace = stat->fail_nospace;

	//memset(lp->app_conn_tab, 0, 
	//		APP_CONN_TAB_SIZE * sizeof(*lp->app_conn_tab));
	RTE_LOG(DEBUG, USER1, "max entries:\t%u;\n"
		"entries in use:\t%u;\n"
		"finds/inserts:\t%" PRIu64 ";\n"
		"entries added:\t%" PRIu64 ";\n"
		"entries deleted by timeout:\t%" PRIu64 ";\n"
		"entries reused by timeout:\t%" PRIu64 ";\n"
		"from_client:\t%" PRIu64 ";\n"
		"from_server:\t%" PRIu64 ";\n"
		"total add failures:\t%" PRIu64 ";\n"
		"add no-space failures:\t%" PRIu64 ";\n"
		"add hash-collisions failures:\t%" PRIu64 ";\n",
		tbl->max_entries,
		tbl->use_entries,
		stat->find_num,
		stat->add_num,
		stat->del_num,
		stat->reuse_num,
		stat->from_client,
		stat->from_server,
		fail_total,
		fail_nospace,
		fail_total - fail_nospace);
	RTE_LOG(DEBUG, USER1, "lcore(%2u) pkt:%8lu/%lu, bytes:%lu/%lu|%lf/%lf(Mb/s), miss_conn_pkt:%lu, hash_count:%lu, frag:%lu, vlan:%lu, rpt:%lu/%lu/%lu, msg_fail:%lu, unknow proto:%lu\n", lcore_id, 
			stat->proc_pkts, stat->total_pkts,
			stat->proc_bytes, stat->total_bytes,
			((double)stat->proc_bytes * 8)/ (60 *  (1<<20)),
			((double)stat->total_bytes * 8)/ (60 *  (1<<20)),
			stat->conn_miss, 
			stat->conn, 
			stat->frag,
			stat->vlan,
			stat->rpt,
			stat->rpt_max,
			stat->rpt_loop,
			stat->msg_fail,
			stat->unknow);

	stat->conn = 0;
	stat->conn_miss = 0;
	stat->frag = 0;
	stat->vlan = 0;
	stat->unknow = 0;
	stat->proc_pkts = 0;
	stat->proc_bytes = 0;
	stat->total_pkts = 0;
	stat->total_bytes = 0;
	stat->rpt = 0;
	stat->rpt_max = 0;
	stat->rpt_loop = 0;
	stat->msg_fail = 0;
}
