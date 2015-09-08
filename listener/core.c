#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>

#include "main.h"
#include "utils.h"
#include "listener.h"

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

	//struct udp_hdr *udp_hdr = NULL;
	//uint32_t hash;
	struct app_protocol *pp;
	if(vlan_offset){
		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, vlan, 1);
	}

	if (lp && rte_cpu_to_be_16(ETHER_TYPE_IPv4) == proto) {
		struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((char *)(eth_hdr + 1) + vlan_offset);

		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, total_pkts, 1);
		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, total_bytes,
				rte_be_to_cpu_16(ipv4_hdr->total_length));

#ifdef HAVE_REASSEMBLE
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
#endif


		pp = app_proto_get(ipv4_hdr->next_proto_id);
		if (unlikely(!pp)){
#define CASE_IPPROTO(p) case IPPROTO_##p: \
			APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, p, 1); \
			break

			switch(ipv4_hdr->next_proto_id){
				CASE_IPPROTO(ICMP);
				CASE_IPPROTO(IGMP);
				CASE_IPPROTO(IPIP);
				CASE_IPPROTO(EGP);
				CASE_IPPROTO(PUP);
				CASE_IPPROTO(IDP);
				CASE_IPPROTO(TP);
				CASE_IPPROTO(DCCP);
				CASE_IPPROTO(IPV6);
				CASE_IPPROTO(RSVP);
				CASE_IPPROTO(GRE);
				CASE_IPPROTO(ESP);
				CASE_IPPROTO(AH);
				CASE_IPPROTO(MTP);
//				CASE_IPPROTO(BEETPH);
				CASE_IPPROTO(ENCAP);
				CASE_IPPROTO(PIM);
				CASE_IPPROTO(COMP);
				CASE_IPPROTO(SCTP);
				CASE_IPPROTO(UDPLITE);
				CASE_IPPROTO(RAW);
				default:
					APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, IPV4_UNKNOW, 1);
					break;
			}
			goto out;
		}

		pp->process_handle(pp, lp->conn_tbl, m, tms, ipv4_hdr);
	/*
	}else if  (rte_cpu_to_be_16(ETHER_TYPE_IPv6) == proto) {
		goto out;
	*/
	}else{
		APP_CONN_TBL_STAT_UPDATE(&lp->conn_tbl->stat, unknow, 1);
	}

out:
	rte_pktmbuf_free(m);
//	m = NULL;
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
	RTE_LOG(DEBUG, USER1, "max entries:\t%d;\n"
		"entries in use:\t%d;\n"
		"finds/inserts:\t%" PRIu64 ";\n"
		"entries add:\t%" PRIu64 ";\n"
		"entries del:\t%" PRIu64 ";\n"
		"entries reused:\t%" PRIu64 ";\n"
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
	RTE_LOG(DEBUG, USER1, "lcore(%2u) pkt:%8lu/%lu, bytes:%lu/%lu|%lf/%lf(Mb/s), miss_conn_pkt:%lu, hash_count:%lu, frag:%lu, vlan:%lu, rpt:%lu, clean:%lu, msg_fail:%lu, unknow proto:%lu\n ICMP:%lu, IGMP:%lu, IPIP:%lu, EGP:%lu, PUP:%lu, IDP:%lu, TP:%lu, DCCP:%lu, IPV6:%lu, RSVP:%lu, GRE:%lu, ESP:%lu, AH:%lu, MTP:%lu, BEETPH:%lu, ENCAP:%lu, PIM:%lu, COMP:%lu, SCTP:%lu, UDPLITE:%lu, RAW:%lu, IPV4_UNKNOW:%lu\n", lcore_id, 
			stat->proc_pkts, stat->total_pkts,
			stat->proc_bytes, stat->total_bytes,
			((double)stat->proc_bytes * 8)/ (60 *  (1<<20)),
			((double)stat->total_bytes * 8)/ (60 *  (1<<20)),
			stat->conn_miss, 
			stat->conn, 
			stat->frag,
			stat->vlan,
			stat->rpt,
			stat->clean,
			stat->msg_fail,
			stat->unknow, 

			stat->ICMP,
			stat->IGMP,
   			stat->IPIP,
   			stat->EGP,
   			stat->PUP,
   			stat->IDP,
   			stat->TP,
   			stat->DCCP,
   			stat->IPV6,
   			stat->RSVP,
   			stat->GRE,
   			stat->ESP,
   			stat->AH,
   			stat->MTP,
 			stat->BEETPH,
   			stat->ENCAP,
   			stat->PIM,
   			stat->COMP,
   			stat->SCTP,
   			stat->UDPLITE,
   			stat->RAW,
   			stat->IPV4_UNKNOW
			);

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
	stat->clean = 0;
	stat->msg_fail = 0;
	stat->ICMP = 0;
	stat->IGMP = 0;
	stat->IPIP = 0;
	stat->EGP  = 0;
	stat->PUP  = 0;
	stat->IDP     = 0;
	stat->TP      = 0;
	stat->DCCP    = 0;
	stat->IPV6    = 0;
	stat->RSVP    = 0;
	stat->GRE     = 0;
	stat->ESP     = 0;
	stat->AH      = 0;
	stat->MTP     = 0;
	stat->BEETPH  = 0;
	stat->ENCAP   = 0;
	stat->PIM     = 0;
	stat->COMP    = 0;
	stat->SCTP    = 0;
	stat->UDPLITE = 0;
	stat->RAW     = 0;
	stat->IPV4_UNKNOW = 0;
}
