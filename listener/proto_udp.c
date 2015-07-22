/* 
 * yubo@xiaomi.com
 * 2015-07-20
 */
#include "main.h"
#include "utils.h"
#include "sender.h"
#include <rte_udp.h>

/* #################### UDP ###################### */
static void udp_conn_add(struct app_conn_tbl *tbl,  struct app_conn *cp,
		const struct app_conn_key *key, uint64_t tms, 
		struct app_protocol *pp)
{
	/* todo: reset conn counter */
	memset(cp, 0, sizeof(*cp));
	cp->last = tms;
	cp->start = tms;
	cp->pp = pp;
	cp->client.key = key[0];
	cp->server.key.addr[0] = key->addr[1];
	cp->server.key.addr[1] = key->addr[0];
	cp->server.key.port[0] = key->addr[1];
	cp->server.key.port[1] = key->addr[0];
	cp->server.key.proto = key->proto;
	cp->server.start = tms;
	cp->server.last = tms;

	cp->client.start = tms;
	cp->client.last = tms;

	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->rpt, cp, rpt);
	tbl->use_entries++;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, add_num, 1);
}

static struct app_conn * udp_conn_find(struct app_protocol *pp, struct rte_mbuf *mb,
		struct app_conn_tbl *tbl, const struct app_conn_key *key, 
		uint64_t tms, int *from_client)
{
	struct app_conn *cp, *free, *stale, *lru;
	uint64_t max_cycles;

	/*
	 * Actually the two line below are totally redundant.
	 * they are here, just to make gcc 4.6 happy.
	 */
	free = NULL;
	stale = NULL;
	max_cycles = tbl->max_cycles;

	if ((cp = conn_lookup(tbl, mb, key, tms, &free, &stale, from_client)) == NULL) {

		/*timed-out entry, free and invalidate it*/
		if (stale != NULL) {
			pp->report_handle(tbl, stale, tms);
			app_conn_tbl_del(tbl, stale);
			free = stale;

			/*
			 * we found a free entry, check if we can use it.
			 * If we run out of free entries in the table, then
			 * check if we have a timed out entry to delete.
			 */
		} else if (free != NULL &&
				tbl->max_entries <= tbl->use_entries) {
			lru = TAILQ_FIRST(&tbl->lru);
			if (max_cycles + lru->last < tms) {
				//ip_frag_tbl_del(tbl, lru);
				pp->report_handle(tbl, lru, tms);
				app_conn_tbl_del(tbl, lru);
			} else {
				free = NULL;
				APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_nospace, 1);
			}
		}

		/* found a free entry to reuse. */
		if (free != NULL){
			if (radix32tree_find(app.ip_list, rte_be_to_cpu_32(key->addr[1]))) {
				udp_conn_add(tbl,  free, key, tms, pp);
				cp = free;
				*from_client = 1;
			}else if(radix32tree_find(app.ip_list, rte_be_to_cpu_32(key->addr[0]))){
				struct app_conn_key k = {
					.addr = {key->addr[1], key->addr[0]},
					.port = {key->port[1], key->port[0]},
					.proto = key->proto,
				};
				udp_conn_add(tbl,  free, &k, tms, pp);
				cp = free;
				*from_client = 0;
			}
		}

		/*
		 * we found the flow, but it is already timed out,
		 * so free associated resources, reposition it in the LRU list,
		 * and reuse it.
		 */
	}
#if 0
	else if (max_cycles + cp->last < tms) {
		//ip_frag_tbl_reuse(tbl, cp, tms);
		//app_conn_tbl_reuse(tbl, cp, tms);
	}
#endif

	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_total, (cp == NULL));

	return (cp);
}

static void udp_process_handle(struct app_protocol *pp, struct app_conn_tbl *tbl,
		struct rte_mbuf *mb, uint64_t tms, struct ipv4_hdr *ip_hdr){
	struct app_conn_stream *sp;
	struct app_conn *cp;
	struct app_conn_key key;
	struct udp_hdr *udp_hdr = NULL;
	size_t ip_hdr_offset;
	int32_t datalen, iplen;
	int from_client;

	iplen = rte_be_to_cpu_16(ip_hdr->total_length);
	ip_hdr_offset = (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
			IPV4_IHL_MULTIPLIER;
	udp_hdr = (struct udp_hdr *)((char *)ip_hdr + ip_hdr_offset);


	if((uint32_t)iplen < ip_hdr_offset + sizeof(struct udp_hdr)){
		RTE_LOG(WARNING, USER5, "ipen(%d) < ip_hdr_offset(%d) + sizeof(struct udp_hdr)(%lu)\n",
				iplen, (int)ip_hdr_offset, sizeof(struct udp_hdr));
		return;
	}
	datalen = rte_be_to_cpu_16(udp_hdr->dgram_len);
	if(iplen - (int32_t)ip_hdr_offset < datalen || datalen < (int32_t)sizeof(struct udp_hdr)){
		RTE_LOG(WARNING, USER5, "datalen warning(%d)\n", datalen);
		return;
	}


	key.src_dst_addr = *((uint64_t *)&ip_hdr->src_addr);
	key.src_dst_port = *((uint32_t *)udp_hdr);

	
	if((cp = udp_conn_find(pp, mb, tbl, &key, tms, &from_client)) == NULL){
		APP_CONN_TBL_STAT_UPDATE(&tbl->stat, conn_miss, 1);
		return;
	}

	// todo: fixit
	if(mb->next){
		rte_pktmbuf_dump(stdout, mb, 256);
	}

	if(from_client){
		sp = &cp->client;
	}else{
		sp = &cp->server;
	}

	// todo: seq / ack 
	// todo: cp->state  cp->stream[0/1].state

	// process 
	sp->bytes += rte_be_to_cpu_16(ip_hdr->total_length);
	sp->pkts++;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, proc_pkts, 1);
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, proc_bytes, rte_be_to_cpu_16(ip_hdr->total_length));

	/*
	   if(cp->state == TCP_CLOSE){
	   cp->pp->report_handle(tbl, cp, tms);
	   }
	 */

	// update timer and lru
	sp->last = tms;
	cp->last = tms;
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);
}

struct app_protocol app_protocol_udp = {
	.name = (char *)"UDP",                        
	.protocol = IPPROTO_UDP,              
	.init = NULL,               
	//.conn_get = udp_conn_get,       
	.debug_packet = tcpudp_debug_packet,
	.process_handle = udp_process_handle,
	.report_handle = tcpudp_report_handle,
	//	.conn_expire_handle = udp_conn_expire_handle,
}; 
