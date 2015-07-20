/* 
 * yubo@xiaomi.com
 * 2015-07-20
 */
#include "main.h"
#include "utils.h"
#include "sender.h"

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
		uint64_t tms, uint32_t *from_client)
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

static struct app_conn * udp_conn_get(struct app_protocol *pp, struct app_conn_tbl *tbl,
		struct rte_mbuf *mb, uint64_t tms, struct ipv4_hdr *ip_hdr, 
		size_t ip_hdr_offset, uint32_t *from_client)
{
	//struct app_conn *cp;
	struct app_conn_key key;
	//const uint64_t *psd;
	//uint16_t ip_len;
	struct udp_hdr *udp_hdr = NULL;
	//uint16_t flag_offset, ip_ofs, ip_flag;

	//flag_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset);
	//ip_ofs = (uint16_t)(flag_offset & IPV4_HDR_OFFSET_MASK);
	//ip_flag = (uint16_t)(flag_offset & IPV4_HDR_MF_FLAG);

	//psd = (uint64_t *)&ip_hdr->src_addr;
	/* use first 8 bytes only */
	key.src_dst_addr = *((uint64_t *)&ip_hdr->src_addr);

	udp_hdr = (struct udp_hdr *)((char *)ip_hdr + ip_hdr_offset);
	key.src_dst_port = *((uint32_t *)udp_hdr);

	//ip_ofs *= IPV4_HDR_OFFSET_UNITS;
	//ip_len = (uint16_t)(rte_be_to_cpu_16(ip_hdr->total_length) -
	//	mb->l3_len);

	/* try to find/add entry into the connection table. */
	return udp_conn_find(pp, mb, tbl, &key, tms, 
			from_client);
}

static void udp_process_handle(struct app_conn_tbl *tbl,
		struct app_conn * cp, __attribute__((unused))struct rte_mbuf *mb, 
		uint64_t tms, struct ipv4_hdr *ip_hdr, 
		__attribute__((unused))size_t ip_hdr_offset, uint32_t from_client){
	struct app_conn_stream *sp;
	//struct tcp_hdr *tcp_hdr = NULL;
	//tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr + ip_hdr_offset);
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
	.conn_get = udp_conn_get,       
	.debug_packet = tcpudp_debug_packet,
	.process_handle = udp_process_handle,
	.report_handle = tcpudp_report_handle,
	//	.conn_expire_handle = udp_conn_expire_handle,
}; 
