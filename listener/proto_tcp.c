/* 
 * yubo@xiaomi.com
 * 2015-07-20
 */
#include "main.h"
#include "utils.h"
#include "sender.h"
#include "tcp.h"
#include <rte_hexdump.h>

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)



static int get_ts(struct tcphdr * tcphdr, uint32_t  *ts)
{
	int len = 4 * tcphdr->th_off;
	uint32_t  tmp_ts;
	unsigned char * options = (unsigned char*)(tcphdr + 1);
	int ind = 0, ret = 0;
	while (ind <=  len - (int)sizeof (struct tcphdr) - 10 ){
		switch (options[ind]) {
			case 0: /* TCPOPT_EOL */
				return ret;
			case 1: /* TCPOPT_NOP */
				ind++;
				continue;
			case 8: /* TCPOPT_TIMESTAMP */
				memcpy((char*)&tmp_ts, options + ind + 2, 4);
				*ts=rte_be_to_cpu_32(tmp_ts);
				ret = 1;
				/* no break, intentionally */
			default:
				if (options[ind+1] < 2 ) /* "silly option" */
					return ret;
				ind += options[ind+1];
		}
	}
	return ret;
}  		

static int get_wscale(struct tcphdr * tcphdr, uint32_t * ws)
{
	int len = 4 * tcphdr->th_off;
	uint32_t tmp_ws;
	unsigned char * options = (unsigned char*)(tcphdr + 1);
	int ind = 0, ret = 0;
	*ws=1;
	while (ind <=  len - (int)sizeof (struct tcphdr) - 3 ){
		switch (options[ind]) {
			case 0: /* TCPOPT_EOL */
				return ret;
			case 1: /* TCPOPT_NOP */
				ind++;
				continue;	
			case 3: /* TCPOPT_WSCALE */
				tmp_ws=options[ind+2];
				if (tmp_ws>14) 
					tmp_ws=14;
				*ws=1<<tmp_ws;
				ret = 1;
				/* no break, intentionally */
			default:	
				if (options[ind+1] < 2 ) /* "silly option" */
					return ret;
				ind += options[ind+1];
		}			
	}
	return ret;
}

static void add2buf(struct app_conn_stream * rcv, char *data, int datalen)
{
	int toalloc;
	char *b;

	if (datalen + rcv->count - rcv->offset > rcv->bufsize) {
		if (!rcv->data) {
			if (datalen < 2048)
				toalloc = 4096;
			else
				toalloc = datalen * 2;
			rcv->data = malloc(toalloc);
			rcv->bufsize = toalloc;
		} else {
			if (datalen < rcv->bufsize)
				toalloc = 2 * rcv->bufsize;
			else	
				toalloc = rcv->bufsize + 2*datalen;
			b = realloc(rcv->data, toalloc);
			if(b){
				rcv->data = b;
				rcv->bufsize = toalloc;
			}else{
				RTE_LOG(WARNING, USER1, "add2buf no meme\n");
			}
		}
		if (!rcv->data){
			RTE_LOG(WARNING, USER1, "add2buf no meme\n");
		}
	}
	memcpy(rcv->data + rcv->count - rcv->offset, data, datalen);
	rcv->count_new = datalen;
	rcv->count += datalen;
}

/*
static uint32_t ms_diff(uint64_t a, uint64_t b){
	if(b > a){
		return ((b - a) * 1000)/rte_get_tsc_hz();
	}else{
		return 0;
	}
}
*/

static uint32_t us_diff(uint64_t a, uint64_t b){
	if(b > a){
		return ((b - a) * 1000000)/rte_get_tsc_hz();
	}else{
		return 0;
	}
}

/*
static uint32_t ns_diff(uint64_t a, uint64_t b){
	if(b > a){
		return ((b - a) * 1000000000)/rte_get_tsc_hz();
	}else{
		return 0;
	}
}
*/



static void event(struct app_conn *cp, char mask, 
		struct app_conn_tbl *tbl, uint64_t tms){
#define LOG_ADDR(a) do{ \
	RTE_LOG(DEBUG, USER3, \
			"TCP "NIPQUAD_FMT":%u"#a NIPQUAD_FMT":%u ", \
			NIPQUAD(cp->client.key.addr[0]), \
			rte_be_to_cpu_16(cp->client.key.port[0]), \
			NIPQUAD(cp->client.key.addr[1]),  \
			rte_be_to_cpu_16(cp->client.key.port[1]) \
			); \
}while(0)

	//LOG_ADDR(->);
	//RTE_LOG(DEBUG, USER2, "state:%d\n", cp->state);

	if (cp->state == CONN_S_JUST_EST){
		//LOG_ADDR(->);
		//RTE_LOG(DEBUG, USER2, "state: CONN_S_JUST_EST\n");
		//cp->conn_time = tms;
		cp->conn_time = us_diff(cp->start, tms);
		return;
	}
	if (cp->state == CONN_S_CLOSE){
		//LOG_ADDR(->);
		//RTE_LOG(DEBUG, USER2, "state: CONN_S_CLOSE\n");
		cp->pp->report_handle(tbl, cp, tms);
		return;
	}
	if (cp->state == CONN_S_TIMED_OUT){
		// todo: remove report_handle from app_conn_table->rpt timeout
		//LOG_ADDR(->);
		//RTE_LOG(DEBUG, USER2, "state: CONN_S_TIMED_OUT\n");
		cp->pp->report_handle(tbl, cp, tms);
		return;
	}
	if (cp->state == CONN_S_RESET){
		//LOG_ADDR(->);
		//RTE_LOG(DEBUG, USER2, "state: CONN_S_RESET\n");
		cp->pp->report_handle(tbl, cp, tms);
		return;
	}
	if (cp->state == CONN_S_DATA){
		switch (mask) {
			case COLLECT_ccu:
				//LOG_ADDR(->);
				//RTE_LOG(DEBUG, USER2, "urgdata:%c\n", cp->client.urgdata);
				break;
			case COLLECT_scu:
				//LOG_ADDR(<-);
				//RTE_LOG(DEBUG, USER2, "urgdata:%c\n", cp->server.urgdata);
				break;
			case COLLECT_cc:
				//LOG_ADDR(<-);
				//RTE_LOG(DEBUG, USER2, "client data:%.*s\n", 
						//cp->client.count_new, cp->client.data);
				//RTE_LOG(DEBUG, USER2, "client datalen:%d\n", 
				//		cp->client.count_new);
				if(rte_be_to_cpu_16(cp->client.key.port[1]) == 80){
					// request
					if (cp->client.offset == 0 && cp->client.count_new > 0){
						uint32_t *resp;
						//RTE_LOG(DEBUG, USER5, "cc offset:%u,%u tms:%lu,%lu count:%d %.10s\n", 
						//	cp->client.offset, cp->server.offset,
						//	cp->req_time, cp->rsp_time, cp->server.count_new, cp->client.data);
						cp->rsp_time = us_diff(cp->start, tms) - cp->req_time;
						resp = (uint32_t *)cp->client.data;
						if(resp[0] == *(uint32_t *)"HTTP" && 
								(resp[1] == *(uint32_t *)"/0.9" || 
								resp[1] == *(uint32_t *)"/1.0" || 
								resp[1] == *(uint32_t *)"/1.1")){
							cp->http_stat_code = atoi((char *)&resp[2]);
						}
					}
				}
				break;
			case COLLECT_sc:
				//LOG_ADDR(->);
				/*
				RTE_LOG(DEBUG, USER2, "data:%.*s\n", 
						cp->server.count_new, cp->server.data);
				*/
				//RTE_LOG(DEBUG, USER2, "server datalen:%d\n", 
				//		cp->server.count_new);
				if(rte_be_to_cpu_16(cp->client.key.port[1]) == 80){
					// response
					if (cp->server.offset == 0 && cp->server.count_new > 0){
						//RTE_LOG(DEBUG, USER5, "sc offset:%u,%u tms:%lu,%lu count:%d %.10s\n", 
						//	cp->client.offset, cp->server.offset,
						//	cp->req_time, cp->rsp_time, cp->server.count_new, cp->server.data);
						cp->req_time = us_diff(cp->start, tms) - cp->conn_time;
					}
				}
				break;
			default:
				break;
		}
	}
}

static void notify(struct app_conn * cp, struct app_conn_stream * rcv,
		struct app_conn_tbl *tbl, uint64_t tms)
{
	//struct lurker_node *i, **prev_addr;
	char mask;

	if (rcv->count_new_urg) {
		if (!rcv->collect_urg)
			return;
		if (rcv == &cp->client)
			mask = COLLECT_ccu;
		else
			mask = COLLECT_scu;
		event(cp, mask, tbl, tms);
		//goto prune_listeners;
		return;
	}
	if (rcv == &cp->client)
		mask = COLLECT_cc;
	else
		mask = COLLECT_sc;
	do {
		int total;
		cp->read = rcv->count - rcv->offset;
		total = cp->read;

		event(cp, mask, tbl, tms);
		if (cp->read > total - rcv->count_new)
			rcv->count_new = total - cp->read;

		if (cp->read > 0) {
			memmove(rcv->data, rcv->data + cp->read, rcv->count - rcv->offset - cp->read);
			rcv->offset += cp->read;
		}
	}while (cp->read>0 && rcv->count_new); 
	// we know that if one_loop_less!=0, we have only one callback to notify
	rcv->count_new=0;	    
}

static void add_from_skb(struct app_conn * cp, struct app_conn_stream * rcv,
		struct app_conn_stream * snd,
		u_char *data, int datalen,
		uint32_t this_seq, char fin, char urg, uint32_t urg_ptr, 
		struct app_conn_tbl *tbl, uint64_t tms)
{
	uint32_t lost = EXP_SEQ - this_seq;
	int to_copy, to_copy2;

	if (urg && after(urg_ptr, EXP_SEQ - 1) &&
			(!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr))) {
		rcv->urg_ptr = urg_ptr;
		rcv->urg_seen = 1;
	}
	if (rcv->urg_seen && after(rcv->urg_ptr + 1, this_seq + lost) &&
			before(rcv->urg_ptr, this_seq + datalen)) {
		to_copy = rcv->urg_ptr - (this_seq + lost);
		if (to_copy > 0) {
			add2buf(rcv, (char *)(data + lost), to_copy);
			notify(cp, rcv, tbl, tms);
		}
		rcv->urgdata = data[rcv->urg_ptr - this_seq];
		rcv->count_new_urg = 1;
		notify(cp, rcv, tbl, tms);
		rcv->count_new_urg = 0;
		rcv->urg_seen = 0;
		rcv->urg_count++;
		to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
		if (to_copy2 > 0) {
			add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
			notify(cp, rcv, tbl, tms);
		}
	} else {
		if (datalen - lost > 0) {
			add2buf(rcv, (char *)(data + lost), datalen - lost);
			notify(cp, rcv, tbl, tms);
		}
	}
	if (fin) {
		snd->state = FIN_SENT;
		//if (rcv->state == TCP_CLOSING)
		//	add_tcp_closing_timeout(cp);
	}
}

static void tcp_queue(struct app_conn * cp, struct tcphdr * tcphdr,
		struct app_conn_stream * snd, struct app_conn_stream * rcv,
		char *data, int datalen, int skblen, struct app_conn_tbl *tbl,
		uint64_t tms)
{
	uint32_t this_seq = rte_be_to_cpu_32(tcphdr->th_seq);
	struct skbuff *pakiet, *tmp;

	/*
	 * Did we get anything new to ack?
	 */

	//RTE_LOG(DEBUG, USER3, "seq:%u, exp_seq:%u\n", this_seq, EXP_SEQ);

	if (!after(this_seq, EXP_SEQ)) {
		if (after(this_seq + datalen + (tcphdr->th_flags & TH_FIN), EXP_SEQ)) {
			//RTE_LOG(DEBUG, USER3, "%s:%d\n", __func__, __LINE__);
			/* the packet straddles our window end */
			get_ts(tcphdr, &snd->curr_ts);
			add_from_skb(cp, rcv, snd, (u_char *)data, datalen, this_seq,
					(tcphdr->th_flags & TH_FIN),
					(tcphdr->th_flags & TH_URG),
					rte_be_to_cpu_16(tcphdr->th_urp) + this_seq - 1,
					tbl, tms);
			/*
			 * Do we have any old packets to ack that the above
			 * made visible? (Go forward from skb)
			 */
			pakiet = rcv->list;
			while (pakiet) {
				if (after(pakiet->seq, EXP_SEQ))
					break;
				if (after(pakiet->seq + pakiet->len + pakiet->fin, EXP_SEQ)) {
					add_from_skb(cp, rcv, snd, pakiet->data,
							pakiet->len, pakiet->seq, pakiet->fin, pakiet->urg,
							pakiet->urg_ptr + pakiet->seq - 1, tbl, tms);
				}
				rcv->rmem_alloc -= pakiet->truesize;
				if (pakiet->prev)
					pakiet->prev->next = pakiet->next;
				else
					rcv->list = pakiet->next;
				if (pakiet->next)
					pakiet->next->prev = pakiet->prev;
				else
					rcv->listtail = pakiet->prev;
				tmp = pakiet->next;
				free(pakiet->data);
				free(pakiet);
				pakiet = tmp;
			}
		} else {
			//RTE_LOG(DEBUG, USER3, "%s:%d\n", __func__, __LINE__);
			return;
		}
	} else {
		//RTE_LOG(DEBUG, USER3, "%s:%d\n", __func__, __LINE__);
		struct skbuff *p = rcv->listtail;

		pakiet = (struct skbuff *)malloc(sizeof(struct skbuff));
		if(pakiet == NULL){
			RTE_LOG(WARNING, USER1, "no memory \n");
			return;
		}
		pakiet->truesize = skblen;
		rcv->rmem_alloc += pakiet->truesize;
		pakiet->len = datalen;
		pakiet->data = malloc(datalen);
		if (!pakiet->data){
			RTE_LOG(WARNING, USER1, "no memory tcp_queue\n");
			free(pakiet);
			return;
		}
		memcpy(pakiet->data, data, datalen);
		pakiet->fin = (tcphdr->th_flags & TH_FIN);
		/* Some Cisco - at least - hardware accept to close a TCP connection
		 * even though packets were lost before the first TCP FIN packet and
		 * never retransmitted; this violates RFC 793, but since it really
		 * happens, it has to be dealt with... The idea is to introduce a 10s
		 * timeout after TCP FIN packets were sent by both sides so that
		 * corresponding libnids resources can be released instead of waiting
		 * for retransmissions which will never happen.  -- Sebastien Raveau
		 */
		if (pakiet->fin) {
			snd->state = TCP_CLOSING;
			//if (rcv->state == FIN_SENT || rcv->state == FIN_CONFIRMED)
			//	add_tcp_closing_timeout(cp);
		}
		pakiet->seq = this_seq;
		pakiet->urg = (tcphdr->th_flags & TH_URG);
		pakiet->urg_ptr = rte_be_to_cpu_16(tcphdr->th_urp);
		for (;;) {
			if (!p || !after(p->seq, this_seq))
				break;
			p = p->prev;
		}
		if (!p) {
			pakiet->prev = 0;
			pakiet->next = rcv->list;
			if (rcv->list)
				rcv->list->prev = pakiet;
			rcv->list = pakiet;
			if (!rcv->listtail)
				rcv->listtail = pakiet;
		} else {
			pakiet->next = p->next;
			p->next = pakiet;
			pakiet->prev = p;
			if (pakiet->next)
				pakiet->next->prev = pakiet;
			else
				rcv->listtail = pakiet;
		}
	}
}

static void handle_ack(struct app_conn_stream * snd, uint32_t acknum)
{
	int ackdiff;

	ackdiff = acknum - snd->ack_seq;
	if (ackdiff > 0) {
		snd->ack_seq = acknum;
	}
}
#if 0
	static void
check_flags(struct ip * iph, struct tcphdr * th)
{
	u_char flag = *(((u_char *) th) + 13);
	if (flag & 0x40 || flag & 0x80)
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BADFLAGS, iph, th);
	//ECN is really the only cause of these warnings...
}


#if HAVE_ICMPHDR
#define STRUCT_ICMP struct icmphdr
#define ICMP_CODE   code
#define ICMP_TYPE   type
#else
#define STRUCT_ICMP struct icmp
#define ICMP_CODE   icmp_code
#define ICMP_TYPE   icmp_type
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH ICMP_UNREACH
#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#define NR_ICMP_UNREACH   ICMP_MAXTYPE
#endif				

void process_icmp(u_char * data)
{
	struct ip *iph = (struct ip *) data;
	struct ip *orig_ip;
	STRUCT_ICMP *pkt;
	struct tcphdr *th;
	struct half_stream *hlf;
	int match_addr;
	struct tcp_stream *cp;
	struct lurker_node *i;

	int from_client;
	/* we will use unsigned, to suppress warning; we must be careful with
	   possible wrap when substracting 
	   the following is ok, as the ip header has already been sanitized */
	uint32_t len = rte_be_to_cpu_16(iph->ip_len) - (iph->ip_hl << 2);

	if (len < sizeof(STRUCT_ICMP))
		return;
	pkt = (STRUCT_ICMP *) (data + (iph->ip_hl << 2));
	if (ip_compute_csum((char *) pkt, len))
		return;
	if (pkt->ICMP_TYPE != ICMP_DEST_UNREACH)
		return;
	/* ok due to check 7 lines above */  
	len -= sizeof(STRUCT_ICMP);
	// sizeof(struct icmp) is not what we want here

	if (len < sizeof(struct ip))
		return;

	orig_ip = (struct ip *) (((char *) pkt) + 8);
	if (len < (unsigned)(orig_ip->ip_hl << 2) + 8)
		return;
	/* subtraction ok due to the check above */
	len -= orig_ip->ip_hl << 2;
	if ((pkt->ICMP_CODE & 15) == ICMP_PROT_UNREACH ||
			(pkt->ICMP_CODE & 15) == ICMP_PORT_UNREACH)
		match_addr = 1;
	else
		match_addr = 0;
	if (pkt->ICMP_CODE > NR_ICMP_UNREACH)
		return;
	if (match_addr && (iph->ip_src.s_addr != orig_ip->ip_dst.s_addr))
		return;
	if (orig_ip->ip_p != IPPROTO_TCP)
		return;
	th = (struct tcphdr *) (((char *) orig_ip) + (orig_ip->ip_hl << 2));
	if (!(cp = find_stream(th, orig_ip, &from_client)))
		return;
	if (cp->addr.dest == iph->ip_dst.s_addr)
		hlf = &cp->server;
	else
		hlf = &cp->client;
	if (hlf->state != TCP_SYN_SENT && hlf->state != TCP_SYN_RECV)
		return;
	cp->nids_state = CONN_S_RESET;
	for (i = cp->listeners; i; i = i->next)
		(i->item) (cp, &i->data);
	nids_free_tcp_stream(cp);
}
#endif

static void tcp_conn_add(struct app_conn_tbl *tbl,  struct app_conn *cp,
		const struct app_conn_key *key, uint64_t tms, 
		struct app_protocol *pp, struct tcphdr *tcphdr)
{
	/* todo: reset conn counter */
	memset(cp, 0, sizeof(*cp));
	cp->last = tms;
	cp->start = tms;
	cp->pp = pp;
	cp->conn_time = -1;
	cp->req_time = -1;
	cp->rsp_time = -1;
	cp->http_stat_code = -1;
	cp->client.key = key[0];
	cp->server.key.addr[0] = key->addr[1];
	cp->server.key.addr[1] = key->addr[0];
	cp->server.key.port[0] = key->port[1];
	cp->server.key.port[1] = key->port[0];
	cp->server.key.proto = key->proto;
	cp->server.start = tms;
	cp->server.last = tms;
	cp->server.state = TCP_CLOSE;

	cp->client.state = TCP_SYN_SENT;
	cp->client.start = tms;
	cp->client.last = tms;

	cp->client.seq = rte_be_to_cpu_32(tcphdr->th_seq) + 1;
	cp->client.seq_tms = tms;
	cp->client.first_data_seq = cp->client.seq;
	cp->client.window = rte_be_to_cpu_16(tcphdr->th_win);
	cp->client.ts_on = get_ts(tcphdr, &cp->client.curr_ts);
	cp->client.wscale_on = get_wscale(tcphdr, &cp->client.wscale);

	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->rpt, cp, rpt);
	tbl->use_entries++;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, add_num, 1);
}



/*
 * Find an entry in the table for the corresponding fragment.
 * If such entry is not present, then allocate a new one.
 * If the entry is stale, then free and reuse it.
 * just fro tcp
 */
static struct app_conn * tcp_conn_find(struct app_protocol *pp, 
		struct rte_mbuf *mb, struct app_conn_tbl *tbl, 
		const struct app_conn_key *key, uint64_t tms, 
		int *from_client, struct tcphdr *tcphdr)
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
			stale->state = CONN_S_TIMED_OUT;
			event(stale, 0, tbl, tms);
			app_conn_tbl_del(tbl, stale);
			free = stale;
			APP_CONN_TBL_STAT_UPDATE(&tbl->stat, reuse_num, 1);

			/*
			 * we found a free entry, check if we can use it.
			 * If we run out of free entries in the table, then
			 * check if we have a timed out entry to delete.
			 */
		} else if (free != NULL &&
				tbl->max_entries <= tbl->use_entries) {
			lru = TAILQ_FIRST(&tbl->lru);
			if (lru && max_cycles + lru->last < tms) {
				lru->state = CONN_S_TIMED_OUT;
				event(lru, 0, tbl, tms);
				app_conn_tbl_del(tbl, lru);
			} else {
				free = NULL;
				APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_nospace, 1);
			}
		}

		/* found a free entry to reuse. */
		if (free != NULL ){
			/* add conn when syn and dst_addr in ip_list */
			if ((tcphdr->th_flags & TH_SYN) && 
					!(tcphdr->th_flags & TH_ACK) &&
					!(tcphdr->th_flags & TH_RST) &&
					radix32tree_find(app.ip_list, rte_be_to_cpu_32(key->addr[1])) != RADIX_NO_VALUE &&
					key->src_dst_addr) {
				tcp_conn_add(tbl,  free, key, tms, pp, tcphdr);
				cp = free;
				*from_client = 1;
			}
		}
	}

	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_total, ((cp == NULL) && (free == NULL)));
	return (cp);
}

#if 0
static void
dump_tcp(FILE *f, const struct rte_mbuf *m, unsigned dump_len, 
		struct ipv4_hdr *ip_hdr, struct tcphdr *tcphdr)
{
	unsigned int len;
	unsigned nb_segs;
	int32_t datalen, iplen;
	int ip_hdr_offset;

	__rte_mbuf_sanity_check(m, 1);
/*
	fprintf(f, "dump mbuf at 0x%p, phys=%"PRIx64", buf_len=%u\n",
	       m, (uint64_t)m->buf_physaddr, (unsigned)m->buf_len);
	fprintf(f, "  pkt_len=%"PRIu32", ol_flags=%"PRIx64", nb_segs=%u, "
	       "in_port=%u\n[", m->pkt_len, m->ol_flags,
	       (unsigned)m->nb_segs, (unsigned)m->port);
		   */

	iplen = rte_be_to_cpu_16(ip_hdr->total_length);
	ip_hdr_offset = (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
			IPV4_IHL_MULTIPLIER;
	datalen = iplen - ip_hdr_offset - 4 * tcphdr->th_off;
	fprintf(f, "dlen:%d [", datalen);
	if(tcphdr->th_flags & TH_FIN) fprintf(f, "F");                 
	if(tcphdr->th_flags & TH_SYN) fprintf(f, "S");
	if(tcphdr->th_flags & TH_RST) fprintf(f, "R");
	if(tcphdr->th_flags & TH_ACK) fprintf(f, ".");
	if(tcphdr->th_flags & TH_PUSH) fprintf(f, "P");
	if(tcphdr->th_flags & TH_URG) fprintf(f, "U");
	fprintf(f, "] " NIPQUAD_FMT ":%u->" NIPQUAD_FMT ":%u seq:%x, ack:%x, next_seq:%x\n", 
			NIPQUAD(ip_hdr->src_addr), rte_be_to_cpu_16(tcphdr->th_sport),
			NIPQUAD(ip_hdr->dst_addr), rte_be_to_cpu_16(tcphdr->th_dport),
			rte_be_to_cpu_32(tcphdr->th_seq), rte_be_to_cpu_32(tcphdr->th_ack), 
			rte_be_to_cpu_32(tcphdr->th_seq) + (datalen > 0 ? datalen : 1));

	nb_segs = m->nb_segs;
	while (m && nb_segs != 0) {
		__rte_mbuf_sanity_check(m, 0);

		fprintf(f, "  segment at 0x%p, data=0x%p, data_len=%u\n",
			m, rte_pktmbuf_mtod(m, void *), (unsigned)m->data_len);
		len = dump_len;
		if (len > m->data_len)
			len = m->data_len;
		if (len != 0)
			rte_hexdump(f, NULL, rte_pktmbuf_mtod(m, void *), len);
		dump_len -= len;
		m = m->next;
		nb_segs --;
	}
}
#endif


static void tcp_process_handle( struct app_protocol *pp, struct app_conn_tbl *tbl,
		struct rte_mbuf *mb, uint64_t tms, struct ipv4_hdr *ip_hdr){
	struct app_conn_stream *snd, *rcv;
	uint32_t tmp_ts;
	size_t ip_hdr_offset;
	int32_t datalen, iplen;
	struct app_conn_key key;
	struct app_conn *cp;
	int from_client;
	struct tcphdr *tcphdr;

	iplen = rte_be_to_cpu_16(ip_hdr->total_length);
	ip_hdr_offset = (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
			IPV4_IHL_MULTIPLIER;
	tcphdr = (struct tcphdr *)((char *)ip_hdr + ip_hdr_offset);

	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, proc_pkts, 1);
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, proc_bytes, iplen);

	if((uint32_t)iplen < ip_hdr_offset + sizeof(struct tcphdr)){
		//RTE_LOG(WARNING, USER3, "ipen(%d) < ip_hdr_offset(%d) + sizeof(struct tcphdr)(%d)\n",
		//		iplen, (int)ip_hdr_offset, (int)sizeof(struct tcphdr));
		return;
	}

	datalen = iplen - ip_hdr_offset - 4 * tcphdr->th_off;
	if(datalen < 0){
		RTE_LOG(WARNING, USER3, "datalen < 0(%d)\n", datalen);
		return;
	}

	// todo : my_tcp_check()

	key.src_dst_addr = *((uint64_t *)&ip_hdr->src_addr);
	key.src_dst_port = *((uint32_t *)tcphdr);
	if(key.src_dst_addr == 0 ){
		return;
	}

	/* try to find/add entry into the connection table. */
	if((cp = tcp_conn_find(pp, mb, tbl, &key, tms, 
			&from_client, tcphdr)) == NULL){
		APP_CONN_TBL_STAT_UPDATE(&tbl->stat, conn_miss, 1);
		return;
	}

	// todo: fixit
	if(mb->next){
		rte_pktmbuf_dump(stdout, mb, 256);
	}

	if(from_client){
		snd = &cp->client;
		rcv = &cp->server;
	}else{
		rcv = &cp->client;
		snd = &cp->server;
	}

	if((tcphdr->th_flags & TH_SYN)){
		if(from_client){
			//RTE_LOG(DEBUG, USER3, "%s:%d\n", __func__, __LINE__);
			return;
		}
		if(cp->client.state != TCP_SYN_SENT || 
				cp->server.state != TCP_CLOSE || !(tcphdr->th_flags & TH_ACK)){
			//RTE_LOG(DEBUG, USER3, "%s:%d\n", __func__, __LINE__);
			return;
		}
		if(cp->client.seq != rte_be_to_cpu_32(tcphdr->th_ack)){
			//RTE_LOG(DEBUG, USER3, "%s:%d\n", __func__, __LINE__);
			return;
		}
		cp->last = tms;
		cp->server.state = TCP_SYN_RECV;
		cp->server.seq = rte_be_to_cpu_32(tcphdr->th_seq) + 1;
		cp->server.seq_tms = tms;
		cp->server.first_data_seq = cp->server.seq;
		cp->server.ack_seq = rte_be_to_cpu_32(tcphdr->th_ack);
		cp->server.window = rte_be_to_cpu_16(tcphdr->th_win);
		if(cp->client.ts_on){
			cp->server.ts_on = get_ts(tcphdr, &cp->server.curr_ts);
			if(!cp->server.ts_on)
				cp->client.ts_on = 0;
		}else{
			cp->server.ts_on = 0;
		}
		if(cp->client.wscale_on){
			cp->server.wscale_on = get_wscale(tcphdr, &cp->server.wscale);
			if (!cp->server.wscale_on) {
				cp->client.wscale_on = 0;
				cp->client.wscale  = 1;
				cp->server.wscale = 1;
			}	
		} else {
			cp->server.wscale_on = 0;	
			cp->server.wscale = 1;
		}
		goto out;
	}
	if (!(!datalen && rte_be_to_cpu_32(tcphdr->th_seq) == rcv->ack_seq) 
		&& (!before(rte_be_to_cpu_32(tcphdr->th_seq), rcv->ack_seq + rcv->window*rcv->wscale) 
			|| before(rte_be_to_cpu_32(tcphdr->th_seq) + datalen, rcv->ack_seq)))
	{
		/*
		RTE_LOG(DEBUG, USER3, "%s:%d datalen:%d seq:%u ack:%u window:%u wscale:%u\n", 
				__func__, __LINE__, datalen, rte_be_to_cpu_32(tcphdr->th_seq), rcv->ack_seq, 
				rcv->window, rcv->wscale);
		*/
		//dump_tcp(stdout, mb, 0, ip_hdr, tcphdr);
		// todo: remove me
		//if(datalen > 65535){
		//	dump_tcp(stdout, mb, 1024, ip_hdr, tcphdr);
		//	rte_pktmbuf_dump(stdout, mb, 1024);
		//	rte_panic();
		//}
		return;
	}

	if ((tcphdr->th_flags & TH_RST)) {
		if (cp->state == CONN_S_DATA) {
			cp->state = CONN_S_RESET;
		}
		/* report */
		//RTE_LOG(DEBUG, USER5, "%s:%d\n", __func__, __LINE__);
		goto out;
	}

	/* PAWS check */
	if (rcv->ts_on && get_ts(tcphdr, &tmp_ts) && 
			before(tmp_ts, snd->curr_ts)){
		//RTE_LOG(DEBUG, USER5, "%s:%d\n", __func__, __LINE__);
		goto out; 
	}

	if ((tcphdr->th_flags & TH_ACK)) {
		if (from_client && cp->client.state == TCP_SYN_SENT &&
				cp->server.state == TCP_SYN_RECV) {
			if (rte_be_to_cpu_32(tcphdr->th_ack) == cp->server.seq) {
				cp->client.state = TCP_ESTABLISHED;
				cp->client.ack_seq = rte_be_to_cpu_32(tcphdr->th_ack);
				cp->last = tms;
				//cp->ts = nids_last_pcap_header->ts.tv_sec;

				cp->server.state = TCP_ESTABLISHED;
				cp->state = CONN_S_JUST_EST;
				event(cp, 0, tbl, tms);
				cp->state = CONN_S_DATA;
			}
		}
	}

	// rtt 
	if(cp->client.state == TCP_ESTABLISHED 
			&& cp->server.state == TCP_ESTABLISHED){
		if(from_client){
			if(after(tcphdr->th_ack, rcv->seq - 1)){
				if(rcv->seq_tms){
					cp->round_trip_time_sum += us_diff(rcv->seq_tms, tms);
					cp->round_trip_time_count++;
					rcv->seq_tms = 0;
				}
			}
		}else{
			snd->seq = tcphdr->th_seq;
			snd->seq_tms = tms;
		}
	}

	if ((tcphdr->th_flags & TH_ACK)) {

		handle_ack(snd, rte_be_to_cpu_32(tcphdr->th_ack));
		if (rcv->state == FIN_SENT)
			rcv->state = FIN_CONFIRMED;
		if (rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED) {
			//struct lurker_node *i;

			cp->state = CONN_S_CLOSE;
			//RTE_LOG(DEBUG, USER5, "%s:%d\n", __func__, __LINE__);
			goto out;
		}
	}

	if (datalen + (tcphdr->th_flags & TH_FIN) > 0){
		tcp_queue(cp, tcphdr, snd, rcv,
				(char *) (tcphdr) + 4 * tcphdr->th_off,
				datalen, mb->buf_len, tbl, tms);
	}/*else if( tcphdr->th_flags & TH_ACK){
		notify(cp, rcv, tbl, tms);
	}*/
	snd->window = rte_be_to_cpu_16(tcphdr->th_win);
	if (rcv->rmem_alloc > 65535)
		prune_queue(rcv);



out:
	// update timer and lru
	snd->bytes += iplen;
	snd->pkts++;
	snd->last = tms;
	cp->last = tms;
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);

	if(cp->state == CONN_S_CLOSE || cp->state == CONN_S_RESET){
		event(cp, 0, tbl, tms);
		app_conn_tbl_del(tbl, cp);
	}
}

/* protocol tcp */
struct app_protocol app_protocol_tcp = {
	.name = (char *)"TCP",                        
	.protocol = IPPROTO_TCP,
	//.init = app_tcp_init,
	.init = NULL,
	//.conn_get = tcp_conn_get,
	.debug_packet = tcpudp_debug_packet,
	.process_handle = tcp_process_handle,
	.report_handle = tcpudp_report_handle,
	//	.conn_expire_handle = tcp_conn_expire_handle,
}; 


