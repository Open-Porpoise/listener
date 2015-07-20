/* 
 * yubo@xiaomi.com
 * 2015-07-20
 */
#include "main.h"
#include "utils.h"
#include "sender.h"

#define CONN_S_JUST_EST 1
#define CONN_S_DATA 2
#define CONN_S_CLOSE 3
#define CONN_S_RESET 4
#define CONN_S_TIMED_OUT 5
#define CONN_S_EXITING   6	/* conn is exiting; last chance to get data */


enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING			/* now a valid state */
};


#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)



static int get_ts(struct tcp_hdr * tcp_hdr, uint32_t  *ts)
{
	int len = 4 * tcp_hdr->data_off;
	uint32_t  tmp_ts;
	unsigned char * options = (unsigned char*)(tcp_hdr + 1);
	int ind = 0, ret = 0;
	while (ind <=  len - (int)sizeof (struct tcp_hdr) - 10 ){
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

static int get_wscale(struct tcp_hdr * tcp_hdr, uint32_t * ws)
{
	int len = 4 * tcp_hdr->data_off;
	uint32_t tmp_ws;
	unsigned char * options = (unsigned char*)(tcp_hdr + 1);
	int ind = 0, ret = 0;
	*ws=1;
	while (ind <=  len - (int)sizeof (struct tcp_hdr) - 3 ){
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

static void lurkers(struct app_conn *cp, char mask){
	if (cp->state == CONN_S_CLOSE){
		return;
	}
	if (cp->state == CONN_S_TIMED_OUT){
		// todo: remove report_handle from app_conn_table->rpt timeout
		return;
	}
	if (cp->state == CONN_S_RESET){
		return;
	}
	if (cp->state == CONN_S_DATA){
		switch (mask) {
			case COLLECT_ccu:
				RTE_LOG(DEBUG, USER3, 
						"TCP "NIPQUAD_FMT":%u->"NIPQUAD_FMT":%u "
						"urgdata:%c\n", 
						NIPQUAD(cp->client.key.addr[0]), 
						rte_be_to_cpu_16(cp->client.key.port[0]),
						NIPQUAD(cp->client.key.addr[1]), 
						rte_be_to_cpu_16(cp->client.key.port[1]),
						cp->client.urgdata);
				break;
			case COLLECT_scu:
				RTE_LOG(DEBUG, USER3, 
						"TCP "NIPQUAD_FMT":%u<-"NIPQUAD_FMT":%u "
						"urgdata:%c\n", 
						NIPQUAD(cp->client.key.addr[0]), 
						rte_be_to_cpu_16(cp->client.key.port[0]),
						NIPQUAD(cp->client.key.addr[1]), 
						rte_be_to_cpu_16(cp->client.key.port[1]),
						cp->server.urgdata);
				break;
			case COLLECT_cc:
				RTE_LOG(DEBUG, USER3, 
						"TCP "NIPQUAD_FMT":%u->"NIPQUAD_FMT":%u "
						"urgdata:%.*s\n", 
						NIPQUAD(cp->client.key.addr[0]), 
						rte_be_to_cpu_16(cp->client.key.port[0]),
						NIPQUAD(cp->client.key.addr[1]), 
						rte_be_to_cpu_16(cp->client.key.port[1]),
						cp->client.count_new, cp->client.data);
				break;
			case COLLECT_sc:
				RTE_LOG(DEBUG, USER3, 
						"TCP "NIPQUAD_FMT":%u<-"NIPQUAD_FMT":%u "
						"data:%.*s\n", 
						NIPQUAD(cp->client.key.addr[0]), 
						rte_be_to_cpu_16(cp->client.key.port[0]),
						NIPQUAD(cp->client.key.addr[1]), 
						rte_be_to_cpu_16(cp->client.key.port[1]),
						cp->server.count_new, cp->server.data);
				break;
			default:
				break;
		}
	}
}

static void notify(struct app_conn * cp, struct app_conn_stream * rcv)
{
	//struct lurker_node *i, **prev_addr;
	char mask;

	//cp->pp->report_handle(tbl, cp, tms);
	if (rcv->count_new_urg) {
		if (!rcv->collect_urg)
			return;
		if (rcv == &cp->client)
			mask = COLLECT_ccu;
		else
			mask = COLLECT_scu;
		lurkers(cp, mask);
		//goto prune_listeners;
		return;
	}
	if (rcv->collect) {
		if (rcv == &cp->client)
			mask = COLLECT_cc;
		else
			mask = COLLECT_sc;
		do {
			int total;
			cp->read = rcv->count - rcv->offset;
			total = cp->read;

			//ride_lurkers(cp, mask);
			lurkers(cp, mask);
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
}

static void add_from_skb(struct app_conn * cp, struct app_conn_stream * rcv,
		struct app_conn_stream * snd,
		u_char *data, int datalen,
		uint32_t this_seq, char fin, char urg, uint32_t urg_ptr)
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
			if (rcv->collect) {
				add2buf(rcv, (char *)(data + lost), to_copy);
				notify(cp, rcv);
			}
			else {
				rcv->count += to_copy;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
		rcv->urgdata = data[rcv->urg_ptr - this_seq];
		rcv->count_new_urg = 1;
		notify(cp, rcv);
		rcv->count_new_urg = 0;
		rcv->urg_seen = 0;
		rcv->urg_count++;
		to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
		if (to_copy2 > 0) {
			if (rcv->collect) {
				add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
				notify(cp, rcv);
			}
			else {
				rcv->count += to_copy2;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}
	else {
		if (datalen - lost > 0) {
			if (rcv->collect) {
				add2buf(rcv, (char *)(data + lost), datalen - lost);
				notify(cp, rcv);
			}
			else {
				rcv->count += datalen - lost;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}
	if (fin) {
		snd->state = FIN_SENT;
		//if (rcv->state == TCP_CLOSING)
		//	add_tcp_closing_timeout(cp);
	}
}

static void tcp_queue(struct app_conn * cp, struct tcp_hdr * tcp_hdr,
		struct app_conn_stream * snd, struct app_conn_stream * rcv,
		char *data, int datalen, int skblen
		)
{
	uint32_t this_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
	struct skbuff *pakiet, *tmp;

	/*
	 * Did we get anything new to ack?
	 */

	if (!after(this_seq, EXP_SEQ)) {
		if (after(this_seq + datalen + (tcp_hdr->tcp_flags & TCP_FIN_FLAG), EXP_SEQ)) {
			/* the packet straddles our window end */
			get_ts(tcp_hdr, &snd->curr_ts);
			add_from_skb(cp, rcv, snd, (u_char *)data, datalen, this_seq,
					(tcp_hdr->tcp_flags & TCP_FIN_FLAG),
					(tcp_hdr->tcp_flags & TCP_URG_FLAG),
					rte_be_to_cpu_16(tcp_hdr->tcp_urp) + this_seq - 1);
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
							pakiet->urg_ptr + pakiet->seq - 1);
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
		}
		else
			return;
	}
	else {
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
			return;
		}
		memcpy(pakiet->data, data, datalen);
		pakiet->fin = (tcp_hdr->tcp_flags & TCP_FIN_FLAG);
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
		pakiet->urg = (tcp_hdr->tcp_flags & TCP_URG_FLAG);
		pakiet->urg_ptr = rte_be_to_cpu_16(tcp_hdr->tcp_urp);
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
		}
		else {
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
check_flags(struct ip * iph, struct tcp_hdr * th)
{
	u_char flag = *(((u_char *) th) + 13);
	if (flag & 0x40 || flag & 0x80)
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BADFLAGS, iph, th);
	//ECN is really the only cause of these warnings...
}

struct tcp_stream * find_stream(struct tcp_hdr * tcp_hdr, struct ip * this_iphdr,
		int *from_client)
{
	struct tuple4 this_addr, reversed;
	struct tcp_stream *cp;

	this_addr.source = rte_be_to_cpu_16(tcp_hdr->th_sport);
	this_addr.dest = rte_be_to_cpu_16(tcp_hdr->th_dport);
	this_addr.saddr = this_iphdr->ip_src.s_addr;
	this_addr.daddr = this_iphdr->ip_dst.s_addr;
	cp = nids_find_tcp_stream(&this_addr);
	if (cp) {
		*from_client = 1;
		return cp;
	}
	reversed.source = rte_be_to_cpu_16(tcp_hdr->th_dport);
	reversed.dest = rte_be_to_cpu_16(tcp_hdr->th_sport);
	reversed.saddr = this_iphdr->ip_dst.s_addr;
	reversed.daddr = this_iphdr->ip_src.s_addr;
	cp = nids_find_tcp_stream(&reversed);
	if (cp) {
		*from_client = 0;
		return cp;
	}
	return 0;
}

struct tcp_stream * nids_find_tcp_stream(struct tuple4 *addr)
{
	int hash_index;
	struct tcp_stream *cp;

	hash_index = mk_hash_index(*addr);
	for (cp = tcp_stream_table[hash_index];
			cp && memcmp(&cp->addr, addr, sizeof (struct tuple4));
			cp = cp->next_node);
	return cp ? cp : 0;
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
	struct tcp_hdr *th;
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
	th = (struct tcp_hdr *) (((char *) orig_ip) + (orig_ip->ip_hl << 2));
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
		struct app_protocol *pp, struct tcp_hdr *tcp_hdr)
{
	/* todo: reset conn counter */
	memset(cp, 0, sizeof(*cp));
	cp->last = tms;
	cp->start = tms;
	cp->pp = pp;
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

	cp->client.seq = rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1;
	cp->client.first_data_seq = cp->client.seq;
	cp->client.window = rte_be_to_cpu_16(tcp_hdr->rx_win);
	cp->client.ts_on = get_ts(tcp_hdr, &cp->client.curr_ts);
	cp->client.wscale_on = get_wscale(tcp_hdr, &cp->client.wscale);

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
static struct app_conn * tcp_conn_find(struct app_protocol *pp, struct rte_mbuf *mb,
		struct app_conn_tbl *tbl, const struct app_conn_key *key, 
		uint64_t tms, uint32_t *from_client, struct tcp_hdr *tcp_hdr)
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
			stale->pp->report_handle(tbl, stale, tms);
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
		if (free != NULL ){
#if 1
			/* add conn when syn and dst_addr in ip_list */
			if ((tcp_hdr->tcp_flags & TCP_SYN_FLAG) && 
					!(tcp_hdr->tcp_flags & TCP_ACK_FLAG) &&
					!(tcp_hdr->tcp_flags & TCP_RST_FLAG) &&
					radix32tree_find(app.ip_list, rte_be_to_cpu_32(key->addr[1]))) {
				tcp_conn_add(tbl,  free, key, tms, pp, tcp_hdr);
				cp = free;
				*from_client = 1;
			}
#else
			tcp_conn_add(tbl,  free, key, tms, pp, tcp_hdr);
			cp = free;
#endif
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

	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_total, ((cp == NULL) && (free == NULL)));

	return (cp);
}

/*
 * Process new mbuf with connection of IPV4 packet.
 * Incoming mbuf should have it's l2_len/l3_len fields setuped correclty.
 * @param tbl
 *   Table where to lookup/add the fragmented packet.
 * @param mb
 *   Incoming mbuf with IPV4 fragment.
 * @param tms
 *   arrival timestamp.
 * @param ip_hdr
 *   Pointer to the IPV4 header
 * @return
 *   Pointer to stream, or NULL if:
 *   - an error occured.
 */
static struct app_conn * tcp_conn_get(struct app_protocol *pp, struct app_conn_tbl *tbl,
		struct rte_mbuf *mb, uint64_t tms, struct ipv4_hdr *ip_hdr, 
		size_t ip_hdr_offset, uint32_t *from_client)
{
	//struct app_conn *cp;
	struct app_conn_key key;
	//const uint64_t *psd;
	//uint16_t ip_len;
	struct tcp_hdr *tcp_hdr = NULL;
	int32_t datalen, iplen;


	iplen = rte_be_to_cpu_32(ip_hdr->total_length);

	if((uint32_t)iplen < ip_hdr_offset + sizeof(struct tcp_hdr)){
		return NULL;
	}

	tcp_hdr = (struct tcp_hdr *)((char *)ip_hdr + ip_hdr_offset);

	datalen = iplen - ip_hdr_offset - 4 * tcp_hdr->data_off;
	if(datalen < 0){
		return NULL;
	}

	/* use first 8 bytes only */
	key.src_dst_addr = *((uint64_t *)&ip_hdr->src_addr);
	key.src_dst_port = *((uint32_t *)tcp_hdr);
	if(key.src_dst_addr == 0 ){
		return NULL;
	}

	/* try to find/add entry into the connection table. */
	return tcp_conn_find(pp, mb, tbl, &key, tms, 
			from_client, tcp_hdr);
}

/*
   static void tcp_process(struct app_protocol *pp, struct app_conn *cp){

   }
   */
static void tcp_process_handle(
		struct app_conn_tbl *tbl,
		struct app_conn *cp, __attribute__((unused))struct rte_mbuf *mb, 
		uint64_t tms, struct ipv4_hdr *ip_hdr, 
		__attribute__((unused))size_t ip_hdr_offset, uint32_t from_client){
	struct app_conn_stream *snd, *rcv;
	struct tcp_hdr *tcp_hdr = NULL;
	int datalen, iplen;
	uint32_t tmp_ts;

	iplen = rte_be_to_cpu_16(ip_hdr->total_length);
	tcp_hdr = (struct tcp_hdr *)((char *)ip_hdr + ip_hdr_offset);
	
	datalen = iplen - ip_hdr_offset - 4 * tcp_hdr->data_off;

	if(from_client){
		snd = &cp->client;
		rcv = &cp->server;
	}else{
		rcv = &cp->client;
		snd = &cp->server;
	}

	if((tcp_hdr->tcp_flags & TCP_SYN_FLAG)){
		if(from_client){
			return;
		}
		if(cp->client.state != TCP_SYN_SENT || 
				cp->server.state != TCP_CLOSE || !(tcp_hdr->tcp_flags & TCP_ACK_FLAG))
			return;
		if(cp->client.seq != rte_be_to_cpu_32(tcp_hdr->recv_ack))
			return;
		cp->last = tms;
		cp->server.state = TCP_SYN_RECV;
		cp->server.seq = rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1;
		cp->server.first_data_seq = cp->server.seq;
		cp->server.ack_seq = rte_be_to_cpu_32(tcp_hdr->recv_ack);
		cp->server.window = rte_be_to_cpu_16(tcp_hdr->rx_win);
		if(cp->client.ts_on){
			cp->server.ts_on = get_ts(tcp_hdr, &cp->server.curr_ts);
			if(!cp->server.ts_on)
				cp->client.ts_on = 0;
		}else{
			cp->server.ts_on = 0;
		}
		if(cp->client.wscale_on){
			cp->server.wscale_on = get_wscale(tcp_hdr, &cp->server.wscale);
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
	if (!(!datalen && rte_be_to_cpu_32(tcp_hdr->sent_seq) == rcv->ack_seq) &&
			(!before(rte_be_to_cpu_32(tcp_hdr->sent_seq), rcv->ack_seq + rcv->window*rcv->wscale) ||
			  before(rte_be_to_cpu_32(tcp_hdr->sent_seq) + datalen, rcv->ack_seq)))     
		return;

	if ((tcp_hdr->tcp_flags & TCP_RST_FLAG)) {
		if (cp->state == CONN_S_DATA) {
			cp->state = CONN_S_RESET;
		}
		/* report */
		cp->pp->report_handle(tbl, cp, tms);
		app_conn_tbl_del(tbl, cp);
		return;
	}

	/* PAWS check */
	if (rcv->ts_on && get_ts(tcp_hdr, &tmp_ts) && 
			before(tmp_ts, snd->curr_ts))
		return; 

	if ((tcp_hdr->tcp_flags & TCP_ACK_FLAG)) {
		if (from_client && cp->client.state == TCP_SYN_SENT &&
				cp->server.state == TCP_SYN_RECV) {
			if (rte_be_to_cpu_32(tcp_hdr->recv_ack) == cp->server.seq) {
				cp->client.state = TCP_ESTABLISHED;
				cp->client.ack_seq = rte_be_to_cpu_32(tcp_hdr->recv_ack);
				cp->last = tms;
				//cp->ts = nids_last_pcap_header->ts.tv_sec;

				cp->server.state = TCP_ESTABLISHED;
				//cp->nids_state = CONN_S_JUST_EST;
				cp->state = CONN_S_DATA;
			}
			// return;
		}
	}
	if ((tcp_hdr->tcp_flags & TCP_ACK_FLAG)) {
		handle_ack(snd, rte_be_to_cpu_32(tcp_hdr->recv_ack));
		if (rcv->state == FIN_SENT)
			rcv->state = FIN_CONFIRMED;
		if (rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED) {
			//struct lurker_node *i;

			cp->state = CONN_S_CLOSE;
			cp->pp->report_handle(tbl, cp, tms);
			app_conn_tbl_del(tbl, cp);
			return;
		}
	}
	if (datalen + (tcp_hdr->tcp_flags & TCP_FIN_FLAG) > 0){
		tcp_queue(cp, tcp_hdr, snd, rcv,
				(char *) (tcp_hdr) + 4 * tcp_hdr->data_off,
				datalen, mb->buf_len);
	}
	snd->window = rte_be_to_cpu_16(tcp_hdr->rx_win);
	if (rcv->rmem_alloc > 65535)
		prune_queue(rcv);

	snd->bytes += rte_be_to_cpu_16(ip_hdr->total_length);
	snd->pkts++;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, proc_pkts, 1);
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, proc_bytes, rte_be_to_cpu_16(ip_hdr->total_length));
	/*
	if (!cp->listeners)
		nids_free_tcp_stream(cp);
	*/

	// todo: seq / ack 
	// todo: cp->state  cp->stream[0/1].state

/*
	if(cp->state == TCP_CLOSE){
		cp->pp->report_handle(tbl, cp, tms);
	}
*/
out:
	// update timer and lru
	snd->last = tms;
	cp->last = tms;
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);
}

/* protocol tcp */
struct app_protocol app_protocol_tcp = {
	.name = (char *)"TCP",                        
	.protocol = IPPROTO_TCP,
	//.init = app_tcp_init,
	.init = NULL,
	.conn_get = tcp_conn_get,
	.debug_packet = tcpudp_debug_packet,
	.process_handle = tcp_process_handle,
	.report_handle = tcpudp_report_handle,
	//	.conn_expire_handle = tcp_conn_expire_handle,
}; 


