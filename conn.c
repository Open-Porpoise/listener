#include "main.h"
#include "utils.h"

#define	conn_HASH_FNUM	2

#if 0
/* free mbufs from death row */
void
rte_conn_free_death_row(struct rte_conn_death_row *dr,
		uint32_t prefetch)
{
	uint32_t i, k, n;

	k = RTE_MIN(prefetch, dr->cnt);
	n = dr->cnt;

	for (i = 0; i != k; i++)
		rte_prefetch0(dr->row[i]);

	for (i = 0; i != n - k; i++) {
		rte_prefetch0(dr->row[i + k]);
		rte_pktmbuf_free(dr->row[i]);
	}

	for (; i != n; i++)
		rte_pktmbuf_free(dr->row[i]);

	dr->cnt = 0;
}
#endif 

/* create  table */
struct app_conn_tbl *
app_conn_table_create(uint32_t bucket_num, uint32_t bucket_entries,
	uint32_t max_entries, uint64_t max_cycles, int socket_id)
{
	struct app_conn_tbl *tbl;
	size_t sz;
	uint64_t nb_entries;

	nb_entries = rte_align32pow2(bucket_num);
	nb_entries *= bucket_entries;
	nb_entries *= APP_CONN_HASH_FNUM;

	/* check input parameters. */
	if (rte_is_power_of_2(bucket_entries) == 0 ||
			nb_entries > UINT32_MAX || nb_entries == 0 ||
			nb_entries < max_entries) {
		RTE_LOG(ERR, USER1, "%s: invalid input parameter\n", __func__);
		return (NULL);
	}

	sz = sizeof (*tbl) + nb_entries * sizeof (tbl->conn[0]);
	if ((tbl = rte_zmalloc_socket(__func__, sz, RTE_CACHE_LINE_SIZE,
			socket_id)) == NULL) {
		RTE_LOG(ERR, USER1,
			"%s: allocation of %zu bytes at socket %d failed do\n",
			__func__, sz, socket_id);
		return (NULL);
	}

	RTE_LOG(INFO, USER1, "%s: allocated of %zu bytes at socket %d\n",
		__func__, sz, socket_id);

	tbl->max_cycles = max_cycles;
	tbl->max_entries = max_entries;
	tbl->nb_entries = (uint32_t)nb_entries;
	tbl->nb_buckets = bucket_num;
	tbl->bucket_entries = bucket_entries;
	tbl->entry_mask = (tbl->nb_entries - 1) & ~(tbl->bucket_entries  - 1);

	TAILQ_INIT(&(tbl->lru));
	return (tbl);
}

/* dump table statistics to file */
void
rte_conn_table_statistics_dump(FILE *f, const struct app_conn_tbl *tbl)
{
	uint64_t fail_total, fail_nospace;

	fail_total = tbl->stat.fail_total;
	fail_nospace = tbl->stat.fail_nospace;

	fprintf(f, "max entries:\t%u;\n"
		"entries in use:\t%u;\n"
		"finds/inserts:\t%" PRIu64 ";\n"
		"entries added:\t%" PRIu64 ";\n"
		"entries deleted by timeout:\t%" PRIu64 ";\n"
		"entries reused by timeout:\t%" PRIu64 ";\n"
		"total add failures:\t%" PRIu64 ";\n"
		"add no-space failures:\t%" PRIu64 ";\n"
		"add hash-collisions failures:\t%" PRIu64 ";\n",
		tbl->max_entries,
		tbl->use_entries,
		tbl->stat.find_num,
		tbl->stat.add_num,
		tbl->stat.del_num,
		tbl->stat.reuse_num,
		fail_total,
		fail_nospace,
		fail_total - fail_nospace);
}

/* check if key is empty */
static  int
app_conn_key_is_empty(const struct app_conn_key * key)
{
	return key->src_dst_addr ? 0 : 1;
}


/* empty the key */
static void
app_conn_key_invalidate(struct app_conn_key * key)
{
	key->src_dst_addr = 0;
}


/* local frag table helper functions */
static void
//app_conn_tbl_del(struct rte_ip_frag_tbl *tbl, struct rte_ip_frag_death_row *dr,
app_conn_tbl_del(struct app_conn_tbl *tbl, 
	struct app_conn *cp)
{
	//ip_frag_free(fp, dr);
	app_conn_key_invalidate(&cp->stream[0].key);
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	tbl->use_entries--;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, del_num, 1);
}


/* compare two keys */
static  int
ipv4_conn_key_cmp(const struct app_conn_key * k1, const struct app_conn_key * k2)
{
	uint64_t val;
	val = k1->src_dst_addr ^ k2->src_dst_addr;
	val |= k1->src_dst_port ^ k2->src_dst_port;
	val |= k1->proto ^ k2->proto;
	return val ? 1 : 0;
}

#define	APP_CONN_TBL_POS(tbl, sig)	\
	((tbl)->conn + ((sig) & (tbl)->entry_mask))

static void
ipv4_conn_hash(__attribute__((unused))const struct app_conn_key *key,
		struct rte_mbuf *mb, uint32_t *v1, uint32_t *v2)
{
	uint32_t v;
	v = mb->hash.usr;

	*v1 =  v;
	*v2 = (v << 7) + (v >> 14);
}


static struct app_conn *
ipv4_conn_lookup(struct app_conn_tbl *tbl,struct rte_mbuf *mb,
	const struct app_conn_key *key, uint64_t tms,
	struct app_conn **free, struct app_conn **stale, uint32_t *from_client)
{
	struct app_conn *p1, *p2;
	struct app_conn *empty, *old;
	uint64_t max_cycles;
	uint32_t i, assoc, sig1, sig2;

	empty = NULL;
	old = NULL;

	max_cycles = tbl->max_cycles;
	assoc = tbl->bucket_entries;

	/* different hashing methods for IPv4 and IPv6 */
	ipv4_conn_hash(key, mb, &sig1, &sig2);

	p1 = APP_CONN_TBL_POS(tbl, sig1);
	p2 = APP_CONN_TBL_POS(tbl, sig2);

	for (i = 0; i != assoc; i++) {
/*
		IP_FRAG_LOG(DEBUG, "%s:%d:\n"
				"tbl: %p, max_entries: %u, use_entries: %u\n"
				"ipv6_frag_pkt line0: %p, index: %u from %u\n"
		"key: <%" PRIx64 ", %#x>, start: %" PRIu64 "\n",
				__func__, __LINE__,
				tbl, tbl->max_entries, tbl->use_entries,
				p1, i, assoc,
		p1[i].key.src_dst[0], p1[i].key.id, p1[i].start);
*/

		if (ipv4_conn_key_cmp(key, &p1[i].stream[0].key) == 0){
			*from_client = 1;
			return (p1 + i);
		}else if (ipv4_conn_key_cmp(key, &p1[i].stream[1].key) == 0) {
			*from_client = 0;
			return (p1 + i);
		} else if (app_conn_key_is_empty(&p1[i].stream[0].key))
			empty = (empty == NULL) ? (p1 + i) : empty;
		else if (max_cycles + p1[i].last < tms)
			old = (old == NULL) ? (p1 + i) : old;
/*
		if (p2->key.key_len == IPV4_KEYLEN)
			IP_FRAG_LOG(DEBUG, "%s:%d:\n"
					"tbl: %p, max_entries: %u, use_entries: %u\n"
					"ipv6_frag_pkt line1: %p, index: %u from %u\n"
			"key: <%" PRIx64 ", %#x>, start: %" PRIu64 "\n",
					__func__, __LINE__,
					tbl, tbl->max_entries, tbl->use_entries,
					p2, i, assoc,
			p2[i].key.src_dst[0], p2[i].key.id, p2[i].start);
*/

		if (ipv4_conn_key_cmp(key, &p2[i].stream[0].key) == 0){
			*from_client = 1;
			return (p2 + i);
		}else if (ipv4_conn_key_cmp(key, &p2[i].stream[1].key) == 0) {
			*from_client = 0;
			return (p2 + i);
		} else if (app_conn_key_is_empty(&p2[i].stream[0].key))
			empty = (empty == NULL) ? (p2 + i) : empty;
		else if (max_cycles + p2[i].last < tms)
			old = (old == NULL) ? (p2 + i) : old;
	}

	*free = empty;
	*stale = old;
	return (NULL);
}

/* reset the fragment */
static void
stream_reset(struct app_conn_stream *sp, uint64_t tms)
{
	sp->start = tms;
	sp->last = tms;
	sp->bytes = 0;
	sp->pkts = 0;
}


static void
app_conn_tbl_add(struct app_conn_tbl *tbl,  struct app_conn *cp,
	const struct app_conn_key *key, uint64_t tms)
{
	/* todo: reset conn counter */
	//memset(cp->stream, 0, sizeof(struct app_conn_stream) * 2);
	cp->last = tms;
	cp->stream[0].key = key[0];
	cp->stream[1].key.addr[0] = key->addr[1];
	cp->stream[1].key.addr[1] = key->addr[0];
	cp->stream[1].key.port[0] = key->addr[1];
	cp->stream[1].key.port[1] = key->addr[0];
	cp->stream[1].key.proto = key->proto;

	stream_reset(&cp->stream[0], tms);
	stream_reset(&cp->stream[1], tms);
	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);
	tbl->use_entries++;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, add_num, 1);
}


/*
 * Find an entry in the table for the corresponding fragment.
 * If such entry is not present, then allocate a new one.
 * If the entry is stale, then free and reuse it.
 * just fro tcp
 */
static struct app_conn *
ipv4_conn_find(struct app_protocol *pp, struct rte_mbuf *mb,
		struct app_conn_tbl *tbl, const struct app_conn_key *key, 
		uint64_t tms, uint32_t *from_client, uint8_t tcp_flags)
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

	if ((cp = ipv4_conn_lookup(tbl, mb, key, tms, &free, &stale, from_client)) == NULL) {

		/*timed-out entry, free and invalidate it*/
		if (stale != NULL) {
			pp->report_handle(pp, tbl, stale);
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
				app_conn_tbl_del(tbl, lru);
			} else {
				free = NULL;
				APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_nospace, 1);
			}
		}

		/* found a free entry to reuse. */
		if (free != NULL && (tcp_flags & TCP_FLAG_ALL) == TCP_SYN_FLAG) {
			app_conn_tbl_add(tbl,  free, key, tms);
			//ip_frag_tbl_add(tbl,  free, key, tms);
			cp = free;
		}

	/*
	 * we found the flow, but it is already timed out,
	 * so free associated resources, reposition it in the LRU list,
	 * and reuse it.
	 */
	} else if (max_cycles + cp->last < tms) {
		//ip_frag_tbl_reuse(tbl, cp, tms);
		//app_conn_tbl_reuse(tbl, cp, tms);
	}

	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, fail_total, (cp == NULL));

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
static struct app_conn *
ipv4_tcp_conn_get(struct app_protocol *pp, struct app_conn_tbl *tbl,
		struct rte_mbuf *mb, uint64_t tms, struct ipv4_hdr *ip_hdr, 
		size_t ip_hdr_offset, uint32_t *from_client)
{
	//struct app_conn *cp;
	struct app_conn_key key;
	//const uint64_t *psd;
	//uint16_t ip_len;
	struct tcp_hdr *tcp_hdr = NULL;
	//uint16_t flag_offset, ip_ofs, ip_flag;

	//flag_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset);
	//ip_ofs = (uint16_t)(flag_offset & IPV4_HDR_OFFSET_MASK);
//ip_flag = (uint16_t)(flag_offset & IPV4_HDR_MF_FLAG);

	//psd = (uint64_t *)&ip_hdr->src_addr;
	/* use first 8 bytes only */
	key.src_dst_addr = *((uint64_t *)&ip_hdr->src_addr);

	tcp_hdr = (struct tcp_hdr *)((char *)ip_hdr + ip_hdr_offset);
	key.src_dst_port = *((uint32_t *)tcp_hdr);


	//ip_ofs *= IPV4_HDR_OFFSET_UNITS;
	//ip_len = (uint16_t)(rte_be_to_cpu_16(ip_hdr->total_length) -
	//	mb->l3_len);

	/* try to find/add entry into the connection table. */
	return ipv4_conn_find(pp, mb, tbl, &key, tms, 
			from_client, tcp_hdr->tcp_flags);
}


/*
 * protocols
 */

#define APP_PROTO_TAB_SIZE        16  /* must be power of 2 */
#define APP_PROTO_HASH(proto)     ((proto) & (APP_PROTO_TAB_SIZE-1))
static struct app_protocol *app_proto_table[APP_PROTO_TAB_SIZE];

/*                                          
 *  register an ipvs protocol               
 */                                         
int register_app_protocol(struct app_protocol *pp)
{
    unsigned hash = APP_PROTO_HASH(pp->protocol);

    pp->next = app_proto_table[hash];
    app_proto_table[hash] = pp;

    if (pp->init != NULL)
        pp->init(pp);

    return 0;
}

/*
 *  get app_protocol object by its proto.
 */ 
struct app_protocol *app_proto_get(unsigned short proto)
{
    struct app_protocol *pp;
    unsigned hash = APP_PROTO_HASH(proto);

    for (pp = app_proto_table[hash]; pp; pp = pp->next) {
        if (pp->protocol == proto)
            return pp;
    }

    return NULL;
}

static void
tcpudp_debug_packet_v4(struct app_protocol *pp,
                 __attribute__((unused))const struct rte_mbuf *mb,
                 struct ipv4_hdr *ih, const char *msg)
{
    char buf[128];
   
    if (ih == NULL)
        sprintf(buf, "%s TRUNCATED", pp->name);
    else if (ih->fragment_offset & htons(IPV4_HDR_OFFSET_MASK))
        sprintf(buf, "%s %pI4->%pI4 frag",
            pp->name, &ih->src_addr, &ih->dst_addr);
    else {
		size_t ip_hdr_offset;
        uint16_t *pptr;
		ip_hdr_offset = (ih->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;
		pptr = (uint16_t *)((char *)ih + ip_hdr_offset);
        sprintf(buf, "%s %pI4:%u->%pI4:%u",
                pp->name,
                &ih->src_addr, ntohs(pptr[0]),
                &ih->dst_addr, ntohs(pptr[1]));
    }
   
    RTE_LOG(DEBUG, USER1, "%s: %s\n", msg, buf);
} 

static void tcpudp_debug_packet(struct app_protocol *pp,
				const struct rte_mbuf *mbuf, void *ip_hdr, 
				const char *msg) {  
	//todo add v6
	tcpudp_debug_packet_v4(pp, mbuf, (struct ipv4_hdr *)ip_hdr, msg);
}


static void tcp_process_handle(__attribute__((unused))struct app_protocol *pp, 
		struct app_conn_tbl *tbl,
		struct app_conn * cp, __attribute__((unused))struct rte_mbuf *mb, 
		uint64_t tms, struct ipv4_hdr *ip_hdr, 
		__attribute__((unused))size_t ip_hdr_offset, uint32_t from_client){
	struct app_conn_stream *sp;
	//struct tcp_hdr *tcp_hdr = NULL;
	//tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr + ip_hdr_offset);
	sp = cp->stream;
	if(!from_client){
		sp++;
	}

	// todo: seq / ack 
	// todo: stat 

	// process 
	sp->bytes += ip_hdr->total_length;
	sp->pkts++;


	if(cp->state == TCP_CLOSE){
		pp->report_handle(pp, tbl, cp);
	}

	// update timer and lru
	sp->last = tms;
	cp->last = tms;
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);
}

static  void tcpudp_report_handle(struct app_protocol *pp, 
		struct app_conn_tbl *tbl, struct app_conn *cp) {
	if (tbl->nu_log < 100){
		printf("%s %pI4:%u->%pI4:%u tx_bytes:%lu tx_pkts:%u rx_bytes:%lu rx_pkts:%u", 
				pp->name, 
				&cp->stream[0].key.addr[0], cp->stream[0].key.port[0], 
				&cp->stream[0].key.addr[1], cp->stream[0].key.port[1], 
				cp->stream[0].bytes, cp->stream[0].pkts,
				cp->stream[1].bytes, cp->stream[1].pkts);
		tbl->nu_log ++;
	}
	return;
}

#if 0
static  void tcp_conn_expire_handle(struct app_protocol *pp, struct app_conn *cp) {
	if (pp && cp ){
		return;
	}
	return;
}
#endif

static void udp_process_handle(__attribute__((unused))struct app_protocol *pp, 
		struct app_conn_tbl *tbl,
		struct app_conn * cp, struct rte_mbuf *mb, 
		uint64_t tms, struct ipv4_hdr *ip_hdr, 
		size_t ip_hdr_offset, uint32_t from_client){
	if (pp && tbl && cp && mb && ip_hdr && ip_hdr_offset && from_client && tms)
		return;
}

#if 0
static void udp_conn_expire_handle(struct app_protocol *pp, struct app_conn *cp) {
	if (pp && cp ){
		return;
	}
	return;
}
#endif

/* protocol tcp */
struct app_protocol app_protocol_tcp = {
	.name = (char *)"TCP",                        
	.protocol = IPPROTO_TCP,
	//.init = app_tcp_init,
	.init = NULL,
	.conn_get = ipv4_tcp_conn_get,
	.debug_packet = tcpudp_debug_packet,
	.process_handle = tcp_process_handle,
	.report_handle = tcpudp_report_handle,
//	.conn_expire_handle = tcp_conn_expire_handle,
}; 

struct app_protocol app_protocol_udp = {
	.name = (char *)"UDP",                        
	.protocol = IPPROTO_UDP,              
	.init = NULL,               
	.conn_get = ipv4_tcp_conn_get,       
	.debug_packet = tcpudp_debug_packet,
	.process_handle = udp_process_handle,
	.report_handle = tcpudp_report_handle,
//	.conn_expire_handle = udp_conn_expire_handle,
}; 
