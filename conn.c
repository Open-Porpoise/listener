
#define	conn_HASH_FNUM	2

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

/* create  table */
struct app_conn_tbl *
rte_conn_table_create(uint32_t bucket_num, uint32_t bucket_entries,
	uint32_t max_entries, uint64_t max_cycles, int socket_id)
{
	struct app_conn_tbl *tbl;
	size_t sz;
	uint64_t nb_entries;

	nb_entries = rte_align32pow2(bucket_num);
	nb_entries *= bucket_entries;
	nb_entries *= CONN_HASH_FNUM;

	/* check input parameters. */
	if (rte_is_power_of_2(bucket_entries) == 0 ||
			nb_entries > UINT32_MAX || nb_entries == 0 ||
			nb_entries < max_entries) {
		RTE_LOG(ERR, USER1, "%s: invalid input parameter\n", __func__);
		return (NULL);
	}

	sz = sizeof (*tbl) + nb_entries * sizeof (tbl->pkt[0]);
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

/*
 * Reassemble fragments into one packet.
 */
struct rte_mbuf *
ipv4_frag_reassemble(const struct app_conn *fp)
{
	struct ipv4_hdr *ip_hdr;
	struct rte_mbuf *m, *prev;
	uint32_t i, n, ofs, first_len;

	first_len = fp->frags[IP_FIRST_FRAG_IDX].len;
	n = fp->last_idx - 1;

	/*start from the last fragment. */
	m = fp->frags[IP_LAST_FRAG_IDX].mb;
	ofs = fp->frags[IP_LAST_FRAG_IDX].ofs;

	while (ofs != first_len) {

		prev = m;

		for (i = n; i != IP_FIRST_FRAG_IDX && ofs != first_len; i--) {

			/* previous fragment found. */
			if(fp->frags[i].ofs + fp->frags[i].len == ofs) {

				ip_frag_chain(fp->frags[i].mb, m);

				/* update our last fragment and offset. */
				m = fp->frags[i].mb;
				ofs = fp->frags[i].ofs;
			}
		}

		/* error - hole in the packet. */
		if (m == prev) {
			return (NULL);
		}
	}

	/* chain with the first fragment. */
	ip_frag_chain(fp->frags[IP_FIRST_FRAG_IDX].mb, m);
	m = fp->frags[IP_FIRST_FRAG_IDX].mb;

	/* update mbuf fields for reassembled packet. */
	m->ol_flags |= PKT_TX_IP_CKSUM;

	/* update ipv4 header for the reassmebled packet */
	ip_hdr = (struct ipv4_hdr*)(rte_pktmbuf_mtod(m, uint8_t *) +
		m->l2_len);

	ip_hdr->total_length = rte_cpu_to_be_16((uint16_t)(fp->total_size +
		m->l3_len));
	ip_hdr->fragment_offset = (uint16_t)(ip_hdr->fragment_offset &
		rte_cpu_to_be_16(IPV4_HDR_DF_FLAG));
	ip_hdr->hdr_checksum = 0;

	return (m);
}

/* check if key is empty */
static inline int
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
app_conn_tbl_del(struct rte_ip_frag_tbl *tbl, struct rte_ip_frag_death_row *dr,
	struct app_conn *cp)
{
	//ip_frag_free(fp, dr);
	ip_frag_key_invalidate(&cp.stream[0]->key);
	//TAILQ_REMOVE(&tbl->lru, fp, lru);
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
	((tbl)->pkt + ((sig) & (tbl)->entry_mask))

static void
ipv4_conn_hash(const struct ip_frag_key *key,
		struct rte_mbuf *mb, uint32_t *v1, uint32_t *v2)
{
	uint32_t v;
	v = mb->hash;

	*v1 =  v;
	*v2 = (v << 7) + (v >> 14);
}


static struct app_conn_stream *
ipv4_conn_lookup(struct app_conn_tbl *tbl,struct rte_mbuf *mb,
	const struct app_conn_key *key, uint64_t tms,
	struct app_conn **free, struct app_conn **stale)
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
		} else if (ipv4_conn_key_is_empty(&p1[i].stream[0].key))
			empty = (empty == NULL) ? (p1 + i) : empty;
		else if (max_cycles + p1[i].start < tms)
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
		} else if (ipv4_conn_key_is_empty(&p2[i].stream[0].key))
			empty = (empty == NULL) ? (p2 + i) : empty;
		else if (max_cycles + p2[i].start < tms)
			old = (old == NULL) ? (p2 + i) : old;
	}

	*free = empty;
	*stale = old;
	return (NULL);
}

static inline void
app_conn_tbl_add(struct app_conn_tbl *tbl,  struct app_conn *cp,
	const struct app_conn_key *key, uint64_t tms)
{
	cp->stream[0].key = key[0];
	cp->stream[1].key.addr[0] = key->addr[1];
	cp->stream[1].key.addr[1] = key->addr[0];
	cp->stream[1].key.port[0] = key->addr[1];
	cp->stream[1].key.port[1] = key->addr[0];
	cp->stream[1].key.proto = key->proto;

	ip_frag_reset(fp, tms);
	TAILQ_INSERT_TAIL(&tbl->lru, fp, lru);
	tbl->use_entries++;
	IP_FRAG_TBL_STAT_UPDATE(&tbl->stat, add_num, 1);
}


/*
 * Find an entry in the table for the corresponding fragment.
 * If such entry is not present, then allocate a new one.
 * If the entry is stale, then free and reuse it.
 */
static struct app_conn *
ipv4_conn_find(struct app_protocol *pp, struct rte_mbuf *mb,
		struct rte_ip_frag_tbl *tbl, const struct app_conn_key *key, 
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

	if ((cp = ipv4_conn_lookup(tbl, key, tms, &free, &stale)) == NULL) {

		/*timed-out entry, free and invalidate it*/
		if (stale != NULL) {
			pp->conn_expire_handle(stale);
			app_conn_tbl_del(tbl, dr, stale);
			free = stale;

		/*
		 * we found a free entry, check if we can use it.
		 * If we run out of free entries in the table, then
		 * check if we have a timed out entry to delete.
		 */
		} else if (free != NULL &&
				tbl->max_entries <= tbl->use_entries) {
			lru = TAILQ_FIRST(&tbl->lru);
			if (max_cycles + lru->start < tms) {
				app_conn_tbl_del(tbl, dr, lru);
			} else {
				free = NULL;
				IP_FRAG_TBL_STAT_UPDATE(&tbl->stat,
					fail_nospace, 1);
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
	} else if (max_cycles + pkt->start < tms) {
		app_conn_tbl_reuse(tbl, dr, pkt, tms);
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
		uint32_t *from_client)
{
	struct app_conn *cp;
	struct app_conn_key key;
	const uint64_t *psd;
	//uint16_t ip_len;
	struct tcp_hdr *tcp_hdr = NULL;
	//uint16_t flag_offset, ip_ofs, ip_flag;

	//flag_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset);
	//ip_ofs = (uint16_t)(flag_offset & IPV4_HDR_OFFSET_MASK);
	size_t ip_hdr_offset;
//ip_flag = (uint16_t)(flag_offset & IPV4_HDR_MF_FLAG);

	psd = (uint64_t *)&ip_hdr->src_addr;
	/* use first 8 bytes only */
	key.src_dst_addr = *((uint64_t *)&ip_hdr->src_addr);

	ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
			IPV4_IHL_MULTIPLIER;
	tcp_hdr = (struct tcp_hdr *)((char *)ip_hdr + ip_hdr_offset);
	key.src_dst_port = *((uint32_t *)tcp_hdr);


	//ip_ofs *= IPV4_HDR_OFFSET_UNITS;
	//ip_len = (uint16_t)(rte_be_to_cpu_16(ip_hdr->total_length) -
	//	mb->l3_len);

	/* try to find/add entry into the connection table. */
	return ipv4_conn_find(pp, mb, tbl, dr, &key, tms, 
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
static int register_app_protocol(struct app_protocol *pp)
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
app_tcpudp_debug_packet_v4(struct app_protocol *pp,
                 const struct rte_mbuf *mb,
                 struct ipv4_hdr *ih, const char *msg)
{
    char buf[128];
   
    if (ih == NULL)
        sprintf(buf, "%s TRUNCATED", pp->name);
    else if (ih->fragment_offset & htons(IPV4_HDR_OFFSET_MASK))
        sprintf(buf, "%s %pI4->%pI4 frag",
            pp->name, &ih->saddr, &ih->daddr);
    else {
		size_t ip_hdr_offset;
        uint16_t *pptr;
		ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
				IPV4_IHL_MULTIPLIER;
		pptr = (uint16_t *)((char *)ipv4_hdr + ip_hdr_offset);
        sprintf(buf, "%s %pI4:%u->%pI4:%u",
                pp->name,
                &ih->src_addr, ntohs(pptr[0]),
                &ih->dst_addr, ntohs(pptr[1]));
    }
   
    RTE_LOG(DEBUG, USR1, "%s: %s\n", msg, buf);
} 

static void app_tcpudp_debug_packet(struct app_protocol *pp,
				const struct rte_mbuf *mbuf, void *ip_hdr, 
				const char *msg) {  
	//todo add v6
	app_tcpudp_debug_packet_v4(pp, mbuf, (struct ipv4_hdr *)ip_hdr, msg);
}


static void tcp_process_handler(struct app_protocol *pp, 
		static struct app_conn * cp, struct rte_mbuf *mb, 
		uint64_t tms, struct ipv4_hdr *ip_hdr, uint32_t *from_client){
	struct tcp_hdr *tcp_hdr = NULL;
	size_t ip_hdr_offset;
	ip_hdr_offset = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) * 
		IPV4_IHL_MULTIPLIER;
	tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr + ip_hdr_offset);
}

static void tcp_conn_expire_handler(struct app_protocol *pp,
				const struct rte_mbuf *mbuf, void *ip_hdr) {
}

static void udp_process_handler(struct app_protocol *pp, 
		static struct app_conn * cp, struct rte_mbuf *mb, 
		uint64_t tms, struct ipv4_hdr *ip_hdr, uint32_t *from_client){
}

static void udp_conn_expire_handler(struct app_protocol *pp,
				const struct rte_mbuf *mbuf, void *ip_hdr) {
}

/* protocol tcp */
struct app_protocol app_protocol_tcp = {
	.name = "TCP",                        
	.protocol = IPPROTO_TCP,
	//.init = app_tcp_init,
	.init = NULL,
	.conn_get = ipv4_tcp_conn_get,
	.debug_packet = app_tcpudp_debug_packet,
	.process_handle = tcp_process_handler,
	.conn_expire_handler = tcp_conn_expire_handler,
}; 

struct app_protocol app_protocol_tcp = {
	.name = "UDP",                        
	.protocol = IPPROTO_UDP,              
	.init = NULL,               
	.conn_get = udp_conn_get,       
	.debug_packet = app_tcpudp_debug_packet,
	.process_handle = udp_process_handler,
	.conn_expire_handler = udp_conn_expire_handler,
}; 
