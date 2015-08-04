/*
 * yubo@xiaomi.com
 * 2015-06-29
 */
#include "main.h"
#include "utils.h"
#include "sender.h"

/* ################## CONN #########################*/
/* create  table */
struct app_conn_tbl *
app_conn_table_create(uint32_t bucket_num, uint32_t bucket_entries,
		uint32_t max_entries, uint64_t max_cycles, uint64_t rpt_cycles, int socket_id)
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
	tbl->rpt_cycles = rpt_cycles;
	tbl->max_entries = max_entries;
	tbl->nb_entries = (uint32_t)nb_entries;
	tbl->nb_buckets = bucket_num;
	tbl->bucket_entries = bucket_entries;
	tbl->entry_mask = (tbl->nb_entries - 1) & ~(tbl->bucket_entries  - 1);

	TAILQ_INIT(&(tbl->lru));
	TAILQ_INIT(&(tbl->rpt));
	return (tbl);
}

static  int conn_is_empty(const struct app_conn *cp)
{
	if(cp && cp->client.key.src_dst_addr == 0)
		return 1;
	return 0;
}

/* empty the key */
static void conn_invalidate(struct app_conn *cp)
{
	cp->client.key.src_dst_addr = 0;
}

void prune_queue(struct app_conn_stream * rcv)
{
	struct skbuff *tmp, *p = rcv->list;

	if(rcv->data){
		free(rcv->data);
		rcv->data = NULL;
		rcv->bufsize = 0;
	}
	while (p) {
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}
	rcv->list = rcv->listtail = NULL;
	rcv->rmem_alloc = 0;
}

/* local frag table helper functions */
void app_conn_tbl_del(struct app_conn_tbl *tbl, 
		struct app_conn *cp)
{
	//ip_frag_free(fp, dr);
	prune_queue(&cp->client);
	prune_queue(&cp->server);
	conn_invalidate(cp);
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	TAILQ_REMOVE(&tbl->rpt, cp, rpt);
	tbl->use_entries--;
	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, del_num, 1);
}

/* compare two keys */
static  int conn_key_cmp(const struct app_conn_key * k1, const struct app_conn_key * k2)
{
	uint64_t val;
	val = k1->src_dst_addr ^ k2->src_dst_addr;
	val |= k1->src_dst_port ^ k2->src_dst_port;
	val |= k1->proto ^ k2->proto;
	return val ? 1 : 0;
}

#define	APP_CONN_TBL_POS(tbl, sig)	\
	((tbl)->conn + ((sig) & (tbl)->entry_mask))

static void conn_hash(__attribute__((unused))const struct app_conn_key *key,
		struct rte_mbuf *mb, uint32_t *v1, uint32_t *v2)
{
	uint32_t v;
	v = mb->hash.usr;

	*v1 =  v;
	*v2 = (v << 7) + (v >> 14);
}

struct app_conn * conn_lookup(struct app_conn_tbl *tbl,struct rte_mbuf *mb,
		const struct app_conn_key *key, uint64_t tms,
		struct app_conn **free, struct app_conn **stale, int *from_client)
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
	conn_hash(key, mb, &sig1, &sig2);

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

		if (conn_key_cmp(key, &p1[i].client.key) == 0){
			APP_CONN_TBL_STAT_UPDATE(&tbl->stat, from_client, 1);
			*from_client = 1;
			return (p1 + i);
		}else if (conn_key_cmp(key, &p1[i].server.key) == 0) {
			APP_CONN_TBL_STAT_UPDATE(&tbl->stat, from_server, 1);
			*from_client = 0;
			return (p1 + i);
		} else if (conn_is_empty(p1+i))
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

		if (conn_key_cmp(key, &p2[i].client.key) == 0){
			*from_client = 1;
			return (p2 + i);
		}else if (conn_key_cmp(key, &p2[i].server.key) == 0) {
			*from_client = 0;
			return (p2 + i);
		} else if (conn_is_empty(p2+i))
			empty = (empty == NULL) ? (p2 + i) : empty;
		else if (max_cycles + p2[i].last < tms)
			old = (old == NULL) ? (p2 + i) : old;
	}

	*free = empty;
	*stale = old;
	return (NULL);
}


