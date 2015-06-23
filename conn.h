/* 
 * yubo@xiaomi.com
 * 2015-06-15
 */

#ifndef _CONN_H_
#define _CONN_H_

#include <stdint.h>
#include <stdio.h>

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include "main.h"

/* app_conn flags */
#define	F_CONN_IN_IDX	0x0001
#define	F_CONN_OUT_IDX	0x0002

#define	APP_CONN_HASH_FNUM	2

/** @internal <src addr, dst_addr, id> to uniquely indetify connection datagram. */
struct app_conn_key {
	union {
		uint64_t src_dst_addr;      /**< src address, first 8 bytes used for IPv4 */
		uint32_t addr[2];
	};
	union{
		uint32_t src_dst_port;           /**< src, dst port */
		uint16_t port[2];
	};
	uint8_t proto;
};

#define conn_DEATH_ROW_LEN 32 /**< death row size (in packets) */

struct app_lcore_params_worker;

#ifdef APP_CONN_TBL_STAT
#define	APP_CONN_TBL_STAT_UPDATE(s, f, v)	((s)->f += (v))
#else
#define	APP_CONN_TBL_STAT_UPDATE(s, f, v)	do {} while (0)
#endif

#if 0
/** mbuf death row (packets to be freed) */
struct rte_conn_death_row {
	uint32_t cnt;          /**< number of mbufs currently on death row */
	struct rte_mbuf *row[conn_DEATH_ROW_LEN * (IP_MAX_CONN_NUM + 1)];
	/**< mbufs to be freed */
};
#endif

//TAILQ_HEAD(ip_pkt_list, ip_frag_pkt); /**< @internal connments tailq */
TAILQ_HEAD(app_conn_list, app_conn); /**< @internal connments tailq */

struct app_conn;

struct app_conn_stream {
	uint32_t flags;
	struct app_conn_key key;
	uint64_t bytes;
	uint32_t pkts;
	uint64_t start;       /**< creation timestamp */
	uint64_t last;       /**< last update timestamp */

	int32_t urg_count;
	uint32_t acked;
	uint32_t seq;
	uint32_t ack_seq;
	uint32_t first_data_seq;
	uint8_t urgdata;
	uint8_t count_new_urg;
	uint8_t urg_seen;
	uint32_t urg_ptr;
	uint16_t window;
	uint8_t ts_on;
	uint8_t wscale_on;
	uint32_t curr_ts; 
	uint32_t wscale;
	struct app_conn *cp;
};

struct app_conn {
	TAILQ_ENTRY(app_conn) lru;   /**< LRU list */
	uint64_t last;       /**< creation timestamp */
	uint32_t state;
	struct app_conn_stream stream[2];
} __rte_cache_aligned;


/** connection table statistics */
struct conn_tbl_stat {
	uint64_t find_num;      /**< total # of find/insert attempts. */
	uint64_t add_num;       /**< # of add ops. */
	uint64_t del_num;       /**< # of del ops. */
	uint64_t reuse_num;     /**< # of reuse (del/add) ops. */
	uint64_t fail_total;    /**< total # of add failures. */
	uint64_t fail_nospace;  /**< # of 'no space' add failures. */
} __rte_cache_aligned;

/** connection table */
struct app_conn_tbl {
	uint64_t             max_cycles;      /**< ttl for table entries. */
	uint32_t             entry_mask;      /**< hash value mask. */
	uint32_t             max_entries;     /**< max entries allowed. */
	uint32_t             use_entries;     /**< entries in use. */
	uint32_t             bucket_entries;  /**< hash assocaitivity. */
	uint32_t             nb_entries;      /**< total size of the table. */
	uint32_t             nb_buckets;      /**< num of associativity lines. */
	uint32_t             nu_log;	      /**< num of log lines. */
	struct conn_pkt *last;         /**< last used entry. */
	struct app_conn_list lru;           /**< LRU list for table entries. */
	struct conn_tbl_stat stat;     /**< statistics counters. */
	struct app_conn conn[0];        /**< hash table. */
};

/*
 * Create a new IP connection table.
 *
 * @param bucket_num
 *   Number of buckets in the hash table.
 * @param bucket_entries
 *   Number of entries per bucket (e.g. hash associativity).
 *   Should be power of two.
 * @param max_entries
 *   Maximum number of entries that could be stored in the table.
 *   The value should be less or equal then bucket_num * bucket_entries.
 * @param max_cycles
 *   Maximum TTL in cycles for each connection packet.
 * @param socket_id
 *   The *socket_id* argument is the socket identifier in the case of
 *   NUMA. The value can be *SOCKET_ID_ANY* if there is no NUMA constraints.
 * @return
 *   The pointer to the new allocated connection table, on success. NULL on error.
 */
struct app_conn_tbl * app_conn_table_create(uint32_t bucket_num,
		uint32_t bucket_entries,  uint32_t max_entries,
		uint64_t max_cycles, int socket_id);

/*
 * Free allocated IP connection table.
 *
 * @param btl
 *   connection table to free.
 */
static inline void
rte_conn_table_destroy( struct app_conn_tbl *tbl)
{
	rte_free(tbl);
}


/**
 * IPv4 connection.
 *
 * This function implements the connection of IPv4 packets.
 *
 * @param pkt_in
 *   The input packet.
 * @param pkts_out
 *   Array storing the output connments.
 * @param nb_pkts_out
 *   Number of connments.
 * @param mtu_size
 *   Size in bytes of the Maximum Transfer Unit (MTU) for the outgoing IPv4
 *   datagrams. This value includes the size of the IPv4 header.
 * @param pool_direct
 *   MBUF pool used for allocating direct buffers for the output connments.
 * @param pool_indirect
 *   MBUF pool used for allocating indirect buffers for the output connments.
 * @return
 *   Upon successful completion - number of output connments placed
 *   in the pkts_out array.
 *   Otherwise - (-1) * errno.
 */
int32_t rte_ipv4_connment_packet(struct rte_mbuf *pkt_in,
			struct rte_mbuf **pkts_out,
			uint16_t nb_pkts_out, uint16_t mtu_size,
			struct rte_mempool *pool_direct,
			struct rte_mempool *pool_indirect);

/*
 * Free mbufs on a given death row.
 *
 * @param dr
 *   Death row to free mbufs in.
 * @param prefetch
 *   How many buffers to prefetch before freeing.
 */
//void rte_conn_free_death_row(struct rte_conn_death_row *dr,
//		uint32_t prefetch);


/*
 * Dump connection table statistics to file.
 *
 * @param f
 *   File to dump statistics to
 * @param tbl
 *   connection table to dump statistics from
 */
void
rte_conn_table_statistics_dump(FILE * f, const struct app_conn_tbl *tbl);

struct app_protocol {
    struct app_protocol *next;
    char *name;
    uint16_t protocol;

	void (*init) (struct app_protocol * pp);

    struct app_conn *                    
        (*conn_get) (struct app_protocol *pp,
			struct app_conn_tbl *tbl,
			struct rte_mbuf *mb, 
			uint64_t tms, struct ipv4_hdr *ip_hdr, 
			size_t ip_hdr_offset, uint32_t *from_client);

	void (*process_handle)(struct app_protocol *pp, 
			struct app_conn_tbl *tbl,
			struct app_conn *cp, struct rte_mbuf *mb, 
			uint64_t tms, struct ipv4_hdr *ip_hdr, 
			size_t ip_hdr_offset, uint32_t from_client);

	void (*debug_packet)(struct app_protocol *pp,
			const struct rte_mbuf *mbuf, void *ip_hdr, 
			const char *msg);

	void (*report_handle)(struct app_protocol *pp,
			struct app_conn_tbl *tbl,
			struct app_conn *cp);
#if 0
	void (*conn_expire_handle)(struct app_protocol *pp, 
			struct app_conn_tbl *tbl,
			struct app_conn *cp);
#endif

};

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
	TCP_CLOSING,	/* Now a valid state */

	TCP_MAX_STATES	/* Leave at the end! */
};


int register_app_protocol(struct app_protocol *pp);
struct app_protocol *app_proto_get(unsigned short proto);
extern struct app_protocol app_protocol_tcp;
extern struct app_protocol app_protocol_udp;

#endif
