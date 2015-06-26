#ifndef _MAIN_H_
#define _MAIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>


#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_tcp.h>
#include <rte_lpm.h>


#include <rte_timer.h>
#include "geolocation.h"
#include "conn.h"

#define CONFIG_APP_PROTO_TCP
#define CONFIG_APP_PROTO_UDP

/* conn */

#define	MAX_CONN_NUM	UINT32_MAX
#define	MIN_CONN_NUM	1
#define	DEF_CONN_NUM	0x80000
#define	APP_CONN_TBL_BUCKET_ENTRIES	2
#define	MAX_CONN_TTL	(3600 * MS_PER_S)
#define	MIN_CONN_TTL	1
#define	DEF_CONN_TTL	(30 * MS_PER_S)
#define	DEF_RPT_TTL		(60 * MS_PER_S)


/* ip reassebly */
#define PREFETCH_OFFSET 3
#define NB_MBUF 8192
/* allow max jumbo frame 9.5 KB */
#define JUMBO_FRAME_MAX_SIZE	0x2600
#define	MAX_FLOW_NUM	UINT16_MAX
#define	MIN_FLOW_NUM	1
#define	DEF_FLOW_NUM	0x1000
/* TTL numbers are in ms. */
#define	MAX_FLOW_TTL	(3600 * MS_PER_S)
#define	MIN_FLOW_TTL	1
#define	DEF_FLOW_TTL	MS_PER_S
#define MAX_FRAG_NUM RTE_LIBRTE_IP_FRAG_MAX_FRAG
/* Should be power of two. */
#define	IP_FRAG_TBL_BUCKET_ENTRIES	16
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */



/* */
#ifndef CONFIG_APP_PROTO_TCP
#define CONFIG_APP_PROTO_TCP 1
#endif

#ifndef CONFIG_APP_PROTO_UDP
#define CONFIG_APP_PROTO_UDP 0
#endif

#ifndef APP_CONN_TAB_SIZE
#define APP_CONN_TAB_SIZE (1<<24)
#endif

#define TIMER_RESOLUTION_CYCLES 20000000ULL /* around 10ms at 2 Ghz */

/* Logical cores */
#ifndef APP_MAX_SOCKETS
#define APP_MAX_SOCKETS 2
#endif

#ifndef APP_MAX_LCORES
#define APP_MAX_LCORES       RTE_MAX_LCORE
#endif

#ifndef APP_MAX_NIC_PORTS
#define APP_MAX_NIC_PORTS    RTE_MAX_ETHPORTS
#endif

#ifndef APP_MAX_RX_QUEUES_PER_NIC_PORT
#define APP_MAX_RX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_TX_QUEUES_PER_NIC_PORT
#define APP_MAX_TX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_IO_LCORES
#define APP_MAX_IO_LCORES 16
#endif
#if (APP_MAX_IO_LCORES > APP_MAX_LCORES)
#error "APP_MAX_IO_LCORES is too big"
#endif

#ifndef APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE
#define APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE 16
#endif

#ifndef APP_MAX_NIC_TX_PORTS_PER_IO_LCORE
#define APP_MAX_NIC_TX_PORTS_PER_IO_LCORE 16
#endif
#if (APP_MAX_NIC_TX_PORTS_PER_IO_LCORE > APP_MAX_NIC_PORTS)
#error "APP_MAX_NIC_TX_PORTS_PER_IO_LCORE too big"
#endif

#ifndef APP_MAX_WORKER_LCORES
#define APP_MAX_WORKER_LCORES 16
#endif
#if (APP_MAX_WORKER_LCORES > APP_MAX_LCORES)
#error "APP_MAX_WORKER_LCORES is too big"
#endif


/* Mempools */
#ifndef APP_DEFAULT_MBUF_SIZE
#define APP_DEFAULT_MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#endif

#ifndef APP_DEFAULT_MEMPOOL_BUFFERS
#define APP_DEFAULT_MEMPOOL_BUFFERS   8192 * 4
#endif

#ifndef APP_DEFAULT_MEMPOOL_CACHE_SIZE
#define APP_DEFAULT_MEMPOOL_CACHE_SIZE  256
#endif

/* LPM Tables */
#ifndef APP_MAX_LPM_RULES
#define APP_MAX_LPM_RULES 1024
#endif

/* NIC RX */
#ifndef APP_DEFAULT_NIC_RX_RING_SIZE
#define APP_DEFAULT_NIC_RX_RING_SIZE 1024
#endif

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#ifndef APP_DEFAULT_NIC_RX_PTHRESH
#define APP_DEFAULT_NIC_RX_PTHRESH  8
#endif

#ifndef APP_DEFAULT_NIC_RX_HTHRESH
#define APP_DEFAULT_NIC_RX_HTHRESH  8
#endif

#ifndef APP_DEFAULT_NIC_RX_WTHRESH
#define APP_DEFAULT_NIC_RX_WTHRESH  4
#endif

#ifndef APP_DEFAULT_NIC_RX_FREE_THRESH
#define APP_DEFAULT_NIC_RX_FREE_THRESH  64
#endif

#ifndef APP_DEFAULT_NIC_RX_DROP_EN
#define APP_DEFAULT_NIC_RX_DROP_EN 0
#endif

/* NIC TX */
#ifndef APP_DEFAULT_NIC_TX_RING_SIZE
#define APP_DEFAULT_NIC_TX_RING_SIZE 1024
#endif

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#ifndef APP_DEFAULT_NIC_TX_PTHRESH
#define APP_DEFAULT_NIC_TX_PTHRESH  36
#endif

#ifndef APP_DEFAULT_NIC_TX_HTHRESH
#define APP_DEFAULT_NIC_TX_HTHRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_WTHRESH
#define APP_DEFAULT_NIC_TX_WTHRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_FREE_THRESH
#define APP_DEFAULT_NIC_TX_FREE_THRESH  0
#endif

#ifndef APP_DEFAULT_NIC_TX_RS_THRESH
#define APP_DEFAULT_NIC_TX_RS_THRESH  0
#endif

/* Software Rings */
#ifndef APP_DEFAULT_RING_RX_SIZE
#define APP_DEFAULT_RING_RX_SIZE 1024
#endif

#ifndef APP_DEFAULT_RING_TX_SIZE
#define APP_DEFAULT_RING_TX_SIZE 1024
#endif

/* Bursts */
#ifndef APP_MBUF_ARRAY_SIZE
#define APP_MBUF_ARRAY_SIZE   512
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_READ
#define APP_DEFAULT_BURST_SIZE_IO_RX_READ  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_READ > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_RX_WRITE  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_TX_READ
#define APP_DEFAULT_BURST_SIZE_IO_TX_READ  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_TX_READ > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_TX_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_TX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_TX_WRITE  144
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_TX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_TX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_WORKER_READ
#define APP_DEFAULT_BURST_SIZE_WORKER_READ  144
#endif
#if ((2 * APP_DEFAULT_BURST_SIZE_WORKER_READ) > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_WORKER_WRITE
#define APP_DEFAULT_BURST_SIZE_WORKER_WRITE  144
#endif
#if (APP_DEFAULT_BURST_SIZE_WORKER_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_WRITE is too big"
#endif

/* Load balancing logic */
#ifndef APP_DEFAULT_IO_RX_LB_POS
#define APP_DEFAULT_IO_RX_LB_POS 29
#endif
#if (APP_DEFAULT_IO_RX_LB_POS >= 64)
#error "APP_DEFAULT_IO_RX_LB_POS is too big"
#endif

struct app_mbuf_array {
	struct rte_mbuf *array[APP_MBUF_ARRAY_SIZE];
	uint32_t n_mbufs;
};

enum app_lcore_type {
	e_APP_LCORE_DISABLED = 0,
	e_APP_LCORE_IO,
	e_APP_LCORE_WORKER
};

struct app_lcore_params_io {
	/* I/O RX */
	struct {
		/* NIC */
		struct {
			uint8_t port;
			uint8_t queue;
		} nic_queues[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint32_t n_nic_queues;

		/* Rings */
		struct rte_ring *rings[APP_MAX_WORKER_LCORES];
		uint32_t n_rings;

		/* Internal buffers */
		struct app_mbuf_array mbuf_in;
		struct app_mbuf_array mbuf_out[APP_MAX_WORKER_LCORES];
		uint8_t mbuf_out_flush[APP_MAX_WORKER_LCORES];

		/* Stats */
		uint32_t nic_queues_count[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint32_t nic_queues_iters[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint32_t rings_count[APP_MAX_WORKER_LCORES];
		uint32_t rings_iters[APP_MAX_WORKER_LCORES];
	} rx;

	/* I/O TX */
	struct {
		/* Rings */
		struct rte_ring *rings[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];

		/* NIC */
		uint8_t nic_ports[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
		uint32_t n_nic_ports;

		/* Internal buffers */
		struct app_mbuf_array mbuf_out[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
		uint8_t mbuf_out_flush[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];

		/* Stats */
		uint32_t rings_count[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];
		uint32_t rings_iters[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];
		uint32_t nic_ports_count[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
		uint32_t nic_ports_iters[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
	} tx;
};

struct app_lcore_params_worker {
	/* Rings */
	struct rte_ring *rings_in[APP_MAX_IO_LCORES];
	uint32_t n_rings_in;
	struct rte_ring *rings_out[APP_MAX_NIC_PORTS];

	/* LPM table */
	struct rte_lpm *lpm_table;
	uint32_t worker_id;

	/* Internal buffers */
	struct app_mbuf_array mbuf_in;
	struct app_mbuf_array mbuf_out[APP_MAX_WORKER_LCORES];
	uint8_t mbuf_out_flush[APP_MAX_NIC_PORTS];

	/* Stats */
	uint32_t rings_in_count[APP_MAX_IO_LCORES];
	uint32_t rings_in_iters[APP_MAX_IO_LCORES];
	uint32_t rings_out_count[APP_MAX_NIC_PORTS];
	uint32_t rings_out_iters[APP_MAX_NIC_PORTS];

	/* ip fragment */
	struct rte_ip_frag_tbl *frag_tbl;
	struct rte_ip_frag_death_row frag_dr;

	/* connction */
	struct app_conn_tbl *conn_tbl;
//	struct rte_conn_death_row conn_dr;

	/* conn_tab */
	//struct list_head *app_conn_tab;
	//uint8_t *app_conn_tab;
	struct rte_timer app_timer;


};


struct app_lcore_params {
	union {
		struct app_lcore_params_io io;
		struct app_lcore_params_worker worker;
	};
	enum app_lcore_type type;
	struct rte_mempool *pool;
} __rte_cache_aligned;

struct app_lpm_rule {
	uint32_t ip;
	uint8_t depth;
	uint8_t if_out;
};

struct app_params {
	/* lcore */
	struct app_lcore_params lcore_params[APP_MAX_LCORES];

	/* NIC */
	uint8_t nic_rx_queue_mask[APP_MAX_NIC_PORTS][APP_MAX_RX_QUEUES_PER_NIC_PORT];
	uint8_t nic_tx_port_mask[APP_MAX_NIC_PORTS];

	/* mbuf pools */
	struct rte_mempool *pools[APP_MAX_SOCKETS];

	/* LPM tables */
	struct rte_lpm *lpm_tables[APP_MAX_SOCKETS];
	struct app_lpm_rule lpm_rules[APP_MAX_LPM_RULES];
	uint32_t n_lpm_rules;

	/* rings */
	uint32_t nic_rx_ring_size;
	uint32_t nic_tx_ring_size;
	uint32_t ring_rx_size;
	uint32_t ring_tx_size;

	/* burst size */
	uint32_t burst_size_io_rx_read;
	uint32_t burst_size_io_rx_write;
	uint32_t burst_size_io_tx_read;
	uint32_t burst_size_io_tx_write;
	uint32_t burst_size_worker_read;
	uint32_t burst_size_worker_write;

	/* load balancing */
	//uint8_t pos_lb;

	/* ip list */
	radix_tree_t *ip_list;


	/* mq */
	int msgid;
} __rte_cache_aligned;

/*
 *      TCP State Values
 */
enum {
	APP_TCP_S_NONE = 0,
	APP_TCP_S_ESTABLISHED,
	APP_TCP_S_SYN_SENT,
	APP_TCP_S_SYN_RECV,
	APP_TCP_S_FIN_WAIT,
	APP_TCP_S_TIME_WAIT,
	APP_TCP_S_CLOSE,
	APP_TCP_S_CLOSE_WAIT,
	APP_TCP_S_LAST_ACK,
	APP_TCP_S_LISTEN,
	APP_TCP_S_SYNACK,
	APP_TCP_S_LAST
};

/*
 *	UDP State Values
 */
enum {
	APP_UDP_S_NORMAL,
	APP_UDP_S_LAST,
};

/*
 *	ICMP State Values
 */
enum {
	APP_ICMP_S_NORMAL,
	APP_ICMP_S_LAST,
};


extern struct app_params app;

int app_parse_args(int argc, char **argv);
void app_print_usage(char *prog);
void app_init(void);
int app_lcore_main_loop(void *arg);

int app_get_nic_rx_queues_per_port(uint8_t port);
int app_get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
int app_get_lcore_for_nic_tx(uint8_t port, uint32_t *lcore_out);
int app_is_socket_used(uint32_t socket);
uint32_t app_get_lcores_io_rx(void);
uint32_t app_get_lcores_worker(void);
void app_print_params(void);


void process_mbuf(struct app_lcore_params_worker *lp, struct rte_mbuf *pkt, uint64_t tms);
void app_worker_counter_reset(uint32_t lcore_id, 
		struct app_lcore_params_worker *lp_worker);

#ifndef  NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif 

#endif /* _MAIN_H_ */
