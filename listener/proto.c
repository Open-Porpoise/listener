/* 
 * yubo@xiaomi.com
 * 2015-07-20
 */
#include "main.h"
#include "utils.h"
#include "sender.h"

void tcpudp_debug_packet_v4(struct app_protocol *pp,
		__attribute__((unused))const struct rte_mbuf *mb,
		struct ipv4_hdr *ih, const char *msg)
{
	char buf[128];

	if (ih == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else if (ih->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_OFFSET_MASK))
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
				&ih->src_addr, rte_be_to_cpu_16(pptr[0]),
				&ih->dst_addr, rte_be_to_cpu_16(pptr[1]));
	}

	RTE_LOG(DEBUG, USER1, "%s: %s\n", msg, buf);
} 

void tcpudp_debug_packet(struct app_protocol *pp,
		const struct rte_mbuf *mbuf, void *ip_hdr, 
		const char *msg) {  
	//todo add v6
	tcpudp_debug_packet_v4(pp, mbuf, (struct ipv4_hdr *)ip_hdr, msg);
}

static int report_is_empty(struct app_conn *cp){
	if(cp->client.pkts | cp->client.bytes | cp->server.pkts | cp->server.bytes)
		return 0;
	return 1;
}

void tcpudp_report_handle(struct app_conn_tbl *tbl, 
		struct app_conn *cp, uint64_t tms) {
	msg_uaq_t mbuf;

	if(report_is_empty(cp))
		return;

	mbuf.mtype = SND_MSG_TYPE_UAQ;
	mbuf.u.protocol = cp->pp->protocol;
	mbuf.u.sip = rte_be_to_cpu_32(cp->client.key.addr[0]);
	mbuf.u.dip = rte_be_to_cpu_32(cp->client.key.addr[1]);
	mbuf.u.sport = rte_be_to_cpu_16(cp->client.key.port[0]);
	mbuf.u.dport = rte_be_to_cpu_16(cp->client.key.port[1]);
	mbuf.u.rx_pkgs = cp->client.pkts;
	mbuf.u.rx_bytes = cp->client.bytes;
	mbuf.u.tx_pkgs = cp->server.pkts;
	mbuf.u.tx_bytes = cp->server.bytes;
	mbuf.u.ttc = cp->ttc;
	mbuf.u.thc = cp->thc;
	mbuf.u.thr = cp->thr;
	

	if (msgsnd(app.msgid, &mbuf, sizeof(uaq_t), IPC_NOWAIT)){
		APP_CONN_TBL_STAT_UPDATE(&tbl->stat, msg_fail, 1);
	}

	if (tbl->nu_log < 100){
		RTE_LOG(DEBUG, USER1, "%s "NIPQUAD_FMT":%u->"NIPQUAD_FMT":%u"
				" tx_bytes:%lu tx_pkts:%u rx_bytes:%lu rx_pkts:%u"
				" last:%lu tms:%lu time:%lu ttc:%u thc:%u thr:%u\n", 
				cp->pp->name, 
				NIPQUAD(cp->client.key.addr[0]), 
				rte_be_to_cpu_16(cp->client.key.port[0]),
				NIPQUAD(cp->client.key.addr[1]), 
				rte_be_to_cpu_16(cp->client.key.port[1]),
				cp->client.bytes, cp->client.pkts,
				cp->server.bytes, cp->server.pkts, 
				cp->last, tms, ((tms - cp->last) * 1000)/rte_get_tsc_hz(),
				mbuf.u.ttc, mbuf.u.thc, mbuf.u.thr);
		tbl->nu_log ++;
	}

	cp->client.bytes = 0;
	cp->server.bytes = 0;
	cp->client.pkts = 0;
	cp->server.pkts = 0;
	cp->start = tms;
	TAILQ_REMOVE(&tbl->lru, cp, lru);
	TAILQ_INSERT_TAIL(&tbl->lru, cp, lru);

	APP_CONN_TBL_STAT_UPDATE(&tbl->stat, rpt, 1);
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
#if 0
static void udp_conn_expire_handle(struct app_protocol *pp, struct app_conn *cp) {
	if (pp && cp ){
		return;
	}
	return;
}
#endif


/* ########################  PROTOCOL  ################### */
#define APP_PROTO_TAB_SIZE        16  /* must be power of 2 */
#define APP_PROTO_HASH(proto)     ((proto) & (APP_PROTO_TAB_SIZE-1))
static struct app_protocol *app_proto_table[APP_PROTO_TAB_SIZE];

/*                                          
 *  register an protocol               
 */                                         
int app_register_protocol(struct app_protocol *pp)
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

