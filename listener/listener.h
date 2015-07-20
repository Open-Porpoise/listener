/* 
 * yubo@xiaomi.com
 * 2015-07-20
 */
#ifndef _LISTENER_H_
#define _LISTENER_H_
#include "conn.h"

extern struct app_protocol app_protocol_tcp; 
extern struct app_protocol app_protocol_udp; 

void prune_queue(struct app_conn_stream * rcv);

int app_register_protocol(struct app_protocol *pp);
struct app_protocol *app_proto_get(unsigned short proto);

void tcpudp_debug_packet_v4(struct app_protocol *pp,
		__attribute__((unused))const struct rte_mbuf *mb,
		struct ipv4_hdr *ih, const char *msg);
void tcpudp_debug_packet(struct app_protocol *pp,
		const struct rte_mbuf *mbuf, void *ip_hdr, 
		const char *msg);
void tcpudp_report_handle(struct app_conn_tbl *tbl, 
		struct app_conn *cp, uint64_t tms);
#endif
