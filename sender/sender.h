/* 
 * yubo@xiaomi.com
 * 2015-06-24
 */

#ifndef _SENDER_H_
#define _SENDER_H_

#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <netinet/in.h>

#define SND_BROKERS "10.106.201.44:21500,10.106.201.45:21500,10.106.201.46:21500"
#define SND_TOPIC "uaq"
#define SND_COMPRESSION "snappy" 
#define SND_MSG_TYPE_UAQ 1
#define SND_MSG_KEY 0x3019


typedef struct {
	uint16_t protocol;
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint32_t rx_pkgs;
	uint32_t tx_pkgs;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint32_t conn_time;
	uint32_t req_time;
	uint32_t rsp_time;
	uint16_t http_stat_code;
}uaq_t;

typedef struct {
	long mtype;
	uaq_t u;
}msg_uaq_t;

#ifndef  NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif 

#endif
