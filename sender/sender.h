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

//#define SND_BROKERS "10.106.201.44:21500,10.106.201.45:21500,10.106.201.46:21500"
#define SND_BROKERS "lg-hadoop-kafka01.bj:21500, lg-hadoop-kafka02.bj:21500,lg-hadoop-kafka03.bj:21500, lg-hadoop-kafka04.bj:21500, lg-hadoop-kafka05.bj:21500,lg-hadoop-kafka06.bj:21500, lg-hadoop-kafka07.bj:21500,lg-hadoop-log07.bj:21500"
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
	int32_t conn_time;
	int32_t req_time;
	int32_t rsp_time;
	int32_t round_trip_time;
	int16_t http_stat_code;
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

#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define HIPQUAD	NIPQUAD
#else
#error "Please fix asm/byteorder.h"
#endif /* __LITTLE_ENDIAN */

#endif
