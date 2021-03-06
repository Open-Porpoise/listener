#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "rdkafka.h"  /* for Kafka driver */
#include "sender.h" 
#include "geolocation.h"


#define BUFF_SIZE 1024
#define _DEBUG

static int msgid;
static uint64_t msg_cnt;
static ips_t *ips;

int main (int argc, char **argv) {
	rd_kafka_topic_t *rkt;
	int partition = RD_KAFKA_PARTITION_UA;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	char errstr[BUFF_SIZE];
	static rd_kafka_t *rk;
	static int run = 1;
	ip_entry *e;
	char pbuf[BUFF_SIZE], *p;
	char *tpl = "{"
		"\"protocol\":\"%s\","
		"\"srcip\":\""NIPQUAD_FMT"\","
		"\"dstip\":\""NIPQUAD_FMT"\","
		"\"src_port\":%u,"
		"\"dst_port\":%u,"
		"\"rx_bytes\":%lu,"
		"\"rx_pkgs\":%u,"
		"\"tx_bytes\":%lu,"
		"\"tx_pkgs\":%u,"
		"\"src_city\":\"%s\","
		"\"src_country\":\"%s\","
		"\"src_isp\":\"%s\","
		"\"src_province\":\"%s\","
		"\"ttc\":\"%d\","
		"\"thc\":\"%d\","
		"\"thr\":\"%d\","
		"\"code\":\"%d\","
		"\"rtt\":\"%d\","
		"\"time\":%u"
		"}";
	size_t msgsize;
	msg_uaq_t mbuf;

	msg_cnt = 0;
	ips = open_ips("ip.txt", GEO_F_ALIAS);
	if(ips == NULL){
		exit(1);
	}


	/* Kafka configuration */
	conf = rd_kafka_conf_new();

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();

	/* Producer config */
	rd_kafka_conf_set(conf, "queue.buffering.max.messages", "500000", NULL, 0);
	rd_kafka_conf_set(conf, "message.send.max.retries", "3", NULL, 0);
	rd_kafka_conf_set(conf, "retry.backoff.ms", "500", NULL, 0);

	/* Consumer config */
	/* Tell rdkafka to (try to) maintain 1M messages
	 * in its internal receive buffers. This is to avoid
	 * application -> rdkafka -> broker  per-message ping-pong
	 * latency.
	 * The larger the local queue, the higher the performance.
	 * Try other values with: ... -X queued.min.messages=1000
	 */
	rd_kafka_conf_set(conf, "queued.min.messages", "1000000", NULL, 0);

	if (rd_kafka_conf_set(conf, "compression.codec",
				SND_COMPRESSION, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", errstr);
		exit(1);
	}

	/* Create Kafka handle */
	if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
					errstr, sizeof(errstr)))) {
		fprintf(stderr,
				"%% Failed to create new producer: %s\n",
				errstr);
		exit(1);
	}

	/* Add brokers */
	if (rd_kafka_brokers_add(rk, SND_BROKERS) == 0) {
		fprintf(stderr, "%% No valid brokers specified\n");
		exit(1);
	}

	/* Create topic */
	rkt = rd_kafka_topic_new(rk, SND_TOPIC, topic_conf);

	rd_kafka_set_log_level(rk, 7);

	if ((msgid = msgget(SND_MSG_KEY, IPC_CREAT|0666)) < 0){
		fprintf(stderr, "msgget error \n");
		exit(1);
	}
	while (run) {
		/* Send/Produce message. */

		if (msgrcv(msgid, &mbuf, sizeof(uaq_t), SND_MSG_TYPE_UAQ, 0) < 0) {
			fprintf(stderr, "msgrcv error \n");
			exit(1);
		}
		msg_cnt++;

#define ALIAS_FILTER(a, b, c, ptr)  \
({                                  \
	ptr = (char *)a; \
	ptr && ptr[0] == b && ptr[1] == c ? &ptr[2] : "-1"; \
})

		e = (ip_entry *)radix32tree_find(ips->tree, mbuf.u.sip);
		msgsize = snprintf(pbuf, BUFF_SIZE, tpl, 
				mbuf.u.protocol == IPPROTO_TCP ? "TCP" : "UDP",
				HIPQUAD(mbuf.u.sip), 
				HIPQUAD(mbuf.u.dip), 
				mbuf.u.sport, 
				mbuf.u.dport,
				mbuf.u.rx_bytes,
				mbuf.u.rx_pkgs,
				mbuf.u.tx_bytes,
				mbuf.u.tx_pkgs,
				(char *)e->city,
				(char *)e->country,
				ALIAS_FILTER(e->isp, 'i', '_', p),       //(char *)e->isp,
				ALIAS_FILTER(e->province, 'p', '_', p),  //(char *)e->province,
				mbuf.u.conn_time,
				mbuf.u.req_time,
				mbuf.u.rsp_time,
				mbuf.u.http_stat_code,
				mbuf.u.round_trip_time,
				time(NULL));

#ifdef _DEBUG
		if((msg_cnt & 0xfff) == 0xfff){
			printf("%s\n", pbuf);
		}
#endif

		while (run && 
				rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY, 
					pbuf, msgsize, NULL, 0, NULL) == -1) {
			if (errno == ESRCH)
				printf("%% No such partition: "
						"%"PRId32"\n", partition);
			else if ((errno != ENOBUFS))
				printf("%% produce error: %s%s\n",
						rd_kafka_err2str( rd_kafka_errno2err( errno)),
						errno == ENOBUFS ?  " (backpressure)":"");

			if (errno != ENOBUFS) {
				run = 0;
				break;
			}
			/* Poll to handle delivery reports */
			rd_kafka_poll(rk, 10);
		}

		/* Must poll to handle delivery reports */
		rd_kafka_poll(rk, 0);
	}

	rd_kafka_dump(stdout, rk);

	/* Wait for messages to be delivered */
	while (run && rd_kafka_poll(rk, 1000) != -1)
		;

	int outq = rd_kafka_outq_len(rk);
	printf("%% %i messages in outq\n", outq);

	rd_kafka_dump(stdout, rk);

	/* Destroy topic */
	rd_kafka_topic_destroy(rkt);

	/* Destroy the handle */
	rd_kafka_destroy(rk);
	clean_ips(ips);

	return 0;

#if 0
	/* Send/Produce message. */
	if (rd_kafka_produce(rkt, partition,
				RD_KAFKA_MSG_F_COPY,
				/* Payload and length */
				buf, len,
				/* Optional key and its length */
				NULL, 0,
				/* Message opaque, provided in
				 * delivery report callback as
				 * msg_opaque. */
				NULL) == -1) {
		fprintf(stderr,
				"%% Failed to produce to topic %s "
				"partition %i: %s\n",
				rd_kafka_topic_name(rkt), partition,
				rd_kafka_err2str(
					rd_kafka_errno2err(errno)));
	}

	/* Wait for messages to be delivered */
	while (rd_kafka_outq_len(rk) > 0)
		usleep(50000);

	/* Destroy topic */
	rd_kafka_topic_destroy(rkt);
	/* Destroy the handle */
	rd_kafka_destroy(rk);
#endif
}
