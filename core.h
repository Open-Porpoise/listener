/* 
 * yubo@xiaomi.com
 * 2015-06-09
 */

#ifndef _CORE_H_
#define _CORE_H_
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_dev.h>
#include <rte_alarm.h>
#include <rte_cycles.h>
#include "main.h"



void deal_pkt(struct app_lcore_params_worker *lp, struct rte_mbuf *pkt);

#endif
