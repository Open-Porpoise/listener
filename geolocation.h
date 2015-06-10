/*
 * yubo@yubo.org
 * 2015-06-04
 */
#ifndef _GEOLOCATION_H
#define _GEOLOCATION_H
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "avl.h"
#include "radix_tree.h"

#define DPRINTF(format, ...) fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#define D(format, ...) do { \
	DPRINTF(format, ##__VA_ARGS__); \
} while (0)

#define MAX_CSV_LINE 2774714 
#define MAX_TEXT_SIZE  200000000
#define ALL_ONES (~(uint32_t)0)

typedef struct _ip_entry{
	uint32_t min;
	uint32_t max;
	char min_addr[16];
	char max_addr[16];
	char country[64];
	char province[64];
	char city[64];
	char village[64];
	char isp[64];
	uintptr_t offset;
}_ip_entry;

typedef struct ip_entry{
#ifdef DEBUG
	uint32_t min;
	uint32_t max;
#endif
    uintptr_t country;
    uintptr_t province;
    uintptr_t city;
    uintptr_t village;
    uintptr_t isp;
}ip_entry;


typedef struct ips_t{
	int e_len;
	int t_len;
	char  t[MAX_TEXT_SIZE];
	ip_entry e[MAX_CSV_LINE];
	radix_tree_t *tree;
}ips_t;

typedef struct key_node_t{
	struct avl_node node;
	char *key;
}key_node_t;

char *u32toa(uint32_t u);
char *_u32toa(uint32_t u);
char *__u32toa(uint32_t u);
void dump_ips(ips_t *ips);
ips_t * open_ips(char *filename);
void clean_ips(ips_t *ips);
void print_ip(ips_t *ips, char *ip);
void dump_ips(ips_t *ips);
int radix_insert(radix_tree_t *tree, uint32_t min, int prefix, uintptr_t value);

#endif
