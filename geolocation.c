#include <unistd.h>  
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "geolocation.h"
#include "avl.h"

char *u32toa(uint32_t u){
	return inet_ntoa((*(struct in_addr*)&u));
}

char *_u32toa(uint32_t u){
	static char buff[16];
	sprintf(buff,"%s", inet_ntoa((*(struct in_addr*)&u)));
	return buff;
}

char *__u32toa(uint32_t u){
	static char buff[16];
	sprintf(buff,"%s", inet_ntoa((*(struct in_addr*)&u)));
	return buff;
}

static int count_righthand_zero_bit(uint32_t number, int bits){
	int i;
	if(number == 0){
		return bits; 
	}
	for(i = 0; i < bits; i++){
		if ((number >> i) % 2 )
			return i;
	}
	return bits;
}

static int get_prefix_length(uint32_t n1, uint32_t n2, int bits){
	int i;
	for(i = 0; i < bits; i++){
		if (n1 >> i == n2 >> i )
			return bits - i;
	}
	return 0;
}

int radix_insert(radix_tree_t *tree, uint32_t min, int prefix, uintptr_t value){
	//radix tree store network byte order
	uint32_t mask = (uint32_t)(0xffffffffu <<(32 - prefix));
	uint32_t addr = min & mask;
	return radix32tree_insert(tree, addr, mask, value);
}


static void set_range(radix_tree_t *tree, uint32_t min, uint32_t max, uintptr_t leaf) {
	// add_min and add_max must be host byte order
	uint32_t _min = min;
	uint32_t current, addend;
	int nbits, prefix;
	while(min <= max){
		nbits = count_righthand_zero_bit(min, 32);
		current = 0;
		while (nbits >= 0) {
			addend = pow(2, nbits) - 1;
			current = min + addend;
			nbits -= 1;
			if (current <= max)
				break;
		}
		prefix = get_prefix_length(min, current, 32);
		radix_insert(tree, _min, prefix, leaf);
		if(current == ALL_ONES)
			break;
		min = current + 1;
		_min = min;
	}
}

static uintptr_t get_key(ips_t *ips, struct avl_tree *tree, char *key){
	char *p = key;
	key_node_t *n;

	//trim key
	if(*key == '"') 
		key++;
	if(*key == '"' || *key == '\0') 
		return 0;
	while(*++p)
		;
	if(*--p == '"')
		*p = '\0';
	if((n = avl_find_element(tree, key, n, node))){
		return (uintptr_t)n->key;
	}else{
		n = calloc(1, sizeof(*n));
		if(n == NULL){
			return 0;
		}

		n->key = ips->t + ips->t_len;
		n->node.key = ips->t + ips->t_len;
		ips->t_len += sprintf(ips->t + ips->t_len, "%s", key);
		ips->t_len++;

		if(avl_insert(tree, &n->node)){
			free(n);
			return 0;
		}

		return (uintptr_t)n->key;
	}
}

static int avl_strcmp(const void *k1, const void *k2,
		__attribute__((unused))void *ptr){
	return strcmp(k1, k2);
}

ips_t * open_ips(char *filename){
	FILE *fp;
	int num;
	char line[1024];
	ips_t *ips;
	_ip_entry _e;
	ip_entry *e;
	struct avl_tree keys;
    struct key_node_t *node, *tmp;

	if((fp = fopen(filename, "r")) == NULL){
		D("fopen %s error\n", filename);
		return NULL;
	}

	ips = calloc(1, sizeof(ips_t));
	if(ips == NULL){
		D("calloc error\n");
		goto out;
	}
	ips->t_len = 1;
	ips->e_len = 0;

	if((ips->tree =  radix_tree_create()) == NULL){
		goto err_alloc_ips;
	}

	// init avl for key
	avl_init(&keys, avl_strcmp, false, NULL);

	for (; fgets(line, sizeof(line), fp);) {
		if(ips->e_len == MAX_CSV_LINE){
			D("MAX_CSV_LINE(%d) not enough\n", MAX_CSV_LINE);
			goto err_alloc_tree;
		}
		e = &ips->e[ips->e_len];
		num = sscanf(line, "%u,%u,%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,\n]", 
				&_e.min, &_e.max, _e.min_addr, _e.max_addr, 
				_e.country, _e.province, _e.city, _e.village, _e.isp);
		if(num < 9 ){
			D("SKIP[%d] %s\n",num, line);
			continue;
		}
		ips->e_len++;

#ifdef DEBUG
		e->min = _e.min;
		e->max = _e.max;
#endif
		e->country  = get_key(ips, &keys, _e.country);
		e->province = get_key(ips, &keys, _e.province);
		e->city     = get_key(ips, &keys, _e.city);
		e->village  = get_key(ips, &keys, _e.village);
		e->isp      = get_key(ips, &keys, _e.isp);
		set_range(ips->tree, _e.min, _e.max, (uintptr_t)e);
	}

out:
	avl_for_each_element_safe(&keys, node, node, tmp) {
	    avl_delete(&keys, &node->node);
	    free(node);
	}
	fclose(fp);
	return ips;

err_alloc_tree:
	avl_for_each_element_safe(&keys, node, node, tmp) {
	    avl_delete(&keys, &node->node);
	    free(node);
	}
	radix_tree_clean(ips->tree);
err_alloc_ips:
	free(ips);
	fclose(fp);
	return NULL;
}

void clean_ips(ips_t *ips){
	radix_tree_clean(ips->tree);
	free(ips);
	ips = NULL;
}

void print_ip(ips_t *ips, char *ip){
	ip_entry *e;
	struct in_addr add;
	inet_aton(ip, &add);
	e = (ip_entry *)radix32tree_find(ips->tree, ntohl(add.s_addr));
	printf("ip[%s], country[%s][%lu], province[%s], city[%s], village[%s], isp[%s]\n", ip,
					(char *)e->country, e->country - (uintptr_t)ips->t, (char *)e->province, (char *)e->city, 
					(char *)e->village, (char *)e->isp );
}

void dump_ips(ips_t *ips){
	if(ips){
#ifdef DEBUG
		int i;
		for(i = 0; i < ips->e_len; i++){
			D("[%d] range(%u, %u) ip(%s, %s) country[%s], province[%s], city[%s], village[%s], isp[%s]\n", 
					i, ips->e[i].min, ips->e[i].max, u32toa(htonl(ips->e[i].min)), _u32toa(htonl(ips->e[i].max)), 
					(char *)ips->e[i].country, (char *)ips->e[i].province, (char *)ips->e[i].city, 
					(char *)ips->e[i].village, (char *)ips->e[i].isp );
		}
#endif
	}
}

 
