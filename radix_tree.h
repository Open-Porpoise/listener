/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/*
 * yubo@xiaomi.com
 * 2015-06-01
 */

#ifndef _RADIX_TREE_H_INCLUDED_
#define _RADIX_TREE_H_INCLUDED_

#include <stdint.h>
#include <sys/types.h>

#define RADIX_NO_VALUE   (uintptr_t) -1

typedef struct radix_node_s  radix_node_t;

struct radix_node_s {
    radix_node_t  *right;
    radix_node_t  *left;
    radix_node_t  *parent;
    uintptr_t      value;
};


typedef struct radix_tree_t{
    radix_node_t  *root;
} radix_tree_t;


radix_tree_t *radix_tree_create(void);

int radix32tree_insert(radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);

int radix32tree_delete(radix_tree_t *tree,
    uint32_t key, uint32_t mask);

uintptr_t radix32tree_find(radix_tree_t *tree, uint32_t key);

void radix_tree_clean(radix_tree_t *tree);

#endif /* _RADIX_TREE_H_INCLUDED_ */
