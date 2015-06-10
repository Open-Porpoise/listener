
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/*
 * yubo@xiaomi.com
 * 2015-06-01
 */

#include "radix_tree.h"

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

radix_tree_t *radix_tree_create(void) {
    radix_tree_t  *tree;

    tree = calloc(1, sizeof(radix_tree_t));
    if (tree == NULL)
        return NULL;

    tree->root = calloc(1, sizeof(radix_node_t));
    if (tree->root == NULL) {
		free(tree);
        return NULL;
    }

    tree->root->right = NULL;
    tree->root->left = NULL;
    tree->root->parent = NULL;
    tree->root->value = RADIX_NO_VALUE;

    return tree;
}

int radix32tree_insert(radix_tree_t *tree, uint32_t key, 
		uint32_t mask, uintptr_t value) {
    uint32_t           bit;
    radix_node_t  *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    while (bit & mask) {
        if (key & bit)
            next = node->right;
        else
            next = node->left;

        if (next == NULL)
            break;

        bit >>= 1;
        node = next;
    }

    if (next) {
        if (node->value != RADIX_NO_VALUE)
            return -2;

        node->value = value;
        return 0;
    }

    while (bit & mask) {
        next = calloc(1, sizeof(radix_node_t));
        if (next == NULL) {
            return -1;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = RADIX_NO_VALUE;

        if (key & bit)
            node->right = next;
        else
            node->left = next;

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return 0;
}


int radix32tree_delete(radix_tree_t *tree, 
		uint32_t key, uint32_t mask) {
    uint32_t           bit;
    radix_node_t  *node;

    bit = 0x80000000;
    node = tree->root;

    while (node && (bit & mask)) {
        if (key & bit)
            node = node->right;
        else
            node = node->left;

        bit >>= 1;
    }

    if (node == NULL) 
        return -1;

    if (node->right || node->left) {
        if (node->value != RADIX_NO_VALUE) {
            node->value = RADIX_NO_VALUE;
            return 0;
        }

        return -1;
    }

    for ( ;; ) {
        if (node->parent->right == node) 
            node->parent->right = NULL;
         else 
            node->parent->left = NULL;

		free(node);

        node = node->parent;

        if (node->right || node->left) 
            break;

		if (node->value != RADIX_NO_VALUE) 
            break;

        if (node->parent == NULL) 
            break;
    }

    return 0;
}


uintptr_t radix32tree_find(radix_tree_t *tree, uint32_t key) {
    uint32_t		bit;
    uintptr_t		value;
    radix_node_t  *node;

    bit = 0x80000000;
    value = RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != RADIX_NO_VALUE) 
            value = node->value;

        if (key & bit) 
            node = node->right;
        else 
            node = node->left;
        bit >>= 1;
    }

    return value;
}

static void radix_node_clean(radix_node_t *node){
	if(node->right)	
		radix_node_clean(node->right);
	if(node->left)
		radix_node_clean(node->left);
	free(node);
	node = NULL;
}

void radix_tree_clean(radix_tree_t *tree){
	radix_node_clean(tree->root);
	free(tree);
	tree = NULL;
}


