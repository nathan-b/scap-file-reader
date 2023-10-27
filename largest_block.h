#ifndef LARGEST_BLOCK_H
#define LARGEST_BLOCK_H
#include <stdint.h>

////////////////////////////
// Largest block tracking

typedef struct _dl_ln
{
	uint32_t data;
	uint32_t value;
	struct _dl_ln* prev;
	struct _dl_ln* next;
} dl_list_node;

typedef struct
{
	dl_list_node* head;
	dl_list_node* tail;
	uint32_t count;
} dl_list;

extern dl_list insert(uint32_t value, uint32_t data, dl_list list);

#endif
