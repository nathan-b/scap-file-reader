#include <stdint.h>
#include <stdlib.h>

#include "largest_block.h"

const uint32_t NUM_LARGEST = 10;

dl_list insert(uint32_t value, uint32_t data, dl_list list)
{
	dl_list_node* curr = list.head, *tail = list.tail;
	dl_list_node* new_node = NULL;

	// See if we even need to insert
	if (list.count >= NUM_LARGEST && tail->value > value)
	{
		return list;
	}

	// Build the new node
	new_node = (dl_list_node*)malloc(sizeof(*new_node));
	new_node->prev = new_node->next = NULL;
	new_node->value = value;
	new_node->data = data;

	/* Do the insertion */

	// Special case -- empty list
	if (list.count == 0 || !list.head)
	{
		list.head = list.tail = new_node;
		list.count = 1;
		return list;
	}

	// Special case -- insert at head
	if (list.head && value > list.head->value)
	{
		new_node->next = list.head;
		list.head->prev = new_node;
		list.head = new_node;
		++list.count;
	}

	// Special case -- insert at tail
	else if (list.tail && value <= list.tail->value)
	{
		new_node->prev = list.tail;
		list.tail->next = new_node;
		list.tail = new_node;
		++list.count;
	}

	// Insert in the middle
	else
	{
		for (curr = list.head; curr && curr != list.tail; curr = curr->next)
		{
			if (curr->value < value)
			{
				new_node->prev = curr->prev;
				new_node->next = curr;
				curr->prev->next = new_node;
				curr->prev = new_node;
				++list.count;
				break;
			}
		}
	}

	// Drop smallest if over count
	while (list.count > NUM_LARGEST + 1)
	{
		dl_list_node* dead = list.tail;
		dead->prev->next = NULL;
		list.tail = dead->prev;
		--list.count;
		free(dead);
	}

	// Return the new list
	return list;
}
