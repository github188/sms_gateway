#ifndef __DLIST_H__
#define __DLIST_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    DLIST_FREE_DATA = 1,
    DLIST_DONOT_FREE_DATA = 2,
};

typedef struct dlist_entry_s dlist_entry_t;

struct dlist_entry_s
{
    dlist_entry_t *prev;
    dlist_entry_t *next;
    void *data;
};

typedef struct dlist_s dlist_t;

struct dlist_s
{
    dlist_entry_t *head;
    dlist_entry_t *tail;
    int len;
};


#define list_for_each(pos, head, tail) \
     for (pos = (head)->next; pos != (tail); pos = pos->next)  

#define list_for_each_tail(pos, head, tail) \
     for (pos = (tail)->prev; pos != (head); pos = pos->prev) 

#define list_pop_tail(pos,head,tail)\
	for(pos = (tail)->prev;pos != (head); pos = (tail)->prev)

#define list_pop(pos,head,tail) \
	for(pos = (head)->next; pos != (tail); pos = (head)->next)

dlist_t *dlist_create();

int dlist_destroy(dlist_t *list);

int dlist_insert(dlist_t* list, void *data);

int dlist_insert_tail(dlist_t *list, void *data);

int dlist_find_insert_from_tail(dlist_t *list, void *data);

int dlist_delete(dlist_t *list, void *data, int is_free_data);

int dlist_delete_by_node(dlist_t* list, dlist_entry_t *node, int is_free_data);

int __dlist_delete_by_node(dlist_t* list, dlist_entry_t *node, int is_free_data);

int dlist_delete_from_tail(dlist_t *list, void *data, int is_free_data);

int dlist_delete_all(dlist_t *list, int is_free_data);

int dlist_find(dlist_t *list, void *data);

int dlist_find_from_tail(dlist_t *list, void *data);

int dlist_get_length(dlist_t *list);

#ifdef __cplusplus
}
#endif

#endif

