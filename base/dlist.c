#include <string.h>
#include <stdlib.h>

#include "compiler.h"
#include "dlist.h"
#include "logger.h"


dlist_t *dlist_create()
{
    dlist_t *list = (dlist_t*)malloc(sizeof(dlist_t));
    if(unlikely(NULL == list))
        goto MALLOC_FAILED;

    list->head = (dlist_entry_t*)malloc(sizeof(dlist_entry_t));
    if(unlikely(NULL == list->head))
        goto MALLOC_FAILED;
    list->head->prev = list->head->next = NULL;
    list->head->data = NULL;

    list->tail = (dlist_entry_t*)malloc(sizeof(dlist_entry_t));
    if(unlikely(NULL == list->tail))
        goto MALLOC_FAILED;
    list->tail->prev = list->tail->next = NULL;
    list->tail->data = NULL;

    list->head->next = list->tail;
    list->tail->prev = list->head;

    list->len = 0;

    return list;

MALLOC_FAILED:

    LOG_ERROR("in init_dlist, malloc failed.\n");

    if(list)
    {
        if(list->head)
            free(list->head);

        free(list);
    }

    return NULL;
}

int dlist_insert(dlist_t *list, void *data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("point is NULL.\n");
        return -1;
    }

    dlist_entry_t *item = (dlist_entry_t*)malloc(sizeof(dlist_entry_t)); 
    if (unlikely(NULL == item))
    {
        LOG_ERROR("malloc failed.\n");
        return -1;
    }

    /*memset(item, 0, sizeof(struct dlist));*/
    item->next = NULL;
    item->prev = NULL;
    item->data = data;

    list->head->next->prev = item;
    item->prev = list->head;
    item->next = list->head->next;
    list->head->next = item;

    list->len++;

    return 0;
}

int dlist_insert_tail(dlist_t *list, void *data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("point is NULL.\n");
        return -1;
    }

    dlist_entry_t *item = (dlist_entry_t*)malloc(sizeof(dlist_entry_t)); 
    if (unlikely(NULL == item))
    {
        LOG_ERROR("dlist_insert_tail:malloc item failed\n");
        return -1;
    }

    item->next = NULL;
    item->prev = NULL;
    item->data = data;

    list->tail->prev->next = item;
    item->next = list->tail;
    item->prev = list->tail->prev;
    list->tail->prev = item;

    list->len++;

    return 0;
}

int dlist_find_insert_from_tail(dlist_t *list, void *data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("point is NULL.\n");
        return -1;
    }

    if (dlist_find_from_tail(list, data) == 0)
    {
        LOG_DEBUG("dlist_find_from_tail same\n");
        return 0;
    }

    return dlist_insert_tail(list, data);
}

int dlist_delete(dlist_t *list, void *data, int is_free_data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("point is NULL.\n");
        return -1;
    }

    dlist_entry_t *item = NULL;
    list_for_each(item, list->head, list->tail)
    {
        if (data == item->data)
        {
            item->prev->next = item->next;
            item->next->prev = item->prev;
            list->len--;

            if(is_free_data == DLIST_FREE_DATA && item->data)
            {
                free(item->data);
                item->data = NULL;
            }

            free(item);
            item = NULL;
            
            return 0;
        }
    }

    LOG_WARN("data not found.\n");
    return -1;
}

int dlist_delete_by_node(dlist_t *list, dlist_entry_t *node, int is_free_data)
{
    if(unlikely(NULL == list || NULL == node))
    {
        LOG_ERROR("pointer is NULL.\n");
        return -1;
    }

    if(node == list->head || node == list->tail)
    {
        LOG_ERROR("can't delete head and tail.\n");
        return -1;
    }
    dlist_entry_t *item = NULL;
    list_for_each(item, list->head, list->tail)
    {
        if (node == item)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->len--;

            if(DLIST_FREE_DATA == is_free_data && node->data)
                free(node->data);

            free(node);

            break;
        }
    }
    return 0;
}

/*
 * WARRING:
 *  This function begin with '__', means you REALLY know what the function do.
 */
int __dlist_delete_by_node(dlist_t *list, dlist_entry_t *node, int is_free_data)
{
    if(unlikely(NULL == list || NULL == node))
    {
        LOG_ERROR("pointer is NULL.\n");
        return -1;
    }

    node->prev->next = node->next;
    node->next->prev = node->prev;
    list->len--;

    if(DLIST_FREE_DATA == is_free_data && node->data)
        free(node->data);

    free(node);

    return 0;
}

int dlist_delete_all(dlist_t *list, int is_free_data)
{
    if (unlikely(NULL == list))
    {
        LOG_ERROR("point is NULL.\n");
        return -1;
    }

    dlist_entry_t *item = NULL;
    for(item = list->head->next; item != list->tail; )
    {
        item->prev->next = item->next;
        item->next->prev = item->prev;
        list->len--;

        dlist_entry_t *tmp = item->next;

        if(is_free_data == DLIST_FREE_DATA && item->data)
        {
            free(item->data);
            item->data = NULL;
        }

        free(item); 

        item = tmp;
    }

    return 0;
}

int dlist_delete_from_tail(dlist_t *list, void *data, int is_free_data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("point is NULL.\n");
        return -1;
    }

    dlist_entry_t *item = NULL;

    for(item = list->tail->prev; item != list->head; item = item->prev)    
    {
        if (data == item->data)
        {
            item->prev->next = item->next;
            item->next->prev = item->prev;
            list->len--;
            
            if(is_free_data == DLIST_FREE_DATA && item->data)  
            {
                free(item->data);
                item->data = NULL;
            }

            free(item);
            item = NULL;

            return 0;
        }
    }

    LOG_WARN("data not found.\n");
    return -1;
}

int dlist_find(dlist_t *list, void *data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("dlist_find:pointer is NULL\n");
        return -1;
    }

    dlist_entry_t *item = NULL;
    list_for_each(item, list->head, list->tail)    
    {
        if (data == item->data)
            return 0;
    }

    return -1;
}

int dlist_find_from_tail(dlist_t *list, void *data)
{
    if (unlikely(NULL == list || NULL == data))
    {
        LOG_ERROR("dlist_find:pointer is NULL\n");
        return -1;
    }

    dlist_entry_t *item = NULL;
    for (item = list->tail->prev; item != list->head; item = item->prev)
    {
        if (data == item->data)
            return 0;
    }

    return -1;
}

int dlist_get_length(dlist_t *list)
{
    if(unlikely(NULL == list))
    {
        LOG_ERROR("dlist_get_length:pointer is NULL\n");
        return -1;
    }

    return list->len;
}

int dlist_destroy(dlist_t *list)
{
    dlist_delete_all(list, DLIST_DONOT_FREE_DATA);

    free(list->head);
    free(list->tail);
    free(list);

    return 0;
}

