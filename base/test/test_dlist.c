#include <stdio.h>

#include "dlist.h"

int main()
{
    dlist_t *list = dlist_create();
    if(NULL == list)
    {
        printf("dlist create failed.\n");
        return -1;
    }

    printf("dlist len = %d\n", list->len);

    const char* p1 = "ddddddddddddd";

    dlist_insert(list, (void*)p1);

    dlist_entry_t *item = NULL;

    list_for_each(item, list->head, list->tail)
    {
        printf("list_for_each:%s\n", (char*)item->data);
    }

    dlist_delete_all(list, DLIST_DONOT_FREE_DATA);
    dlist_destroy(list);

    return 0;
    /* aaaa  */
}


