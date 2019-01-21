#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "tsbase.h"

poller_t *cur_poller = &epoll_poller;
fd_list_t *g_con;
int g_fd_size;

int handle_read(dlist_t *read)
{
    int evs = poller_do_poll();
    if(evs == 0)
        return -1;

    ev_events_t *events = cur_poller->ev;
    for(int i = 0; i < evs; i++)
    {
        int fd = events[i].fd;
        int type = g_con[fd].type;
        connection_t *pcon = g_con[fd].con;

        if(type == CON_T_SERVER || type == CON_T_CLIENT)
        {
            recv_data(pcon);
        }

        if(pcon->con_status == CON_S_BROKEN)
        {
            poller_del_fd(fd);
            close(fd);
        }
    }

    return 0;
}

int process_data(dlist_t* read, dlist_t *write)
{
    dlist_entry_t *item = read->head->next;

    connection_t *con = (connection_t*)item->data;
    buffer_t *rcvbuf = con->rcvbuf;
    buffer_t *sndbuf = con->sndbuf;

    char *writeptr = sndbuf->get_write_ptr(sndbuf);

    int datalen = snprintf(writeptr, 1024, "aaaaaaaaaaaaaaaaaaaa");

    rcvbuf->set_read_size(rcvbuf , 0);
    sndbuf->set_write_size(sndbuf ,datalen);

    dlist_insert_tail(write, con);

    return 0;
}

void handle_write(dlist_t *write)
{
    dlist_entry_t *item;
    list_for_each(item, write->head, write->tail)
    {
        connection_t *con = (connection_t*)item->data;
        send_data(con);
    }

    dlist_delete_all(write, DLIST_DONOT_FREE_DATA);

}

int main(int argc, char* argv[])
{
    g_fd_size = SOCK_DEFAULT_FD_SIZE;
    g_con = (fd_list_t*)malloc(sizeof(fd_list_t) * g_fd_size);

    for(int i = 0; i < g_fd_size; i++)
    {
        g_con[i].con = NULL;
        g_con[i].type = -1;
    }

    poller_ev_init();
    
    int fd = connect_ipv4_serv_buffsize_block("127.0.0.1", 5000, 10240);
    if(fd < 0)
    {
        printf("connect_ipv4_serv failed.\n");
        return -1;
    }

    dlist_t *read = dlist_create();
    dlist_t *write = dlist_create();
   
    dlist_insert_tail(read, g_con[fd].con);

    int i = 0;
    while(i++ < 10)
    {
        handle_read(read);
        process_data(read, write);
        handle_write(write);

        sleep(1);
    }
 
    dlist_delete_all(read, DLIST_DONOT_FREE_DATA);
    dlist_destroy(read);
    dlist_destroy(write);

    poller_del_fd(fd);
    close(fd);
    destroy_fd_con(fd);
    poller_ev_term();
    free(g_con);

}



