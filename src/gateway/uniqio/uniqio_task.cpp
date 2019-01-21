#include "uniqio_task.h"
#include "protocol.h"
#include "uniqio_biz.h"

int read_net_task(dlist_t *read)
{
    if ( read == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    int evs = poller_do_poll();
    if (evs == 0) 
    {
        return -1;
    }

    //循环处理EPOLL事件
    ev_events_t *events = poller_get_events();
    for (int i = 0; i < evs; i++)
    {
        int fd = events[i].fd;
        int type = g_con[fd].type;
        connection_t *pcon = g_con[fd].con;

        if (type == CON_T_LISTEN)
        {
            //int acc_fd = accept_client(pcon);
            int acc_fd = accept_client_buffsize(pcon,g_conf.package_buff_size);
            LOG_DEBUG("accept_client fd = %d\n", acc_fd);
        }
        else if (type == CON_T_SERVER || type == CON_T_CLIENT)
        {
            LOG_DEBUG("recv_data, ip = [%s], port = [%d],  fd = %d\n", 
                inet_ntoa(pcon->proto.remote_addr.addr.ipv4.sin_addr), 
                pcon->proto.remote_addr.addr.ipv4.sin_port, fd);
            int r = recv_data(pcon);
            if (r >= 0)
            {
                if (pcon->rcvbuf->data_len > 0)
                    dlist_insert_tail(read, pcon);
            }
            else
            {
                LOG_ERROR("recv data failed.\n");
            }
        }
        //读取报文时，连接断开
        if (pcon->con_status == CON_S_BROKEN)
        {
            LOG_DEBUG("connection closed, fd = %d\n", fd);
            poller_del_fd(fd);
            close(fd);
        }
    }
    return 0;
}

int process_task(dlist_t *read, dlist_t *write)
{
    if ( read == NULL || write == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    dlist_entry_t *item = NULL;
    list_for_each(item, read->head, read->tail)
    {
        connection_t *con = (connection_t*)item->data;
        if (con == NULL || con->rcvbuf == NULL)
        {
            dlist_delete_by_node(read, item, DLIST_DONOT_FREE_DATA);
            continue;
        }

        buffer_t *rcvbuf = con->rcvbuf;
        const char *readptr = rcvbuf->get_read_ptr(rcvbuf);
        int datalen = rcvbuf->get_data_size(rcvbuf);

        int ret = is_packet_complete(readptr, datalen);
        if(ret < 0 )
        {
            LOG_ERROR("is_packet_complete fatal error.\n");
            dlist_delete_by_node(read, item, DLIST_DONOT_FREE_DATA);
        }
        else
        {
            if(ret > 0)
            {
                // complete
                ret = handle_packet(con);
                if( ret < 0 )
                {
                    // 处理出错，告警
                    LOG_ERROR("handle_packet failed.\n");
                }
                else if ( ret == 0 )
                {
                    // 处理正确，需要返回网络
                    LOG_DEBUG("handle_packet success, put packet in connection.\n");
                    dlist_insert_tail(write, con);
                }
                else
                {
                    // 处理正确，不需要返回网络
                    LOG_DEBUG("handle_packet success, no need to put packet in connection.\n");
                }
            }
        }
        if(rcvbuf->data_len == 0)
        {
            dlist_delete_by_node(read, item, DLIST_DONOT_FREE_DATA);
        }
    }
    return 0;
}

int write_net_task(dlist_t *write)
{
    if ( write == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }
    dlist_entry_t *item;
    list_for_each(item, write->head, write->tail)
    {
        connection_t *con = (connection_t*)item->data;
        if(con == NULL)
        {
            LOG_ERROR("con is null\n");
            continue;
        }

        buffer_t* buf = con->sndbuf;
        int ret = send_data(con);
        if ( ret < 0 )
        {
            LOG_ERROR("send data failed.\n");
            //连接断开
            if( con->con_status == CON_S_BROKEN )
            {
                LOG_DEBUG("connection close. fd=%d\n", con->fd);
                poller_del_fd(con->fd);
                close (con->fd);
                dlist_delete_by_node(write, item, DLIST_DONOT_FREE_DATA);
            }
        }

        if(buf->data_len == 0)
        {
            dlist_delete_by_node(write, item, DLIST_DONOT_FREE_DATA);
        }
    }
    return 0;
}

int timeout_task()
{
    if( g_gateway_dict == NULL )
    {
        return -1;
    }

    //遍历网关信息hash
    dict_iterator* dict_it = dict_get_iterator( g_gateway_dict );
    dict_entry* dict_en = NULL;
    while( ( dict_en = dict_next(dict_it) ) != NULL )
    {
        gateway_info_t *pinfo = (gateway_info_t *)dict_get_entry_val( dict_en );
        if( pinfo == NULL )
        {
            dict_delete(g_gateway_dict, dict_en->key, dict_en->keylen);
            continue;
        }

        time_t now = time(NULL);
        time_t interval = now - pinfo->last_send_time;
        if ( interval >= g_conf.heartbeat_interval )
        {
            LOG_INFO("gateway timeout! fd[%d]channel_type[%s]channel_id[%s]\n",
                                        pinfo->fd,
                                        pinfo->channel_type,
                                        pinfo->channel_id);
            close( pinfo->fd );
            dict_delete( g_gateway_dict, dict_en->key, dict_en->keylen );
        }
    }
    
    dict_release_iterator( dict_it );

    return 0;
}