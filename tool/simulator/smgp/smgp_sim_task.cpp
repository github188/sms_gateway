#include "smgp_sim_task.h"
#include "smgp_sim_biz.h"

extern int      g_client_fd;
extern long     g_cnt;
extern dlist_t *g_phonelist;

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
            int acc_fd = accept_client(pcon);
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
            g_exit = 1;
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
                g_exit = 1;
            }
        }

        if(buf->data_len == 0)
        {
            dlist_delete_by_node(write, item, DLIST_DONOT_FREE_DATA);
        }
    }
    return 0;
}

int time_task(dlist_t *write)
{
    if ( write == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }
    char outbuf[MAX_PACKET_LEN];
    dlist_entry_t *item = NULL;
    list_for_each(item, g_phonelist->head, g_phonelist->tail)
    {
        phone_info_t *pInfo = (phone_info_t*)item->data;
        if(pInfo == NULL)
        {
            LOG_ERROR("pInfo is null\n");
            continue;
        }

        //组状态报告包
        connection_t *pcon = g_con[g_client_fd].con;
        if (pcon == NULL)
        {
            LOG_ERROR("pcon is null!\n");
            return -1;
        }

        //取缓冲区指针
        buffer_t * pbuffer = pcon->sndbuf;
        int freesize = pbuffer->get_free_size(pbuffer);
        char* writeptr = pbuffer->get_write_ptr(pbuffer);

        //报文体
        smgp_body_deliver_req_t req;

        //报文体赋值
        strncpy(req.MsgId,pInfo->msg_id.c_str(),sizeof(req.MsgId));
        req.IsReport = 0x01;
        strncpy(req.DestTermId,pInfo->src_phone.c_str(),sizeof(req.DestTermId));
        strncpy(req.SrcTermId,pInfo->dest_phone.c_str(),sizeof(req.SrcTermId));

        strncpy(req.deliverMessage.MsgId,pInfo->msg_id.c_str(),sizeof(req.MsgId));
        strcpy(req.deliverMessage.Stat,"DELIVRD");

        //报文体序列化
        int body_len = g_smgp.make_deliver_req(outbuf, req);
        if( body_len <= 0 )
        {
            LOG_ERROR("make_deliver_req fail.\n");
            return -1;
        }
        //报文头
        smgp_header_t hdr;
        hdr.RequestId = CMPP_DELIVER;
        hdr.SequenceId = g_cnt;
        hdr.PacketLength = body_len + SMGP_HEADER_LENGTH;

        if( freesize < (int)hdr.PacketLength )
        {
            break;
        }

        g_smgp.make_header(&hdr,writeptr,SMGP_HEADER_LENGTH);
        //拷贝报文体
        memcpy(writeptr + SMGP_HEADER_LENGTH, outbuf, body_len);

        //设置缓冲区游标
        pbuffer->set_write_size(pbuffer, hdr.PacketLength);

        dlist_insert_tail(write, pcon);
        
        //回复了状态报告就删除了
        dlist_delete_by_node(g_phonelist, item, DLIST_FREE_DATA);
    }
    
    return 0;
}