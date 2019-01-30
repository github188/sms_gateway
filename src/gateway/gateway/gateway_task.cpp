#include "gateway_task.h"
#include "gateway_biz.h"
#include "gateway_db.h"

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
            LOG_INFO("accept_client fd = %d\n", acc_fd);
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
            LOG_INFO("connection closed, fd = %d\n", fd);
            poller_del_fd(fd);
            close(fd);
            vector<server_info_t>::iterator it = g_conf.server_info.begin();
            for(;it!=g_conf.server_info.end();it++)
            {
                if(it->fd == fd)
                {
                    it->fd = 0;
                    break;
                }
            }
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
        int ret = 0;
        if ( con->con_type == CON_T_SERVER )
        {
            //通道过来的报文
            ret = handle_channel_packet( &con );
        }
        else
        {
            //内部报文
            ret = handle_gateway_packet( &con );
        }
        
        if( ret == -1 )
        {
            // 处理出错，告警
            LOG_ERROR("handle_packet failed.\n");
        }
        else if( ret == -2 )//无效报文
        {
            LOG_ERROR("invalid packet\n");
            rcvbuf->set_read_size(rcvbuf, rcvbuf->data_len);
        }
        else if ( ret == 0 )
        {
            if ( con != NULL ) 
            {
                LOG_DEBUG("handle packet success, put packet in connection.\n");
                dlist_insert_tail(write, con);// 处理正确，需要返回网络
            }
        }
        else 
        {
            // 处理正确，不需要返回网络
            LOG_DEBUG("handle packet success, no need to put packet in connection.\n");
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
                vector<server_info_t>::iterator it = g_conf.server_info.begin();
                for(;it!=g_conf.server_info.end();it++)
                {
                    if(it->fd == con->fd)
                    {
                        it->fd = 0;
                        break;
                    }
                }
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

int timeout_task(dlist_t *read, dlist_t *write)
{
    if( read == NULL || write == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    vector<server_info_t>::iterator it = g_conf.server_info.begin();
    for(;it!=g_conf.server_info.end();it++)
    {
        //尚未建立连接
        if( it->fd <= 0 )
        {
            //建立连接
            time_t now = get_utc_miliseconds();
            time_t reconn_diff = now - it->last_connect_time;
            if (reconn_diff > it->reconnect_interval * 1000)
            {
                it->fd = connect_ipv4_serv_buffsize(it->ip,it->port,g_conf.package_buff_size);
                it->last_connect_time = get_utc_miliseconds();
                it->is_reg = false;
            }
        }
        else // 连接已建立，则发送心跳报文
        {
            connection_t *con = g_con[it->fd].con;
            if (con == NULL)
            {
                LOG_ERROR("con is null!\n");
                return -1;
            }

            time_t now = time(NULL);
            time_t diff = now - con->recv_time;
            if ( diff > it->heartbeat_interval )
            {
                con->recv_time = now;
                
                message_head_t hdr;
                make_default_header(&hdr, 0, 0);
                hdr.command = CMD_HEARTBEAT_REQ;
                
                char szSessionID[64] = {0};
                get_sid_str(0,szSessionID,sizeof(szSessionID));
            
                HeartBeatReq req;
                req.set_sid(szSessionID);
                if (make_req(&hdr, &req, con) < 0)
                {
                    LOG_ERROR("make heartbeat req failed.\n");
                    return -1;
                }
                dlist_insert_tail(write, con);
            }
        }
        //如果连接成功
        if( it->fd > 0 )
        {
            //如果尚未注册，则向服务器发送注册请求
            if( !it->is_reg )
            {
                connection_t *con = g_con[it->fd].con;
                if (con == NULL)
                {
                    LOG_ERROR("con is null!\n");
                    return -1;
                }
                message_head_t hdr;
                make_default_header(&hdr, 0, 0);
                hdr.command = CMD_SVR_REG_REQ;
                
                char szSessionID[64] = {0};
                get_sid_str(0,szSessionID,sizeof(szSessionID));
                
                SvrRegReq req;
                req.set_sid(szSessionID);
                req.set_protocoltype(g_conf.channel_type);
                req.set_channelid(g_conf.channel_id);
                if (make_req(&hdr, &req, con) < 0)
                {
                    LOG_ERROR("make SvrRegReq req failed.\n");
                    return -1;
                }
                dlist_insert_tail(write, con);
                //只发送一次注册报文
                it->is_reg = true;
            }
        }
    }
    return 0;
}
//数据库任务
int db_task()
{
    //定时从redis里取数据处理写入mq
    time_t now = get_utc_miliseconds();
    time_t db_diff = now - g_conf.db_last_read_time;
    if ( db_diff > g_conf.db_interval )
    {
        g_conf.db_last_read_time = get_utc_miliseconds();

        string msg_json;
        int ret = get_channel_msg(g_conf.channel_id,msg_json);
        if( ret < 0 )
        {
            LOG_ERROR("get_channel_msg failed.\n");
            return -1;
        }
        if( ret == 0 ) //通道队列有数据
        {
            poller_set_timeout(0);
            char szSessionID[64] = {0};
            get_sid_str(0,szSessionID,sizeof(szSessionID));

            GateWayMsgSendReq send_req;
            send_req.set_sid(szSessionID);
            map<string,sms_attribute_t> phonelist;
            json_to_msg(msg_json,&send_req,phonelist);

            while( phonelist.size() > 0 )
            {
                g_msgform->mtype = 1L;

                if( g_channel_conf.uMassSupport == 0 )
                {
                    //单发通道只发一个号码
                    get_phone_packet(&phonelist,&send_req,1);
                }
                else
                {
                    //群发通道取最大值
                    uint32_t uMassNum = (g_channel_conf.uMassNum > 0 ) ? g_channel_conf.uMassNum : 30;
                    get_phone_packet(&phonelist,&send_req,uMassNum);
                }
                
                send_req.SerializeToArray(g_msgform->mtext, sizeof(g_msgform->mtext));
                g_msgform->data_len = send_req.ByteSize();
                int mq_len = g_msgform->data_len + sizeof(long);
                //写入mq
                if( g_mq.write(g_msgform, mq_len, IPC_NOWAIT) < 0 )
                {
                    LOG_WARN("write mq failed.len:%d,err:%s\n", mq_len, strerror(errno));
                    string one_msg;
                    msg_to_json(&send_req,one_msg);
                    //mq满了，重写回redis
                    int ret = save_channel_msg( g_conf.channel_id, one_msg );
                    if( ret != 0 )
                    {
                        LOG_ERROR("save_channel_msg failed.\n");
                        break;
                    }
                    //为了避免太多小包
                    sleep(1);
                }
            }
        }
        else
        {
            //通道队列没有数据，epool等待网络事件超时时间为1秒
            poller_set_timeout(1000);
        }
    }
    return 0;
}

int mq_task()
{
    handle_mq_msg();
    return 0;
}
