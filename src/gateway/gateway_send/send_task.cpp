#include "send_task.h"
#include "send_biz.h"
#include "send_db.h"
#include "send_util.h"

int read_mq_task(dlist_t *read, dlist_t *write, dict* wq)
{
    if ( read == NULL || write == NULL || wq == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    msgform_t mq_msg;
    while( true )
    {
        if( g_connect_fd == 0 )
        {
            LOG_WARN("gateway server is unavailable.\n");
            break;
        }
        //从消息队列里读取数据出来
        int ret = g_mq.read(&mq_msg, sizeof(msgform_t), 1, IPC_NOWAIT);
        if( ret <= 0 )
        {
            //将还没扣减的条数扣减掉
            if( g_phone_size > 0 )
            {
                //扣减发送量
                deduct_remaining(g_phone_size);
                g_phone_size = 0;
            }
            //退出循环
            break;
        }

        message_packet_t packet;
        if( !parse_message(mq_msg.mtext,mq_msg.data_len,&packet) )
        {
            LOG_ERROR("parse_message fail.\n");
            break;
        }

        g_phone_size += packet.mPhoneList.size();
        
        //每隔timeout时间才去写一次redis
        time_t now = get_utc_miliseconds();
		if( ( now - g_conf.last_opr_redis_time ) >= g_channel_conf.uTimeout )
		{
			g_conf.last_opr_redis_time = now;
			//扣减发送量
			deduct_remaining(g_phone_size);
			g_phone_size = 0;
        }
        
        //处理签名
        do_sign(g_channel_conf.uSignType,packet.sMessageContent);
        //组包
        handle_send_msg(write,&packet,wq);
        //发送报文
        write_net_task(write);
        //接收网络报文
        read_net_task(read);
        //处理网络报文
        process_task(read, write,wq);

        //http协议发送完后，需要去拉取状态
        if( g_channel_conf.uProtoType == 3 )
        {
            http_pull_task(read, write, wq);
        }

        //处理信号
        signal_handler();
        //响应kill信号
        if( g_exit )
        {
            break;
        }
    }
    
    return 0;
}

//http拉去状态任务
int http_pull_task(dlist_t *read, dlist_t *write, dict* wq)
{
    if ( read == NULL || write == NULL || wq == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    //组包
    handle_channel_timer_process( write, wq );
    //发送报文
    write_net_task(write);
    //接收网络报文
    read_net_task(read);
    //处理网络报文
    process_task(read, write,wq);

    return 0;
}

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
            g_connect_fd = 0;
            g_is_login_success = 0;
            LOG_DEBUG("connection closed, fd = %d\n", fd);
            poller_del_fd(fd);
            close(fd);
        }
    }
    return 0;
}

int process_task(dlist_t *read, dlist_t *write, dict* wq)
{
    if ( read == NULL || write == NULL || wq == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    if(unlikely(g_biz == NULL)) 
    {
        LOG_ERROR("biz dll pointer is null!\n");
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

        //调用业务库判断报文是否完整
        int ret = g_biz->is_packet_complete(readptr, datalen);
        if( ret < 0 )
        {
            LOG_ERROR("is_packet_complete fatal error.\n");
            dlist_delete_by_node(read, item, DLIST_DONOT_FREE_DATA);
        }
        else
        {
            if( ret > 0 )
            {
                // complete
                ret = handle_packet(con,ret,wq);
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
                g_connect_fd = 0;
                g_is_login_success = 0;
                LOG_DEBUG("connection close. fd=%d\n", con->fd);
                poller_del_fd(con->fd);
                close (con->fd);
                dlist_delete_by_node(write, item, DLIST_DONOT_FREE_DATA);
            }
        }
        //发送数据成功
        if( ret == 0 )
        {
            if( g_channel_conf.uProtoType == 3 )
            {
                //http协议等待时间为180秒
                poller_set_timeout(180000);
            }
            else
            {
                poller_set_timeout(0);
            }
        }
        if(buf->data_len == 0)
        {
            dlist_delete_by_node(write, item, DLIST_DONOT_FREE_DATA);
        }
        if( con->fd == g_connect_fd )
        {
            g_conf.last_heartbeat_time = get_utc_miliseconds();
        }
    }
    return 0;
}

int time_task(dlist_t *write, dict* wq)
{
    if ( write == NULL || wq == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    if ( g_connect_fd > 0 )
    {
        time_t now = get_utc_miliseconds();
        time_t diff = now - g_conf.last_heartbeat_time;
        if ( diff >= g_channel_conf.lHeartbeatInterval )
        {
            //获取登录状态
            g_biz->is_login_success( g_is_login_success );
            //尚未登录
            if( g_is_login_success == 0 )
            {
                //发送登录请求
                handle_channel_login( write );
            }
            else
            {
                //定时任务
                handle_channel_timer_process( write, wq );
            }
        }
    }

    return 0;
}

int timeout_task(dlist_t *read, dlist_t *write, dict* wq)
{
    if ( read == NULL || write == NULL || wq == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }
    if ( g_connect_fd <= 0 )
    {
        //建立连接
        time_t now = get_utc_miliseconds();
        time_t reconn_diff = now - g_conf.last_connect_time;
        if (reconn_diff > g_conf.reconnect_interval * 1000)
        {
            g_conf.last_connect_time = get_utc_miliseconds();
            g_connect_fd = connect_ipv4_serv_buffsize(g_channel_conf.sIpAddress.c_str(),
                                                      g_channel_conf.lPort,
                                                      g_conf.package_buff_size);
            if( g_connect_fd > 0 )
            {
                LOG_INFO("connect channel server[%s:%u] succeful,fd[%d]\n",
                                    g_channel_conf.sIpAddress.c_str(),
                                    g_channel_conf.lPort,
                                    g_connect_fd);
                //登录成功后，发送注册报文
                handle_channel_login( write );
            }
            else
            {
                LOG_ERROR("fail to connect channel server[%s:%u]\n",
                                    g_channel_conf.sIpAddress.c_str(),
                                    g_channel_conf.lPort);
                //重连失败次数递增
                g_reconnect_times++;
                //写连接状态
                handle_channel_status(g_conf.channel_id,-1);
            }
        }
    }
    return 0;
}
