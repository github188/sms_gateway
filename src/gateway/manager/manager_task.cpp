#include "manager_task.h"
#include "protocol.h"
#include "manager_db.h"
#include "manager_biz.h"
#include <json/json.h>

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
    if( g_conf.isAuto == 0 )
    {
        //不启用自动启动通道程序
        return 0;
    }
    dlist_entry_t *item = NULL;
    list_for_each(item, g_channel_info->head, g_channel_info->tail)
    {
        channel_info_t  *info = (channel_info_t*)item->data;
        if(info == NULL)
        {
            LOG_ERROR("info is null\n");
            continue;
        }

        time_t now = get_utc_miliseconds();
        time_t interval = now - info->heartbeat_time;
        if ( interval > ( g_conf.channel_time_out * 1000  ) )
        {
            info->heartbeat_time = get_utc_miliseconds();
            
            LOG_WARN("channel timeout!  [%s][%s][%d]\n",
                info->channel_type.c_str(),
                info->channel_id.c_str(),
                interval/1000);
            //close fd
            if( info->fd > 0 )
            {
                close(info->fd);
                info->fd = 0;
            }
            if( info->pid > 0 )
            {
                //杀死子进程
                kill(info->pid, SIGTERM);
                //等待子进程退出，防止僵尸进程
                waitpid(info->pid, NULL, 0);
                info->pid = 0;
            }
            //fork 子进程
            pid_t pid = 0;
            if((pid = fork()) > 0)// parent
            { 
                LOG_INFO("fork channel. child id=%d\n",pid);
                info->pid = pid;
            }
            else if(pid == 0)// child
            {
                //关闭日志
                log_only_close(g_log);
                
                //执行通道进程
                int ret = execl(g_conf.exe_name,g_conf.exe_name,
                                "-t",info->channel_type.c_str(),
                                "-i",info->channel_id.c_str(),
                                "-c",g_conf.exe_conf,
                                (char*)NULL);
                if(ret == -1)
                {
                    perror("execl");
                    exit(0);
                }
            }
            else
            {
                LOG_ERROR("execl channel failed.\n");
                return -1;
            }
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

    time_t now = get_utc_miliseconds();
    time_t diff = now - g_conf.timing_task_time;
    if ( diff >= g_conf.timing_task_interval * 1000 )
    {
        g_conf.timing_task_time = now;

        string update_info;
        int ret = get_channel_update(update_info);
        if( ret < 0 )
        {
            LOG_ERROR("get_channel_update failed.\n");
            return -1;
        }
        if( ret > 0 )
        {
            //没有数据
            return 0;
        }

        //解析json
        Json::Reader jsonReader;
        Json::Value jsonValue;
        if (!jsonReader.parse(update_info, jsonValue))
        {
            LOG_ERROR("Parse update_info is failure.");
            return -1;
        }

        //通道id
        string channelid = jsonValue["channelid"].asString();
        //操作类型
        string command = jsonValue["command"].asString();

        //判断操作类型
        if( command.compare("add") == 0  )//增加通道
        {
            //根据通道id读取通道列表,如果读取到数据加入循环列表，读取不到数据，直接报错（可能同步数据有问题,同步太慢）。
            string channel_info;
            ret = query_channel_info(channelid.c_str(),channel_info);
            if( ret != 0 )
            {
                LOG_ERROR("query_channel_info failed.\n");
                return -1;
            }
            //加入循环列表
            add_channel(channelid,channel_info);
        }
        else if( command.compare("update") == 0  ) //修改通道
        {
            //根据通道id读取通道列表，发送更新通道报文给发送模块
            string channel_info;
            ret = query_channel_info(channelid.c_str(),channel_info);
            if( ret != 0 )
            {
                LOG_ERROR("query_channel_info failed.\n");
                return -1;
            }
            //发送更新通道报文
            update_channel(channelid,write);
        }
        else if( command.compare("delete") == 0  )//删除通道
        {
            //删除循环列表中该通道。发送退出报文给发送模块，同时杀死该通道子进程。
            delete_channel(channelid,write);
        }
        else
        {
            LOG_ERROR("unknown command.[%s]\n",command.c_str());
        }
    }
    return 0;
}