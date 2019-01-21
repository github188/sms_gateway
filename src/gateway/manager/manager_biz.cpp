#include "manager_db.h"
#include "manager_biz.h"
#include "gateway_util.h"
#include <json/json.h>

int handle_packet( connection_t *con )
{
    // 1. 参数合法性检查
	if ( con == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }

    int ret = 0;
    
	// 2. 从读缓存中读出数据
    buffer_t *rcvbuf = con->rcvbuf;
    if (rcvbuf == NULL)
    {
        LOG_ERROR("rcvbuf is null!\n");
        return -1;
    }
    const char* readptr = rcvbuf->get_read_ptr(rcvbuf);
    int datalen = rcvbuf->get_data_size(rcvbuf);

    // 3. 解析报文头
    message_head_t hdr;
    if (parse_header(readptr, datalen, &hdr) != 0)
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }
    char pbuf[MAX_PACKET_LEN];
    memcpy(pbuf, readptr, hdr.length);
    rcvbuf->set_read_size(rcvbuf, hdr.length);

    //更新通道心跳时间
    dlist_entry_t *item = NULL;
    list_for_each(item, g_channel_info->head, g_channel_info->tail)
    {
        channel_info_t  *info = (channel_info_t*)item->data;
        if(info == NULL)
        {
            LOG_ERROR("info is null\n");
            continue;
        }
        if( con->fd == info->fd )
        {
            info->heartbeat_time = get_utc_miliseconds();
            break;
        }
    }

    // 4. 根据命令码，处理各种报文
    switch(hdr.command)
    {
    case CMD_HEARTBEAT_REQ:// 心跳请求
        {
            ret = handle_heartbeat_req(&hdr, pbuf + PROTOCOL_HEADER_LENGTH, hdr.length - PROTOCOL_HEADER_LENGTH,con);
        }
        break;
    case CMD_SVR_REG_REQ: //注册请求
        {
            ret = handle_svr_reg_req(&hdr, pbuf + PROTOCOL_HEADER_LENGTH, hdr.length - PROTOCOL_HEADER_LENGTH,con);
        }
        break;
	case CMD_CHANNEL_MGR_RSP: //通道参数变更应答
		{
			ret = handle_channel_update_rsp(&hdr, pbuf + PROTOCOL_HEADER_LENGTH, hdr.length - PROTOCOL_HEADER_LENGTH);
		}
		break;
	default:
	    {
    		LOG_ERROR("unknown command : 0x%x\n", hdr.command);
    	    ret = -1;
    		break;
        }
    }

    return ret;
}

// 处理心跳请求包
int handle_heartbeat_req(message_head_t* hdr, const char* data, int len, connection_t *pcon)
{
    HeartBeatReq req;
    if (parse_msg(data, len, &req) != 0)
    {
        LOG_ERROR("parse HeartBeatReq failed.\n");
        return -1;
    }
    dump(hdr, &req);
    
    LOG_INFO("heartbeat! sid=[%s]fd=[%d]\n",req.sid().c_str(),pcon->fd);

    HeartBeatRsp rsp;
    rsp.set_sid(req.sid());

    if (make_rsp(hdr, &rsp, pcon) != 0)
    {
        LOG_ERROR("make HeartBeatRsp failed.\n");
        return -1;
    }

    dump(hdr, &rsp);
    
    return 0;
}

//处理注册请求包
int handle_svr_reg_req(message_head_t* hdr, const char* data, int len, connection_t *pcon)
{
    SvrRegReq req;
    if (parse_msg(data, len, &req) != 0)
    {
        LOG_ERROR("parse SvrRegReq failed.\n");
        return -1;
    }
    dump(hdr, &req);
    
    LOG_INFO("SvrRegReq! sid=[%s]ProtocolType[%s]ChannelId[%s]fd[%d]\n",
                        req.sid().c_str(),
                        req.protocoltype().c_str(),
                        req.channelid().c_str(),
                        pcon->fd);
    
    //加入注册列表
    dlist_entry_t *item = NULL;
    list_for_each(item, g_channel_info->head, g_channel_info->tail)
    {
        channel_info_t  *info = (channel_info_t*)item->data;
        if(info == NULL)
        {
            LOG_ERROR("info is null\n");
            continue;
        }
        if( (info->channel_type == req.protocoltype()) && 
            (info->channel_id == req.channelid()) )
        {
            info->fd = pcon->fd;
            info->heartbeat_time = get_utc_miliseconds();
            break;
        }
    }
    
    //回复注册请求报文
    SvrRegRsp rsp;
    rsp.set_sid(req.sid());
    rsp.set_retcode(0);

    if (make_rsp(hdr, &rsp, pcon) != 0)
    {
        LOG_ERROR("make SvrRegRsp failed.\n");
        return -1;
    }
    
    return 0;
}

//通道参数变更应答包
int handle_channel_update_rsp(message_head_t* hdr, const char* data, int len)
{
    ChannelMgrRsp rsp;
    if (parse_msg(data, len, &rsp) != 0)
    {
        LOG_ERROR("parse ChannelMgrRsp failed.\n");
        return -1;
    }
    dump(hdr, &rsp);

    LOG_INFO("ChannelMgrRsp! sid=[%s]retcode[%d]]\n",
                        rsp.sid().c_str(),
                        rsp.retcode());

	return 1;
}

// 增加通道
int add_channel(string channel_id,string channel_info)
{
    if( channel_id.empty() || channel_info.empty() )
    {
        return -1;
    }
    
    channel_info_t  *pInfo = new channel_info_t;
    if( pInfo == NULL )
    {
        return -1;
    }
    pInfo->fd = 0;
    pInfo->pid = 0;
    pInfo->heartbeat_time = 0L;
    pInfo->channel_id = channel_id;

    Json::Reader jsonReader;
    Json::Value jsonValue;
    if (!jsonReader.parse(channel_info, jsonValue))
    {
        LOG_ERROR("Parse the channel json is failure.The channelid:%s.", channel_id.c_str());
        return -1;
    }

    uint32_t channel_type = jsonValue["sc_proto_type"].asUInt();
    if ( channel_type == 0 )
    {
        pInfo->channel_type = CMPP2_CHANNEL_TYPE;
    } 
    else if( channel_type == 1 )
    {
        pInfo->channel_type = SGIP_CHANNEL_TYPE;
    }
    else if( channel_type == 2 )
    {
        pInfo->channel_type = SMGP_CHANNEL_TYPE;
    }
    else if( channel_type == 3 )
    {
        pInfo->channel_type = HTTP_CHANNEL_TYPE;
    }
    else if( channel_type == 4 )
    {
        pInfo->channel_type = CMPP3_CHANNEL_TYPE;
    }
    else
    {
        LOG_WARN("unknown channel type.type[%u]\n",channel_type);
        return -1;
    }

    pInfo->channel_name = jsonValue["sc_channel_name"].asString();

    dlist_insert_tail(g_channel_info, pInfo);

    return 0;
}

//更新通道
int update_channel(string channel_id,dlist_t *write)
{
    if( channel_id.empty() || write == NULL )
    {
        return -1;
    }

    //寻出通道对应的fd
    int client_fd = 0;
    string channel_type;
    dlist_entry_t *item = NULL;
    list_for_each(item, g_channel_info->head, g_channel_info->tail)
    {
        channel_info_t  *info = (channel_info_t*)item->data;
        if(info == NULL)
        {
            LOG_ERROR("info is null\n");
            continue;
        }

        if( info->channel_id.compare(channel_id) == 0 )
        {
            if( info->fd > 0 )
            {
                client_fd = info->fd;
                channel_type = info->channel_type;
            }
            break;
        }
    }

    //组更新包
    if( client_fd > 0 )
    {
        connection_t *con = g_con[client_fd].con;
        if (con == NULL)
        {
            LOG_ERROR("con is null!\n");
            return -1;
        }
        message_head_t hdr;
        make_default_header(&hdr, 0, 0);
        hdr.command = CMD_CHANNEL_MGR_REQ;
        
        char szSessionID[64];
        memset(szSessionID,0,sizeof(szSessionID));
        get_sid_str(0,szSessionID,sizeof(szSessionID));
    
        ChannelMgrReq req;
        req.set_sid(szSessionID);
        req.set_mgrtype(1);//0 启用通道; 1 修改通道参数; 2 禁用通道
        req.set_channelid(channel_id);
        if (make_req(&hdr, &req, con) < 0)
        {
            LOG_ERROR("make ChannelMgrReq failed.\n");
            return -1;
        }
        dlist_insert_tail(write, con);
    }

    return 0;
}

// 删除通道
int delete_channel(string channel_id,dlist_t *write)
{
    if( channel_id.empty() || write == NULL )
    {
        return -1;
    }

    //寻出通道对应的fd
    int client_fd = 0;
    string channel_type;
    dlist_entry_t *item = NULL;
    list_for_each(item, g_channel_info->head, g_channel_info->tail)
    {
        channel_info_t  *info = (channel_info_t*)item->data;
        if(info == NULL)
        {
            LOG_ERROR("info is null\n");
            continue;
        }

        if( info->channel_id.compare(channel_id) == 0 )
        {
            if( info->pid > 0 )
            {
                //杀死子进程
                kill(info->pid, SIGTERM);
                //等待子进程退出，防止僵尸进程
                waitpid(info->pid, NULL, 0);
                info->pid = 0;
            }
            else
            {
                if( info->fd > 0 )
                {
                    client_fd = info->fd;
                    channel_type = info->channel_type;
                }
            }
            //从队列中删除掉
            dlist_delete_by_node(g_channel_info, item, DLIST_FREE_DATA);
            break;
        }
    }

    //组退出包
    if( client_fd > 0 )
    {
        connection_t *con = g_con[client_fd].con;
        if (con == NULL)
        {
            LOG_ERROR("con is null!\n");
            return -1;
        }
        message_head_t hdr;
        make_default_header(&hdr, 0, 0);
        hdr.command = CMD_CHANNEL_MGR_REQ;
        
        char szSessionID[64];
        memset(szSessionID,0,sizeof(szSessionID));
        get_sid_str(0,szSessionID,sizeof(szSessionID));
    
        ChannelMgrReq req;
        req.set_sid(szSessionID);
        req.set_mgrtype(2);//0 启用通道; 1 修改通道参数; 2 禁用通道
        req.set_channelid(channel_id);
        if (make_req(&hdr, &req, con) < 0)
        {
            LOG_ERROR("make ChannelMgrReq failed.\n");
            return -1;
        }
        dlist_insert_tail(write, con);
    }

    return 0;
}

//程序异常退出告警信息
int send_exit_alarm_msg(int pid,string channel)
{
    string sTemplateParam,sTime;
    char error_msg[128] = {0};
    snprintf(error_msg,sizeof(error_msg),"网关程序[%d]异常退出",pid);

    sTime = MakeDateTime();
    sTemplateParam = "{\"pid\":\"";
    sTemplateParam += to_string(pid);
    sTemplateParam += "\",\"time\":\"";
    sTemplateParam += sTime;
    sTemplateParam += "\",\"channel\":\"";
    sTemplateParam += channel;
    sTemplateParam += "\"}";

    Json::FastWriter jsonWriter;
    Json::Value jsonValue;
    jsonValue["modle_name"] = Json::Value("gateway");
    jsonValue["level"] = Json::Value(5);
    jsonValue["error_msg"] = Json::Value(error_msg);
    jsonValue["sms_template_id"] = Json::Value(g_conf.template_id);
    jsonValue["sms_template_param"] = Json::Value(sTemplateParam);
    jsonValue["send_time"] = Json::Value(sTime);

    string json_msg = jsonWriter.write(jsonValue);

    save_alarm_msg(json_msg);

    return 0;
}
