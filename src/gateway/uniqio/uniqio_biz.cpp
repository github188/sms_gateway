#include "uniqio_db.h"
#include "uniqio_biz.h"
#include "uniqio_util.h"
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

    char *pbuf = (char *)malloc( g_conf.package_buff_size );
    if( pbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for package.\n");
        return -1;
    }
    memcpy(pbuf, readptr, hdr.length);
    rcvbuf->set_read_size(rcvbuf, hdr.length);

    // 4. 根据命令码，处理各种报文
    switch(hdr.command)
    {
    case CMD_HEARTBEAT_REQ:// 心跳请求
        {
            ret = handle_heartbeat_req(&hdr, 
                                       pbuf + PROTOCOL_HEADER_LENGTH, 
                                       hdr.length - PROTOCOL_HEADER_LENGTH,
                                       con);
        }
        break;
    case CMD_SVR_REG_REQ: //注册请求
        {
            ret = handle_svr_reg_req(&hdr, 
                                     pbuf + PROTOCOL_HEADER_LENGTH, 
                                     hdr.length - PROTOCOL_HEADER_LENGTH,
                                     con);
        }
        break;
	case CMD_GATEWAY_MSG_SEND_REQ: //信息发送请求
		{
			ret = handle_gateway_msg_send_req(&hdr, 
                                              pbuf + PROTOCOL_HEADER_LENGTH, 
                                              hdr.length - PROTOCOL_HEADER_LENGTH,
                                              con);
		}
		break;
    case CMD_GATEWAY_MSG_SEND_RSP: //信息发送应答
		{
			ret = handle_gateway_msg_send_rsp(&hdr, 
                                              pbuf + PROTOCOL_HEADER_LENGTH, 
                                              hdr.length - PROTOCOL_HEADER_LENGTH);
		}
		break;
	default:
	    {
    		LOG_ERROR("unknown command : 0x%x\n", hdr.command);
    	    ret = -1;
    		break;
        }
    }

    if( pbuf != NULL )
    {
        free(pbuf);
        pbuf = NULL;
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
        if( pinfo->fd == pcon->fd )
        {
            pinfo->last_send_time = time(NULL);
            break;
        }
    }
    dict_release_iterator( dict_it );

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
    
    //加入注册hash表
    gateway_info_t info;
    info.fd = pcon->fd;
    strcpy(info.channel_id,req.channelid().c_str());
    strcpy(info.channel_type,req.protocoltype().c_str());
    info.last_send_time = time(NULL);
    info.count = 0;

    if( get_gateway_data( g_gateway_dict, req.channelid().c_str() ) != NULL )
    {
        delete_gateway_data( g_gateway_dict, req.channelid().c_str() );
    }
    insert_gateway_data( g_gateway_dict,info );
    
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

//信息发送请求
int handle_gateway_msg_send_req(message_head_t* hdr, const char* data, int len, connection_t *pcon)
{
    GateWayMsgSendReq req;
    if (parse_msg(data, len, &req) != 0)
    {
        LOG_ERROR("parse_msg failed.\n");
        return -1;
    }
    dump(hdr, &req);

    LOG_INFO("recv msg send req! [%s][%s]\n",
                        req.sid().c_str(),
                        req.channelid().c_str());

    int gateway_fd = 0;
    //根据channelid在hash中寻找成功注册上来的网关信息
    gateway_info_t *pinfo = get_gateway_data( g_gateway_dict,req.channelid().c_str() );
    if( pinfo == NULL )
    {
        //找不到，证明网关还没注册上来
        LOG_WARN("can not find the gateway.save data to db.\n");
        //保存信息到数据库
        save_msg( &req );
        return 1;
    }
    else
    {
        gateway_fd = pinfo->fd;
        pinfo->last_send_time = time(NULL);
        pinfo->count++;
    }
    //找到了，向这个网关转发报文
    pcon = g_con[gateway_fd].con;
    if (make_req(hdr,&req,pcon) < 0)
    {
        LOG_ERROR("make GateWayMsgSendReq failed.\n");
        return -1;
    }
	return 0;
}

int save_msg( GateWayMsgSendReq *req )
{
    //组装成json
    Json::FastWriter jsonWriter;
    Json::Value jsonRoot, jsonArgument;

    jsonRoot["src_phone"] = Json::Value(req->srcphone());
    jsonRoot["message_content"] = Json::Value(req->messagecontent());
    jsonRoot["channel_type"] = Json::Value(req->channeltype());
    jsonRoot["channel_id"] = Json::Value(req->channelid());
    jsonRoot["channel_groupid"] = Json::Value(req->channelgroupid());
    // 拼装sms_argument
    jsonArgument["datetime"] = Json::Value(req->datetime());
    jsonArgument["submit_id"] = Json::Value(req->submitid());
    jsonArgument["batchno"] = Json::Value(req->batchno());
    jsonArgument["operator_id"] = Json::Value(req->operatorid());
    jsonArgument["client_id"] = Json::Value(req->customerid());
    jsonArgument["account_id"] = Json::Value(req->accountid());
    jsonArgument["company_id"] = Json::Value(req->companyid());
    jsonArgument["submit_way"] = Json::Value(req->submitway());
    bool isotosend;
    if( req->isotosend() == 1 )
    {
        isotosend = true;
    }
    else
    {
        isotosend = false;
    }
    jsonArgument["oto_send"] = Json::Value(isotosend);

    if( req->issmsresend() == 1 )
    {
        isotosend = true;
    }
    else
    {
        isotosend = false;
    }
    jsonArgument["sms_resend"] = Json::Value(isotosend);
    
    jsonArgument["return_type"] = Json::Value(req->returntype());
    jsonArgument["smsdata"] = Json::Value(req->smsdata());
    jsonRoot["sms_argument"] = jsonArgument;
    // 拼装phone_list
    for ( int index = 0; index < req->phonelist_size(); index++ )
    {
        const GateWayMsgSendReq::PhoneListGroup& phonelist = req->phonelist(index);

        Json::Value jsonPhone;
        jsonPhone["send_id"] = Json::Value(phonelist.sendid());
        if( phonelist.isneedsend() == 1 )
        {
            isotosend = true;
        }
        else
        {
            isotosend = false;
        }
        jsonPhone["need_send"] = Json::Value(isotosend);
        jsonPhone["virtual_status"] = Json::Value(phonelist.virtualstatus());
        jsonPhone["convert_status"] = Json::Value(phonelist.convertstatus());
        jsonPhone["mobile_phone"] = Json::Value(phonelist.mobilephone());
        jsonPhone["sms_content"] = Json::Value(phonelist.smscontent());
        jsonPhone["mobile_city"] = Json::Value(phonelist.mobilecity());
        jsonRoot["phone_list"].append(jsonPhone);
    }

    string msg_json = jsonWriter.write(jsonRoot);

    int ret = save_channel_msg( req->channelid().c_str(), msg_json );
    if( ret != 0 )
    {
        LOG_ERROR("save_channel_msg failed.\n");
        return ret;
    }
    
    return 0;
}

//信息发送应答
int handle_gateway_msg_send_rsp(message_head_t* hdr, const char* data, int len)
{
    GateWayMsgSendRsp rsp;
    if (parse_msg(data, len, &rsp) != 0)
    {
        LOG_ERROR("parse GateWayMsgSendRsp failed.\n");
        return -1;
    }
    dump(hdr, &rsp);

    LOG_INFO("GateWayMsgSendRsp! sid=[%s]retcode[%d]]\n",
                        rsp.sid().c_str(),
                        rsp.retcode());

	return 1;
}