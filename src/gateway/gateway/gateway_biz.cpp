#include "gateway_db.h"
#include "gateway_biz.h"
#include "gateway_util.h"
#include <json/json.h>

int handle_channel_packet( connection_t** pcon )
{
    if ( *pcon == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }

    if(unlikely(g_biz == NULL)) 
    {
        LOG_ERROR("biz dll pointer is null!\n");
        return -1;
    }

    buffer_t *rcvbuf = (*pcon)->rcvbuf;
    const char *readptr = rcvbuf->get_read_ptr(rcvbuf);
    int datalen = rcvbuf->get_data_size(rcvbuf);
    if (datalen <= 0)
    {
        *pcon = NULL;
        return 0;
    }

    //从缓冲区复制数据出来
    char* inbuf = (char *)malloc( g_conf.package_buff_size );
    if( inbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for inbuf.\n");
        return -1;
    }
    memcpy(inbuf, readptr, datalen);
    inbuf[datalen] = '\0';

    //调用业务库判断是否为完整报文
    int ret = g_biz->is_packet_complete(inbuf, datalen);
    if( ret <= 0 )
    {
        *pcon = NULL;
        if( inbuf != NULL )
        {
            free(inbuf);
            inbuf = NULL;
        }
        if(ret == 0)  // 不完整报文
        {
            return ret;
        }
        else          // 无效报文
        {
            LOG_ERROR("is_packet_complete fatal error.\n");
            return -2;
        }
    }
    datalen = ret;
    rcvbuf->set_read_size(rcvbuf, datalen);

    //完整报文
    //输出缓冲区
    char* outbuf = (char *)malloc( g_conf.package_buff_size );
    if( outbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for outbuf.\n");
        return -1;
    }
    int  outlen = 0;

    //调用业务库处理
    ret = g_biz->channel_req(inbuf, datalen,outbuf, outlen);
    if (unlikely(ret < 0))
    {
        LOG_ERROR("channel_req failed!\n");
        if( inbuf != NULL )
        {
            free(inbuf);
            inbuf = NULL;
        }
        if( outbuf != NULL )
        {
            free(inbuf);
            outbuf = NULL;
        }
        return -1;
    }

    if ( ret > 0 || outlen <= 0 )
    {
        if( inbuf != NULL )
        {
            free(inbuf);
            inbuf = NULL;
        }
        if( outbuf != NULL )
        {
            free(inbuf);
            outbuf = NULL;
        }
        return 1;
    }

    //写数据进发送缓冲区
    buffer_t * pbuffer = (*pcon)->sndbuf;
    int freesize = pbuffer->get_free_size(pbuffer);
    char* writeptr = pbuffer->get_write_ptr(pbuffer);
    if (outlen <= freesize) 
    {                  
        memcpy(writeptr, outbuf, outlen);
        pbuffer->set_write_size(pbuffer, outlen);
    }

    if( inbuf != NULL )
    {
        free(inbuf);
        inbuf = NULL;
    }
    if( outbuf != NULL )
    {
        free(inbuf);
        outbuf = NULL;
    }
    return ret;
}

int handle_gateway_packet( connection_t** pcon )
{
    if ( *pcon == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }

    buffer_t *rcvbuf = (*pcon)->rcvbuf;
    const char *readptr = rcvbuf->get_read_ptr(rcvbuf);
    int datalen = rcvbuf->get_data_size(rcvbuf);
    if (datalen <= 0)
    {
        *pcon = NULL;
        return 0;
    }

    int ret = is_packet_complete(readptr, datalen);
    if( ret <= 0 )
    {
        *pcon = NULL;
        if(ret == 0)  // 不完整报文
        {
            return ret;
        }
        else          // 无效报文
        {
            LOG_ERROR("is_packet_complete fatal error.\n");
            return -2;
        }
    }

    //解析报文头
    message_head_t hdr;
    if (parse_header(readptr, datalen, &hdr) != 0)
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }

    //从缓冲区复制数据出来
    char* inbuf = (char *)malloc( g_conf.package_buff_size );
    if( inbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for inbuf.\n");
        return -1;
    }
    memcpy(inbuf, readptr, hdr.length);
    rcvbuf->set_read_size(rcvbuf, hdr.length);

    switch(hdr.command)
    {
    case CMD_HEARTBEAT_RSP://处理心跳应答
        {
            ret = handle_heartbeat_rsp(&hdr, 
                                       inbuf + PROTOCOL_HEADER_LENGTH, 
                                       hdr.length - PROTOCOL_HEADER_LENGTH);
        }
        break;
    case CMD_SVR_REG_RSP://处理注册应答
        {
            ret = handle_svr_reg_rsp(&hdr, 
                                     inbuf + PROTOCOL_HEADER_LENGTH, 
                                     hdr.length - PROTOCOL_HEADER_LENGTH,
                                     *pcon);
        }
        break;
    case CMD_CHANNEL_MGR_REQ: // 通道参数变更请求
        {
            ret = handle_channel_mgr_req(&hdr,
                                            inbuf + PROTOCOL_HEADER_LENGTH,
                                            hdr.length - PROTOCOL_HEADER_LENGTH,
                                            *pcon);
        }
        break;
	case CMD_GATEWAY_MSG_SEND_REQ: //信息发送请求
		{
			ret = handle_gateway_msg_send_req(&hdr,
                                              inbuf + PROTOCOL_HEADER_LENGTH,
                                              hdr.length - PROTOCOL_HEADER_LENGTH,
                                              *pcon);
		}
		break;
	default:
	    {
    		LOG_ERROR("unknown command : 0x%x\n", hdr.command);
    	    ret = -1;
    		break;
        }
    }
    if( inbuf != NULL )
    {
        free(inbuf);
        inbuf = NULL;
    }
    return ret;
}

// 处理心跳应答包
int handle_heartbeat_rsp(message_head_t* hdr, const char* data, int len)
{
    HeartBeatRsp rsp;
    if (parse_msg(data, len, &rsp) != 0)
    {
        LOG_ERROR("parse_msg HeartBeatRsp failed.\n");
        return -1;
    }
    dump(hdr, &rsp);

    return 1;
}

//处理注册应答包
int handle_svr_reg_rsp(message_head_t* hdr, const char* data, int len, connection_t *pcon)
{
    SvrRegRsp rsp;
    if (parse_msg(data, len, &rsp) != 0)
    {
        LOG_ERROR("parse_msg SvrRegRsp failed.\n");
        return -1;
    }
    dump(hdr, &rsp);

    LOG_INFO("svr reg rsp! [%s][%d]\n",rsp.sid().c_str(),rsp.retcode());

    vector<server_info_t>::iterator it = g_conf.server_info.begin();
    for(;it!=g_conf.server_info.end();it++)
    {
        if(it->fd == pcon->fd)
        {
            if(rsp.retcode() == 0)
            {
                it->is_reg = true;
            }
            else
            {
                it->is_reg = false;
            }
        }
    }

    return 1;
}

// 通道参数变更请求
int handle_channel_mgr_req(message_head_t* hdr, const char* data, int len, connection_t *pcon)
{
    ChannelMgrReq req;
    if (parse_msg(data, len, &req) != 0)
    {
        LOG_ERROR("parse_msg ChannelMgrReq failed.\n");
        return -1;
    }
    dump(hdr, &req);

    LOG_INFO("channel mgr req! [%s][%s][%d]\n",
                        req.sid().c_str(),
                        req.channelid().c_str(),
                        req.mgrtype());

    int ret = 0;
    //收到退出报文，退出程序
    if( req.mgrtype() == 2 )
    {
        g_exit = 1;
    }
    else
    {
        //更新通道参数报文
        if( strcasecmp(g_conf.channel_id,req.channelid().c_str()) == 0 )
        {
            //加载通道参数
            ret = load_channel_info(req.channelid().c_str());
            if( ret == 0 )
            {
                LOG_INFO("reload channel successful.channelid[%s]\n",req.channelid().c_str());
                //调用业务库重读参数
                g_biz->reload_channel( &g_channel_conf );

                //处理子进程退出
                handle_child_exit();

                //重启所有发送子进程
                ret = fork_proc();
                if( ret != 0 )
                {
                    LOG_ERROR("fail to fork_proc!\n");
                }
                //数据设置成可发送
                g_ready_to_send = 1;
            }
            else
            {
                LOG_ERROR("reload channel failed.\n");
            }
        }
    }

    ChannelMgrRsp rsp;
    rsp.set_sid(req.sid());
    rsp.set_retcode(ret);
    if (make_rsp(hdr, &rsp, pcon) < 0)
    {
        LOG_ERROR("make_rsp failed.\n");
        return -1;
    }
    return 0;
}

//信息发送请求
int handle_gateway_msg_send_req(message_head_t* hdr, const char* data, int len, connection_t *pcon)
{
    GateWayMsgSendReq req;
    if (parse_msg(data,len,&req) != 0)
    {
        LOG_ERROR("parse_msg failed.\n");
        return -1;
    }
    dump(hdr,&req);

    LOG_INFO("gateway msg send req! [%s][%s]\n",
                        req.sid().c_str(),
                        req.channelid().c_str());

    int ret = msg_send(hdr,&req);
    if( ret != 0 )
    {
        LOG_ERROR("msg_send failed.\n");
    }

    GateWayMsgSendRsp rsp;
    rsp.set_sid(req.sid());
    rsp.set_retcode(ret);
    if (make_rsp(hdr, &rsp, pcon) < 0)
    {
        LOG_ERROR("make_rsp failed.\n");
        return -1;
    }
    return 0;
}

int msg_to_json( GateWayMsgSendReq *req,string &msg_json )
{
    if( req == NULL ) return -1;

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
    msg_json = jsonWriter.write(jsonRoot);

    return 0;
}

int get_phone_packet(map<string,sms_attribute_t> *plist,GateWayMsgSendReq *req,int num)
{
    if( plist == NULL || req == NULL ) return -1;

    //情况之前号码列表
    req->clear_phonelist();
    map<string, sms_attribute_t>::iterator itPhone = plist->begin();
    for( int i = 0; i < num; i++ )
    {
        if( itPhone != plist->end() )
        {
            GateWayMsgSendReq::PhoneListGroup* phonelist = req->add_phonelist();
            phonelist->set_sendid(itPhone->first);
            phonelist->set_isneedsend(itPhone->second.bNeedSend);
            phonelist->set_virtualstatus(itPhone->second.sVirtualStatus);
            phonelist->set_convertstatus(itPhone->second.sConvertStatus);
            phonelist->set_mobilephone(itPhone->second.sMobilePhone);
            phonelist->set_smscontent(itPhone->second.sSmsContent);
            phonelist->set_mobilecity(itPhone->second.sMobileCity);

            plist->erase(itPhone++);
        }
    }
    return 0;
}

int msg_send(message_head_t* hdr,GateWayMsgSendReq *req)
{
    if( hdr == NULL || req == NULL ) return -1;

    GateWayMsgSendReq send_req;
    send_req.set_sid(req->sid());
    send_req.set_srcphone(req->srcphone());
    send_req.set_messagecontent(req->messagecontent());
    send_req.set_channeltype(req->channeltype());
    send_req.set_channelid(req->channelid());
    send_req.set_channelgroupid(req->channelgroupid());
    send_req.set_datetime(req->datetime());
    send_req.set_submitid(req->submitid());
    send_req.set_batchno(req->batchno());
    send_req.set_operatorid(req->operatorid());
    send_req.set_customerid(req->customerid());
    send_req.set_accountid(req->accountid());
    send_req.set_companyid(req->companyid());
    send_req.set_submitway(req->submitway());
    send_req.set_isotosend(req->isotosend());
    send_req.set_issmsresend(req->issmsresend());
    send_req.set_returntype(req->returntype());
    send_req.set_smsdata(req->smsdata());

    map<string,sms_attribute_t> phonelist;
    for ( int index = 0; index < req->phonelist_size(); index++ )
    {
        const GateWayMsgSendReq::PhoneListGroup& phone_group = req->phonelist(index);

        sms_attribute_t phone;
        string sSendId = phone_group.sendid();
        phone.bNeedSend = phone_group.isneedsend();
        phone.sVirtualStatus = phone_group.virtualstatus();
        phone.sConvertStatus = phone_group.convertstatus();
        phone.sMobilePhone = phone_group.mobilephone();
        phone.sSmsContent = phone_group.smscontent();
        phone.sMobileCity = phone_group.mobilecity();
        phonelist[sSendId] = phone;
    }

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
            string msg_json;
            msg_to_json(&send_req,msg_json);
            //mq满了，重写回redis
            int ret = save_channel_msg( g_conf.channel_id, msg_json );
            if( ret != 0 )
            {
                LOG_ERROR("save_channel_msg failed.\n");
                break;
            }
        }
    }
    
    return 0;
}

int load_channel_info(const char* channel_id)
{
    string info;
    int ret = query_channel_info(channel_id,info);
    if( ret != 0 )
    {
        LOG_ERROR("query_channel_info fail.\n");
        return -1;
    }

    Json::Reader jsonReader;
    Json::Value  jsonValue;
    if (!jsonReader.parse(info, jsonValue))
    {
        LOG_ERROR("Parse json is failure.The json:%s.", info.c_str());
        return -1;
    }

    uint32_t http_type = 0;
    uint32_t uProtoType = jsonValue["sc_proto_type"].asUInt();
    if ( uProtoType == 3 )
    {
        string sInterfaceId = jsonValue["sc_it_id"].asString();
        ret = query_httpchannel_info(sInterfaceId.c_str(),http_type);
        if( ret != 0 )
        {
            LOG_ERROR("query_httpchannel_info fail.\n");
            return -1;
        }
    }

    g_channel_conf.sChannelId = jsonValue["sc_id"].asString();
    g_channel_conf.sChannelName = jsonValue["sc_channel_name"].asString();
    g_channel_conf.uProtoType = uProtoType;
    g_channel_conf.uMassSupport = jsonValue["sc_mass_support"].asUInt();
    g_channel_conf.uMassNum = jsonValue["sc_mass_num"].asUInt();
    g_channel_conf.lHeartbeatInterval = jsonValue["sc_heartbeat_interval"].asUInt();
    g_channel_conf.uSendSpeed = jsonValue["sc_send_speed"].asUInt();
    g_channel_conf.uLinkCount = jsonValue["sc_link_count"].asUInt();
    g_channel_conf.sIpAddress = jsonValue["sc_server_addr"].asString();
    g_channel_conf.lPort = jsonValue["sc_server_port"].asUInt();
    g_channel_conf.uListenPort = jsonValue["sc_listen_port"].asUInt();
    g_channel_conf.uSignType = jsonValue["sc_sign_type"].asUInt();
    g_channel_conf.uTimeout = jsonValue["sc_send_timeout"].asUInt();
    g_channel_conf.sAccessCode = jsonValue["sc_access_code"].asString();
    g_channel_conf.sUserName = jsonValue["sc_login_name"].asString();
    g_channel_conf.sPassword = jsonValue["sc_login_passwd"].asString();
    g_channel_conf.sSpId = jsonValue["sc_sp_code"].asString();
    g_channel_conf.sServiceId = jsonValue["sc_service_id"].asString();
    g_channel_conf.sFeeType = jsonValue["sc_fee_type"].asString();
    g_channel_conf.sFeeCode = jsonValue["sc_fee_code"].asString();
    g_channel_conf.sVersion = 0x0;
    g_channel_conf.uSpnodeCode = atoi(jsonValue["sc_spnode_code"].asString().c_str());
    g_channel_conf.uHttpType = http_type;
    g_channel_conf.sHttpUrl = jsonValue["sc_http_url"].asString();
    g_channel_conf.uCustomParam1 = jsonValue["sc_custom_param1"].asUInt();
    g_channel_conf.uCustomParam2 = jsonValue["sc_custom_param2"].asUInt();
    g_channel_conf.uCustomParam3 = jsonValue["sc_custom_param3"].asUInt();
    g_channel_conf.uCustomParam4 = jsonValue["sc_custom_param4"].asUInt();
    g_channel_conf.uCustomParam5 = jsonValue["sc_custom_param5"].asUInt();

    if (g_channel_conf.lHeartbeatInterval == 0)
        g_channel_conf.lHeartbeatInterval = 30000; // 默认为30s
    if (g_channel_conf.uTimeout == 0)
        g_channel_conf.uTimeout = 5000;            // 默认为5s
    
    return 0;
}

int json_to_msg(string msg_json,GateWayMsgSendReq *req,map<string,sms_attribute_t> &phonelist)
{
    if( msg_json.empty() || req == NULL ) return -1;

    // 解析json
    try
    {
        Json::Reader jsonReader;
        Json::Value jsonRoot, jsonValue;
        if (!jsonReader.parse(msg_json, jsonRoot))
        {
            LOG_ERROR("Parse the json is failure.\n");
            return -1;
        }
        // 消息包组装
        // 接入号
        jsonValue = jsonRoot["src_phone"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("src_phone property is not exist\n");
            return -1;
        }
        req->set_srcphone(jsonValue.asString());

        // 通用内容
        jsonValue = jsonRoot["message_content"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("message_content property is not exist\n");
            return -1;
        }
        req->set_messagecontent(jsonValue.asString());

        // 通道类型
        jsonValue = jsonRoot["channel_type"];
        if (jsonValue.isNull() || !jsonValue.isInt())
        {
            LOG_ERROR("channel_type property is not exist.\n");
            return -1;
        }
        req->set_channeltype(jsonValue.asInt());

        // 通道ID
        jsonValue = jsonRoot["channel_id"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("channel_id property is not exist.\n");
            return -1;
        }
        req->set_channelid(jsonValue.asString());

        // 通道组ID
        jsonValue = jsonRoot["channel_groupid"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("channel_groupid property is not exist.\n");
            return -1;
        }
        req->set_channelgroupid(jsonValue.asString());

        // sms_argument
        Json::Value jsonArgument = jsonRoot["sms_argument"];
        if (jsonArgument.isNull())
        {
            LOG_ERROR("sms_argument property is not exist.\n");
            return -1;
        }
        // 日期
        jsonValue = jsonArgument["datetime"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.datetime property is not exist.\n");
            return -1;
        }
        req->set_datetime(jsonValue.asString());

        // 子批次号
        jsonValue = jsonArgument["submit_id"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.submit_id property is not exist.\n");
            return -1;
        }
        req->set_submitid(jsonValue.asString());

        // 批次号
        jsonValue = jsonArgument["batchno"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.batchno property is not exist.\n");
            return -1;
        }
        req->set_batchno(jsonValue.asString());

        // 操作员ID
        jsonValue = jsonArgument["operator_id"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.operator_id property is not exist.\n");
            return -1;
        }
        req->set_operatorid(jsonValue.asString());

        // 客户ID
        jsonValue = jsonArgument["client_id"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.client_id property is not exist.\n");
            return -1;
        }
        req->set_customerid(jsonValue.asString());

        // 账号ID
        jsonValue = jsonArgument["account_id"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.account_id property is not exist.\n");
            return -1;
        }
        req->set_accountid(jsonValue.asString());

        // 公司ID
        jsonValue = jsonArgument["company_id"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            LOG_ERROR("sms_argument.company_id property is not exist.\n");
            return -1;
        }
        req->set_companyid(jsonValue.asString());

        // 提交方式
        jsonValue = jsonArgument["submit_way"];
        if (jsonValue.isNull() || !jsonValue.isInt())
        {
            LOG_ERROR("sms_argument.submit_way property is not exist.\n");
            return -1;
        }
        req->set_submitway(jsonValue.asInt());

        // 是否一对一短信
        jsonValue = jsonArgument["oto_send"];
        if (jsonValue.isNull() || !jsonValue.isBool())
        {
            LOG_ERROR("sms_argument.oto_send property is not exist.\n");
            return -1;
        }
        bool oto_send = jsonValue.asBool();
        if( oto_send )
        {
            req->set_isotosend(1);
        }
        else
        {
            req->set_isotosend(0);
        }

        // 是否重发短信
        jsonValue = jsonArgument["sms_resend"];
        if (jsonValue.isNull() || !jsonValue.isBool())
        {
            LOG_ERROR( "sms_argument.sms_resend property is not exist.\n");
            return -1;
        }
        bool sms_resend = jsonValue.asBool();
        if( sms_resend )
        {
            req->set_issmsresend(1);
        }
        else
        {
            req->set_issmsresend(0);
        }

        // 返量类型
        jsonValue = jsonArgument["return_type"];
        if (jsonValue.isNull() || !jsonValue.isInt())
        {
            LOG_ERROR( "sms_argument.return_type property is not exist.\n");
            return -1;
        }
        req->set_returntype(jsonValue.asInt());

        // SMS数据
        jsonValue = jsonArgument["smsdata"];
        if (jsonValue.isNull() || !jsonValue.isString())
        {
            req->set_smsdata("");
        }
        else
        {
            req->set_smsdata(jsonValue.asString());
        }

        // phone_list
        Json::Value jsonPhoneList = jsonRoot["phone_list"];
        if (jsonPhoneList.isNull() || !jsonPhoneList.isArray())
        {
            LOG_ERROR( "phone_list property is not exist.\n");
            return -1;
        }
        for (unsigned int index = 0; index < jsonPhoneList.size(); index++)
        {
            Json::Value jsonSms = jsonPhoneList[index];
            // 发送ID
            jsonValue = jsonSms["send_id"];
            if (jsonValue.isNull() || !jsonValue.isString())
            {
                continue;
            }
            // 是否实发
            jsonValue = jsonSms["need_send"];
            if (jsonValue.isNull() || !jsonValue.isBool())
            {
                continue;
            }
            // 虚拟状态
            jsonValue = jsonSms["virtual_status"];
            if (jsonValue.isNull() || !jsonValue.isString())
            {
                continue;
            }
            // 转换状态
            jsonValue = jsonSms["convert_status"];
            if (jsonValue.isNull() || !jsonValue.isString())
            {
                continue;
            }
            // 手机号码
            jsonValue = jsonSms["mobile_phone"];
            if (jsonValue.isNull() || !jsonValue.isString())
            {
                continue;
            }
            // 一对一短信内容
            jsonValue = jsonSms["sms_content"];
            if (jsonValue.isNull() || !jsonValue.isString())
            {
                continue;
            }
            // 手机号码所属城市
            jsonValue = jsonSms["mobile_city"];
            if (jsonValue.isNull() || !jsonValue.isString())
            {
                continue;
            }
            // PhoneList组装结构
            sms_attribute_t smsAttribute;
            std::string sSendId = jsonSms["send_id"].asString();
            smsAttribute.bNeedSend = jsonSms["need_send"].asBool();
            smsAttribute.sVirtualStatus = jsonSms["virtual_status"].asString();
            smsAttribute.sConvertStatus = jsonSms["convert_status"].asString();
            smsAttribute.sMobilePhone = jsonSms["mobile_phone"].asString();
            smsAttribute.sSmsContent = jsonSms["sms_content"].asString();
            smsAttribute.sMobileCity = jsonSms["mobile_city"].asString();
            phonelist[sSendId] = smsAttribute;
        }
    }
    catch (Json::LogicError &ex)
    {
        LOG_ERROR( "Parse the json is failure.The json:%s.\n", msg_json.c_str());
        return -1;
    }

    return 0;
}

int fork_proc()
{
    //是否启用多连接
    if( g_conf.is_need_multi_conn == 0 )
    {
        //不启用，连接数为1个
        g_channel_conf.uLinkCount = 1;
    }
    for(uint32_t i = 0; i < g_channel_conf.uLinkCount; i++)
    {
        pid_t pid = 0;
        if((pid = fork()) > 0)// parent
        { 
            LOG_INFO("fork send. child id=%d\n",pid);
            g_send_pid.push_back(pid);
        }
        else if(pid == 0)// child
        {
            //关闭日志
            log_only_close(g_log);
            //执行通道进程
            int ret = execl(g_conf.exe_name,g_conf.exe_name,
                            "-t",g_conf.channel_type,
                            "-i",g_conf.channel_id,
                            "-c",g_conf.conf_file,
                            (char*)NULL);
            if(ret == -1)
            {
                perror("execl");
                exit(0);
            }
        }
        else
        {
            LOG_ERROR("execl send failed.\n");
            return -1;
        }
    }

    return 0;
}

//程序异常退出告警信息
int send_exit_alarm_msg(int pid)
{
    string sTemplateParam,sTime;
    char error_msg[128] = {0};
    snprintf(error_msg,sizeof(error_msg),"网关发送子程序[%d]退出",pid);

    sTime = MakeDateTime();
    sTemplateParam = "{\"pid\":\"";
    sTemplateParam += to_string(pid);
    sTemplateParam += "\",\"time\":\"";
    sTemplateParam += sTime;
    sTemplateParam += "\",\"channel\":\"";
    sTemplateParam += g_channel_conf.sChannelName;
    sTemplateParam += "\"}";

    Json::FastWriter jsonWriter;
    Json::Value jsonValue;
    jsonValue["modle_name"] = Json::Value("gateway_send");
    jsonValue["level"] = Json::Value(5);
    jsonValue["error_msg"] = Json::Value(error_msg);
    jsonValue["sms_template_id"] = Json::Value(g_conf.template_id);
    jsonValue["sms_template_param"] = Json::Value(sTemplateParam);
    jsonValue["send_time"] = Json::Value(sTime);
    
    string json_msg = jsonWriter.write(jsonValue);

    save_alarm_msg(json_msg);

    return 0;
}

int handle_mq_msg()
{
    msgform_t mq_msg;
    while( true )
    {
        //从消息队列里读取数据出来
        int ret = g_mq.read(&mq_msg, sizeof(msgform_t), 1, IPC_NOWAIT);
        if( ret <= 0 )
        {
            //mq里没数据,退出循环
            break;
        }
        //解包
        GateWayMsgSendReq req;
        if (parse_msg(mq_msg.mtext,mq_msg.data_len,&req) != 0)
        {
            LOG_ERROR("parse_msg GateWayMsgSendReq failed.\n");
            break;
        }
        //组成json
        string one_msg;
        msg_to_json(&req,one_msg);
        //重写回redis
        ret = save_channel_msg( g_conf.channel_id, one_msg );
        if( ret != 0 )
        {
            LOG_ERROR("save_channel_msg failed.\n");
            break;
        }
    }
    
    return 0;
}

int handle_child_exit()
{
    //将mq数据回填redis
    handle_mq_msg();

    //杀死所有发送子进程
    vector<pid_t>::iterator it = g_send_pid.begin();
    for(;it!=g_send_pid.end();)
    {
        //杀死子进程
        kill(*it, SIGTERM);
        //等待子进程退出，防止僵尸进程
        waitpid(*it, NULL, 0);
        it=g_send_pid.erase(it); //从列表删除
    }

    return 0;
}