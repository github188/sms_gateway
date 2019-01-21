#include "send_db.h"
#include "send_biz.h"
#include "send_util.h"

bool parse_message(const char *buf,int data_len,message_packet_t *msgPacket)
{
    if ( buf == NULL || msgPacket == NULL )   return false;

    GateWayMsgSendReq req;
    if (parse_msg(buf,data_len,&req) != 0)
    {
        LOG_ERROR("parse_msg GateWayMsgSendReq failed.\n");
        return false;
    }

    msgPacket->sSrcPhone = req.srcphone();
    msgPacket->sMessageContent = req.messagecontent();
    msgPacket->uChannelType = req.channeltype();
    msgPacket->sChannelId = req.channelid();
    msgPacket->sChannelGroupId = req.channelgroupid();
    msgPacket->smsArgument.sDateTime = req.datetime();
    msgPacket->smsArgument.sSubmitId = req.submitid();
    msgPacket->smsArgument.sBatchno = req.batchno();
    msgPacket->smsArgument.sOperatorId = req.operatorid();
    msgPacket->smsArgument.sClientId = req.customerid();
    msgPacket->smsArgument.sAccountId = req.accountid();
    msgPacket->smsArgument.sCompanyId = req.companyid();
    msgPacket->smsArgument.sSmsContent = req.messagecontent();
    msgPacket->smsArgument.uSubmitWay = req.submitway();
    msgPacket->smsArgument.bOtoSend = req.isotosend();
    msgPacket->smsArgument.bSmsResend = req.issmsresend();
    msgPacket->smsArgument.uReturnType = req.returntype();
    msgPacket->smsArgument.sSmsData = req.smsdata();

    //phonelist
    for ( int index = 0; index < req.phonelist_size(); index++ )
    {
        const GateWayMsgSendReq::PhoneListGroup& phone_group = req.phonelist(index);
        sms_attribute_t phone;
        string sSendId = phone_group.sendid();
        phone.bNeedSend = phone_group.isneedsend();
        phone.sVirtualStatus = phone_group.virtualstatus();
        phone.sConvertStatus = phone_group.convertstatus();
        phone.sMobilePhone = phone_group.mobilephone();
        phone.sSmsContent = phone_group.smscontent();
        phone.sMobileCity = phone_group.mobilecity();
        msgPacket->mPhoneList[sSendId] = phone;
    }

    return true;
}

bool deduct_remaining( uint32_t cnt )
{
    // 减少的数量
    int deduct_cnt = 0 - cnt;
    // 减少完之后的结果
    int result_cnt = 0;
    int ret = save_channel_remaining(g_conf.channel_id,deduct_cnt,result_cnt);
    if ( ret != 0 )
    {
        LOG_ERROR("save_channel_remaining fail.\n");
        return false;
    }
/*
    // 操作redis成功，并被减少到0以下,需要将0以下的部分补回
    if ( result_cnt < 0 )
    {
        int addValue = 0 - result_cnt;
        ret = save_channel_remaining(g_conf.channel_id,addValue,result_cnt);
        if ( ret != 0 )
        {
            LOG_ERROR("save_channel_remaining fail.\n");
            return false;
        }
    }
*/
    return true;
}

void do_sign(uint32_t uSignType, string &msg)
{
    if (uSignType == 3) return;

    string sMessageContent = msg;
    size_t nPosLen = strlen("【");
    size_t nEndPos = sMessageContent.find("】");
    size_t nBeginPos = sMessageContent.find("【");
    if (nEndPos <= nBeginPos || (nEndPos - nBeginPos) < nPosLen)  return;
    if (uSignType == 1)
    {// 前置签名
        if ((nEndPos + nPosLen) == sMessageContent.length())
        {// 后置签名，改为前置签名
            string sSignContent = sMessageContent.substr(nBeginPos);
            string sBodyContent = sMessageContent.substr(0, nBeginPos);
            msg = sSignContent + sBodyContent;
        }
    }
    else if(uSignType == 2)
    {// 后置签名
        if (nBeginPos == 0)
        {// 前置签名，改为后置签名
            string sSignContent = sMessageContent.substr(nBeginPos, (nEndPos - nBeginPos + nPosLen));
            string sBodyContent = sMessageContent.substr(nEndPos - nBeginPos + nPosLen);
            msg = sBodyContent + sSignContent;
        }
    }
}

int handle_packet(connection_t *con,int datalen, dict* wq)
{
	if ( con == NULL || wq == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }
    
    int ret = 0;

	//从读缓存中读出数据
    buffer_t *rcvbuf = con->rcvbuf;
    if (rcvbuf == NULL)
    {
        LOG_ERROR("rcvbuf is null!\n");
        return -1;
    }
    const char* readptr = rcvbuf->get_read_ptr(rcvbuf);

    //从缓冲区复制数据出来
    char* inbuf = (char *)malloc( g_conf.package_buff_size );
    if( inbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for inbuf.\n");
        return -1;
    }
    memcpy(inbuf, readptr, datalen);
    inbuf[datalen] = '\0';

    rcvbuf->set_read_size(rcvbuf, datalen);

    //输出缓冲区
    char* outbuf = (char *)malloc( g_conf.package_buff_size );
    if( outbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for outbuf.\n");
        return -1;
    }
    int  outlen = 0;

    char sidbuf[MAX_SID_LEN] = {0};
    if( g_channel_conf.uProtoType == 3 )
    {
        channel_reserved_t * er = get_channel_reserved_data(g_channel_dict,con->fd);
        if (er == NULL)
        {
            LOG_ERROR("get_channel_reserved_data failed.\n");
        }
        else
        {
            strcpy(sidbuf, er->sid);
        }
        delete_channel_reserved_data(g_channel_dict,con->fd);
        //http协议关闭连接
        close(con->fd);
        g_connect_fd = 0;
    }
    
    //调用业务库处理
    ret = g_biz->channel_rsp(wq,inbuf, datalen,sidbuf,outbuf, outlen);
    if (unlikely(ret < 0))
    {
        LOG_ERROR("channel_rsp failed!\n");
        if( inbuf != NULL )
        {
            free(inbuf);
            inbuf = NULL;
        }
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        return -1;
    }

    //不需要向网络发送数据
    if ( ret > 0 || outlen <= 0 )
    {
        if( inbuf != NULL )
        {
            free(inbuf);
            inbuf = NULL;
        }
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        return 1;
    }

    if( g_channel_conf.uProtoType == 3 )
    {
        //如果不是作为服务器端，则重新连接
        if( con->con_type != CON_T_SERVER )
        {
            g_connect_fd = connect_ipv4_serv_buffsize(g_channel_conf.sIpAddress.c_str(),
                                                      g_channel_conf.lPort,
                                                      g_conf.package_buff_size);
            g_conf.last_connect_time = get_utc_miliseconds();
            if( g_connect_fd <= 0 )
            {
                LOG_ERROR("new connect to channel error!\n");
                if( inbuf != NULL )
                {
                    free(inbuf);
                    inbuf = NULL;
                }
                if( outbuf != NULL )
                {
                    free(outbuf);
                    outbuf = NULL;
                }
                return -1;
            }
            con = g_con[g_connect_fd].con;
        }
    }

    //写数据进发送缓冲区
    buffer_t * pbuffer = con->sndbuf;
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
        free(outbuf);
        outbuf = NULL;
    }
    
    return ret;
}

int handle_channel_login(dlist_t *write)
{
    if ( write == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }

    if(unlikely(g_biz == NULL)) 
    {
        LOG_ERROR("biz dll pointer is null!\n");
        return -1;
    }

    char* outbuf = (char *)malloc( g_conf.package_buff_size );
    if( outbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for outbuf.\n");
        return -1;
    }
    int  outlen = 0;

    //调用业务库组装报文
    int ret = g_biz->channel_login_req(outbuf,outlen);
    if (unlikely(ret < 0))
    {
        LOG_ERROR("channel_login_req failed!\n");
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        return -1;
    }

    if ( ret > 0 || outlen <= 0 )
    {
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        return 1;
    }

    connection_t *pcon = g_con[g_connect_fd].con;
    if (pcon == NULL)
    {
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        LOG_ERROR("pcon is null\n");
        return -1;
    }
    buffer_t * pbuffer = pcon->sndbuf;
    int freesize = pbuffer->get_free_size(pbuffer);
    char* writeptr = pbuffer->get_write_ptr(pbuffer);
    if (outlen <= freesize) 
    {                  
        memcpy(writeptr, outbuf, outlen);
        pbuffer->set_write_size(pbuffer, outlen);
    }

    dlist_insert_tail(write, pcon);

    if( outbuf != NULL )
    {
        free(outbuf);
        outbuf = NULL;
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

    if ( g_channel_conf.lHeartbeatInterval == 0 )
        g_channel_conf.lHeartbeatInterval = 30000; // 默认为30s

    if ( g_channel_conf.uTimeout == 0 )
        g_channel_conf.uTimeout = 5000;            // 默认为5s
    
    if ( g_conf.is_need_multi_conn == 1 )
        g_channel_conf.uSendSpeed /= g_channel_conf.uLinkCount;  //每条连接的总流速
    
    //计算每条耗时多少微秒
    g_channel_conf.uSendSpeed = 1000000 / g_channel_conf.uSendSpeed;
    
    return 0;
}

int handle_channel_timer_process(dlist_t *write, dict* wq)
{
    if ( write == NULL || wq == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }

    if(unlikely(g_biz == NULL)) 
    {
        LOG_ERROR("biz dll pointer is null!\n");
        return -1;
    }

    char* outbuf = (char *)malloc( g_conf.package_buff_size );
    if( outbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for outbuf.\n");
        return -1;
    }
    int  outlen = 0;

    char szSessionID[MAX_SID_LEN] = {0};
    get_sid_str(0,szSessionID,sizeof(szSessionID));

    if( g_channel_conf.uProtoType == 3 )
    {
        channel_reserved_t er;
        er.fd = g_connect_fd;
        strcpy(er.sid,szSessionID);
        er.fd_begin_time = time(NULL);
        if (get_channel_reserved_data(g_channel_dict, g_connect_fd) != NULL)
        {
            delete_channel_reserved_data(g_channel_dict, g_connect_fd);
        }
        insert_channel_reserved_data(g_channel_dict, er);
    }

    //调用业务库组装报文
    int ret = g_biz->timer_process(wq,szSessionID,outbuf,outlen);
    if (unlikely(ret < 0))
    {
        LOG_ERROR("timer_process failed!\n");
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        return -1;
    }

    if ( ret > 0 || outlen <= 0 )
    {
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        return 1;
    }

    connection_t *pcon = g_con[g_connect_fd].con;
    if (pcon == NULL)
    {
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        LOG_ERROR("pcon is null\n");
        return -1;
    }
    buffer_t * pbuffer = pcon->sndbuf;
    int freesize = pbuffer->get_free_size(pbuffer);
    char* writeptr = pbuffer->get_write_ptr(pbuffer);
    if (outlen <= freesize) 
    {                  
        memcpy(writeptr, outbuf, outlen);
        pbuffer->set_write_size(pbuffer, outlen);
    }

    dlist_insert_tail(write, pcon);

    if( outbuf != NULL )
    {
        free(outbuf);
        outbuf = NULL;
    }
    return 0;
}

int handle_send_msg(dlist_t *write,message_packet_t *packet, dict* wq)
{
    if ( write == NULL || packet == NULL || wq == NULL )
    {
        LOG_ERROR("Parameters are illegal!\n");
        return -1;
    }

    if(unlikely(g_biz == NULL)) 
    {
        LOG_ERROR("biz dll pointer is null!\n");
        return -1;
    }
    
    char* outbuf = (char *)malloc( g_conf.package_buff_size );
    if( outbuf == NULL )
    {
        LOG_ERROR("failed to allocate memory for outbuf.\n");
        return -1;
    }
    int  outlen = 0;

    char szSessionID[MAX_SID_LEN] = {0};
    if( g_channel_conf.uProtoType == 3 )
    {
        get_sid_str(0,szSessionID,sizeof(szSessionID));
        channel_reserved_t er;
        er.fd = g_connect_fd;
        strcpy(er.sid,szSessionID);
        er.fd_begin_time = time(NULL);
        if (get_channel_reserved_data(g_channel_dict, g_connect_fd) != NULL)
        {
            delete_channel_reserved_data(g_channel_dict, g_connect_fd);
        }
        insert_channel_reserved_data(g_channel_dict, er);
    }

    //调用业务库组装报文
    int ret = g_biz->send_msg_req(wq,packet,szSessionID,outbuf,outlen);
    if (unlikely(ret < 0))
    {
        LOG_ERROR("send_msg_req format failed!\n");
        
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        
        return -1;
    }
    if ( ret > 0 || outlen <= 0 )
    {
        
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        
        return 1;
    }

    connection_t *pcon = g_con[g_connect_fd].con;
    if (pcon == NULL)
    {
        LOG_ERROR("pcon is null\n");
        
        if( outbuf != NULL )
        {
            free(outbuf);
            outbuf = NULL;
        }
        
        return -1;
    }
    buffer_t * pbuffer = pcon->sndbuf;
    int freesize = pbuffer->get_free_size(pbuffer);
    char* writeptr = pbuffer->get_write_ptr(pbuffer);
    if (outlen <= freesize)
    {
        memcpy(writeptr, outbuf, outlen);
        pbuffer->set_write_size(pbuffer, outlen);
    }

    dlist_insert_tail(write, pcon);

    if( outbuf != NULL )
    {
        free(outbuf);
        outbuf = NULL;
    }

    return 0;
}
