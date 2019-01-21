#include "masmobile.h"
#include "gateway_util.h"
#include <json/json.h>

MasBiz::MasBiz()
{

}

MasBiz::~MasBiz()
{

}

int MasBiz::is_need_to_listen(int& need_to_listen,int& listen_port)
{
    if( m_channel == NULL )
    {
        LOG_ERROR("m_channel is null.\n");
        return -1;
    }

    if( m_channel->uCustomParam2 > 1024 || m_channel->uCustomParam2 < 65535 )
    {
        need_to_listen = 1;
        listen_port = m_channel->uCustomParam2;
    }
    else
    {
        need_to_listen = 0;
    }

    return 0;
}

int MasBiz::channel_req(const char* in_msg,int in_len,char* out_msg,int& out_len)
{
    if( in_msg == NULL || out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }
    
    const char *pos_uri = strstr(in_msg, " ");
    if (pos_uri == NULL) 
    {
        return -1;
    }
    const char *pos_uri_end = strstr(pos_uri+1, " ");
    if (pos_uri_end == NULL) 
    {
        return -1;
    }

    char uri[MAX_PATH_LEN] = {0};
    strncpy(uri, pos_uri + 1, pos_uri_end - (pos_uri + 1));

    LOG_INFO("req uri = [%s]\n", uri);

    //Content
    char body[MAX_PACKET_LEN] = {0};
    int body_len = 0;
    int ret = parse_http_hdr(in_msg,in_len,0,body,body_len);
    if( ret < 0 )
    {
        LOG_ERROR("parse_http_hdr fail.\n");
        return -1;
    }

    if ( strcmp(uri, "/smsrecv") == 0 )
    {
        string sType = http_get_field(body, "type");
        if( sType.empty() )
        {
            LOG_ERROR("type is null.\n");
            return -1;
        }

        string status_json = http_get_field(body, "status");
        if( status_json.empty() )
        {
            LOG_ERROR("status_json is null.\n");
            return -1;
        }

        if (sType.compare("0") == 0)
        {
            // 状态报告
            // 解析json
            Json::Reader jsonReader;
            Json::Value  jsonReportList;
            try
            {
                if (!jsonReader.parse(status_json, jsonReportList))
                {
                    LOG_ERROR("parse report list json is failure.json:%s.\n", status_json.c_str());
                    return -1;
                }

                for (uint32_t index = 0; index < jsonReportList.size(); index++)
                {
                    string sFlag = jsonReportList[index]["flag"].asString();
                    string sMobile = jsonReportList[index]["mobile"].asString();
                    string sStatus = jsonReportList[index]["status"].asString();
                    string sRecvTime = jsonReportList[index]["responseTime"].asString();
                    string sMsgId = jsonReportList[index]["smsId"].asString();
                    if (sFlag.compare("success") == 0 && sStatus.compare("0") == 0) 
                        sStatus = "DELIVRD";
                    LOG_INFO("recv report rsp.msgid[%s]phone[%s]status[%s]\n",
                                        sMsgId.c_str(),
                                        sMobile.c_str(),
                                        sStatus.c_str());
                    //状态写入redis
                    save_message_report(sMsgId,sMobile,"",sStatus,sStatus);
                }
            }
            catch (Json::LogicError &ex)
            {
                LOG_ERROR("parse report is failure.the exception:%s.\n", ex.what());
                return -1;
            }
        }
        else if (sType.compare("1") == 0)
        {
            // 上行短信
            // 解析json
            Json::Reader jsonReader;
            Json::Value  jsonUplinkList;
            try
            {
                if (!jsonReader.parse(status_json, jsonUplinkList))
                {
                    LOG_ERROR("parse report list json is failure.json:%s.\n", status_json.c_str());
                    return -1;
                }
                for (uint32_t index = 0; index < jsonUplinkList.size(); index++)
                {
                    string sMsgId = jsonUplinkList[index]["msgId"].asString();
                    string sMobilephone = jsonUplinkList[index]["mobile"].asString();
                    string sAccessCode = jsonUplinkList[index]["destMobile"].asString();
                    string sMessageContent = jsonUplinkList[index]["message"].asString();
                    LOG_INFO("recv uplink rsp.msgid[%s]srcphone[%s]destphone[%s]\n",
                                        sMsgId.c_str(),
                                        sMobilephone.c_str(),
                                        sAccessCode.c_str());
                    //将上行短信写入redis
                    save_message_uplink(sMobilephone,sAccessCode,sMessageContent);
                }
            }
            catch (Json::LogicError &ex)
            {
                LOG_ERROR("parse report is failure.the exception:%s.\n", ex.what());
                return -1;
            }
        }
        else
        {
            LOG_ERROR("unknown type. %s\n",sType.c_str());
            return -1;
        }
    }
    else
    {
        LOG_ERROR("unknown command. %s\n",uri);
        return -1;
    }

    out_len = sprintf(out_msg,  "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "\r\n");

    LOG_INFO("return message[%d]\n%s\n", out_len, out_msg);

    return 0;
}

int MasBiz::channel_rsp(dict* wq,
                          const char* in_msg, 
                          int in_len,
                          char *sid,
                          char* out_msg, 
                          int& out_len)
{
    if( in_msg == NULL || out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }
    
    http_wait_cache_t* cache = get_wait_cache(wq, sid);
    if( cache == NULL )
    {
        LOG_ERROR("cache not found, maybe it is timeout. sid = %s\n", sid);
        return -1;
    }

    char body[MAX_PACKET_LEN] = {0};
    int body_len = 0;
    int ret = parse_http_hdr(in_msg,in_len,0,body,body_len);
    if( ret < 0 )
    {
        LOG_ERROR("parse_http_hdr fail.\n");
        return -1;
    }

    string content = body;

    string sMessageid;
    string sRespCode;
    Json::Reader jsonReader;
    Json::Value jsonValue;
    try
    {
        if (!jsonReader.parse(content, jsonValue))
        {
            LOG_ERROR("Parse report list json is failure.The json:%s.\n", content.c_str());
            return -1;
        }
        // 获取提交结果
        sRespCode = jsonValue["code"].asString();
        // 获取消息id
        sMessageid = jsonValue["siSmsId"].asString();
    }
    catch (Json::LogicError &ex)
    {
        LOG_ERROR("parse message submit is failure.The exception:%s.\n", ex.what());
        return -1;
    }

    if (sRespCode.compare("0") != 0)
    {
        //生成内部msgsid
        char szSessionID[64];
        memset(szSessionID,0,sizeof(szSessionID));
        get_sid_str(0,szSessionID,sizeof(szSessionID));
        sMessageid = szSessionID;
    }

    LOG_INFO("recv submit rsp.msgid[%s]status[%s]\n",sMessageid.c_str(),sRespCode.c_str());

    //将应答报文写入redis
    save_message_response(cache->seq_id,sRespCode,sMessageid);

    delete_wait_cache(wq, sid);

    return 1;
}

int MasBiz::send_msg_req(dict* wq,
                             message_packet_t *packet,
                             char *sid,
                             char* out_msg, 
                             int& out_len)
{
    if( packet == NULL || out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }

    uint32_t seq_id = get_ui_seq();

    LOG_INFO("Sendmsg to channel.phone size[%d]seq_id[%u]\n",packet->mPhoneList.size(),seq_id);

    string sPhoneList;
    map<string,sms_attribute_t>::iterator itPhone;
    for (itPhone = packet->mPhoneList.begin(); itPhone != packet->mPhoneList.end();)
    {
        if( !itPhone->second.bNeedSend )// 黑名单、扣量短信算提交成功
        {
            message_response_t msgResponse;
            msgResponse.sSrcPhone = packet->sSrcPhone;
            msgResponse.uSmsCount = GetSmsCount(packet->sMessageContent);
            msgResponse.uChannelType = packet->uChannelType;
            msgResponse.sChannelId = packet->sChannelId;
            msgResponse.sChannelGroupId = packet->sChannelGroupId;
            msgResponse.smsArgument = packet->smsArgument;
            msgResponse.uNosendCount = 0;
            msgResponse.uErrorCount = 0;
            msgResponse.uSuccessCount = 0;
            msgResponse.uFailCount = 0;
            msgResponse.sSendTime = MakeDateTime();
            msgResponse.mPhoneList[itPhone->first] = itPhone->second;
            //写redis
            save_message_response( 0,&msgResponse );
            packet->mPhoneList.erase(itPhone++);
            continue;
        }
        else
        {
            if( sPhoneList.empty() )
            {
                sPhoneList = itPhone->second.sMobilePhone;
            }
            else
            {
                sPhoneList += "," + itPhone->second.sMobilePhone;
            }
            ++itPhone;
        }
    }
    if( sPhoneList.empty() )
    {
        LOG_INFO("no phone need send to channel.\n");
        out_len = 0;
        return 1;
    }

    //加入应答映射表
    append_response_map(seq_id,packet);

    //短信内容URL编码
    char msg[MAX_MSG_LEN] = {0};
    url_encode(packet->sMessageContent.c_str(),msg,MAX_MSG_LEN);

    string sPostContent;
    sPostContent.append("operatorId=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&password=");
    sPostContent.append(m_channel->sPassword);
    sPostContent.append("&mobiles=");
    sPostContent.append(sPhoneList);
    sPostContent.append("&message=");
    sPostContent.append(msg);
    sPostContent.append("&channelId=");
    sPostContent.append(to_string(m_channel->uCustomParam1));
    sPostContent.append("&sendMethod=0&needDelivery=1&sendLevel=0");

    //http://sms.cnmas.cn:5001/ws/sendSms
    string uri;
    size_t szHttpEnd = m_channel->sHttpUrl.find("//");
    if( szHttpEnd == string::npos )
    {
        szHttpEnd = m_channel->sHttpUrl.find("/");
		if( szHttpEnd == string::npos )
		{
			uri = "";
		}
		else
		{
			uri = m_channel->sHttpUrl.substr(szHttpEnd, m_channel->sHttpUrl.length() - szHttpEnd );
		}
    }
    else
    {
        string tmp = m_channel->sHttpUrl.substr(szHttpEnd + 2, 
                                                m_channel->sHttpUrl.length() - szHttpEnd - 2 );
        size_t szPreEnd = tmp.find("/");
		if( szPreEnd == string::npos )
		{
			uri = "";
		}
		else
		{
			uri = tmp.substr(szPreEnd, tmp.length() - szPreEnd );
		}
    }

    out_len = sprintf(out_msg,"POST %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "Content-Length: %lu\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "\r\n"
                        "%s",
                        uri.c_str(),
                        m_channel->sIpAddress.c_str(),
                        m_channel->lPort,
                        sPostContent.length(),
                        sPostContent.c_str());

    LOG_INFO("out_msg[%d]\n%s\n", out_len, out_msg);

    http_wait_cache_t wi;
    strncpy(wi.sid, sid, sizeof(wi.sid) - 1);
    wi.busi_type = 0;
    wi.uptime = get_utc_miliseconds();
    wi.seq_id = seq_id;

    insert_wait_cache(wq, wi);

    return 0;
}

int MasBiz::timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len )
{
    if( wq == NULL || m_channel == NULL )
    {
        return -1;
    }

    out_len = 0;
    
    //清理超时报文
    clear_time_out_rsp(wq);
    
    return 1;
}
