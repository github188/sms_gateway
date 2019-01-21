#include "wcwxunicom.h"
#include "gateway_util.h"
#include "charset_conv.h"
#include <json/json.h>
#include <list>

int WcwxUnicomBiz::random = 0;

WcwxUnicomBiz::WcwxUnicomBiz()
{

}

WcwxUnicomBiz::~WcwxUnicomBiz()
{

}

int WcwxUnicomBiz::channel_rsp(dict* wq,
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

    //判断报文类型
    switch( cache->busi_type )
    {
    case 0://发送应答
        {
            ret = handle_submit_rsp(cache->seq_id,body,body_len);
            break;
        }
    case 1://状态报告应答
        {
            ret = handle_report_rsp(cache->seq_id,body,body_len);
            break;
        }
    case 2://上行短信应答
        {
            ret = handle_uplink_rsp(cache->seq_id,body,body_len);
            break;
        }
	default:
	    {
    		LOG_ERROR("unknown busi_type : %d\n", cache->busi_type);
            ret = -1;
    		break;
        }
    }
    delete_wait_cache(wq, sid);
    return ret;
}

int WcwxUnicomBiz::send_msg_req(dict* wq,
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

    list<string> lstPhones;
    string sPhoneList;
    uint32_t uPhoneCount = 0;
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
            if( uPhoneCount >= 500 )
            {
                lstPhones.push_back(sPhoneList);
                uPhoneCount = 0;
                sPhoneList = "";
            }
            uPhoneCount++;
            ++itPhone;
        }
    }
    if (uPhoneCount > 0)
    {
        lstPhones.push_back(sPhoneList);
    }
    if( lstPhones.size() == 0 )
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

    // 组装JSON
    Json::Value jsonRoot, jsonParams, jsonSubmits;
    Json::FastWriter jsonWriter;
    list<string>::iterator it_ls;
    for (it_ls = lstPhones.begin(); it_ls != lstPhones.end(); it_ls++)
    {
        Json::Value jsonSubmit;
        jsonSubmit["phone"] = Json::Value(*it_ls);
        jsonSubmit["content"] = Json::Value(msg);
        jsonSubmits.append(jsonSubmit);
    }
    jsonParams["userid"] = Json::Value(m_channel->sUserName);
    jsonParams["password"] = Json::Value(m_channel->sPassword);
    jsonParams["submit"] = jsonSubmits;
    jsonRoot["id"] = Json::Value(1);
    jsonRoot["method"] = Json::Value(std::string("send"));
    jsonRoot["params"] = jsonParams;

    string sPostContent = jsonWriter.write(jsonRoot);
    
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

    uri.append("/jsonrpc2.jsp");

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

int WcwxUnicomBiz::timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len )
{
    if( wq == NULL || m_channel == NULL )
    {
        return -1;
    }

    //清理超时报文
    clear_time_out_rsp(wq);

    //---------------------------轮询发送获取短信状态或上行短信---------------------------
    http_wait_cache_t wi;
    strncpy(wi.sid, sid, sizeof(wi.sid) - 1);
    wi.uptime = get_utc_miliseconds();
    wi.seq_id = get_ui_seq();

    Json::Value jsonRoot, jsonParam;
    Json::FastWriter jsonWriter;
    string sPostContent;
    if( random == 0 )
    {
        random = 1;
        //发送获取短信报告
        jsonParam["userid"] = Json::Value(m_channel->sUserName);
        jsonParam["password"] = Json::Value(m_channel->sPassword);
        jsonRoot["id"] = Json::Value(1);
        jsonRoot["method"] = Json::Value("report");
        jsonRoot["params"] = jsonParam;
        wi.busi_type = 1;
    }
    else
    {
        random = 0;
        //获取上行短信
        jsonParam["userid"] = Json::Value(m_channel->sUserName);
        jsonParam["password"] = Json::Value(m_channel->sPassword);
        jsonRoot["id"] = Json::Value(1);
        jsonRoot["method"] = Json::Value("upmsg");
        jsonRoot["params"] = jsonParam;
        wi.busi_type = 2;
    }
    sPostContent = jsonWriter.write(jsonRoot);
    
    insert_wait_cache(wq, wi);
    
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

    uri.append("/jsonrpc2.jsp");

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

    return 0;
}

int WcwxUnicomBiz::handle_submit_rsp(uint32_t seq_id,const char* body,int len)
{
    string sMessageid;
    string sRespCode;
    string sPostResponse = body;
    Json::Value jsonValue;
    Json::Reader jsonReader;
    if (!jsonReader.parse(sPostResponse, jsonValue))
    {
        LOG_ERROR("Parse the post response is failure.The post response:%s\n", sPostResponse.c_str());
        return -1;
    }
    Json::Value jsonResult = jsonValue["result"];
    if (jsonResult.size() == 0)
    {
        //生成内部msgsid
        char szSessionID[64];
        memset(szSessionID,0,sizeof(szSessionID));
        get_sid_str(0,szSessionID,sizeof(szSessionID));
        sMessageid = szSessionID;
        sRespCode = "-1";
    }
    else
    {
        //每个号码的msgid不一样?
        for (uint32_t uIndex = 0; uIndex < jsonResult.size(); uIndex++)
        {
            string sMobilePhone = jsonResult[uIndex]["phone"].asString();
            sMessageid = jsonResult[uIndex]["msgid"].asString();
        }
        //转换成统一成功返回码
        sRespCode = "0";
    }
    LOG_INFO("recv submit rsp.msgid[%s]status[%s]\n",sMessageid.c_str(),sRespCode.c_str());
    //将应答报文写入redis
    save_message_response(seq_id,sRespCode,sMessageid);

    return 1;
}

int WcwxUnicomBiz::handle_report_rsp(uint32_t seq_id,const char* body,int len)
{
    string sPostResponse = body;
    Json::Value jsonValue;
    Json::Reader jsonReader;
    if (!jsonReader.parse(sPostResponse, jsonValue))
    {
        LOG_ERROR("Parse the post response is failure.The post response:%s.\n", sPostResponse.c_str());
        return -1;
    }
    Json::Value jsonResult = jsonValue["result"];
    for (uint32_t uIndex = 0; uIndex < jsonResult.size(); uIndex++)
    {
        string sMobilePhone = jsonResult[uIndex]["phone"].asString();
        string sMessageId = jsonResult[uIndex]["msgid"].asString();
        string sStatus = jsonResult[uIndex]["status"].asString();
        if (sStatus.compare("0") == 0)
            sStatus = "DELIVRD";
        else
            sStatus = "UNDELIV";

        LOG_INFO("recv report rsp.msgid[%s]phone[%s]status[%s]\n",
                                        sMessageId.c_str(),
                                        sMobilePhone.c_str(),
                                        sStatus.c_str());
        //将状态报告写入redis
        save_message_report(sMessageId,sMobilePhone,"",sStatus,sStatus);
    }

    return 1;
}

int WcwxUnicomBiz::handle_uplink_rsp(uint32_t seq_id,const char* body,int len)
{
    string sPostResponse = body;
    Json::Value jsonValue;
    Json::Reader jsonReader;
    if( !jsonReader.parse(sPostResponse, jsonValue) )
    {
        LOG_ERROR("Parse the post response is failure.The post response:%s.\n", sPostResponse.c_str());
        return -1;
    }
    Json::Value jsonResult = jsonValue["result"];
    for (uint32_t uIndex = 0; uIndex < jsonResult.size(); uIndex++)
    {
        string sPhone = jsonResult[uIndex]["phone"].asString();
        string sContent = jsonResult[uIndex]["msgcontent"].asString();
        string accesscode = "";
        LOG_INFO("recv uplink rsp.src_phone[%s]dest_phone[%s]\n",
                                        sPhone.c_str(),
                                        accesscode.c_str());
        //将上行短信写入redis
        save_message_uplink(sPhone,accesscode,sContent);
    }

    return 1;
}
