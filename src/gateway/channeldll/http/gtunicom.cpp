#include "gtunicom.h"
#include "gateway_util.h"
#include "charset_conv.h"
#include "Markup.h"

int GtUnicomBiz::random = 0;

GtUnicomBiz::GtUnicomBiz()
{

}

GtUnicomBiz::~GtUnicomBiz()
{

}

int GtUnicomBiz::channel_rsp(dict* wq,
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

int GtUnicomBiz::send_msg_req(dict* wq,
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

    //短信内容
    string gbk;
    utf8_to_ascii(packet->sMessageContent,gbk);

    //短信内容URL编码
    char msg[MAX_MSG_LEN] = {0};
    url_encode(gbk.c_str(),msg,MAX_MSG_LEN);

    string sPostContent;
    sPostContent.append("act=sendmsg&unitid=100&username=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&passwd=");
    sPostContent.append(m_channel->sPassword);
    sPostContent.append("&phone=");
    sPostContent.append(sPhoneList);
    sPostContent.append("&msg=");
    sPostContent.append(msg);

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
    wi.seq_id = seq_id;
    wi.uptime = get_utc_miliseconds();

    insert_wait_cache(wq, wi);

    return 0;
}

int GtUnicomBiz::timer_process( dict* wq,
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
    wi.seq_id = get_ui_seq();
    wi.uptime = get_utc_miliseconds();

    string sPostContent;
    if( random == 0 )
    {
        random = 1;
        //发送获取短信报告
        sPostContent.append("act=getstatue&unitid=100&username=");
        sPostContent.append(m_channel->sUserName);
        sPostContent.append("&passwd=");
        sPostContent.append(m_channel->sPassword);
        sPostContent.append("&rowid=0");
        wi.busi_type = 1;
    }
    else
    {
        random = 0;
        //获取上行短信
        sPostContent.append("act=smsrecord&unitid=100&username=");
        sPostContent.append(m_channel->sUserName);
        sPostContent.append("&passwd=");
        sPostContent.append(m_channel->sPassword);
        sPostContent.append("&rowid=0");
        wi.busi_type = 2;
    }
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

int GtUnicomBiz::handle_submit_rsp(uint32_t seq_id,const char* body,int len)
{
    string sMessageid;
    string sRespCode;
    string utf8;
    ascii_to_utf8(body,utf8);

    size_t uRespIndex = utf8.find(',');
    if( uRespIndex == string::npos )
    {
        LOG_ERROR("submit rsp is null. buf[%s]\n",body);
        return -1;
    }
    sRespCode = utf8.substr(0, uRespIndex);
    utf8 = utf8.substr(uRespIndex+1);
    uRespIndex = utf8.find(',');
    if( uRespIndex == string::npos )
    {
        sMessageid = "";
    }
    else
    {
        sMessageid = utf8.substr(0, uRespIndex);
    }

    if( sRespCode.compare("1") != 0 )
    {
        //生成内部msgsid
        char szSessionID[64];
        memset(szSessionID,0,sizeof(szSessionID));
        get_sid_str(0,szSessionID,sizeof(szSessionID));
        sMessageid = szSessionID;
    }
    else
    {
        //转换成统一成功返回码
        sRespCode = "0";
    }
    LOG_INFO("recv submit rsp.msgid[%s]status[%s]\n",sMessageid.c_str(),sRespCode.c_str());
    //将应答报文写入redis
    save_message_response(seq_id,sRespCode,sMessageid);

    return 1;
}

int GtUnicomBiz::handle_report_rsp(uint32_t seq_id,const char* body,int len)
{
    string sPostResponse = body;

    vector<string> report_vec;
    SplitString(report_vec,sPostResponse,"|;|");

    vector<string>::iterator iter;
    for (iter = report_vec.begin(); iter != report_vec.end(); iter++)
    {
        vector<string> item_vec;
        SplitString(item_vec,*iter,"|^|");
        if( item_vec.size() < 3 )
        {
            continue;
        }
        // 获取消息ID
        string sMessageId = item_vec[0];
        // 获取手机号码
        string sPhone = item_vec[1];
            // 获取短信状态
        string sStatus = item_vec[2];
        LOG_INFO("recv report rsp.msgid[%s]phone[%s]status[%s]\n",
                                        sMessageId.c_str(),
                                        sPhone.c_str(),
                                        sStatus.c_str());
        //将状态报告写入redis
        save_message_report(sMessageId,sPhone,"",sStatus,sStatus);
    }

    return 1;
}

int GtUnicomBiz::handle_uplink_rsp(uint32_t seq_id,const char* body,int len)
{
    string sPostResponse = body;

    vector<string> uplink_vec;
    SplitString(uplink_vec,sPostResponse,"|;|");

    vector<string>::iterator iter;
    for (iter = uplink_vec.begin(); iter != uplink_vec.end(); iter++)
    {
        vector<string> item_vec;
        SplitString(item_vec,*iter,"|^|");
        if( item_vec.size() < 3 )
        {
            continue;
        }

        // 获取消息ID
        string sMessageId = item_vec[0];
        // 获取手机号码
        string sPhone = item_vec[1];
            // 获取短信内容
        string sContent = item_vec[2];

        string utf8;
        ascii_to_utf8(sContent,utf8);

        //接入号需要到mangodb查询
        string accesscode = "";
        if (!m_mongo_db.GetAccessCode(sMessageId, sPhone, accesscode))
        {
            LOG_ERROR("Get access code is fail.taskid[%s]mobile[%s]content[%s]",
                                        sMessageId.c_str(),
                                        sPhone.c_str(),
                                        utf8.c_str());
        }
        LOG_INFO("recv uplink rsp.msgid[%s]src_phone[%s]dest_phone[%s]\n",
                                        sMessageId.c_str(),
                                        sPhone.c_str(),
                                        accesscode.c_str());
        //将上行短信写入redis
        save_message_uplink(sPhone,accesscode,utf8);
    }

    return 1;
}
