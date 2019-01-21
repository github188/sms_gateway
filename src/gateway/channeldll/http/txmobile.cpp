#include "txmobile.h"
#include "gateway_util.h"
#include "gateway_crypt.h"
#include "charset_conv.h"
#include <json/json.h>

TxMobileBiz::TxMobileBiz()
{

}

TxMobileBiz::~TxMobileBiz()
{

}

int TxMobileBiz::is_need_to_listen(int& need_to_listen,int& listen_port)
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

int TxMobileBiz::channel_req(const char* in_msg,int in_len,char* out_msg,int& out_len)
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

    if ( strcmp(uri, "/smsreport") == 0 )
    {
        //解析请求参数
        string sReport = http_get_field(body, "report");
        if ( sReport.empty() )
        {
            LOG_ERROR("The request param is error.\n");
            return -1;
        }

        vector<string> report_vec;
        SplitString(report_vec,sReport,";");
        vector<string>::iterator iter;
        for (iter = report_vec.begin(); iter != report_vec.end(); iter++)
        {
            vector<string> item_vec;
            SplitString(item_vec,*iter,",");
            if( item_vec.size() < 4 )
            {
                continue;
            }
            // 获取手机号码
            string sPhone = item_vec[0];
                // 获取短信状态
            string sStatus = item_vec[1];
            // 获取消息ID
            string sMessageId = item_vec[3];
            LOG_INFO("recv report rsp.msgid[%s]phone[%s]status[%s]\n",
                                        sMessageId.c_str(),
                                        sPhone.c_str(),
                                        sStatus.c_str());
            //将状态报告写入redis
            save_message_report(sMessageId,sPhone,"",sStatus,sStatus);
        }
    }
    else if( strcmp(uri, "/smsmo") == 0  )
    {
        //解析请求参数
        string sMobilePhone = http_get_field(body, "sender");
        string sMessageContent = http_get_field(body, "content");
        string sDestPhone = http_get_field(body, "receiver");

        if ( sMobilePhone.empty() || sMessageContent.empty() || sDestPhone.empty() )
        {
            LOG_ERROR("The request param is error.\n");
            return -1;
        }
        LOG_INFO("recv uplink rsp.src_phone[%s]dest_phone[%s]\n",
                                        sMobilePhone.c_str(),
                                        sDestPhone.c_str());
        //将上行短信写入redis
        save_message_uplink(sMobilePhone,sDestPhone,sMessageContent);
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

int TxMobileBiz::channel_rsp(dict* wq,
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

    string sMessageid = http_get_field(body, "linkid");
    string sRespCode = http_get_field(body, "result");

    if( sRespCode.empty() )
    {
        LOG_ERROR("submit rsp result is null.\n");
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

int TxMobileBiz::send_msg_req(dict* wq,
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

    //当前时间
    char sDateTime[15] = {0};
    get_date_time(sDateTime,sizeof(sDateTime));
    string strMd5Password = m_channel->sPassword + sDateTime;
    //对密码+当前时间做md5
    char MD5result[33] = {0};
    my_compute_md5(strMd5Password.c_str(),strMd5Password.length(),MD5result,sizeof(MD5result));

    string sPostContent;
    sPostContent.append("username=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&password=");
    sPostContent.append(MD5result);
    sPostContent.append("&content=");
    sPostContent.append(msg);
    sPostContent.append("&mobiles=");
    sPostContent.append(sPhoneList);
    sPostContent.append("&timestamp=");
    sPostContent.append(sDateTime);

    //http://api.sms1086.com/api/Sendutf8.aspx
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

int TxMobileBiz::timer_process( dict* wq,
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
    
    return 1;
}
