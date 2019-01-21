#include "mengxin.h"
#include "gateway_util.h"
#include "charset_conv.h"
#include "Markup.h"

int MengxinBiz::random = 0;

MengxinBiz::MengxinBiz()
{

}

MengxinBiz::~MengxinBiz()
{

}

int MengxinBiz::channel_rsp(dict* wq,
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

int MengxinBiz::send_msg_req(dict* wq,
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
    string utf8;
    // 将GBK编码转为UTF-8编码
    ascii_to_utf8(packet->sMessageContent,utf8);

    //短信内容URL编码
    char msg[MAX_MSG_LEN] = {0};
    url_encode(utf8.c_str(),msg,MAX_MSG_LEN);

    string sPostContent;
    sPostContent.append("Account=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&Password=");
    sPostContent.append(m_channel->sPassword);
    sPostContent.append("&Phones=");
    sPostContent.append(sPhoneList);
    sPostContent.append("&Content=");
    sPostContent.append(msg);
    sPostContent.append("&Channel=1&SendTime=");

    string uri = "/SendSms.asp";

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

int MengxinBiz::timer_process( dict* wq,
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

    string uri;
    string sPostContent;
    sPostContent.append("Account=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&Password=");
    sPostContent.append(m_channel->sPassword);
    if( random == 0 )
    {
        random = 1;
        //发送获取短信报告
        uri = "/GetReport.asp";
        wi.busi_type = 1;
    }
    else
    {
        random = 0;
        //获取上行短信
        uri = "/GetMessage.asp";
        wi.busi_type = 2;
    }
    insert_wait_cache(wq, wi);
    
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

int MengxinBiz::handle_submit_rsp(uint32_t seq_id,const char* body,int len)
{
    string sMessageid = body;
    string sRespCode = "-1";
    if( atoi( body ) <= 0 )
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

int MengxinBiz::handle_report_rsp(uint32_t seq_id,const char* body,int len)
{
    string gbk;
    //响应内容转成gbk
    utf8_to_ascii(body,gbk);

    vector<string> report_vec;
    SplitString(report_vec,gbk,"||||");

    vector<string>::iterator iter;
    for (iter = report_vec.begin(); iter != report_vec.end(); iter++)
    {
        vector<string> item_vec;
        SplitString(item_vec,*iter,"$$$$");
        if( item_vec.size() < 5 )
        {
            continue;
        }
        // 获取消息ID
        string sMessageId = item_vec[0];
        // 获取手机号码
        string sPhone = item_vec[1];
            // 获取短信状态
        string sStatus = item_vec[4];
        LOG_INFO("recv report rsp.msgid[%s]phone[%s]status[%s]\n",
                                        sMessageId.c_str(),
                                        sPhone.c_str(),
                                        sStatus.c_str());
        //将状态报告写入redis
        save_message_report(sMessageId,sPhone,"",sStatus,sStatus);
    }

    return 1;
}

int MengxinBiz::handle_uplink_rsp(uint32_t seq_id,const char* body,int len)
{
    string gbk;
    //响应内容转成gbk
    utf8_to_ascii(body,gbk);

    vector<string> uplink_vec;
    SplitString(uplink_vec,gbk,"||||");

    vector<string>::iterator iter;
    for (iter = uplink_vec.begin(); iter != uplink_vec.end(); iter++)
    {
        vector<string> item_vec;
        SplitString(item_vec,*iter,"$$$$");
        if( item_vec.size() < 2 )
        {
            continue;
        }
        // 获取手机号码
        string sPhone = item_vec[0];
            // 获取短信内容
        string sContent = item_vec[1];

        LOG_INFO("recv uplink rsp.src_phone[%s]\n",sPhone.c_str());
        //将上行短信写入redis
        save_message_uplink(sPhone,"",sContent);
    }

    return 1;
}
