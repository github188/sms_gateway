#include "ytmobile.h"
#include "gateway_util.h"
#include "gateway_crypt.h"
#include "Markup.h"

int YtMobileBiz::random = 0;

YtMobileBiz::YtMobileBiz()
{

}

YtMobileBiz::~YtMobileBiz()
{

}

int YtMobileBiz::channel_rsp(dict* wq,
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

int YtMobileBiz::send_msg_req(dict* wq,
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

    //短信内容URL编码
    char msg[MAX_MSG_LEN] = {0};
    url_encode(packet->sMessageContent.c_str(),msg,MAX_MSG_LEN);

    //密码做md5
    char MD5result[33] = {0};
    my_compute_md5(m_channel->sPassword.c_str(),m_channel->sPassword.length(),MD5result,sizeof(MD5result));

    string sPostContent;
    sPostContent.append("action=send&account=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&password=");
    sPostContent.append(MD5result);
    sPostContent.append("&mobile=");
    sPostContent.append(sPhoneList);
    sPostContent.append("&content=");
    sPostContent.append(msg);
    sPostContent.append("&sendTime=&extno=");

    string uri = "/sms.aspx";
    
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

int YtMobileBiz::timer_process( dict* wq,
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
    char MD5result[33] = {0};
    my_compute_md5(m_channel->sPassword.c_str(),m_channel->sPassword.length(),MD5result,sizeof(MD5result));

    http_wait_cache_t wi;
    strncpy(wi.sid, sid, sizeof(wi.sid) - 1);
    wi.uptime = get_utc_miliseconds();
    wi.seq_id = get_ui_seq();
    string uri;
    if( random == 0 )
    {
        random = 1;
        //发送获取短信报告
        uri = "/statusApi.aspx";
        wi.busi_type = 1;
    }
    else
    {
        random = 0;
        //获取上行短信
        uri = "/callApi.aspx";
        wi.busi_type = 2;
    }
    insert_wait_cache(wq, wi);

    string sPostContent;
    sPostContent.append("action=query");
    sPostContent.append("&account=");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("&password=");
    sPostContent.append(MD5result);

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

int YtMobileBiz::handle_submit_rsp(uint32_t seq_id,const char* body,int len)
{
    string sRespCode;
    string sMessageid;
    CMarkup xml;
    xml.SetDoc(body);
    if ( xml.FindElem("returnsms") )
    {
        xml.IntoElem();
        HTTP_XML_GETITEM(xml, "returnstatus", sRespCode);
        HTTP_XML_GETITEM(xml, "taskID", sMessageid);
        xml.OutOfElem();
    }
    //响应无数据
    if( sRespCode.empty() )
    {
        LOG_ERROR("submit rsp is null. buf[%s]\n",body);
        return -1;
    }
    if( sRespCode.compare("Success") != 0 )
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

int YtMobileBiz::handle_report_rsp(uint32_t seq_id,const char* body,int len)
{
    CMarkup xml;
    xml.SetDoc(body);
    if ( xml.FindElem("returnsms") )
    {
        xml.IntoElem();
        while( xml.FindElem("statusbox") )
        {
            xml.IntoElem();
            string mobile;
            string msgid;
            string status;
            string receivetime;
            string errorcode;
            HTTP_XML_GETITEM(xml, "mobile", mobile);
            HTTP_XML_GETITEM(xml, "taskid", msgid);
            HTTP_XML_GETITEM(xml, "status", status);
            HTTP_XML_GETITEM(xml, "receivetime", receivetime);
            HTTP_XML_GETITEM(xml, "errorcode", errorcode);
            if( mobile.empty() ||
                msgid.empty() ||
                status.empty() ||
                errorcode.empty() )
            {
                continue;
            }
            LOG_INFO("recv report rsp.msgid[%s]phone[%s]status[%s]\n",
                                        msgid.c_str(),
                                        mobile.c_str(),
                                        status.c_str());
            //将状态报告写入redis
            save_message_report(msgid,mobile,"",errorcode,errorcode);
            xml.OutOfElem();
        }
        xml.OutOfElem();
    }
    return 1;
}

int YtMobileBiz::handle_uplink_rsp(uint32_t seq_id,const char* body,int len)
{
    CMarkup xml;
    xml.SetDoc(body);
    if ( xml.FindElem("returnsms") )
    {
        xml.IntoElem();
        while( xml.FindElem("callbox") )
        {
            xml.IntoElem();
            string mobile;
            string msgid;
            string content;
            string receivetime;
            HTTP_XML_GETITEM(xml, "mobile", mobile);
            HTTP_XML_GETITEM(xml, "extno", msgid);
            HTTP_XML_GETITEM(xml, "content", content);
            HTTP_XML_GETITEM(xml, "receivetime", receivetime);
            if( mobile.empty() ||
                msgid.empty() ||
                content.empty() )
            {
                continue;
            }
            //接入号需要到mangodb查询
            string accesscode = m_channel->sAccessCode + msgid;
            LOG_INFO("recv uplink rsp.msgid[%s]src_phone[%s]dest_phone[%s]\n",
                                        msgid.c_str(),
                                        mobile.c_str(),
                                        accesscode.c_str());
            //将上行短信写入redis
            save_message_uplink(mobile,accesscode,content);
            xml.OutOfElem();
        }
        xml.OutOfElem();
    }
    return 1;
}
