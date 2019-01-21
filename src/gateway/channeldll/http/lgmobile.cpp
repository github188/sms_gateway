#include "lgmobile.h"
#include "gateway_util.h"
#include "Markup.h"

LgMobileBiz::LgMobileBiz()
{

}

LgMobileBiz::~LgMobileBiz()
{

}

int LgMobileBiz::channel_rsp(dict* wq,
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

int LgMobileBiz::send_msg_req(dict* wq,
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

    //短信内容base64编码
    string msg_ct;
    int nHeader = packet->sMessageContent.find("【");
    int nTail = packet->sMessageContent.find("】");
    if (nHeader == 0)
    {
        msg_ct = packet->sMessageContent.substr(nTail + 3, packet->sMessageContent.length() - nTail - 3);
    }
    else
    {
        msg_ct = packet->sMessageContent.substr(0, packet->sMessageContent.length() - nHeader);
    }

    char *pMsg = new char[MAX_PACKET_LEN];
    if( pMsg == NULL )
    {
        LOG_ERROR("failed to allocate memory for pMsg.\n");
        return -1;
    }
    memset(pMsg,0,MAX_PACKET_LEN);
    int base64_len = MAX_PACKET_LEN;
    int ret = base64_encode((unsigned char*)msg_ct.c_str(),msg_ct.length(),
                            (unsigned char*)pMsg,&base64_len);
    if( ret != 0 )
    {
        LOG_ERROR("base64_encode fail.src len[%d]\n",msg_ct.length());
        delete [] pMsg;
        pMsg = NULL;
        return -1;
    }

    string sPostContent;
    sPostContent.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
    sPostContent.append("<Root version=\"2.0\" User=\"");
    sPostContent.append(m_channel->sUserName);
    sPostContent.append("\" PWD=\"");
    sPostContent.append(m_channel->sPassword);
    sPostContent.append("\" UserType=\"8\"");
    sPostContent.append(" CorpCode=\"");
    sPostContent.append(m_channel->sAccessCode);
    sPostContent.append("\" >");
    sPostContent.append("<SMS>");
    sPostContent.append("<M>");
    sPostContent.append(pMsg);
    sPostContent.append("</M>");
    sPostContent.append("<H M=\"");
    sPostContent.append(sPhoneList);
    sPostContent.append("\" />");
    sPostContent.append("</SMS></Root>");

    //整体报文做base64
    memset(pMsg,0,MAX_PACKET_LEN);
    base64_len = MAX_PACKET_LEN;
    ret = base64_encode((unsigned char*)sPostContent.c_str(),sPostContent.length(),
                        (unsigned char*)pMsg,&base64_len);
    if( ret != 0 )
    {
        LOG_ERROR("base64_encode fail.src len[%d]\n",sPostContent.length());
        delete [] pMsg;
        pMsg = NULL;
        return -1;
    }

    //http://218.206.201.28:10657
    string uri = "/SMS";
    
    out_len = sprintf(out_msg,"POST %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "Content-Length: %d\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "\r\n"
                        "%s",
                        uri.c_str(),
                        m_channel->sIpAddress.c_str(),
                        m_channel->lPort,
                        base64_len,
                        pMsg);

    LOG_INFO("out_msg[%d]\n%s\n", out_len, out_msg);

    delete [] pMsg;
    pMsg = NULL;

    http_wait_cache_t wi;
    strncpy(wi.sid, sid, sizeof(wi.sid) - 1);
    wi.busi_type = 0;
    wi.uptime = get_utc_miliseconds();
    wi.seq_id = seq_id;

    insert_wait_cache(wq, wi);

    return 0;
}

int LgMobileBiz::timer_process( dict* wq,
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

int LgMobileBiz::handle_submit_rsp(uint32_t seq_id,const char* body,int len)
{
    string sRespCode;
    string sMessageid;
    CMarkup xml;
    xml.SetDoc(body);
    if ( xml.FindElem("Root") )
    {
        xml.IntoElem();
        if ( xml.FindElem("SMS") )
        {
            xml.IntoElem();
            if ( xml.FindElem("Return") )
            {
                xml.IntoElem();
                HTTP_XML_GETITEM(xml, "State", sRespCode);
                xml.OutOfElem();
            }
            xml.OutOfElem();
        }
        xml.OutOfElem();
    }
    //响应无数据
    if( sRespCode.empty() )
    {
        LOG_ERROR("submit rsp is null. buf[%s]\n",body);
        return -1;
    }

    char szSessionID[64];
    memset(szSessionID,0,sizeof(szSessionID));
    get_sid_str(0,szSessionID,sizeof(szSessionID));
    sMessageid = szSessionID;

    LOG_INFO("recv submit rsp.msgid[%s]status[%s]\n",sMessageid.c_str(),sRespCode.c_str());
    //将应答报文写入redis
    save_message_response(seq_id,sRespCode,sMessageid);

    return 1;
}

int LgMobileBiz::handle_report_rsp(uint32_t seq_id,const char* body,int len)
{
    //没有状态报告
    return 1;
}

int LgMobileBiz::handle_uplink_rsp(uint32_t seq_id,const char* body,int len)
{
    //没有上行
    return 1;
}
