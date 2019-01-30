#include <json/json.h>
#include "interface.h"
#include "channel_db.h"
#include "gateway_util.h"
#include "charset_conv.h"

uint32_t SgipBiz::ui_seq_id = 0;
unsigned char SgipBiz::uc_seq_id = 0;

extern logger_t     *g_log;

extern "C" BIZAPI IChannelBiz* GetBizInterface( uint32_t proto_type )
{
    if( proto_type == 1 )
        return new SgipBiz;
    else
        return NULL;
}

SgipBiz::SgipBiz()
{
    m_pid = getpid();
    m_login_success = 0;
    m_rsp_cnt = 0;
    m_last_rsp_opr_redis_time = 0;
    m_report_cnt = 0;
    m_last_report_opr_redis_time = 0;
}

SgipBiz::~SgipBiz()
{

}

int SgipBiz::init_biz(const char* conf, void* args,channel_conf_t *channel)
{
    LOG_INFO("%s:%d:%s:pid=%d\n", __FILE__, __LINE__, __func__, getpid());
    if (conf == NULL || args == NULL || channel == NULL)
    {
        return -1;
    }
    g_log = (logger_t *)args;
    m_channel = channel;
    
    //读取配置文件

    // 初始化数据库
    if (init_db( conf ) != 0)
    {
        LOG_ERROR("fail to initialize biz db.\n");
        return -1;
    }
	LOG_INFO("biz db initialize successful.\n");

    return 0;
}

int SgipBiz::uninit_biz()
{
    // todo 

    uninit_db();

    return 0;
}

int SgipBiz::is_login_success(int& is_success )
{
    is_success = m_login_success;
    return 0;
}

int SgipBiz::is_need_to_listen(int& need_to_listen,int& listen_port)
{
    need_to_listen = 1;
    listen_port = m_channel->uListenPort;
    return 0;
}

/* @description 判断报文的完整性
 * @return 不完整则返回0， 完整则返回整个报文的长度，无效报文则返回-1
 */
int SgipBiz::is_packet_complete(const char* msg, int len)
{
    if( msg == NULL ) return -1;

    if ( len < SGIP_HEADER_LENGTH )
    {
        return 0;
    }

    //解析报文头
    sgip_header_t header;
    int ret = m_sgip.parse_header(msg,len,&header);
    if( ret != 0 )
    {
        return -1;
    }

    if ( (uint32_t)len < header.MessageLength ) 
    {
        return 0;
    }

    return header.MessageLength;
}

int SgipBiz::channel_req(const char* in_msg,int in_len,char* out_msg,int& out_len)
{
    if( in_msg == NULL || out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }

    int ret = 0;

    //解析报文头
    sgip_header_t hdr;
    ret = m_sgip.parse_header(in_msg,in_len,&hdr);
    if( ret != 0 )
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }

    //判断报文类型
    switch( hdr.CommandId )
    {
    case SGIP_BIND://登录请求报文
        {
            ret = handle_bind_req(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case SGIP_DELIVER://上行短信请求报文
        {
            ret = handle_deliver_req(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case SGIP_REPORT://状态报文请求报文
        {
            ret = handle_report_req(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case SGIP_UNBIND: //停止服务请求报文
        {
            ret = handle_unbind_req(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
	default:
	    {
    		LOG_ERROR("unknown CommandId : 0x%x\n", hdr.CommandId);
    	    ret = -1;
    		break;
        }
    }

    return ret;
}

int SgipBiz::channel_rsp(dict* wq,
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

    int ret = 0;

    //解析报文头
    sgip_header_t hdr;
    ret = m_sgip.parse_header(in_msg,in_len,&hdr);
    if( ret != 0 )
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }

    //判断报文类型
    switch( hdr.CommandId )
    {
    case SGIP_BIND_RESP://登录应答报文
        {
            ret = handle_bind_rsp(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH);
            break;
        }
    case SGIP_SUBMIT_RESP://发送短信应答报文
        {
            ret = handle_submit_rsp(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH);
            break;
        }
    case SGIP_TRACE_RESP://查询某条短信状态应答
        {
            ret = handle_trace_rsp(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH);
            break;
        }
    case SGIP_UNBIND_RESP://停止服务应答
        {
            ret = handle_unbind_rsp(&hdr,
                                    in_msg + SGIP_HEADER_LENGTH,
                                    hdr.MessageLength - SGIP_HEADER_LENGTH);
            break;
        }
	default:
	    {
    		LOG_ERROR("unknown CommandId : 0x%x\n", hdr.CommandId);
    	    ret = -1;
    		break;
        }
    }

    return ret;
}

int SgipBiz::send_msg_req(dict* wq,
                             message_packet_t *packet,
                             char *sid,
                             char* out_msg, 
                             int& out_len)
{
    if( packet == NULL || out_msg == NULL || m_channel == NULL)
    {
        return -1;
    }

    LOG_INFO("Sendmsg to channel.phone size[%d]\n",packet->mPhoneList.size());

    char timestamp[10 + 1] = {0};
    get_datetime(timestamp,sizeof(timestamp));

    //报文头
    sgip_header_t hdr;
    hdr.CommandId = SGIP_SUBMIT;
    hdr.SequenceId[0] = m_channel->uSpnodeCode;
    hdr.SequenceId[1] = atoi(timestamp);
    hdr.SequenceId[2] = get_ui_seq();

    //报文体
    sgip_body_submit_req_t bodySubmit;
    memset(&bodySubmit,0,sizeof(sgip_body_submit_req_t));

    char sUserPhone[14]={0};
    unsigned short cnt = 0;
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
        memset(sUserPhone,0,sizeof(sUserPhone));
        snprintf(sUserPhone,sizeof(sUserPhone),"86%s",itPhone->second.sMobilePhone.c_str());
        strncpy(bodySubmit.UserNumber[cnt],sUserPhone,sizeof(bodySubmit.UserNumber[cnt]));
        ++itPhone;
        cnt++;
    }
    if( cnt == 0 )
    {
        LOG_INFO("no phone need send to channel.\n");
        out_len = 0;
        return 1;
    }

    //加入应答映射表
    append_response_map(hdr.SequenceId[2],packet);

    strncpy(bodySubmit.SPNumber, packet->sSrcPhone.c_str(), sizeof(bodySubmit.SPNumber));
    //000000000000000000000
    memset(bodySubmit.ChargeNumber, 0x30, sizeof(bodySubmit.ChargeNumber)-1);
    bodySubmit.UserCount = cnt;

    strncpy(bodySubmit.CorpId,m_channel->sSpId.c_str(),sizeof(bodySubmit.CorpId));

    //20190125新增加需求
    if( packet->sServiceId.length() > 0 )
    {
        //使用上游模块传来的业务代码
        strncpy(bodySubmit.ServiceType, packet->sServiceId.c_str(), sizeof(bodySubmit.ServiceType));
    }
    else
    {
        //使用配置的默认业务代码
        strncpy(bodySubmit.ServiceType, m_channel->sServiceId.c_str(), sizeof(bodySubmit.ServiceType));
    }
    bodySubmit.FeeType = 0x04;
    bodySubmit.AgentFlag = 0x00;
    bodySubmit.MorelatetoMTFlag = 0x02;
    bodySubmit.Priority = 0x00;
    bodySubmit.TPPid = 0x00;
    bodySubmit.MessageType = 0x00;
    if (m_channel->uCustomParam3 == 1)
        bodySubmit.MessageCoding = 0x9;
    else
        bodySubmit.MessageCoding = 0x8;

    uint32_t uTextLen = GetUtf8TextLength( packet->sMessageContent );
    if (uTextLen <= 70)
    {
        //普通短信
        // 流速限制
        limit_submit_speed();
        bodySubmit.ReportFlag = 0x01;
        bodySubmit.TPUdhi = 0x00;
        bodySubmit.MessageLength = uTextLen * sizeof(unsigned short);

        //短信内容编码转换 utf-8 to ucs-2
        unsigned short *pwText = new unsigned short[uTextLen];
        if( pwText == NULL ) return -1;
        if (!TransCodeToUnicodeBE(pwText,uTextLen,packet->sMessageContent))
        {
            LOG_ERROR("Translate code from utf-8 to ucs-2 is failure.\n");
            if( pwText != NULL )
            {
                delete [] pwText;
                pwText = NULL;
            }
            return -1;
        }
        memcpy(bodySubmit.MessageContent,pwText,bodySubmit.MessageLength);
        if( pwText != NULL )
        {
            delete [] pwText;
            pwText = NULL;
        }

        char buf[MAX_PACKET_LEN];
        int body_len = m_sgip.make_submit_req(buf,bodySubmit);
        hdr.MessageLength = body_len + SGIP_HEADER_LENGTH;
        m_sgip.make_header(&hdr,out_msg,SGIP_HEADER_LENGTH);

        out_len = hdr.MessageLength;
        memcpy(out_msg + SGIP_HEADER_LENGTH,buf,body_len);
    }
    else
    {
        //长短信 需要将短信内容拆分成多条
        uint32_t uPkTotal = 0;
        uint32_t uLastLen = uTextLen % 67;
        if (uLastLen == 0)
            uPkTotal = uTextLen / 67;
        else
            uPkTotal = uTextLen / 67 + 1;

        unsigned char cLongGatewayHeader[6] = { 0x05,0x00,0x03,0x00,0x00,0x00 };
        cLongGatewayHeader[3] = get_uc_seq();
        cLongGatewayHeader[4] = (unsigned char)uPkTotal;
        bodySubmit.TPUdhi = 0x1;
        //短信内容编码转换 utf-8 to ucs-2
        unsigned short *pwText = new unsigned short[uTextLen];
        unsigned short *ptr = pwText;
        if( pwText == NULL ) return -1;
        if (!TransCodeToUnicodeBE(pwText,uTextLen,packet->sMessageContent))
        {
            LOG_ERROR("Translate code from utf-8 to ucs-2 is failure.\n");
            if( pwText != NULL )
            {
                delete [] pwText;
                pwText = NULL;
            }
            return -1;
        }

        int total_len = 0;
        unsigned short index = 0;
        for (index = 1; index <= uPkTotal; index++)
        {
            // 流速限制
            limit_submit_speed();
            cLongGatewayHeader[5] = (unsigned char)index;
            char *pMsgContent = bodySubmit.MessageContent;
            memcpy(pMsgContent, cLongGatewayHeader, sizeof(cLongGatewayHeader));
            pMsgContent += sizeof(cLongGatewayHeader);
            if (index != uPkTotal)  // 如果不是最后一条，以67个UCS-2字符取内容
            {
                // 设置第一条返回状态报告
                if (index == 1)
                    bodySubmit.ReportFlag = 0x1;
                else
                    bodySubmit.ReportFlag = 0x2;
                uint32_t uPartLen = 67 * sizeof(unsigned short);
                bodySubmit.MessageLength = 0x6 + uPartLen;
                memcpy(pMsgContent, ptr, uPartLen);
                ptr += 67;
            }
            else    //最后一条
            {
                bodySubmit.ReportFlag = 0x2;
                if (uLastLen == 0)
                {
                    uint32_t uPartLen = 67 * sizeof(unsigned short);
                    bodySubmit.MessageLength = 0x6 + uPartLen;
                    memcpy(pMsgContent, ptr, uPartLen);
                    ptr += 67;
                }
                else
                {
                    uint32_t uPartLen = uLastLen * sizeof(unsigned short);
                    bodySubmit.MessageLength = 0x6 + uPartLen;
                    memcpy(pMsgContent, ptr, uPartLen);
                    ptr += uLastLen;
                }
            }

            if (index != 1)
            {
                hdr.SequenceId[0] = m_channel->uSpnodeCode;
                hdr.SequenceId[1] = atoi(timestamp);
                hdr.SequenceId[2] = get_uc_seq();
            }
            
            char buf[MAX_PACKET_LEN];
            int body_len = m_sgip.make_submit_req(buf,bodySubmit);
            hdr.MessageLength = body_len + SGIP_HEADER_LENGTH;
            m_sgip.make_header(&hdr,out_msg + total_len ,SGIP_HEADER_LENGTH);

            memcpy(out_msg + total_len + SGIP_HEADER_LENGTH,buf,body_len);
            total_len += hdr.MessageLength;
        }
        if( pwText != NULL )
        {
            delete [] pwText;
            pwText = NULL;
        }
        out_len = total_len;
    }

    return 0;
}

int SgipBiz::channel_login_req(char* out_msg, int& out_len)
{
    if( out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }
    LOG_INFO("Sendchannel login req.\n");
    //发送登录请求
    //报文体
    sgip_body_bind_req_t bodyBind;
    bodyBind.LoginType = 0x01;
    strncpy(bodyBind.LoginName, m_channel->sUserName.c_str(), sizeof(bodyBind.LoginName));
    strncpy(bodyBind.LoginPassword, m_channel->sPassword.c_str(), sizeof(bodyBind.LoginPassword));

    char buf[MAX_PACKET_LEN];
    int body_len = m_sgip.make_bind_req(buf, bodyBind);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_bind_req fail.\n");
        return -1;
    }

    char timestamp[10 + 1] = {0};
    get_datetime(timestamp,sizeof(timestamp));
    
    //报文头
    sgip_header_t hdr;
    hdr.CommandId = SGIP_BIND;
    hdr.SequenceId[0] = m_channel->uSpnodeCode;
    hdr.SequenceId[1] = atoi(timestamp);
    hdr.SequenceId[2] = get_ui_seq();
    
    hdr.MessageLength = body_len + SGIP_HEADER_LENGTH;
    m_sgip.make_header(&hdr,out_msg,SGIP_HEADER_LENGTH);

    out_len = hdr.MessageLength;
    memcpy(out_msg + SGIP_HEADER_LENGTH,buf,body_len);

    return 0;
}

int SgipBiz::timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len )
{
    if( out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }

    out_len = 0;

    //将剩余条数写入redis
    if( m_rsp_cnt > 0 )
    {
        save_channel_rsp_remaining(m_channel->sChannelId.c_str(),m_rsp_cnt);
        m_rsp_cnt = 0;
    }

    if( m_report_cnt > 0 )
    {
        save_channel_report_remaining(m_channel->sChannelId.c_str(),m_report_cnt);
        m_report_cnt = 0;
    }
    
    //清理超时短信
    do_message_response_timeout();

    return 0;
}

int SgipBiz::handle_bind_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    sgip_body_bind_req_t req;
    int tmp_len = m_sgip.parse_bind_req(const_cast<char *>(body),req);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_bind_req fail.\n");
        return -1;
    }

    LOG_INFO("Recv channel bind message.LoginType[%u]LoginName[%s]LoginPassword[%s]\n",
                            req.LoginType,
                            req.LoginName,
                            req.LoginPassword);

    unsigned char Result = 0x1;
    /*
    1：SP向SMG建立的连接，用于发送命令
    2：SMG向SP建立的连接，用于发送命令
    */
    if( req.LoginType == 0x2 )
    {
        /*
        if( strcmp( req.LoginName,m_channel->sUserName.c_str() ) == 0 &&
            strcmp( req.LoginPassword,m_channel->sPassword.c_str() ) == 0 )
        {
            Result = 0x0;
        }
        */
        Result = 0x0;
    }

    //返回应答报文
    sgip_body_bind_rsp_t rsp;
    rsp.Result = Result;

    char buf[MAX_PACKET_LEN];
    int body_len = m_sgip.make_bind_rsp(buf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_bind_rsp fail.\n");
        return -1;
    }

    //报文头
    sgip_header_t head;
    head.CommandId = SGIP_BIND_RESP;
    memcpy(head.SequenceId,hdr->SequenceId,sizeof(head.SequenceId));
    head.MessageLength = body_len + SGIP_HEADER_LENGTH;
    m_sgip.make_header(&head,out_msg,SGIP_HEADER_LENGTH);

    out_len = head.MessageLength;
    memcpy(out_msg + SGIP_HEADER_LENGTH,buf,body_len);

    return 0;
}

int SgipBiz::handle_deliver_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    sgip_body_deliver_req_t req;
    int tmp_len = m_sgip.parse_deliver_req(const_cast<char *>(body),req);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_deliver_req fail.\n");
        return -1;
    }

    string sMessageContent;
    if (req.MessageCoding == 0x08)    // 消息内容为Unicode编码，转化为UTF-8
    {
        unsigned int uUcs2Len = req.MessageLength / sizeof(unsigned short);
        TransCodeFromUnicodeBE(sMessageContent, req.WMsgContent, uUcs2Len);
    }
    else
    {
        // 将GBK编码转为UTF-8编码
        ascii_to_utf8(req.MessageContent,sMessageContent);
    }

    LOG_INFO("Recv channel deliver message.UserNumber[%s]SPNumber[%s]MsgFormat[%u]MsgContent[%s]\n",
                        req.UserNumber,
                        req.SPNumber,
                        req.MessageCoding,
                        sMessageContent.c_str());

    save_message_uplink(req.UserNumber,req.SPNumber,sMessageContent);

    //返回应答报文
    sgip_body_deliver_rsp_t rsp;
    rsp.Result = 0x0;

    char buf[MAX_PACKET_LEN];
    int body_len = m_sgip.make_deliver_rsp(buf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_deliver_rsp fail.\n");
        return -1;
    }

    //报文头
    sgip_header_t head;
    head.CommandId = SGIP_DELIVER_RESP;
    memcpy(head.SequenceId,hdr->SequenceId,sizeof(head.SequenceId));
    head.MessageLength = body_len + SGIP_HEADER_LENGTH;
    m_sgip.make_header(&head,out_msg,SGIP_HEADER_LENGTH);

    out_len = head.MessageLength;
    memcpy(out_msg + SGIP_HEADER_LENGTH,buf,body_len);

    return 0;
}

int SgipBiz::handle_report_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    sgip_body_report_req_t req;
    int tmp_len = m_sgip.parse_report_req(const_cast<char *>(body),req);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_report_req fail.\n");
        return -1;
    }

    char sMessageid[32] = {0};
    snprintf(sMessageid,sizeof(sMessageid),"%u%010u%u",req.SubmitSequenceNumber[0],req.SubmitSequenceNumber[1],req.SubmitSequenceNumber[2]);
    
    char sStatus[8] = { 0 };
    if (req.State == 0x0)
        strncpy(sStatus, "DELIVRD", sizeof(sStatus));
    else
        snprintf(sStatus,sizeof(sStatus),"SG:%04u",(unsigned int)req.ErrorCode);
    
    LOG_INFO("Recv channel report message.MsgId[%s]srcphone[%s]status[%s]\n", 
                            sMessageid,
                            req.UserNumber,
                            sStatus);

    save_message_report(sMessageid,req.UserNumber,"",sStatus,sStatus);

    //返回应答报文
    sgip_body_report_rsp_t rsp;
    rsp.Result = 0x0;

    char buf[MAX_PACKET_LEN];
    int body_len = m_sgip.make_report_rsp(buf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_report_rsp fail.\n");
        return -1;
    }

    //报文头
    sgip_header_t head;
    head.CommandId = SGIP_REPORT_RESP;
    memcpy(head.SequenceId,hdr->SequenceId,sizeof(head.SequenceId));
    head.MessageLength = body_len + SGIP_HEADER_LENGTH;
    m_sgip.make_header(&head,out_msg,SGIP_HEADER_LENGTH);

    out_len = head.MessageLength;
    memcpy(out_msg + SGIP_HEADER_LENGTH,buf,body_len);

    return 0;
}

int SgipBiz::handle_unbind_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{

    LOG_INFO("Recv channel unbind req message!\n");

    out_len = m_sgip.make_unbind_rsp(out_msg,hdr->SequenceId);

    return 0;
}

int SgipBiz::handle_bind_rsp(sgip_header_t *hdr,const char* body,int len)
{
    sgip_body_bind_rsp_t rsp;
    int tmp_len = m_sgip.parse_bind_rsp(const_cast<char *>(body),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_bind_rsp fail.\n");
        return -1;
    }

    char sMessageid[32] = { 0 };
    snprintf(sMessageid,sizeof(sMessageid),"%u%010u%u",hdr->SequenceId[0],hdr->SequenceId[1],hdr->SequenceId[2]);

    LOG_INFO("Recv sgip bind rsp.Id[%s]Result[%d]\n",
                                     sMessageid,
                                     rsp.Result);

    if( rsp.Result == 0x0 )
    {
        handle_channel_status(m_channel->sChannelId,0);
        m_login_success = 1;
    }
    else
    {
        handle_channel_status(m_channel->sChannelId,rsp.Result);
        m_login_success = 0;
    }

    return 1;
}

int SgipBiz::handle_submit_rsp(sgip_header_t *hdr,const char* body,int len)
{
    sgip_body_submit_rsp_t rsp;
    int tmp_len = m_sgip.parse_submit_rsp(const_cast<char *>(body),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_submit_rsp fail.\n");
        return -1;
    }
    
    char sMessageid[32] = { 0 };
    snprintf(sMessageid,sizeof(sMessageid),"%u%010u%u",hdr->SequenceId[0],hdr->SequenceId[1],hdr->SequenceId[2]);

    LOG_INFO("Recv channel submit rsp.MsgId[%s]Result[%u]\n",sMessageid,rsp.Result);

    //将应答报文写入redis
    save_message_response(hdr->SequenceId[2],rsp.Result,sMessageid);

    return 1;
}

int SgipBiz::handle_trace_rsp(sgip_header_t *hdr,const char* body,int len)
{
    LOG_INFO("Recv channel trace rsp message!\n");
    return 1;
}

int SgipBiz::handle_unbind_rsp(sgip_header_t *hdr,const char* body,int len)
{
    LOG_INFO("Recv channel unbind rsp message!\n");
    return 1;
}

uint32_t SgipBiz::get_ui_seq()
{
    uint32_t seq_id;
    seq_id = m_pid << 16;
    seq_id &= 0xFFFF0000;
    seq_id |= ui_seq_id;
    
    if( ui_seq_id == 0xFFFF )
    {
        ui_seq_id = 0;
    }
    ui_seq_id++; 
    return seq_id;
}

unsigned char SgipBiz::get_uc_seq()
{
    return uc_seq_id++;
}


int SgipBiz::append_response_map(uint32_t seq_id,message_packet_t *req)
{
    message_response_t msgResponse;
    msgResponse.sSrcPhone = req->sSrcPhone;
    msgResponse.uSmsCount = GetSmsCount(req->sMessageContent);
    msgResponse.uChannelType = req->uChannelType;
    msgResponse.sChannelId = req->sChannelId;
    msgResponse.sChannelGroupId = req->sChannelGroupId;
    msgResponse.smsArgument = req->smsArgument;
    msgResponse.uNosendCount = 0;
    msgResponse.uErrorCount = 0;
    msgResponse.uSuccessCount = 0;
    msgResponse.uFailCount = 0;
    msgResponse.sSendTime = MakeDateTime();
    msgResponse.nsend_time = time(NULL);
    msgResponse.mPhoneList = req->mPhoneList;

    m_MessageResponse[seq_id] = msgResponse;

    return 0;
}

void SgipBiz::save_message_response( int type,message_response_t *rsp )
{
    if( rsp == NULL ) return;

    //内部产生的msgid
    char szSessionID[64] = {0};
    get_sid_str(0,szSessionID,sizeof(szSessionID));

    if( type == 0 )
    {
        //扣量短信
        rsp->uNosendCount = rsp->mPhoneList.size();
    }
    else
    {
        //超时未响应短信
        rsp->uErrorCount = rsp->mPhoneList.size();
    }

    //设置返回msgid
    map<string, sms_attribute_t>::iterator itPhoneList;
    for (itPhoneList = rsp->mPhoneList.begin(); 
         itPhoneList != rsp->mPhoneList.end(); 
         itPhoneList++)
    {
        itPhoneList->second.sMessageid = szSessionID;
    }

    string sMessagePacket;
    if ( !format_to_json( rsp, sMessagePacket ) )
    {
        LOG_ERROR("Format message response to json is failure\n");
        return;
    }

    //增加响应量
    save_channel_rsp_remaining(rsp->sChannelId.c_str(),1);

    // 响应写入redis
    save_channel_rsp( sMessagePacket );

    for (itPhoneList = rsp->mPhoneList.begin(); 
         itPhoneList != rsp->mPhoneList.end(); 
         itPhoneList++)
    {
        if( type != 0 )
        {
            itPhoneList->second.sVirtualStatus = "NS:0002";
            itPhoneList->second.sConvertStatus = "NS:0002";
        }
        //提交失败的和扣量的号码内部产生状态报告
        save_message_report(itPhoneList->second.sMessageid,
                            itPhoneList->second.sMobilePhone,
                            rsp->sSrcPhone,
                            itPhoneList->second.sVirtualStatus,
                            itPhoneList->second.sConvertStatus);
    }
}

void SgipBiz::save_message_response(uint32_t seq_id,uint32_t result,string msg_id)
{
    message_response_t response = m_MessageResponse[seq_id];
    if( response.mPhoneList.size() == 0 )
    {
        LOG_WARN("response not find.seqid[%u]\n",seq_id);
        return;
    }

    if( result == 0 )
    {
        // 提交成功
        response.uSuccessCount = response.mPhoneList.size();
    }
    else
    {
        //提交失败
        response.uFailCount = response.mPhoneList.size();
    }
    //设置返回msgid
    map<string, sms_attribute_t>::iterator itPhoneList;
    for (itPhoneList = response.mPhoneList.begin(); 
         itPhoneList != response.mPhoneList.end(); 
         itPhoneList++)
    {
        itPhoneList->second.sMessageid =  msg_id ;
    }

    string sMessagePacket;
    if ( !format_to_json( &response, sMessagePacket ) )
    {
        LOG_ERROR("Format message response to json is failure\n");
        return;
    }

    ++m_rsp_cnt;
    time_t now = get_utc_miliseconds();
	if( ( now - m_last_rsp_opr_redis_time ) >= m_channel->uTimeout )
	{
		m_last_rsp_opr_redis_time = now;
		//增加响应量
		save_channel_rsp_remaining(response.sChannelId.c_str(),m_rsp_cnt);
		m_rsp_cnt = 0;
	}

    // 响应写入redis
    save_channel_rsp( sMessagePacket );

    for (itPhoneList = response.mPhoneList.begin(); 
         itPhoneList != response.mPhoneList.end(); 
         itPhoneList++)
    {
        //提交失败的，内部产生状态报告
        if( result != 0 )
        {
            char aGenerateStatus[16] = {0};
            snprintf(aGenerateStatus, sizeof(aGenerateStatus), "NSM%04u", result);
            itPhoneList->second.sVirtualStatus = aGenerateStatus;
            itPhoneList->second.sConvertStatus = aGenerateStatus;
            save_message_report(itPhoneList->second.sMessageid,
                                itPhoneList->second.sMobilePhone,
                                response.sSrcPhone,
                                itPhoneList->second.sVirtualStatus,
                                itPhoneList->second.sConvertStatus);
        }
    }

    //处理完，清空列表
    m_MessageResponse.erase(seq_id);
}

bool SgipBiz::format_to_json(message_response_t *rsp,string &sRecvJson)
{
    if( rsp == NULL ) return false;
    uint32_t uYear,uMonth,uDay;
    Json::FastWriter jsonWriter;
    Json::Value jsonRoot, jsonSmsArgument, jsonDateTime;

    if( rsp->smsArgument.sDateTime.length() >= 8 )
    {
        uYear = atoi(rsp->smsArgument.sDateTime.substr(0,4).c_str());
        uMonth = atoi(rsp->smsArgument.sDateTime.substr(4, 2).c_str());
        uDay = atoi(rsp->smsArgument.sDateTime.substr(6, 2).c_str());
    }
    else
    {
        time_t t;
        struct tm ts;
        time(&t);
        localtime_r(&t, &ts);
        uYear = ts.tm_year + 1900;
        uMonth = ts.tm_mon + 1;
        uDay = ts.tm_mday;
    }

    jsonRoot["PacketType"] = Json::Value(0); //返回类型 0 应答 1 状态 2上行 
    jsonRoot["SrcPhone"] = Json::Value(rsp->sSrcPhone);
    jsonRoot["SmsCount"] = Json::Value(rsp->uSmsCount);
    jsonRoot["ChannelType"] = Json::Value(rsp->uChannelType);
    jsonRoot["ChannelId"] = Json::Value(rsp->sChannelId);
    jsonRoot["ChannelGroupId"] = Json::Value(rsp->sChannelGroupId);
    jsonDateTime["Year"] = Json::Value(uYear);
    jsonDateTime["Month"] = Json::Value(uMonth);
    jsonDateTime["Day"] = Json::Value(uDay);
    jsonSmsArgument["DateTime"] = jsonDateTime;
    jsonSmsArgument["SmsResend"] = Json::Value(rsp->smsArgument.bSmsResend);
    jsonSmsArgument["SubmitId"] = Json::Value(rsp->smsArgument.sSubmitId);
    jsonSmsArgument["BatchId"] = Json::Value(rsp->smsArgument.sBatchno);
    jsonSmsArgument["OperatorId"] = Json::Value(rsp->smsArgument.sOperatorId);
    jsonSmsArgument["ClientId"] = Json::Value(rsp->smsArgument.sClientId);
    jsonSmsArgument["AccountId"] = Json::Value(rsp->smsArgument.sAccountId);
    jsonSmsArgument["CompanyId"] = Json::Value(rsp->smsArgument.sCompanyId);
    jsonSmsArgument["SmsContent"] = Json::Value(rsp->smsArgument.sSmsContent);
    jsonSmsArgument["SubmitWay"] = Json::Value(rsp->smsArgument.uSubmitWay);
    jsonSmsArgument["IsOtoSend"] = Json::Value(rsp->smsArgument.bOtoSend);
    jsonSmsArgument["ReturnType"] = Json::Value(rsp->smsArgument.uReturnType);
    jsonSmsArgument["smsdata"] = Json::Value(rsp->smsArgument.sSmsData);
    jsonRoot["SmsArgument"] = jsonSmsArgument;
    jsonRoot["NosendCount"] = Json::Value(rsp->uNosendCount);
    jsonRoot["ErrorCount"] = Json::Value(rsp->uErrorCount);
    jsonRoot["SuccessCount"] = Json::Value(rsp->uSuccessCount);
    jsonRoot["FailureCount"] = Json::Value(rsp->uFailCount);
    jsonRoot["SendTime"] = Json::Value(rsp->sSendTime);

    map<string, sms_attribute_t>::iterator itPhoneList;
    for (itPhoneList = rsp->mPhoneList.begin();itPhoneList != rsp->mPhoneList.end();itPhoneList++)
    {
        Json::Value jsonOnePhone;
        jsonOnePhone["SendId"] = Json::Value(itPhoneList->first);
        jsonOnePhone["IsNeedSend"] = Json::Value(itPhoneList->second.bNeedSend);
        jsonOnePhone["VirtualStatus"] = Json::Value(itPhoneList->second.sVirtualStatus);
        jsonOnePhone["ConvertStatus"] = Json::Value(itPhoneList->second.sConvertStatus);
        jsonOnePhone["MobilePhone"] = Json::Value(itPhoneList->second.sMobilePhone);
        jsonOnePhone["SmsContent"] = Json::Value(itPhoneList->second.sSmsContent);
        jsonOnePhone["MessageId"] = Json::Value(itPhoneList->second.sMessageid);

        jsonRoot["PhoneList"].append(jsonOnePhone);
    }
    
    sRecvJson = jsonWriter.write(jsonRoot);
    return true;
}

void SgipBiz::save_message_report(string sMessageid,
                                  string sSrcPhone,
                                  string sDestPhone,
                                  string sRealStatus,
                                  string sConvertStatus)
{
    // 判断并去除号码前缀
    string src_phone;
    if( sSrcPhone.length() > 11 )
    {
        src_phone = sSrcPhone.erase( 0, sSrcPhone.length() - 11 );
    }
    else
    {
        src_phone = sSrcPhone;
    }

    Json::FastWriter jsonWriter;
    Json::Value jsonRoot;
    jsonRoot["PacketType"] = Json::Value(1);                    //返回类型 0 应答 1 状态 2上行 
    jsonRoot["scid"] = Json::Value(m_channel->sChannelId);      // 通道的ID
    jsonRoot["MessageId"] = Json::Value(sMessageid);            // 消息ID
    jsonRoot["SrcPhone"] = Json::Value(src_phone);              // 手机号码
    jsonRoot["DestPhone"] = Json::Value(sDestPhone);            // 接入号
    jsonRoot["RealStatus"] = Json::Value(sRealStatus);          // 原始短信状态
    jsonRoot["ConvertStatus"] = Json::Value(sConvertStatus);    // 转换后状态
    jsonRoot["RecvTime"] = Json::Value(MakeDateTime());         // 信息接收时间，该时间应该取报文返回时间
    jsonRoot["LifeCycle"] = Json::Value(0);                     // 消息生命周期
    string report_json = jsonWriter.write(jsonRoot);

    ++m_report_cnt;
    time_t now = get_utc_miliseconds();
	if( ( now - m_last_report_opr_redis_time ) >= m_channel->uTimeout )
	{
		m_last_report_opr_redis_time = now;
		//状态报告增加量
		save_channel_report_remaining(m_channel->sChannelId.c_str(),m_report_cnt);
		m_report_cnt = 0;
	}

    //写入redis
    save_channel_report(report_json);
}

void SgipBiz::save_message_uplink(string sSrcPhone,string sDestPhone,string sMessageContent)
{
    // 判断并去除号码前缀
    string src_phone;
    if( sSrcPhone.length() > 11 )
    {
        src_phone = sSrcPhone.erase( 0, sSrcPhone.length() - 11 );
    }
    else
    {
        src_phone = sSrcPhone;
    }

    Json::FastWriter jsonWriter;
    Json::Value jsonRoot;
    jsonRoot["PacketType"] = Json::Value(2);                            //返回类型 0 应答 1 状态 2上行
    jsonRoot["ProtoType"] = Json::Value(m_channel->uProtoType);         //协议类型
    jsonRoot["SrcPhone"] = Json::Value(src_phone);                      //手机号码
    jsonRoot["DestPhone"] = Json::Value(sDestPhone);                    //接收号码
    jsonRoot["MessageContent"] = Json::Value(sMessageContent);          //上行内容
    jsonRoot["ChannelId"] = Json::Value(m_channel->sChannelId);         //通道ID
    jsonRoot["CustomUplink"] = Json::Value(m_channel->uCustomParam5);   //自定义参数5
    jsonRoot["AccessCode"] = Json::Value(m_channel->sAccessCode);       //接入号
    string uplink_json = jsonWriter.write(jsonRoot);

    //写入redis
    save_channel_uplink(uplink_json);
}

void SgipBiz::do_message_response_timeout()
{
    //清理超时未响应的短信
    map<uint32_t,message_response_t>::iterator rsp_it;
    for (rsp_it = m_MessageResponse.begin();rsp_it != m_MessageResponse.end();)
    {
        time_t now = time(NULL);
        if( ( now - rsp_it->second.nsend_time ) > m_channel->uTimeout )
        {
            save_message_response( 1,&rsp_it->second );
            m_MessageResponse.erase(rsp_it++);
        }
        else
        {
            ++rsp_it;
        }
    }
}
