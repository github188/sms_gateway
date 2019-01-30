#include <json/json.h>
#include "interface.h"
#include "channel_db.h"
#include "gateway_util.h"
#include "gateway_crypt.h"
#include "charset_conv.h"

uint32_t SmgpBiz::ui_seq_id = 0;
unsigned char SmgpBiz::uc_seq_id = 0;

extern logger_t     *g_log;

extern "C" BIZAPI IChannelBiz* GetBizInterface( uint32_t proto_type )
{
    if( proto_type == 2 )
        return new SmgpBiz;
    else
        return NULL;
}

SmgpBiz::SmgpBiz()
{
    m_pid = getpid();
    m_login_success = 0;
    m_rsp_cnt = 0;
    m_last_rsp_opr_redis_time = 0;
    m_report_cnt = 0;
    m_last_report_opr_redis_time = 0;
}

SmgpBiz::~SmgpBiz()
{

}

int SmgpBiz::init_biz(const char* conf, void* args,channel_conf_t *channel)
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

int SmgpBiz::uninit_biz()
{
    // todo 

    uninit_db();

    return 0;
}

int SmgpBiz::is_login_success(int& is_success )
{
    is_success = m_login_success;
    return 0;
}

/* @description 判断报文的完整性
 * @return 不完整则返回0， 完整则返回整个报文的长度，无效报文则返回-1
 */
int SmgpBiz::is_packet_complete(const char* msg, int len)
{
    if( msg == NULL ) return -1;

    if ( len < SMGP_HEADER_LENGTH )
    {
        return 0;
    }

    //解析报文头
    smgp_header_t header;
    int ret = m_smgp.parse_header(msg,len,&header);
    if( ret != 0 )
    {
        return -1;
    }

    if ( (uint32_t)len < header.PacketLength ) 
    {
        return 0;
    }

    return header.PacketLength;
}

int SmgpBiz::channel_rsp(dict* wq,
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
    smgp_header_t hdr;
    ret = m_smgp.parse_header(in_msg,in_len,&hdr);
    if( ret != 0 )
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }

    //判断报文类型
    switch( hdr.RequestId )
    {
    case SMGP_ACTIVE_TEST://心跳请求报文
        {
            ret = handle_active_test_req(&hdr,
                                    in_msg + SMGP_HEADER_LENGTH,
                                    hdr.PacketLength - SMGP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case SMGP_ACTIVE_TEST_RESP://心跳应答报文
        {
            LOG_INFO("Recv a smgp_active_test_resp message.The sequenceId:%u\n",hdr.SequenceId);
            ret = 1; //不需要返回报文
            break;
        }
    case SMGP_EXIT://停止服务请求报文
        {
            ret = handle_terminate_req(&hdr,
                                    in_msg + SMGP_HEADER_LENGTH,
                                    hdr.PacketLength - SMGP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case SMGP_EXIT_RESP: //停止服务应答报文
        {
            LOG_INFO("Recv a smgp_terminate message.The sequenceId:%u\n",hdr.SequenceId);
            ret = 1; //不需要返回报文
            break;
        }
	case SMGP_LOGIN_RESP: //登录应答报文
		{
			ret = handle_connect_rsp(&hdr,
                                    in_msg + SMGP_HEADER_LENGTH,
                                    hdr.PacketLength - SMGP_HEADER_LENGTH);
            break;
		}
    case SMGP_SUBMIT_RESP: //发送信息应答报文
		{
			ret = handle_submit_rsp(&hdr,
                                    in_msg + SMGP_HEADER_LENGTH,
                                    hdr.PacketLength - SMGP_HEADER_LENGTH);
            break;
		}
    case SMGP_DELIVER: //状态、上行短信请求报文
		{
			ret = handle_deliver_req(&hdr,
                                    in_msg + SMGP_HEADER_LENGTH,
                                    hdr.PacketLength - SMGP_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
		}
	default:
	    {
    		LOG_ERROR("unknown requestId : 0x%x\n", hdr.RequestId);
    	    ret = -1;
    		break;
        }
    }

    return ret;
}

int SmgpBiz::send_msg_req(dict* wq,
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

    //报文头
    smgp_header_t hdr;
    hdr.RequestId = SMGP_SUBMIT;
    hdr.SequenceId = get_ui_seq();

    //报文体
    smgp_body_submit_req_t bodySubmit;
    memset(&bodySubmit,0,sizeof(smgp_body_submit_req_t));

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
        strncpy(bodySubmit.DestTermId[cnt], itPhone->second.sMobilePhone.c_str(), sizeof(bodySubmit.DestTermId[cnt]));
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
    append_response_map(hdr.SequenceId,packet);

    bodySubmit.MsgType = 0x06;
    bodySubmit.Priority = 0x01;

    //20190125新增加需求
    if( packet->sServiceId.length() > 0 )
    {
        //使用上游模块传来的业务代码
        strncpy(bodySubmit.ServiceId, packet->sServiceId.c_str(), sizeof(bodySubmit.ServiceId));
    }
    else
    {
        //使用配置的默认业务代码
        strncpy(bodySubmit.ServiceId, m_channel->sServiceId.c_str(), sizeof(bodySubmit.ServiceId));
    }
    strncpy(bodySubmit.FeeType, "00", sizeof(bodySubmit.FeeType));
    strncpy(bodySubmit.FeeCode, "0", sizeof(bodySubmit.FeeCode));
    strncpy(bodySubmit.FixedFee, "0", sizeof(bodySubmit.FixedFee));
    strncpy(bodySubmit.SrcTermId, packet->sSrcPhone.c_str(), sizeof(bodySubmit.SrcTermId));
    bodySubmit.DestTermIdCount = cnt;

    uint32_t uTextLen = GetUtf8TextLength( packet->sMessageContent );
    if (uTextLen <= 70)
    {
        //普通短信
        // 流速限制
        limit_submit_speed();
        bodySubmit.bIsLongSms = false;
        bodySubmit.NeedReport = 0x01;
        bodySubmit.MsgFormat = 0x08;
        bodySubmit.MsgLength = uTextLen * sizeof(unsigned short);

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
        memcpy(bodySubmit.MsgContent,pwText,bodySubmit.MsgLength);
        if( pwText != NULL )
        {
            delete [] pwText;
            pwText = NULL;
        }

        char buf[MAX_PACKET_LEN];
        int body_len = m_smgp.make_submit_req(buf,bodySubmit);
        hdr.PacketLength = body_len + SMGP_HEADER_LENGTH;
        m_smgp.make_header(&hdr,out_msg,SMGP_HEADER_LENGTH);

        out_len = hdr.PacketLength;
        memcpy(out_msg + SMGP_HEADER_LENGTH,buf,body_len);
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
        bodySubmit.bIsLongSms = true;
        bodySubmit.MsgFormat = 0x8;
        bodySubmit.TPUdhi = 0x1;
        bodySubmit.PkTotal = (unsigned char)uPkTotal;
        cLongGatewayHeader[4] = (unsigned char)uPkTotal;

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
            bodySubmit.PkNumber = (unsigned char)index;
            cLongGatewayHeader[5] = (unsigned char)index;
            char *pMsgContent = bodySubmit.MsgContent;
            memcpy(pMsgContent, cLongGatewayHeader, sizeof(cLongGatewayHeader));
            pMsgContent += sizeof(cLongGatewayHeader);
            if (index != uPkTotal)  // 如果不是最后一条，以67个UCS-2字符取内容
            {
                // 设置第一条返回状态报告
                if (index == 1)
                    bodySubmit.NeedReport = 0x1;
                else
                    bodySubmit.NeedReport = 0x0;
                uint32_t uPartLen = 67 * sizeof(unsigned short);
                bodySubmit.MsgLength = 0x6 + uPartLen;
                memcpy(pMsgContent, ptr, uPartLen);
                ptr += 67;
            }
            else    //最后一条
            {
                bodySubmit.NeedReport = 0x0;
                if (uLastLen == 0)
                {
                    uint32_t uPartLen = 67 * sizeof(unsigned short);
                    bodySubmit.MsgLength = 0x6 + uPartLen;
                    memcpy(pMsgContent, ptr, uPartLen);
                    ptr += 67;
                }
                else
                {
                    uint32_t uPartLen = uLastLen * sizeof(unsigned short);
                    bodySubmit.MsgLength = 0x6 + uPartLen;
                    memcpy(pMsgContent, ptr, uPartLen);
                    ptr += uLastLen;
                }
            }

            if (index != 1)
            {
                hdr.SequenceId = get_uc_seq();
            }
            
            char buf[MAX_PACKET_LEN];
            int body_len = m_smgp.make_submit_req(buf,bodySubmit);
            hdr.PacketLength = body_len + SMGP_HEADER_LENGTH;
            m_smgp.make_header(&hdr,out_msg + total_len ,SMGP_HEADER_LENGTH);

            memcpy(out_msg + total_len + SMGP_HEADER_LENGTH,buf,body_len);
            total_len += hdr.PacketLength;
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

int SmgpBiz::channel_login_req(char* out_msg, int& out_len)
{
    if( out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }
    LOG_INFO("Sendchannel login req.\n");
    //发送登录请求
    //报文体
    smgp_body_login_req_t login;
    char timestamp[10 + 1] = {0};
    get_datetime(timestamp,sizeof(timestamp));

    //源地址 spid
    strncpy(login.ClientId, m_channel->sUserName.c_str(), sizeof(login.ClientId));
    login.Timestamp = atoi( timestamp );
    // ClientId+7个0x00+SharedSecret+timestamp的MD5加密
    //AuthenticatorClient
    int buf_len = m_channel->sUserName.length() + m_channel->sPassword.length() + 7 + 10;
    char *auth_src = (char *)malloc(buf_len + 1);
    if( auth_src == NULL )  return -1;
    memset(auth_src, 0x00, buf_len + 1);
    char *ptr = auth_src;
    SetBufferString(ptr, m_channel->sUserName.c_str(), m_channel->sUserName.length());
    SetBufferZero(ptr, 7);
    SetBufferString(ptr, m_channel->sPassword.c_str(), m_channel->sPassword.length());
    SetBufferString(ptr, timestamp, sizeof(timestamp) - 1 );
    unsigned char MD5result[16] = {0};
    MD5((const unsigned char*)auth_src,buf_len,MD5result);
    memcpy(login.AuthenticatorClient,MD5result,sizeof(login.AuthenticatorClient));
    free(auth_src);
    auth_src = NULL;

    // 登陆模式
    login.LoginMode = 0x02;
    //Version
    login.ClientVersion = 0x30;

    char buf[MAX_PACKET_LEN];
    int body_len = m_smgp.make_login_req(buf, login);
    if( body_len <= 0 )
    {
        LOG_ERROR("make login req fail.\n");
        return -1;
    }

    //报文头
    smgp_header_t hdr;
    hdr.RequestId = SMGP_LOGIN;
    hdr.SequenceId = get_ui_seq();
    hdr.PacketLength = body_len + SMGP_HEADER_LENGTH;
    m_smgp.make_header(&hdr,out_msg,SMGP_HEADER_LENGTH);

    out_len = hdr.PacketLength;
    memcpy(out_msg + SMGP_HEADER_LENGTH,buf,body_len);

    return 0;
}

int SmgpBiz::timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len )
{
    if( out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }

    //发送心跳
    uint32_t seq_id = get_ui_seq();
    out_len = m_smgp.make_activeTest_req(out_msg,seq_id);
    
    LOG_INFO("Sendchannel heartbeat req.\n");

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


uint32_t SmgpBiz::get_ui_seq()
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

unsigned char SmgpBiz::get_uc_seq()
{
    return uc_seq_id++;
}


int SmgpBiz::handle_active_test_req(smgp_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    //心跳请求报文
    out_len = m_smgp.make_activeTest_rsp(out_msg,hdr->SequenceId);
    return 0;
}

int SmgpBiz::handle_terminate_req(smgp_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    //拆除连接请求报文
    out_len = m_smgp.make_terminal_rsp(out_msg,hdr->SequenceId);
    return 0;
}

int SmgpBiz::handle_connect_rsp(smgp_header_t *hdr,const char* body,int len)
{
    smgp_body_login_rsp_t rsp;
    int tmp_len = m_smgp.parse_login_rsp(const_cast<char *>(body),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_login_rsp fail.\n");
        return -1;
    }

    LOG_INFO("Recv smgp login rsp.Id[%u]status[%u]\n",
                                     hdr->SequenceId,
                                     rsp.Status);
    if( rsp.Status == 0 )
    {
        handle_channel_status(m_channel->sChannelId,0);
        m_login_success = 1;
    }
    else
    {
        handle_channel_status(m_channel->sChannelId,rsp.Status);
        m_login_success = 0;
    }

    return 1;
}

int SmgpBiz::handle_submit_rsp(smgp_header_t *hdr,const char* body,int len)
{
    smgp_body_submit_rsp_t rsp;
    int tmp_len = m_smgp.parse_submit_rsp(const_cast<char *>(body),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_submit_rsp fail.\n");
        return -1;
    }

    // 生成消息ID
    char cByte[3] = { 0 };
    string sMessageId;
    for (uint32_t index = 0; index < sizeof(rsp.MsgId); index++)
    {
        memset(cByte, 0, sizeof(cByte));
        snprintf(cByte, sizeof(cByte), "%02x",rsp.MsgId[index]);
        sMessageId.append(cByte);
    }
    
    LOG_INFO("Recv channel submit rsp.MsgId[%s]Status[%u]\n",sMessageId.c_str(),rsp.Status);

    //将应答报文写入redis
    save_message_response(hdr->SequenceId,rsp.Status,sMessageId);

    return 1;
}

int SmgpBiz::handle_deliver_req(smgp_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    //状态报告、上行短信报文
    smgp_body_deliver_req_t req;
    int tmp_len = m_smgp.parse_deliver_req(const_cast<char *>(body),len,req);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_deliver_req fail.\n");
        return -1;
    }

    // 生成消息ID
    char cByte[3] = { 0 };
    string sMessageId;
    // Deliver消息为非状态报告
    if ( req.IsReport == 0x0 )
    {
        string sMessageContent;
        if (req.MsgFormat == 0x08)    // 消息内容为Unicode编码，转化为UTF-8
        {
            unsigned int uUcs2Len = req.MsgLength / sizeof(unsigned short);
            TransCodeFromUnicodeBE(sMessageContent, req.WMsgContent, uUcs2Len);
        }
        else
        {
            // 将GBK编码转为UTF-8编码
            ascii_to_utf8(req.MsgContent,sMessageContent);
        }

        // 生成消息ID
        for (uint32_t index = 0; index < sizeof(req.MsgId); index++)
        {
            memset(cByte, 0, sizeof(cByte));
            snprintf(cByte, sizeof(cByte), "%02x",req.MsgId[index]);
            sMessageId.append(cByte);
        }

        LOG_INFO("Recv channel uplink message.MsgId[%s]MsgFormat[%u]MsgContent[%s]\n",
                            sMessageId.c_str(),
                            req.MsgFormat,
                            sMessageContent.c_str());
        save_message_uplink(req.SrcTermId,req.DestTermId,sMessageContent);
    }
    else // Deliver消息为状态报告
    {
        string sSendState = req.deliverMessage.Stat;

        // 生成消息ID
        for (uint32_t index = 0; index < sizeof(req.deliverMessage.MsgId); index++)
        {
            memset(cByte, 0, sizeof(cByte));
            snprintf(cByte, sizeof(cByte), "%02x",req.deliverMessage.MsgId[index]);
            sMessageId.append(cByte);
        }

        LOG_INFO("Recv channel report message.MsgId[%s]srcphone[%s]destphone[%s]status[%s]\n", 
                            sMessageId.c_str(),
                            req.SrcTermId,
                            req.DestTermId,
                            sSendState.c_str());
                            
        save_message_report(sMessageId,req.SrcTermId,req.DestTermId,sSendState,sSendState);
    }

    //返回应答报文
    smgp_body_deliver_rsp_t rsp;
    memcpy(rsp.MsgId, req.MsgId, sizeof(rsp.MsgId));
    rsp.Status = 0x0;

    char buf[MAX_PACKET_LEN];
    int body_len = m_smgp.make_deliver_rsp(buf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_deliver_rsp fail.\n");
        return -1;
    }

    //报文头
    smgp_header_t head;
    head.RequestId = SMGP_DELIVER_RESP;
    head.SequenceId = hdr->SequenceId;
    head.PacketLength = body_len + SMGP_HEADER_LENGTH;
    m_smgp.make_header(&head,out_msg,SMGP_HEADER_LENGTH);

    out_len = head.PacketLength;
    memcpy(out_msg + SMGP_HEADER_LENGTH,buf,body_len);

    return 0;
}

int SmgpBiz::append_response_map(uint32_t seq_id,message_packet_t *req)
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

void SmgpBiz::save_message_response( int type,message_response_t *rsp )
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

void SmgpBiz::save_message_response(uint32_t seq_id,uint32_t result,string msg_id)
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
        //提供成功的返回状态不修改
    }
    //处理完，清空列表
    m_MessageResponse.erase(seq_id);
}

bool SmgpBiz::format_to_json(message_response_t *rsp,string &sRecvJson)
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
    for (itPhoneList = rsp->mPhoneList.begin(); 
            itPhoneList != rsp->mPhoneList.end(); 
            itPhoneList++)
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

void SmgpBiz::save_message_report(string sMessageid,
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

void SmgpBiz::save_message_uplink(string sSrcPhone,string sDestPhone,string sMessageContent)
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

void SmgpBiz::do_message_response_timeout()
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
