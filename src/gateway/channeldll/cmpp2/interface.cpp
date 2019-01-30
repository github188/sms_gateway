#include <json/json.h>
#include <regex>
#include "interface.h"
#include "channel_db.h"
#include "gateway_util.h"
#include "gateway_crypt.h"
#include "Markup.h"
#include "charset_conv.h"

uint32_t Cmpp2Biz::ui_seq_id = 0;
unsigned char Cmpp2Biz::uc_seq_id = 0;

extern logger_t     *g_log;


extern "C" BIZAPI IChannelBiz* GetBizInterface( uint32_t proto_type )
{
    if( proto_type == 0 )
        return new Cmpp2Biz;
    else
        return NULL;
}

Cmpp2Biz::Cmpp2Biz()
{
    m_pid = getpid();
    m_login_success = 0;
    m_rsp_cnt = 0;
    m_last_rsp_opr_redis_time = 0;
    m_report_cnt = 0;
    m_last_report_opr_redis_time = 0;
}

Cmpp2Biz::~Cmpp2Biz()
{

}

int Cmpp2Biz::init_biz(const char* conf, void* args,channel_conf_t *channel)
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

int Cmpp2Biz::uninit_biz()
{
    // todo 

    uninit_db();

    return 0;
}

int Cmpp2Biz::is_login_success(int& is_success )
{
    is_success = m_login_success;
    return 0;
}

/* @description 判断报文的完整性
 * @return 不完整则返回0， 完整则返回整个报文的长度，无效报文则返回-1
 */
int Cmpp2Biz::is_packet_complete(const char* msg, int len)
{
    if( msg == NULL ) return -1;

    if ( len < CMPP2_HEADER_LENGTH )
    {
        return 0;
    }

    //解析报文头
    cmpp_header_t header;
    int ret = m_cmpp2.parse_header(msg,len,&header);
    if( ret != 0 )
    {
        return -1;
    }

    if ( (uint32_t)len < header.TotalLength ) 
    {
        return 0;
    }

    return header.TotalLength;
}

int Cmpp2Biz::channel_rsp(dict* wq,
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
    cmpp_header_t hdr; 
    ret = m_cmpp2.parse_header(in_msg,in_len,&hdr);
    if( ret != 0 )
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }

    //判断报文类型
    switch( hdr.CommandId )
    {
    case CMPP_ACTIVE_TEST://心跳请求报文
        {
            ret = handle_active_test_req(&hdr,
                                    in_msg + CMPP2_HEADER_LENGTH,
                                    hdr.TotalLength - CMPP2_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case CMPP_ACTIVE_TEST_RESP://心跳应答报文
        {
            LOG_INFO("Recv cmpp_active_test_resp.seq_id[%u]\n",hdr.SequenceId);
            ret = 1; //不需要返回报文
            break;
        }
    case CMPP_TERMINATE://停止服务请求报文
        {
            ret = handle_terminate_req(&hdr,
                                    in_msg + CMPP2_HEADER_LENGTH,
                                    hdr.TotalLength - CMPP2_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
        }
    case CMPP_TERMINATE_RESP: //停止服务应答报文
        {
            LOG_INFO("Recv cmpp_terminate_resp.seq_id[%u]\n",hdr.SequenceId);
            ret = 1; //不需要返回报文
            break;
        }
	case CMPP_CONNECT_RESP: //登录应答报文
		{
			ret = handle_connect_rsp(&hdr,
                                    in_msg + CMPP2_HEADER_LENGTH,
                                    hdr.TotalLength - CMPP2_HEADER_LENGTH);
            break;
		}
    case CMPP_SUBMIT_RESP: //发送信息应答报文
		{
			ret = handle_submit_rsp(&hdr,
                                    in_msg + CMPP2_HEADER_LENGTH,
                                    hdr.TotalLength - CMPP2_HEADER_LENGTH);
            break;
		}
    case CMPP_DELIVER: //状态、上行短信请求报文
		{
			ret = handle_deliver_req(&hdr,
                                    in_msg + CMPP2_HEADER_LENGTH,
                                    hdr.TotalLength - CMPP2_HEADER_LENGTH,
                                    out_msg,
                                    out_len);
            break;
		}
	default:
	    {
    		LOG_ERROR("unknown command : 0x%x\n", hdr.CommandId);
    	    ret = -1;
    		break;
        }
    }

    return ret;
}


int Cmpp2Biz::send_msg_req(dict* wq,
                             message_packet_t *packet,
                             char *sid,
                             char* out_msg, 
                             int& out_len)
{
    if( packet == NULL || out_msg == NULL || m_channel == NULL)
    {
        return -1;
    }

    //报文头
    cmpp_header_t hdr;
    hdr.CommandId = CMPP_SUBMIT;
    hdr.SequenceId = get_ui_seq();

    LOG_INFO("Sendmsg to channel.phone size[%d]seq_id[%u]\n",packet->mPhoneList.size(),hdr.SequenceId);

    //报文体
    cmpp_body_submit_t bodySubmit;
    memset(&bodySubmit,0,sizeof(cmpp_body_submit_t));

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
        strncpy(bodySubmit.DestTerminalId[cnt], itPhone->second.sMobilePhone.c_str(), sizeof(bodySubmit.DestTerminalId[cnt]));
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

    // 信息级别
    bodySubmit.MsgLevel = 0x0;
    // 计费用户类型字段2:对SP计费
    bodySubmit.FeeUserType = 0x0;
    // GSM协议类型
    bodySubmit.TPPId = 0x0;
    // 企业代码
    strncpy(bodySubmit.MsgSrc, m_channel->sSpId.c_str(),sizeof(bodySubmit.MsgSrc));

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
    // 资费类别
    strncpy(bodySubmit.FeeType, m_channel->sFeeType.c_str(),sizeof(bodySubmit.FeeType));
    // 资费代码
    strncpy(bodySubmit.FeeCode, m_channel->sFeeCode.c_str(),sizeof(bodySubmit.FeeCode));
    //接入号 源号码
    strncpy(bodySubmit.SrcId,packet->sSrcPhone.c_str(),sizeof(bodySubmit.SrcId));
    
    //未知需求
    if( m_channel->uCustomParam3 == 1 )
        bodySubmit.MsgFmt = 0x9;
    else
        bodySubmit.MsgFmt = 0x8;

    //特殊通道需求
    if( m_channel->uCustomParam4 == 1 )
    {  // 固定签名，处理掉签名
        const char *pFeeTerminalId = "15056141414";
        bodySubmit.FeeUserType = 0x3;
        memcpy(bodySubmit.FeeTerminalId, pFeeTerminalId, strlen(pFeeTerminalId));
        RemoveSmsSign(packet->sMessageContent);
    }

    // 接收信息的用户数量
    bodySubmit.DestUsrtl = (unsigned char)cnt;

    if ( m_channel->uCustomParam2 == 1 )
    {
        //模板短信
        bool bFound = false;
        string sTemp;
        string sGbk;
        bodySubmit.MsgFmt = 0xF;
        //这里重复
        strncpy(bodySubmit.SrcId, m_channel->sAccessCode.c_str(), sizeof(bodySubmit.SrcId));

        map<string,string>::iterator it_temp;
        for (it_temp = m_mCmppTemplate.begin(); it_temp != m_mCmppTemplate.end(); it_temp++)
        {
            if (make_template_xml(it_temp->first, it_temp->second,packet->sMessageContent, sTemp))
            {
                bFound = true;
                break;
            }
        }
        if (!bFound) return -1;
        // 将UTF-8编码转为GBK编码
        utf8_to_ascii(sTemp,sGbk);

        // 流速限制
        limit_submit_speed();

        bodySubmit.RegisteredDelivery = 0x1;
        bodySubmit.Pktotal = 0x1;
        bodySubmit.Pknumber = 0x1;
        bodySubmit.TPUdhi = 0x0;
        bodySubmit.MsgLength = sGbk.length();
        memcpy(bodySubmit.MsgContent, sGbk.c_str(), bodySubmit.MsgLength);

        char buf[MAX_PACKET_LEN];
        int body_len = m_cmpp2.make_submit_req(buf,bodySubmit);
        hdr.TotalLength = body_len + CMPP2_HEADER_LENGTH;
        m_cmpp2.make_header(&hdr,out_msg,CMPP2_HEADER_LENGTH);

        out_len = hdr.TotalLength;
        memcpy(out_msg + CMPP2_HEADER_LENGTH,buf,body_len);
    }
    else if ( m_channel->uCustomParam2 == 2 ) // 编码MSG_FMT为15的短信发送
    {
        string sGbk;
        // 流速限制
        limit_submit_speed();
        // 将UTF-8编码转为GBK编码
        utf8_to_ascii(packet->sMessageContent,sGbk);
        bodySubmit.MsgFmt = 0xF;
        bodySubmit.RegisteredDelivery = 0x1;
        bodySubmit.Pktotal = 0x1;
        bodySubmit.Pknumber = 0x1;
        bodySubmit.TPUdhi = 0x0;
        memset(bodySubmit.Reserve, 0x0, sizeof(bodySubmit.Reserve));
        bodySubmit.MsgLength = sGbk.length();
        memcpy(bodySubmit.MsgContent, sGbk.c_str(), bodySubmit.MsgLength);
        
        char buf[MAX_PACKET_LEN];
        int body_len = m_cmpp2.make_submit_req(buf,bodySubmit);
        hdr.TotalLength = body_len + CMPP2_HEADER_LENGTH;
        m_cmpp2.make_header(&hdr,out_msg,CMPP2_HEADER_LENGTH);

        out_len = hdr.TotalLength;
        memcpy(out_msg + CMPP2_HEADER_LENGTH,buf,body_len);
    }
    else
    {
        uint32_t uTextLen = GetUtf8TextLength( packet->sMessageContent );
        if (uTextLen <= 70)
        {
            //普通短信
            // 流速限制
            limit_submit_speed();
            bodySubmit.RegisteredDelivery = 0x1;
            bodySubmit.Pktotal = 0x1;
            bodySubmit.Pknumber = 0x1;
            bodySubmit.TPUdhi = 0x0;
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
            int body_len = m_cmpp2.make_submit_req(buf,bodySubmit);
            hdr.TotalLength = body_len + CMPP2_HEADER_LENGTH;
            m_cmpp2.make_header(&hdr,out_msg,CMPP2_HEADER_LENGTH);

            out_len = hdr.TotalLength;
            memcpy(out_msg + CMPP2_HEADER_LENGTH,buf,body_len);
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
            bodySubmit.Pktotal = (unsigned char)uPkTotal;
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

            bodySubmit.TPUdhi = 0x1;

            int total_len = 0;
            unsigned short index;
            for (index = 1; index <= uPkTotal; index++)
            {
                // 流速限制
                limit_submit_speed();
                bodySubmit.Pknumber = (unsigned char)index;
                cLongGatewayHeader[5] = (unsigned char)index;
                char *pMsgContent = bodySubmit.MsgContent;
                memcpy(pMsgContent, cLongGatewayHeader, sizeof(cLongGatewayHeader));
                pMsgContent += sizeof(cLongGatewayHeader);
                if (index != uPkTotal)  // 如果不是最后一条，以67个UCS-2字符取内容
                {
                    // 设置第一条返回状态报告
                    if (index == 1)
                        bodySubmit.RegisteredDelivery = 0x1;
                    else
                        bodySubmit.RegisteredDelivery = 0x0;
                    uint32_t uPartLen = 67 * sizeof(unsigned short);
                    bodySubmit.MsgLength = 0x6 + uPartLen;
                    memcpy(pMsgContent, ptr, uPartLen);
                    ptr += 67;
                }
                else    //最后一条
                {
                    bodySubmit.RegisteredDelivery = 0x0;
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
                int body_len = m_cmpp2.make_submit_req(buf,bodySubmit);
                hdr.TotalLength = body_len + CMPP2_HEADER_LENGTH;
                m_cmpp2.make_header(&hdr,out_msg + total_len ,CMPP2_HEADER_LENGTH);

                memcpy(out_msg + total_len + CMPP2_HEADER_LENGTH,buf,body_len);
                total_len += hdr.TotalLength;
            }
            if( pwText != NULL )
            {
                delete [] pwText;
                pwText = NULL;
            }
            out_len = total_len;
        }
    }

    return 0;
}

int Cmpp2Biz::channel_login_req(char* out_msg, int& out_len)
{
    if( out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }
    
    //发送登录请求
    //报文体
    cmpp_body_connect_t cmpp_connect;
    char timestamp[10 + 1] = {0};
    get_datetime(timestamp,sizeof(timestamp));

    //Source_Addr
    strncpy(cmpp_connect.SourceAddr, m_channel->sUserName.c_str(), sizeof(cmpp_connect.SourceAddr));
    
    //AuthenticatorSource
    int buf_len = m_channel->sUserName.length() + m_channel->sPassword.length() + 9 + 10;
    char *auth_src = (char *)malloc(buf_len + 1);
    if( auth_src == NULL )  return -1;
    memset(auth_src, 0x00, buf_len + 1);
    char *ptr = auth_src;
    SetBufferString(ptr, m_channel->sUserName.c_str(), m_channel->sUserName.length());
    SetBufferZero(ptr, 9);
    SetBufferString(ptr, m_channel->sPassword.c_str(), m_channel->sPassword.length());
    SetBufferString(ptr, timestamp, sizeof(timestamp) - 1 );
    unsigned char MD5result[16] = {0};
    MD5((const unsigned char*)auth_src,buf_len,MD5result);
    memcpy(cmpp_connect.AuthenticatorSource,MD5result,sizeof(cmpp_connect.AuthenticatorSource));
    free(auth_src);
    auth_src = NULL;
    //Version
    cmpp_connect.Version = 0x20;
    //Timestamp
    cmpp_connect.Timestamp = atoi(timestamp);

    char buf[MAX_PACKET_LEN];
    int body_len = m_cmpp2.make_connect_req(buf, cmpp_connect);
    if( body_len <= 0 )
    {
        LOG_ERROR("make connect req fail.\n");
        return -1;
    }

    //报文头
    cmpp_header_t hdr;
    hdr.CommandId = CMPP_CONNECT;
    hdr.SequenceId = get_ui_seq();
    hdr.TotalLength = body_len + CMPP2_HEADER_LENGTH;
    m_cmpp2.make_header(&hdr,out_msg,CMPP2_HEADER_LENGTH);

    out_len = hdr.TotalLength;
    memcpy(out_msg + CMPP2_HEADER_LENGTH,buf,body_len);

    LOG_INFO("Sendchannel login req.seq_id[%u]\n",hdr.SequenceId);

    return 0;
}

int Cmpp2Biz::timer_process( dict* wq,
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
    out_len = m_cmpp2.make_activeTest_req(out_msg,seq_id);

    LOG_INFO("Sendchannel heartbeat req.seq_id[%u]\n",seq_id);
    
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

    //加载模板
    if ( m_channel->uCustomParam2 == 1 )
    {
        //加载CMPP短信模板
        load_template();
    }

    return 0;
}

uint32_t Cmpp2Biz::get_ui_seq()
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

unsigned char Cmpp2Biz::get_uc_seq()
{
    return uc_seq_id++;
}

int Cmpp2Biz::load_template()
{
    string info;
    int ret = query_channel_template(m_channel->sChannelId.c_str(),info);
    if( ret != 0 )
    {
        LOG_ERROR("query_channel_template fail. channel_id[%s]\n",m_channel->sChannelId.c_str());
        return -1;
    }

    m_mCmppTemplate.clear();

    Json::Reader jsonReader;
    Json::Value  jsonRoot;
    if (!jsonReader.parse(info, jsonRoot))
    {
        LOG_ERROR("Parse json is failure.The json:%s.", info.c_str());
        return -1;
    }

    Json::Value jsonTemplate = jsonRoot["template"];
    if (jsonTemplate.isNull() || !jsonTemplate.isArray())
        return -1;
    for (unsigned int index = 0; index < jsonTemplate.size(); index++)
    {
        Json::Value jsonItem = jsonTemplate[index];
        Json::Value jsonValue = jsonItem["m_code"];
        if (jsonValue.isNull() || !jsonValue.isString())
            continue;
        string sTemplateCode = jsonValue.asString();
        jsonValue = jsonItem["m_content"];
        if (jsonValue.isNull() || !jsonValue.isString())
            continue;
        string sTemplateContent = jsonValue.asString();
        m_mCmppTemplate[sTemplateCode] = sTemplateContent;
        LOG_DEBUG("code[%s],content[%s]\n", sTemplateCode.c_str(), sTemplateContent.c_str());
    }

    return 0;
}
bool Cmpp2Biz::make_template_xml(string code,string content,string msg_content,string &temp_content)
{
    if (code.empty() || content.empty() || msg_content.empty())
    {
        return false;
    }

    regex regTemplate(content.c_str());
    sregex_iterator it(msg_content.begin(), msg_content.end(), regTemplate);
    sregex_iterator end;
    if (it == end)
        return false;
    if (it->size() <= 0)
        return false;

    CMarkup xml;
    xml.SetDoc("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
    xml.AddElem("cmppTemplate");
    xml.IntoElem();
    xml.AddElem("template", code);

    for (size_t pos = 1; pos < it->size(); ++pos)
    {
        char sNodeName[10] = {0};
        snprintf(sNodeName,sizeof(sNodeName),"node%zu",pos);
        xml.AddElem(sNodeName, (*it)[pos].str());
    }
    /*
    string raw_data = xml.GetDoc();
    size_t index = raw_data.find("<cmppTemplate>");
    if ( index != string::npos )
        temp_content = raw_data.substr(index);
    */
    temp_content = xml.GetDoc();
    return true;
}

int Cmpp2Biz::handle_active_test_req(cmpp_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    //心跳请求报文

    LOG_INFO("Recv active_test_req.seq_id[%u]\n",hdr->SequenceId);

    out_len = m_cmpp2.make_activeTest_rsp(out_msg,hdr->SequenceId,0x0);

    return 0;
}

int Cmpp2Biz::handle_terminate_req(cmpp_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    //拆除连接请求报文

    LOG_INFO("Recv terminate_req.seq_id[%u]\n",hdr->SequenceId);

    out_len = m_cmpp2.make_terminal_rsp(out_msg,hdr->SequenceId);

    return 0;
}

int Cmpp2Biz::handle_connect_rsp(cmpp_header_t *hdr,const char* body,int len)
{
    cmpp_body_connect_resp_t rsp;
    int tmp_len = m_cmpp2.parse_connect_rsp(const_cast<char *>(body),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_connect_rsp fail.\n");
        return -1;
    }

    LOG_INFO("Recv connect_resp.seq_id[%u]status[%d]\n",
                                     hdr->SequenceId,
                                     rsp.Status);
    if( rsp.Status == 0x0 )
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

int Cmpp2Biz::handle_submit_rsp(cmpp_header_t *hdr,const char* body,int len)
{
    cmpp_body_submit_resp_t rsp;
    int tmp_len = m_cmpp2.parse_submit_rsp(const_cast<char *>(body),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_submit_rsp fail.\n");
        return -1;
    }

/*
    //旧msgid生产方法
    uint64_t tmp = htonl64(rsp.MsgId); //转成网络序
    uint32_t uMsgId[3];
    uMsgId[0] = (tmp & 0xFFFF000000000000) >> 48;
    uMsgId[1] = (tmp & 0xFFFFFC000000) >> 26;
    uMsgId[2] = (tmp & 0x3FFFFFF);
    uint64_t msgid = ( (uint64_t)uMsgId[2] << 38 ) | ( (uint64_t)uMsgId[1] << 16 ) | uMsgId[0];
*/
    LOG_INFO("Recv channel submit rsp.seq_id[%u]MsgId[%lu]Result[%u]\n",hdr->SequenceId,rsp.MsgId,rsp.Result);

    //将应答报文写入redis
    save_message_response(hdr->SequenceId,rsp.Result,rsp.MsgId);

    return 1;
}

int Cmpp2Biz::handle_deliver_req(cmpp_header_t *hdr,const char* body,int len,char* out_msg,int& out_len)
{
    //状态报告、上行短信报文
    cmpp_body_deliver_t req;
    int tmp_len = m_cmpp2.parse_deliver_req(const_cast<char *>(body),req);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_deliver_req fail.\n");
        return -1;
    }

    // Deliver消息为非状态报告
    if ( req.RegisteredDelivery == 0x0 )
    {
        string sMessageContent;
        if (req.MsgFmt == 0x08)    // 消息内容为Unicode编码，转化为UTF-8
        {
            unsigned int uUcs2Len = req.MsgLength / sizeof(unsigned short);
            TransCodeFromUnicodeBE(sMessageContent, req.WMsgContent, uUcs2Len);
        }
        else
        {
            // 将GBK编码转成UTF-8编码
            ascii_to_utf8(req.MsgContent,sMessageContent);
        }
        LOG_INFO("Recv uplink message.seq_id[%u]MsgId[%llu]msgfmt[%u]content[%s]\n",
                            hdr->SequenceId,
                            req.MsgId,
                            req.MsgFmt,
                            sMessageContent.c_str());
        save_message_uplink(req.SrcTerminalId,req.DestId,sMessageContent);
    }
    else // Deliver消息为状态报告
    {
        string sSendState = req.deliverMessage.Stat;
        uint64_t uMessageid = req.deliverMessage.MsgId;
        string sMessageid = to_string(uMessageid);

        LOG_INFO("Recv report message.seq_id[%u]MsgId[%lu]srcphone[%s]destphone[%s]status[%s]\n", 
                            hdr->SequenceId,
                            uMessageid,
                            req.SrcTerminalId,
                            req.DestId,
                            sSendState.c_str());
                            
        save_message_report(sMessageid,req.SrcTerminalId,req.DestId,sSendState,sSendState);
    }

    //返回应答报文
    cmpp_body_deliver_resp_t rsp;
    rsp.MsgId = req.MsgId;
    rsp.Result = 0x0;

    char buf[MAX_PACKET_LEN];
    int body_len = m_cmpp2.make_deliver_rsp(buf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_deliver_rsp fail.\n");
        return -1;
    }

    //报文头
    cmpp_header_t head;
    head.CommandId = CMPP_DELIVER_RESP;
    head.SequenceId = hdr->SequenceId;
    head.TotalLength = body_len + CMPP2_HEADER_LENGTH;
    m_cmpp2.make_header(&head,out_msg,CMPP2_HEADER_LENGTH);

    out_len = head.TotalLength;
    memcpy(out_msg + CMPP2_HEADER_LENGTH,buf,body_len);

    return 0;
}

int Cmpp2Biz::append_response_map(uint32_t seq_id,message_packet_t *req)
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

void Cmpp2Biz::save_message_response( int type,message_response_t *rsp )
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
        //提交错误的号码状态
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

void Cmpp2Biz::save_message_response(uint32_t seq_id,uint32_t result,uint64_t msg_id)
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

    uint64_t uMsgId = msg_id;
    //设置返回msgid
    map<string, sms_attribute_t>::iterator itPhoneList;
    for (itPhoneList = response.mPhoneList.begin(); 
         itPhoneList != response.mPhoneList.end(); 
         itPhoneList++)
    {
        LOG_INFO("response msgid=[%lu],phone[%s]\n",uMsgId,itPhoneList->second.sMobilePhone.c_str());
        itPhoneList->second.sMessageid = to_string( uMsgId );
        //cmpp群发时,响应包只有一个msgid
        //状态报告中的msgid是由响应包中的msgid递增的。
        uMsgId++;
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

bool Cmpp2Biz::format_to_json(message_response_t *rsp,string &sRecvJson)
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

    jsonRoot["PacketType"] = Json::Value(0);
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

void Cmpp2Biz::save_message_report(string sMessageid,
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

void Cmpp2Biz::save_message_uplink(string sSrcPhone,string sDestPhone,string sMessageContent)
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

void Cmpp2Biz::do_message_response_timeout()
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

void Cmpp2Biz::RemoveSmsSign(string &sMessageContent)
{
    if (sMessageContent.empty())    return;
    try
    {
        size_t nEndPos = 0;
        size_t nBeginPos = sMessageContent.find("【");
        if (nBeginPos == std::string::npos)
            return;
        if (nBeginPos == 0)
        {
            nEndPos = sMessageContent.find("】");
            if (nEndPos == std::string::npos)
                return;
        }
        else
        {
            nEndPos = sMessageContent.rfind("】");
            if (nEndPos != (sMessageContent.length() - strlen("】")))
                return;
            else
                nBeginPos = sMessageContent.rfind("【");
        }
        if (nEndPos <= nBeginPos)
            return;

        if (nBeginPos == 0)     
            sMessageContent = sMessageContent.substr(nEndPos + strlen("】"));
        else                    
            sMessageContent = sMessageContent.substr(0, nBeginPos);
        return;
    }
    catch (...)
    {
        return;
    }
}
