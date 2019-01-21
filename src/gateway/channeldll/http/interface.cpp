#include <json/json.h>
#include "interface.h"
#include "channel_db.h"
#include "gateway_util.h"
#include "gateway_crypt.h"
#include "charset_conv.h"
#include "hbtelecom.h"
#include "buyun.h"
#include "unmobile.h"
#include "gtunicom.h"
#include "spacei.h"
#include "dinghan.h"
#include "mengxin.h"
#include "hxtelecom.h"
#include "zytelecom.h"
#include "lgmobile.h"
#include "masmobile.h"
#include "wcwxunicom.h"
#include "kdmobile.h"
#include "txmobile.h"
#include "ytmobile.h"

extern logger_t     *g_log;

uint32_t HttpBiz::ui_seq_id = 0;
unsigned char HttpBiz::uc_seq_id = 0;

extern "C" BIZAPI IChannelBiz* GetBizInterface( uint32_t proto_type )
{
    /*
    系统目前用到的http通道
    1002
    1005
    1008
    1018
    1032
    1038
    1041
    */
    if ( proto_type == 1002 || proto_type == 1004 || proto_type == 1006 ||
         proto_type == 1007 || proto_type == 1009 || proto_type == 1010 ||
         proto_type == 1011 || proto_type == 1012 || proto_type == 1013 ||
         proto_type == 1014 || proto_type == 1015 || proto_type == 1016 ||
         proto_type == 1017 || proto_type == 1019 || proto_type == 1020 ||
         proto_type == 1021 || proto_type == 1023 || proto_type == 1025 ||
         proto_type == 1026 )
    {
        return new HbTelecomBiz();
    }
    else if( proto_type == 1001 ) // 步云HTTP接口
    {
        //uCustomParam2   port
        //  /smsreport
        //  /smsuplink
        return new BuYunBiz();
    }
    else if( proto_type == 1003 ) // 服务器已经不可以访问
    {
        return new UnMobileBiz();
    }
    else if( proto_type == 1005 ) // 共图股票通道 上行短信有问题
    {
        return new GtUnicomBiz();
    }
    else if( proto_type == 1008 ) // 空间畅想通道
    {
        return new SpaceiBiz();
    }
    else if( proto_type == 1018 ) // 广州鼎汉
    {
        return new DinghanBiz();
    }
    else if( proto_type == 1024 || proto_type == 1027 ) // KD移动房产固签
    {
        return new KdMobileBiz();
    }
    else if( proto_type == 1028 ) // TX通道接口
    {
        return new TxMobileBiz();
    }
    else if( proto_type == 1030 ) // YT通道接口
    {
        return new YtMobileBiz();
    }
    else if( proto_type == 1032 ) // 短信通 盟信互通
    {
        return new MengxinBiz();
    }
    else if( proto_type == 1033 ) // MCWX通道接口
    {
        return new WcwxUnicomBiz();
    }
    else if( proto_type == 1035 ) // 移动Mas通道接口
    {
        return new MasBiz();
    }
    else if( proto_type == 1038 ) // HX通道接口
    {
        return new HxTelecomBiz();
    }
    else if( proto_type == 1039 ) // 鹿港Mas通道接口
    {
        return new LgMobileBiz();
    }
    else if( proto_type == 1041 ) // zyHTTP接口
    {
        return new ZYTelecomBiz();
    }
    else
    {
        return NULL;
    }
}

HttpBiz::HttpBiz()
{

}

HttpBiz::~HttpBiz()
{

}

int HttpBiz::init_biz(const char* conf, void* args,channel_conf_t *channel)
{
    if (conf == NULL || args == NULL || channel == NULL)
    {
        return -1;
    }
    g_log = (logger_t *)args;
    m_channel = channel;
    
    //读取配置文件

    // 初始化redis数据库
    if (init_db( conf ) != 0)
    {
        LOG_ERROR("fail to initialize biz redis.\n");
        return -1;
    }
	LOG_INFO("biz redis initialize successful.\n");

    // 初始化Mongodb数据库
    if (m_mongo_db.init_db( conf ) != 0)
    {
        LOG_ERROR("fail to initialize biz mongo_db.\n");
        return -1;
    }
	LOG_INFO("biz mongo_db initialize successful.\n");

    m_pid = getpid();

    return 0;
}

int HttpBiz::uninit_biz()
{
    // todo 

    uninit_db();

    return 0;
}

int HttpBiz::is_need_to_listen(int& need_to_listen,int& listen_port)
{
    need_to_listen = 0;
    return 0;
}

/* @description 判断报文的完整性
 * @return 不完整则返回0， 完整则返回整个报文的长度，无效报文则返回-1
 */
int HttpBiz::is_packet_complete(const char* msg, int len)
{
    if( msg == NULL ) return -1;

    const char* pos_begin = NULL;
    const char* pos_end = NULL;
    const char* pos_head_end = NULL;

    char len_buf[32] = { 0 };
    int body_len = 0;

    // http head
    pos_begin = strstr(msg, "\r\n\r\n");
    if (pos_begin == NULL) 
    {
        return 0;
    }
    pos_head_end = pos_begin + strlen("\r\n\r\n");
    int hdr_len = pos_head_end - msg;
    
    //Connection
    pos_begin = strstr(msg, "Keep-Alive");
    if( pos_begin != NULL )
    {
        // Content-Length
        pos_begin = strstr(msg, "Content-Length:");
        if (pos_begin == NULL) 
        {
            // Transfer-Encoding: chunked
            pos_begin = strstr(msg, "Transfer-Encoding: chunked");
            if(pos_begin == NULL) 
            {
                // Content-Length/Transfer-Encoding: chunked
                LOG_ERROR("Content-Length/Transfer-Encoding: chunked, not valid http protocol\n");
                return -1;
            }

            int cnt_len = parse_http_chunked_data(msg + hdr_len, len - hdr_len, NULL, body_len);
            if(cnt_len > 0)
            {
                return cnt_len + hdr_len;
            }
            return cnt_len;
        }

        pos_end = strstr(pos_begin, "\r\n");
        if (pos_end == NULL) 
        {
            return 0;
        }
        body_len = strlen("Content-Length:");
        memcpy(len_buf, pos_begin + body_len, pos_end - pos_begin - body_len);
        body_len = atoi(len_buf);

        int cnt_len = len - hdr_len;
        if (cnt_len >= body_len) 
        {
            return body_len + hdr_len;
        }
    }
    else
    {
        return len;
    }
    
    return 0;
}

int HttpBiz::channel_req(const char* in_msg,int in_len,char* out_msg,int& out_len)
{
    if( in_msg == NULL || out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }
    return 0;
}

int HttpBiz::channel_rsp(dict* wq,
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

    return 0;
}

int HttpBiz::send_msg_req(dict* wq,
                             message_packet_t *packet,
                             char *sid,
                             char* out_msg, 
                             int& out_len)
{
    if( packet == NULL || out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }

    return 0;
}

int HttpBiz::timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len )
{
    if( out_msg == NULL || m_channel == NULL )
    {
        return -1;
    }

    return 0;
}

uint32_t HttpBiz::get_ui_seq()
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

unsigned char HttpBiz::get_uc_seq()
{
    return uc_seq_id++;
}

int HttpBiz::append_response_map(uint32_t seq_id,message_packet_t *req)
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
    msgResponse.nsend_time = get_utc_miliseconds();
    msgResponse.mPhoneList = req->mPhoneList;

    m_MessageResponse[seq_id] = msgResponse;
    
    return 0;
}

void HttpBiz::save_message_response( int type,message_response_t *rsp )
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

void HttpBiz::save_message_response(uint32_t seq_id,string result,string msg_id)
{
    message_response_t response = m_MessageResponse[seq_id];
    if( response.mPhoneList.size() == 0 )
    {
        LOG_WARN("response not find.seqid[%u]\n",seq_id);
        return;
    }

    if( result.compare("0") == 0 )
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

    //增加响应量
    save_channel_rsp_remaining(response.sChannelId.c_str(),1);

    // 响应写入redis
    save_channel_rsp( sMessagePacket );

    for (itPhoneList = response.mPhoneList.begin(); 
         itPhoneList != response.mPhoneList.end(); 
         itPhoneList++)
    {
        //提交失败的，内部产生状态报告
        if( result.compare("0") != 0 )
        {
            char aGenerateStatus[16] = {0};
            snprintf(aGenerateStatus, sizeof(aGenerateStatus), "NSM%s", result.c_str());
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

bool HttpBiz::format_to_json(message_response_t *rsp,string &sRecvJson)
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

void HttpBiz::save_message_report(string sMessageid,
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

    //状态报告增加量
    save_channel_report_remaining(m_channel->sChannelId.c_str(),1);

    //写入redis
    save_channel_report(report_json);
}

void HttpBiz::save_message_uplink(string sSrcPhone,string sDestPhone,string sMessageContent)
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

void HttpBiz::do_message_response_timeout()
{
    //清理超时未响应的短信
    map<uint32_t,message_response_t>::iterator rsp_it;
    for (rsp_it = m_MessageResponse.begin();rsp_it != m_MessageResponse.end();)
    {
        time_t now = get_utc_miliseconds();
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

void HttpBiz::clear_time_out_rsp(dict* wq)
{
    if( wq == NULL  )
    {
        return;
    }
    //清理超时报文
    dict_iterator* di = dict_get_safe_iterator(wq);
    dict_entry* de = NULL;
    time_t now = get_utc_miliseconds();
    while ((de = dict_next(di)) != NULL)
    {
        http_wait_cache_t* wi = (http_wait_cache_t*) dict_get_entry_val(de);
        if (wi == NULL)
        {
            LOG_WARN("TIMEOUT\n");
            dict_delete(wq, de->key, de->keylen);
            continue;
        }

        time_t diff = now - wi->uptime;
        if ( diff > m_channel->lHeartbeatInterval )
        {
            LOG_DEBUG("diff = %d, timeout=%u\n", diff, m_channel->lHeartbeatInterval);
            dict_delete(wq, de->key, de->keylen);
            continue;
        }
    }
    dict_release_iterator(di);
}
