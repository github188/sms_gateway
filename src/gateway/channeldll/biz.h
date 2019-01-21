#ifndef __BIZ_H__
#define __BIZ_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <map>
#include <set>
#include "public.h"

//windows
#ifdef _MSC_VER
#  ifdef BIZDLL
#    define BIZAPI __declspec(dllexport)
#  else
#    define BIZAPI __declspec(dllimport)
#  endif
#else
#  define BIZAPI
#endif


#define HTTP_XML_GETITEM(xml, tag, value) \
    do { \
        value.clear(); \
        xml.ResetMainPos(); \
        if (tag && xml.FindElem(tag)) { \
            value = xml.GetData(); \
        } \
    }while(0) 


typedef struct http_wait_cache_s {
    char sid[MAX_SID_LEN];
    int  busi_type;
    uint32_t seq_id;
    long uptime;
    http_wait_cache_s() 
    {
        memset(this, 0, sizeof(*this));
        uptime =  get_utc_miliseconds();
    }
}http_wait_cache_t;

typedef struct channel_conf_s
{
    std::string sChannelId;             // 通道ID
    std::string sChannelName;           //通道名称
    uint32_t uProtoType;                // 网关协议类型(0:CMPP2.0 1:SGIP1.2 2:SMGP3.0 3:HTTP)
    uint32_t uMassSupport;              // 是否支持群发
    uint32_t uMassNum;                  // 群发消息量
    uint32_t lHeartbeatInterval;        // 心跳间隔
    uint32_t uSendSpeed;                // 发送流速
    uint32_t uLinkCount;                //连接数
    std::string sIpAddress;                 // 网关地址
    unsigned short lPort;                   // 网关端口
    unsigned short uListenPort;             // 本地监听端口（仅对SGIP）
    uint32_t uSignType;                 // 签名类型(1:前置2:后置3:不限)
    uint32_t uTimeout;                  // 发送超时时间 （没有用到）
    std::string sAccessCode;                // 通道接入号
    std::string sUserName;                  // 用户名
    std::string sPassword;                  // 密码
    std::string sSpId;                      // 企业代码
    std::string sServiceId;                 // 业务代码
    std::string sFeeType;                   // 资费类别
    std::string sFeeCode;                   // 资费代码
    unsigned char sVersion;                 // 版本号 （有用到，没赋值）
    uint32_t uSpnodeCode;               // 节点编号（没有用到）
    uint32_t uHttpType;                  // HTTP接口类型
    std::string sHttpUrl;                   // HTTP短信提交URL
    uint32_t uCustomParam1;             // 自定义参数1
    uint32_t uCustomParam2;             // 自定义参数2
    uint32_t uCustomParam3;             // 自定义参数3
    uint32_t uCustomParam4;             // 自定义参数4
    uint32_t uCustomParam5;             // 自定义参数5
} channel_conf_t;

typedef struct sms_attribute_s
{
    bool bNeedSend;
    std::string sVirtualStatus;
    std::string sConvertStatus;
    std::string sMobilePhone;
    std::string sSmsContent;
    std::string sMessageid;
    std::string sMobileCity;
}sms_attribute_t;

typedef struct sms_argument_s
{
    std::string sDateTime;
    std::string sSubmitId;
    std::string sBatchno;
    std::string sOperatorId;
    std::string sClientId;
    std::string sAccountId;
    std::string sCompanyId;
    std::string sSmsContent;    // 普通短信内容
    uint32_t uSubmitWay;
    bool bOtoSend;
    bool bSmsResend;
    uint32_t uReturnType;       // 返量类型    (0:默认 1:驳回返  2:驳回不返)
    std::string sSmsData;       // SMS数据
} sms_argument_t;

typedef struct message_response_s
{
    std::string sSrcPhone;                                  // 接入号
    uint32_t uSmsCount;                                     // 短信条数
    uint32_t uChannelType;                                  // 通道类型
    std::string sChannelId;                                 // 通道ID
    std::string sChannelGroupId;                            // 通道组ID
    sms_argument_t smsArgument;                             // 短信发送参数
    uint32_t uNosendCount;                                  // 不处理数
    uint32_t uErrorCount;                                   // 发送错误数
    uint32_t uSuccessCount;                                 // 发送成功数
    uint32_t uFailCount;                                    // 发送失败数
    std::string sSendTime;                                  // 发送时间 YYYY-MM-DD hh:mm:ss
    time_t nsend_time;                                      //发送时间 毫秒
    std::map<std::string, sms_attribute_t> mPhoneList;      // 目标号码对应的属性集合
 } message_response_t;

typedef struct message_packet_s
{
    std::string sSrcPhone;                                  // 接入号
    std::string sMessageContent;                            // 短信内容
    uint32_t uChannelType;                                  // 通道类型
    std::string sChannelId;                                 // 通道ID
    std::string sChannelGroupId;                            // 通道组ID
    sms_argument_t smsArgument;                             // 短信发送参数
    std::map<std::string, sms_attribute_t> mPhoneList;      // 目标号码对应的属性集合
}message_packet_t;

class BIZAPI IChannelBiz
{
public:
    IChannelBiz() : m_channel(NULL),
                    m_sendcheck(0),
                    m_microseconds(0)
    {

    }
    
    virtual ~IChannelBiz(){}
    
    /* @description 初始化通道业务
     * @param conf  配置文件
     * @param args  日志库
     * @param channel  通道参数
     * @return 0 成功，其他 失败
     */
    virtual int init_biz( const char* conf, 
                         void* args,
                         channel_conf_t *channel ) = 0;

    /* @description 通道业务清理
     * @return 0 成功，其他 失败
     */
    virtual int uninit_biz() = 0;

    /* @description 是否需要监听服务
     * @return 0 成功，其他 失败
     */
    virtual int is_need_to_listen(int& need_to_listen,int& listen_port)
    {
        need_to_listen = 0;
        listen_port = 0;
        return 0;
    }

    /* @description 是否登录成功
     * @return 0 成功，其他 失败
     */
    virtual int is_login_success(int& is_success )
    {
        is_success = 1;
        return 0;
    }

    /* @description 判断报文的完整性
     * @return 不完整则返回0， 完整则返回整个报文的长度，无效报文则返回-1
    */
    virtual int is_packet_complete(const char* msg, int len) = 0;
    

    /* @description 通道应答的报文
     * @return 成功返回0， 其他 失败
    */
    virtual int channel_rsp(dict* wq,
                          const char* in_msg, 
                          int in_len,
                          char *sid,
                          char* out_msg, 
                          int& out_len) = 0;


    /* @description 通道主动请求的报文
     * @return 成功返回0， 其他 失败
    */
    virtual int channel_req(const char* in_msg,int in_len,char* out_msg,int& out_len)
    {
        return 0;
    }


    /* @description 信息发送请求
     * @return 成功返回0， 其他 失败
    */
    virtual int send_msg_req(dict* wq,
                             message_packet_t *packet,
                             char *sid,
                             char* out_msg, 
                             int& out_len) = 0;

    /* @description 通道登录请求
     * @return 成功返回0， 其他 失败
    */
    virtual int channel_login_req(char* out_msg, int& out_len)
    {
        out_len = 0;
        return 0;
    }

    /* @description 定时任务,心跳发送，状态、上行短信拉取
     * @return 成功返回0， 其他 失败
    */
    virtual int timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len )
    {
        return 0;
    }

    /* @description 通道参数重置
     * @return 成功返回0， 其他 失败
    */
    virtual int reload_channel(channel_conf_t *channel)
    {
        if( channel == NULL )
        {
            return -1;
        }
        m_channel = channel;
        return 0;
    }

    /* @description 限速
     * @return 
    */
    virtual void limit_submit_speed()
    {
        if( m_channel == NULL )
        {
            return;
        }

        //初始化时记录一个时间点
        if( m_sendcheck == 0 )
        {
            m_microseconds = get_utc_microseconds();
            m_sendcheck = 1;
        }
        else
        {
            int64_t now = get_utc_microseconds();
            int64_t interval = now - m_microseconds;
            if( interval < m_channel->uSendSpeed )
            {
                usleep( m_channel->uSendSpeed - interval  );
                m_microseconds = get_utc_microseconds();
            }
            else
            {
                m_microseconds = now;
            }
        }
    }

public:
    channel_conf_t          *m_channel; //通道参数
    uint32_t                m_sendcheck;
    int64_t                 m_microseconds;

};

// dll导出的函数原型
typedef IChannelBiz* (*GetBizInterfaceFunc)( uint32_t proto_type );

extern "C" BIZAPI IChannelBiz* GetBizInterface( uint32_t proto_type );

#endif
