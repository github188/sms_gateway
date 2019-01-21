#ifndef __SGIP_H__
#define __SGIP_H__

#include <stdint.h>

#define SGIP_BIND                   0x00000001
#define SGIP_BIND_RESP              0x80000001
#define SGIP_UNBIND                 0x00000002
#define SGIP_UNBIND_RESP            0x80000002
#define SGIP_SUBMIT                 0x00000003
#define SGIP_SUBMIT_RESP            0x80000003
#define SGIP_DELIVER                0x00000004
#define SGIP_DELIVER_RESP           0x80000004
#define SGIP_REPORT                 0x00000005
#define SGIP_REPORT_RESP            0x80000005
#define SGIP_ADDSP                  0x00000006
#define SGIP_ADDSP_RESP             0x80000006
#define SGIP_MODIFYSP               0x00000007
#define SGIP_MODIFYSP_RESP          0x80000007
#define SGIP_DELETESP               0x00000008
#define SGIP_DELETESP_RESP          0x80000008
#define SGIP_QUERYROUTE             0x00000009
#define SGIP_QUERYROUTE_RESP        0x80000009
#define SGIP_ADDTELESEG             0x0000000A
#define SGIP_ADDTELESEG_RESP        0x8000000A
#define SGIP_MODIFYTELESEG          0x0000000B
#define SGIP_MODIFYTELESEG_RESP     0x8000000B
#define SGIP_DELETETELESEG          0x0000000C
#define SGIP_DELETETELESEG_RESP     0x8000000C
#define SGIP_ADDSMG                 0x0000000D
#define SGIP_ADDSMG_RESP            0x8000000D
#define SGIP_MODIFYSMG              0x0000000E
#define SGIP_MODIFYSMG_RESP         0x8000000E
#define SGIP_DELETESMG              0x0000000F
#define SGIP_DELETESMG_RESP         0x8000000F
#define SGIP_CHECKUSER              0x00000010
#define SGIP_CHECKUSER_RESP         0x80000010
#define SGIP_USERRPT                0x00000011
#define SGIP_USERRPT_RESP           0x80000011
#define SGIP_TRACE                  0x00001000
#define SGIP_TRACE_RESP             0x80001000

// 协议头长度
enum {
    SGIP_HEADER_LENGTH = 20,
};

//------------------------sgip报文头----------------------------------
typedef struct sgip_header_s
{
    uint32_t MessageLength;         // 消息的总长度(字节)
    uint32_t CommandId;             // 命令ID
    uint32_t SequenceId[3];         // 消息流水号
} sgip_header_t;

//-------------------------sgip报文体---------------------------------

//登录请求
typedef struct sgip_body_bind_req_s 
{
    unsigned char LoginType;                              // 登陆类型
    char LoginName[16 + 1];                               // 登陆名
    char LoginPassword[16 + 1];                           // 密码
    char Reserve[8 + 1];                                  // 保留字段
}sgip_body_bind_req_t;

//登录应答
typedef struct sgip_body_bind_rsp_s 
{
    unsigned char Result;                                 // 结果状态
    char Reserve[8 + 1];                                  // 保留字段
}sgip_body_bind_rsp_t;

//发送短信请求
typedef struct sgip_body_submit_req_s 
{
    char SPNumber[21 + 1];                                // SP的接入号码
    char ChargeNumber[21 + 1];                            // 付费号码
    unsigned char UserCount;                              // 接收短消息的手机数量，取值范围1至100
    char UserNumber[100][21 + 1];                         // 接收该短消息的手机号数组
    char CorpId[5 + 1];                                   // 企业代码
    char ServiceType[10 + 1];                             // 业务代码
    unsigned char FeeType;                                // 计费类型
    char FeeValue[6 + 1];                                 // 取值范围0-99999，该条短消息的收费值，单位为分
    char GivenValue[6 + 1];                               // 取值范围0-99999，赠送用户的话费，单位为分
    unsigned char AgentFlag;                              // 代收费标志，0：应收；1：实收
    unsigned char MorelatetoMTFlag;                       // 引起MT消息的原因(0-MO点播引起的第一条MT消息 1-MO点播引起的非第一条MT消息 2-非MO点播引起的MT消息 3-系统反馈引起的MT消息)
    unsigned char Priority;                               // 优先级0-9从低到高，默认为0
    char ExpireTime[16 + 1];                              // 短消息寿命的终止时间，如果为空，表示使用短消息中心的缺省值。时间内容为16个字符，格式为”yymmddhhmmsstnnp” ，其中“tnnp”取固定值“032+”，即默认系统为北京时间
    char ScheduleTime[16 + 1];                            // 短消息定时发送的时间，如果为空，表示立刻发送该短消息。时间内容为16个字符，格式为“yymmddhhmmsstnnp” ，其中“tnnp”取固定值“032+”
    unsigned char ReportFlag;                             // 状态报告标记(0-该条消息只有最后出错时要返回状态报告 1-该条消息无论最后是否成功都要返回状态报告 2-该条消息不需要返回状态报告 3-该条消息仅携带包月计费信息，不下发给用户，要返回状态报告)
    unsigned char TPPid;                                  // GSM协议类型。详细解释请参考GSM03.40中的9.2.3.9
    unsigned char TPUdhi;                                 // GSM协议类型。详细解释请参考GSM03.40中的9.2.3.23,仅使用1位，右对齐
    unsigned char MessageCoding;                          // 短消息的编码格式(0：纯ASCII字符串 3：写卡操作 4：二进制编码 8：UCS2编码 15: GBK编码)
    unsigned char MessageType;                            // 信息类型(0-短消息信息 其它：待定)
    uint32_t MessageLength;                           // 短消息的长度
    char MessageContent[160 + 1];                         // 短消息的内容
    char Reserve[8 + 1];                                  // 保留，扩展用
}sgip_body_submit_req_t;

//发送短信应答
typedef struct sgip_body_submit_rsp_s
{
    unsigned char Result;                                 // Submit命令是否成功接收(0：接收成功 其它：错误码)
    char Reserve[8 + 1];                                  // 保留，扩展用
}sgip_body_submit_rsp_t;

//上行短信请求
typedef struct sgip_body_deliver_req_s 
{
    char UserNumber[21 + 1];                              // 发送短消息的用户手机号，手机号码前加“86”国别标志
    char SPNumber[21 + 1];                                // SP的接入号码
    unsigned char TPPid;                                  // GSM协议类型。详细解释请参考GSM03.40中的9.2.3.9
    unsigned char TPUdhi;                                 // GSM协议类型。详细解释请参考GSM03.40中的9.2.3.23,仅使用1位，右对齐
    unsigned char MessageCoding;                          // 短消息的编码格式(0：纯ASCII字符串 3：写卡操作 4：二进制编码 8：UCS2编码 15: GBK编码)
    uint32_t MessageLength;                           // 短消息的长度
    char MessageContent[160 + 1];                         // 当MessageCoding为0、15时，取该内容
    unsigned short WMsgContent[160 + 1];                  // 当MessageCoding为8时，取该内容
    char Reserve[8 + 1];                                  // 保留，扩展用
}sgip_body_deliver_req_t;

//上行短信应答
typedef struct sgip_body_deliver_rsp_s
{
    unsigned char Result;                                 // Deliver命令是否成功接收(0：接收成功 其它：错误码)
    char Reserve[8 + 1];                                  // 保留，扩展用
}sgip_body_deliver_rsp_t;

//信息到达状态报告请求
typedef struct sgip_body_report_req_s 
{
    uint32_t SubmitSequenceNumber[3];                     // 该命令所涉及的Submit或deliver命令的序列号
    unsigned char ReportType;                             // Report命令类型(0：对先前一条Submit命令的状态报告 1：对先前一条前转Deliver命令的状态报告)
    char UserNumber[21 + 1];                              // 接收短消息的手机号，手机号码前加“86”国别标志
    unsigned char State;                                  // 该命令所涉及的短消息的当前执行状态(0：发送成功 1：等待发送 2：发送失败)
    unsigned char ErrorCode;                              // 当State=2时为错误码值，否则为0
    char Reserve[8 + 1];                                  // 保留，扩展用
}sgip_body_report_req_t;

//信息到达状态报告应答
typedef struct sgip_body_report_rsp_s
{
    unsigned char Result;                                 // Report命令是否成功接收(0：接收成功 其它：错误码)
    char Reserve[8 + 1];                                  // 保留，扩展用
}sgip_body_report_rsp_t;

//获取某条信息状态请求
typedef struct sgip_body_trace_req_s
{
    uint32_t SubmitSequenceNumber[3];
    char UserNumber[21 + 1];
    char Reserve[8 + 1];
}sgip_body_trace_req_t;

//获取某条信息状态应答
typedef struct sgip_body_trace_rsp_s
{
    unsigned char Count;
    unsigned char Result;
    char NodeId[6 + 1];
    char ReceiveTime[16 + 1];
    char SendTime[16 + 1];
    char Reserve[8 + 1];
}sgip_body_trace_rsp_t;

class Sgip
{
public:
    Sgip();
    ~Sgip();
    
    uint32_t get_header_len();

    int parse_header(const char* buf, int len, sgip_header_t* header);
    int make_header(sgip_header_t* header, char* buf, int len);

    int make_bind_req(char *buf, sgip_body_bind_req_t body);
    int make_bind_rsp(char *buf, sgip_body_bind_rsp_t body);
    int parse_bind_req(char *buf, sgip_body_bind_req_t &body);
    int parse_bind_rsp(char *buf, sgip_body_bind_rsp_t &body);
    
    int make_submit_req(char *buf, sgip_body_submit_req_t body);
    int parse_submit_rsp(char *buf, sgip_body_submit_rsp_t &body);

    int make_deliver_rsp(char *buf, sgip_body_deliver_rsp_t body);
    int parse_deliver_req(char *buf, sgip_body_deliver_req_t &body);

    int make_report_rsp(char *buf, sgip_body_report_rsp_t body);
    int parse_report_req(char *buf, sgip_body_report_req_t &body);

    int make_unbind_req(char *buf, uint32_t seq_id[3]);
    int make_unbind_rsp(char *buf, uint32_t seq_id[3]);

    int make_trace_req(char *buf, sgip_body_trace_req_t body);
    int parse_trace_rsp(char *buf, sgip_body_trace_rsp_t &body);
};

#endif