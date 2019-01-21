#ifndef __CMPP2_H__
#define __CMPP2_H__

#include <stdint.h>

#define CMPP_CONNECT                    0x00000001
#define CMPP_CONNECT_RESP               0x80000001
#define CMPP_TERMINATE                  0x00000002
#define CMPP_TERMINATE_RESP             0x80000002
#define CMPP_SUBMIT                     0x00000004
#define CMPP_SUBMIT_RESP                0x80000004
#define CMPP_DELIVER                    0x00000005
#define CMPP_DELIVER_RESP               0x80000005
#define CMPP_QUERY                      0x00000006
#define CMPP_QUERY_RESP                 0x80000006
#define CMPP_CANCEL                     0x00000007
#define CMPP_CANCEL_RESP                0x80000007
#define CMPP_ACTIVE_TEST                0x00000008
#define CMPP_ACTIVE_TEST_RESP           0x80000008
#define CMPP_FWD                        0x00000009
#define CMPP_FWD_RESP                   0x80000009
#define CMPP_MT_ROUTE                   0x00000010
#define CMPP_MT_ROUTE_RESP              0x80000010
#define CMPP_MO_ROUTE                   0x00000011
#define CMPP_MO_ROUTE_RESP              0x80000011
#define CMPP_GET_ROUTE                  0x00000012
#define CMPP_GET_ROUTE_RESP             0x80000012
#define CMPP_MT_ROUTE_UPDATE            0x00000013
#define CMPP_MT_ROUTE_UPDATE_RESP       0x80000013
#define CMPP_MO_ROUTE_UPDATE            0x00000014
#define CMPP_MO_ROUTE_UPDATE_RESP       0x80000014
#define CMPP_PUSH_MT_ROUTE_UPDATE       0x00000015
#define CMPP_PUSH_MT_ROUTE_UPDATE_RESP  0x80000015
#define CMPP_PUSH_MO_ROUTE_UPDATE       0x00000016
#define CMPP_PUSH_MO_ROUTE_UPDATE_RESP  0x80000016

// 协议头长度
enum {
    CMPP2_HEADER_LENGTH = 12,
};

//------------------------cmpp报文头----------------------------------
typedef struct cmpp_header_s
{
    uint32_t TotalLength;            // 消息的总长度(字节) 头+体
    uint32_t CommandId;              // 命令ID
    uint32_t SequenceId;             // 消息流水号
} cmpp_header_t;

//-------------------------cmpp报文体---------------------------------

//注册请求
typedef struct cmpp_body_connect_s
{
    char SourceAddr[6 + 1];                // 企业代码
    unsigned char AuthenticatorSource[16]; // 源地址鉴别码
    unsigned char Version;                 // 双方协商的版本号
    uint32_t Timestamp;               // 时间戳MMDDHHmmss(月日时分秒)
} cmpp_body_connect_t;

//注册应答
typedef struct cmpp_body_connect_resp_s
{
    unsigned char Status;                  // 0:正确 1:消息结构错 2:非法源地址 3:认证错 4:版本太高 5:其他错误
    unsigned char AuthenticatorISMG[16];   // ISMG认证码
    unsigned char Version;                 // 服务器支持的最高版本号
} cmpp_body_connect_resp_t;

//短信发送请求
typedef struct cmpp_body_submit_s
{
    uint64_t MsgId;                // 信息标识
    unsigned char Pktotal;                 // 相同Msg_Id的信息总条数
    unsigned char Pknumber;                // 相同Msg_Id的信息序号
    unsigned char RegisteredDelivery;      // 是否要求状态确认（0：不需要 1：需要 2：产生SMC话单）
    unsigned char MsgLevel;                // 信息级别
    char ServiceId[10 + 1];                // 业务类型
    unsigned char FeeUserType;             // 计费用户类型字段(0:对目的终端手机计费 1:对源终端手机计费 2:对SP计费 3:表示本字段无效，对谁计费参见Fee_terminal_Id字段)
    unsigned char FeeTerminalId[21];       // 被计费用户的号码
    unsigned char TPPId;                   // GSM协议类型
    unsigned char TPUdhi;                  // GSM协议类型
    unsigned char MsgFmt;                  // 信息格式(0：ASCII串 3：短信写卡操作 4：二进制信息 8：UCS2编码 15：含GB汉字)
    char MsgSrc[6 + 1];                    // 信息内容来源
    char FeeType[2 + 1];                   // 资费类别(01：对“计费用户号码”免费 02：对“计费用户号码”按条计信息费 03：对“计费用户号码”按包月收取信息费 04：对“计费用户号码”的信息费封顶 05：对“计费用户号码”的收费是由SP实现)
    char FeeCode[6 + 1];                   // 资费代码
    char ValIdTime[17 + 1];                // 存活有效期
    char AtTime[17 +1];                    // 定时发送时间
    char SrcId[21 + 1];                    // 源号码
    unsigned char DestUsrtl;               // 接收信息的用户数量
    char DestTerminalId[500][21 + 1];      // 接收短信的手机号码
    unsigned char MsgLength;               // 消息长度
    char MsgContent[1072 + 1];             // 消息内容
    char Reserve[8 + 1];                   // 保留字段
} cmpp_body_submit_t;

//短信发送应答
typedef struct cmpp_body_submit_resp_s
{
    uint64_t MsgId;                // 信息标识
    unsigned char Result;                  // (0：正确 1：消息结构错 2：命令字错 3：消息序号重复4：消息长度错 5：资费代码错 6：超过最大信息长 7：业务代码错 8：流量控制错 9~ ：其他错误)
} cmpp_body_submit_resp_t;


// CMPP_BODY_DELIVER消息为状态报告时，MsgContent的内容
typedef struct cmpp_deliver_message_s
{
    uint64_t MsgId;                // 信息标识
    char Stat[7 + 1];                      // 发送短信的应答结果
    char SubmitTime[10 + 1];               // YYMMDDHHMM
    char DoneTime[10 + 1];                 // YYMMDDHHMM
    char DestTerminalId[21 + 1];           // 目的终端手机号码
    uint32_t SMSCSequence;            // 取自SMSC发送状态报告的消息体中的消息标识
} cmpp_deliver_message_t;

//状态推送，上行短信请求
typedef struct cmpp_body_deliver_s
{
    uint64_t MsgId;                // 信息标识
    char DestId[21 + 1];                   // 目的号码
    char ServiceId[10 + 1];                // 业务类型
    unsigned char TPPid;                   // GSM协议类型
    unsigned char TPUdhi;                  // GSM协议类型
    unsigned char MsgFmt;                  // 信息格式(0：ASCII串 3：短信写卡操作 4：二进制信息 8：UCS2编码 15：含GB汉字)
    char SrcTerminalId[21 + 1];            // 源终端手机号码
    unsigned char RegisteredDelivery;      // 是否要求状态报告(0:非状态报告 1:状态报告)
    unsigned char MsgLength;               // 消息长度
    char MsgContent[160 + 1];              // 当为RegisteredDelivery为0且MsgFmt为0、15时，取该内容
    unsigned short WMsgContent[160 + 1];   // 当为RegisteredDelivery为0且MsgFmt为8时，取该内容
    cmpp_deliver_message_t deliverMessage;   // 当为RegisteredDelivery为1时，取该内容
    char Reserved[8 + 1];                  // 保留字段
} cmpp_body_deliver_t;

//状态推送，上行短信应答
typedef struct cmpp_body_deliver_resp_s
{
    uint64_t MsgId;                // 信息标识
    unsigned char Result;           // 0：正确 1：消息结构错 2：命令字错 3：消息序号重复 4：消息长度错 5：资费代码错 6：超过最大信息长 7：业务代码错 8: 流量控制错 9~ ：其他错误
} cmpp_body_deliver_resp_t;

class Cmpp2
{
public:
    Cmpp2();
    ~Cmpp2();
    
    uint32_t get_header_len();

    int parse_header(const char* buf, int len, cmpp_header_t* header);
    int make_header(cmpp_header_t* header, char* buf, int len);

    int make_connect_req(char *buf, cmpp_body_connect_t body);
    int make_connect_rsp(char *buf, cmpp_body_connect_resp_t body);
    int parse_connect_req(char *buf, cmpp_body_connect_t & body);
    int parse_connect_rsp(char *buf, cmpp_body_connect_resp_t &body);
    
    int make_submit_req(char *buf, cmpp_body_submit_t body);
    int make_submit_rsp(char *buf, cmpp_body_submit_resp_t body);
    int parse_submit_req(char *buf, cmpp_body_submit_t &body);
    int parse_submit_rsp(char *buf, cmpp_body_submit_resp_t &body);
    
    int make_deliver_req(char *buf, cmpp_body_deliver_t body);
    int make_deliver_rsp(char *buf, cmpp_body_deliver_resp_t body);
    int parse_deliver_req(char *buf, cmpp_body_deliver_t &body);
    int parse_deliver_rsp(char *buf, cmpp_body_deliver_resp_t &body);

    int make_terminal_req(char *buf,uint32_t seq_id);
    int make_terminal_rsp(char *buf,uint32_t seq_id);

    int make_activeTest_req(char *buf,uint32_t seq_id);
    int make_activeTest_rsp(char *buf,uint32_t seq_id,unsigned char Reserved);

};

#endif