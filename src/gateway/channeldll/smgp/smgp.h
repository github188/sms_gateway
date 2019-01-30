#ifndef __SMGP_H__
#define __SMGP_H__

#include <stdint.h>

#define SMGP_LOGIN                       0x00000001
#define SMGP_LOGIN_RESP                  0x80000001
#define SMGP_SUBMIT                      0x00000002
#define SMGP_SUBMIT_RESP                 0x80000002
#define SMGP_DELIVER                     0x00000003
#define SMGP_DELIVER_RESP                0x80000003
#define SMGP_ACTIVE_TEST                 0x00000004
#define SMGP_ACTIVE_TEST_RESP            0x80000004
#define SMGP_FORWARD                     0x00000005
#define SMGP_FORWARD_TEST                0x80000005
#define SMGP_EXIT                        0x00000006
#define SMGP_EXIT_RESP                   0x80000006
#define SMGP_QUERY                       0x00000007
#define SMGP_QUERY_RESP                  0x80000007
#define SMGP_QUERY_TE_ROUTE              0x00000008
#define SMGP_QUERY_TE_ROUTE_RESP         0x80000008
#define SMGP_QUERY_SP_ROUTE              0x00000009
#define SMGP_QUERY_SP_ROUTE_RESP         0x80000009
#define SMGP_PAYMENT_REQUEST             0x0000000A
#define SMGP_PAYMENT_REQUEST_RESP        0x8000000A
#define SMGP_PAYMENT_AFFIRM              0x0000000B
#define SMGP_PAYMENT_AFFIRM_RESP         0x8000000B
#define SMGP_QUERY_USERSTATE             0x0000000C
#define SMGP_QUERY_USERSTATE_RESP        0x8000000C
#define SMGP_GET_ALL_TE_ROUTE            0x0000000D
#define SMGP_GET_ALL_TE_ROUTE_RESP       0x8000000D
#define SMGP_GET_ALL_SP_ROUTE            0x0000000E
#define SMGP_GET_ALL_SP_ROUTE_RESP       0x8000000E
#define SMGP_UPDATE_TE_ROUTE             0x0000000F
#define SMGP_UPDATE_TE_ROUTE_RESP        0x8000000F
#define SMGP_UPDATE_SP_ROUTE             0x00000010
#define SMGP_UPDATE_SP_ROUTE_RESP        0x80000010
#define SMGP_PUSH_UPDATE_TE_ROUTE        0x00000011
#define SMGP_PUSH_UPDATE_TE_ROUTE_RESP   0x80000011
#define SMGP_PUSH_UPDATE_SP_ROUTE        0x00000012
#define SMGP_PUSH_UPDATE_SP_ROUTE_RESP   0x80000012

// TLV tag type 
#define SMGP_TAG_TP_PID                  0x0001
#define SMGP_TAG_TP_UDHI                 0x0002
#define SMGP_TAG_LINKID                  0x0003
#define SMGP_TAG_CHARGEUSERTYPE          0x0004
#define SMGP_TAG_CHARGETERMTYPE          0x0005
#define SMGP_TAG_CHARGETERMPSEUDO        0x0006
#define SMGP_TAG_DESTTERMTYPE            0x0007
#define SMGP_TAG_DESTTERMPSEUDO          0x0008
#define SMGP_TAG_PKTOTAL                 0x0009
#define SMGP_TAG_PKNUMBER                0x000A
#define SMGP_TAG_SUBMITMSGTYPE           0x000B
#define SMGP_TAG_SPDEALRESLT             0x000C
#define SMGP_TAG_SRCTERMTYPE             0x000D
#define SMGP_TAG_SRCTERMPSEUDO           0x000E
#define SMGP_TAG_NODESCOUNT              0x000F
#define SMGP_TAG_MSGSRC                  0x0010
#define SMGP_TAG_SRCTYPE                 0x0011
#define SMGP_TAG_MSERVICEID              0x0012

// 协议头长度
enum {
    SMGP_HEADER_LENGTH = 12,
};

//------------------------smgp报文头----------------------------------
typedef struct smgp_header_s
{
    uint32_t PacketLength;
    uint32_t RequestId;
    uint32_t SequenceId;
} smgp_header_t;

//-------------------------smgp报文体---------------------------------

typedef struct smgp_variable_tlv_s
{
    unsigned short Tag;
    unsigned short Length;
    char Value[20 + 1];
} smgp_variable_tlv_t;

typedef struct smgp_common_tlv_s
{
    unsigned short Tag;
    unsigned short Length;
    unsigned char Value;
} smgp_common_tlv_t;

typedef struct smgp_tlv_s
{
    smgp_common_tlv_t TPPid;
    smgp_common_tlv_t TPUdhi;
    smgp_variable_tlv_t LinkId;
    smgp_common_tlv_t ChargeUserType;
    smgp_common_tlv_t ChargeTermType;
    smgp_variable_tlv_t ChargeTermPseudo;
    smgp_common_tlv_t DestTermType;
    smgp_variable_tlv_t DestTermPseudo;
    smgp_common_tlv_t PkTotal;
    smgp_common_tlv_t PkNumber;
    smgp_common_tlv_t SubmitMsgType;
    smgp_common_tlv_t SPDealResult;
    smgp_common_tlv_t SrcTermType;
    smgp_variable_tlv_t SrcTermPseudo;
    smgp_common_tlv_t NodesCount;
    smgp_variable_tlv_t MsgSrc;
    smgp_common_tlv_t SrcType;
    smgp_variable_tlv_t MServiceId;
} smgp_tlv_t;

//登录请求
typedef struct smgp_body_login_req_s
{
    char ClientId[8 + 1];                               // 客户端用来登录服务器端的用户账号
    char AuthenticatorClient[16 + 1];                   // 客户端认证码，用来鉴别客户端的合法性
    unsigned char LoginMode;                            // 客户端用来登录服务器端的登录类型
    uint32_t Timestamp;                                 // 时间戳
    unsigned char ClientVersion;                        // 客户端支持的协议版本号
} smgp_body_login_req_t;

//登录应答
typedef struct smgp_body_login_rsp_s
{
    uint32_t Status;                                    // 请求返回结果
    char AuthenticatorServer[16 + 1];                   // 服务器端返回给客户端的认证码
    unsigned char ServerVersion;                        // 服务器端支持的最高版本号
} smgp_body_login_rsp_t;

//发送短信请求
typedef struct smgp_body_submit_req_s 
{
    unsigned char MsgType;                              // 短消息类型
    unsigned char NeedReport;                           // SP是否要求返回状态报告
    unsigned char Priority;                             // 短消息发送优先级
    char ServiceId[10 + 1];                             // 业务代码
    char FeeType[2 + 1];                                // 收费类型
    char FeeCode[6 + 1];                                // 资费代码
    char FixedFee[6 + 1];                               // 包月费 封顶费
    unsigned char MsgFormat;                            // 短消息格式
    char ValidTime[17 + 1];                             // 短消息有效时间
    char AtTime[17 + 1];                                // 短消息定时发送时间
    char SrcTermId[21 + 1];                             // 短信息发送方号码
    char ChargeTermId[21 + 1];                          // 计费用户号码
    unsigned char DestTermIdCount;                      // 短消息接收号码总数
    char DestTermId[100][21 + 1];                       // 短消息接收号码
    unsigned char MsgLength;                            // 短消息长度
    char MsgContent[160 + 1];                           // 短消息内容
    char Reserve[8 + 1];                                // 保留字段
    bool bIsLongSms;                                    // 是否长短信
    unsigned char TPUdhi;                               // GSM协议类型
    unsigned char PkTotal;                              // 长短信消息的总条数
    unsigned char PkNumber;                             // 长短信消息当前序号
}smgp_body_submit_req_t;

//发送短信应答
typedef struct smgp_body_submit_rsp_s
{
    unsigned char MsgId[10];                           // 短消息流水号
    uint32_t Status;                               // 请求返回结果
} smgp_body_submit_rsp_t;

//状态报告
typedef struct smgp_status_report_s
{
    unsigned char MsgId[10];                            // 状态报告对应原短消息的MsgID
    char Sub[3 + 1];                                    // 取缺省值001
    char Dlvrd[3 + 1];                                  // 取缺省值001
    char SubmitDate[10 + 1];                            // 短消息提交时间(格式：年年月月日日时时分分)
    char DoneDate[10 + 1];                              // 短消息下发时间(格式：年年月月日日时时分分)
    char Stat[7 + 1];                                   // 短消息的最终状态
    char Err[3 + 1];                                    // 错误代码
    char Txt[20 + 1];                                   // 前3个字节，表示短消息长度（用ASCII码表示），后17个字节表示短消息的内容（保证内容不出现乱码）
} smgp_status_report_t;

//上行短信、状态报告请求
typedef struct smgp_body_deliver_req_s
{
    unsigned char MsgId[10];                            // 短消息流水号
    unsigned char IsReport;                             // 是否为状态报告
    unsigned char MsgFormat;                            // 短消息格式
    char RecvTime[14 + 1];                              // 短消息接收时间
    char SrcTermId[21 + 1];                             // 短消息发送号码
    char DestTermId[21 + 1];                            // 短消息接收号码
    unsigned char MsgLength;                            // 短消息长度
    char MsgContent[160 + 1];                           // 当为IsReport为0且MsgFmt为0、15时，取该内容
    unsigned short WMsgContent[160 + 1];                // 当为IsReport为0且MsgFmt为8时，取该内容
    smgp_status_report_t deliverMessage;                  // 当为IsReport为1时，取该内容
    char Reserve[8 + 1];                                // 保留字段
    smgp_common_tlv_t tppid;                              // tppid TLV
    smgp_common_tlv_t tpudhi;                             // tpudhi TLV
    smgp_variable_tlv_t linkId;                           // LinkId TLV
} smgp_body_deliver_req_t;

//上行短信、状态报告应答
typedef struct smgp_body_deliver_rsp_s
{
    unsigned char MsgId[10];                            // 短消息流水号
    unsigned int Status;                                // 请求返回结果
} smgp_body_deliver_rsp_t;


class Smgp
{
public:
    Smgp();
    ~Smgp();
    
    uint32_t get_header_len();

    int parse_header(const char* buf, int len, smgp_header_t* header);
    int make_header(smgp_header_t* header, char* buf, int len);

    int make_login_req(char *buf, smgp_body_login_req_t body);
    int parse_login_rsp(char *buf, smgp_body_login_rsp_t &body);
    
    int make_submit_req(char *buf, smgp_body_submit_req_t body);
    int parse_submit_rsp(char *buf, smgp_body_submit_rsp_t &body);

    int make_deliver_rsp(char *buf, smgp_body_deliver_rsp_t body);
    int parse_deliver_req(char *buf,uint32_t body_len,smgp_body_deliver_req_t &body);

    int make_terminal_req(char *buf,uint32_t seq_id);
    int make_terminal_rsp(char *buf,uint32_t seq_id);

    int make_activeTest_req(char *buf,uint32_t seq_id);
    int make_activeTest_rsp(char *buf,uint32_t seq_id);

private:
    int parse_tlv(char *&buf, uint32_t tlvLength, smgp_tlv_t &tlv);
};

#endif