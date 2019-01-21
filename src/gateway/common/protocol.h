#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include "gateway.pb.h"

using namespace gatewaymsg;

typedef struct connection_s connection_t;

// 协议头长度
enum {
    PROTOCOL_HEADER_LENGTH = 32,
};

enum {
    PROTOCOL_VERSION = 1,
};

//命令码
enum {
    // 注意，所有请求报文都时奇数，所有应答报文都是偶数
    //////////////////////////////////////////////////////////////////////
    // 心跳类
    //////////////////////////////////////////////////////////////////////
    CMD_HEARTBEAT_REQ                          = 0x00010001, // 心跳请求
    CMD_HEARTBEAT_RSP                          = 0x00010002, // 心跳应答

    //////////////////////////////////////////////////////////////////////
    // 注册类
    //////////////////////////////////////////////////////////////////////
    CMD_SVR_REG_REQ                            = 0x00010003, // 服务注册请求
    CMD_SVR_REG_RSP                            = 0x00010004, // 服务注册应答


    CMD_CHANNEL_MGR_REQ                        = 0x00020001, // 通道管理请求
    CMD_CHANNEL_MGR_RSP                        = 0x00020002, // 通道管理应答
    CMD_CHANNEL_INFO_REQ                       = 0x00020003, // 通道连接信息请求
    CMD_CHANNEL_INFO_RSP                       = 0x00020004, // 通道连接信息应答
    CMD_GATEWAY_MSG_SEND_REQ                   = 0x00020005, // 信息发送请求
    CMD_GATEWAY_MSG_SEND_RSP                   = 0x00020006, // 信息发送应答

};

//协议结构体
 typedef struct message_head_s
{
    uint32_t version;
    uint32_t length;
    uint32_t command;
    uint32_t vender_id;
    uint32_t market;
    uint32_t is_cksum;
    uint32_t check_sum;
    uint32_t extend;

    message_head_s()
    {
        memset(this, 0, sizeof(*this));
    }

}message_head_t;

/////////////////////////////////////////////////////////////////////
// 返回协议头长度
uint32_t get_header_len();

// 检查报文是不时完整, -1 出错 0 没完成 > 完成
int is_packet_complete(const char* buf, unsigned len);

// 报文头
int parse_header(const char* buf, int len, message_head_t* header);
int make_header(message_head_t* header, char* buf, int len);
int make_default_header(message_head_t* header, int vender_id, int market_id);

// 通用报文
int parse_msg(const char* buf, int len, ::google::protobuf::Message* req);

int make_req(message_head_t *header, ::google::protobuf::Message* req,
        connection_t* con);

int make_req(message_head_t *header, ::google::protobuf::Message* req,
        char* buf, int flen);      

int make_rsp(message_head_t *header, ::google::protobuf::Message* rsp,
        connection_t* con);

int make_rsp(message_head_t *header, ::google::protobuf::Message* rsp,
        char* buf, int flen);

/////////////////////////////////////////
void dump(::google::protobuf::Message* msg);
void dump(const char* buf, int len);
void dump(message_head_t *header);
void dump(message_head_t *header, ::google::protobuf::Message* msg);

#endif
