#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include "gateway.pb.h"

using namespace gatewaymsg;

typedef struct connection_s connection_t;

// Э��ͷ����
enum {
    PROTOCOL_HEADER_LENGTH = 32,
};

enum {
    PROTOCOL_VERSION = 1,
};

//������
enum {
    // ע�⣬���������Ķ�ʱ����������Ӧ���Ķ���ż��
    //////////////////////////////////////////////////////////////////////
    // ������
    //////////////////////////////////////////////////////////////////////
    CMD_HEARTBEAT_REQ                          = 0x00010001, // ��������
    CMD_HEARTBEAT_RSP                          = 0x00010002, // ����Ӧ��

    //////////////////////////////////////////////////////////////////////
    // ע����
    //////////////////////////////////////////////////////////////////////
    CMD_SVR_REG_REQ                            = 0x00010003, // ����ע������
    CMD_SVR_REG_RSP                            = 0x00010004, // ����ע��Ӧ��


    CMD_CHANNEL_MGR_REQ                        = 0x00020001, // ͨ����������
    CMD_CHANNEL_MGR_RSP                        = 0x00020002, // ͨ������Ӧ��
    CMD_CHANNEL_INFO_REQ                       = 0x00020003, // ͨ��������Ϣ����
    CMD_CHANNEL_INFO_RSP                       = 0x00020004, // ͨ��������ϢӦ��
    CMD_GATEWAY_MSG_SEND_REQ                   = 0x00020005, // ��Ϣ��������
    CMD_GATEWAY_MSG_SEND_RSP                   = 0x00020006, // ��Ϣ����Ӧ��

};

//Э��ṹ��
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
// ����Э��ͷ����
uint32_t get_header_len();

// ��鱨���ǲ�ʱ����, -1 ���� 0 û��� > ���
int is_packet_complete(const char* buf, unsigned len);

// ����ͷ
int parse_header(const char* buf, int len, message_head_t* header);
int make_header(message_head_t* header, char* buf, int len);
int make_default_header(message_head_t* header, int vender_id, int market_id);

// ͨ�ñ���
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
