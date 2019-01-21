#include <typeinfo>
#include "protocol.h"
#include "public.h"

// 返回协议头长度
uint32_t get_header_len()
{
    return PROTOCOL_HEADER_LENGTH;
}

// 检查报文是不是完整
int is_packet_complete(const char* buf, unsigned len)
{
    if(len <= get_header_len())
    {
        return 0;
    }

    message_head_t header;
    memset(&header, 0, sizeof(message_head_t));

    int ret = parse_header(buf, len, &header);
    if(ret != 0)
    {
        return -1;
    }

    if(len < header.length)
    {
        return 0;
    }
    return header.length;
}

// 报文头
int parse_header(const char* buf, int len, message_head_t* header)
{
    uint32_t version = 0;
    uint32_t length = 0;
    uint32_t command = 0;
    uint32_t vender_id = 0;
    uint32_t market = 0;
    uint32_t is_cksum = 0;
    uint32_t check_sum = 0;
    uint32_t extend = 0;

    int offset = 0;

    memcpy(&version, buf + offset, sizeof(uint32_t));
    header->version = ntohl(version);

    offset += sizeof(uint32_t);
    memcpy(&length, buf + offset, sizeof(uint32_t));
    header->length = ntohl(length);

    offset += sizeof(uint32_t);
    memcpy(&command, buf + offset, sizeof(uint32_t));
    header->command = ntohl(command);

    offset += sizeof(uint32_t);
    memcpy(&vender_id, buf + offset, sizeof(uint32_t));
    header->vender_id = ntohl(vender_id);

    offset += sizeof(uint32_t);
    memcpy(&market, buf + offset, sizeof(uint32_t));
    header->market = ntohl(market);

    offset += sizeof(uint32_t);
    memcpy(&is_cksum, buf + offset, sizeof(uint32_t));
    header->is_cksum = ntohl(is_cksum);

    offset += sizeof(uint32_t);
    memcpy(&check_sum, buf + offset, sizeof(uint32_t));
    header->check_sum = ntohl(check_sum);

    offset += sizeof(uint32_t);
    memcpy(&extend, buf + offset, sizeof(uint32_t));
    header->extend = ntohl(extend);

    return 0;
}

// make header
int make_header(message_head_t* header, char* buf, int len)
{
    if(len < PROTOCOL_HEADER_LENGTH)
    {
        return -1;
    }
    uint32_t version = 0;
    uint32_t length = 0;
    uint32_t command = 0;
    uint32_t vender_id = 0;
    uint32_t market = 0;
    uint32_t is_cksum = 0;
    uint32_t check_sum = 0;
    uint32_t extend = 0;

    uint32_t offset = 0;

    version = htonl(header->version);
    memcpy(buf + offset, &version, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    length = htonl(header->length);
    memcpy(buf + offset, &length, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    command = htonl(header->command);
    memcpy(buf + offset, &command, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    vender_id = htonl(header->vender_id);
    memcpy(buf + offset, &vender_id, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    market = htonl(header->market);
    memcpy(buf + offset, &market, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    is_cksum = htonl(header->is_cksum);
    memcpy(buf + offset, &is_cksum, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    check_sum = htonl(header->check_sum);
    memcpy(buf + offset, &check_sum, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    extend = htonl(header->extend);
    memcpy(buf + offset, &extend, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    return offset;
}

// make default header
int make_default_header(message_head_t* header, int vender_id, int market_id)
{
    if(header == NULL)
    {
        return -1;
    }
    header->version = PROTOCOL_VERSION;
    header->vender_id = vender_id;
    header->market = market_id;

    return 0;
}

// 通用报文
int parse_msg(const char* buf, int len, ::google::protobuf::Message* req)
{
    if (req != NULL) 
    {
        if (!req->ParseFromArray(buf, len)) 
        {
            LOG_ERROR("protocol buffer ParseFromArray failed.\n");
            return -1;
        }
        if (CHECK_IS_DEBUG()) 
        {
            if (typeid(*req) != typeid(HeartBeatReq)
                    && typeid(*req) != typeid(HeartBeatRsp)) 
            {
                LOG_DEBUG("%s\n", req->ShortDebugString().c_str());
            }
        }

        return 0;
    }
    return -1;
}

// make req
int make_req(message_head_t *header, ::google::protobuf::Message* req,
        connection_t* con)
{
    buffer_t* sndbuf = con->sndbuf;
    char* sbuf = sndbuf->get_write_ptr(sndbuf);
    int slen = sndbuf->get_free_size(sndbuf);

    int packet_len = make_req(header, req, sbuf, slen);

    if (packet_len <= 0) 
    {
        LOG_ERROR("make_req failed.\n");
        return -1;
    }

    sndbuf->set_write_size(sndbuf, packet_len);

    return 0;
}

// make req
int make_req(message_head_t *header, ::google::protobuf::Message* req,
        char* buf, int flen)
{
    char p_buf[MAX_PACKET_LEN] = {0};
    req->SerializeToArray(p_buf, MAX_PACKET_LEN);

    int body_length = req->ByteSize();
    
    header->length = get_header_len() + body_length;
     
    int header_length = PROTOCOL_HEADER_LENGTH;
    
    if(flen < (header_length + body_length))
        return -1;
    
    if (CHECK_IS_DEBUG()) 
    {
        if ( !(header->command == CMD_HEARTBEAT_REQ
                || header->command == CMD_HEARTBEAT_RSP) ) 
        {
            LOG_DEBUG("req packet:\n");
            dump(header, req);
        }
    }
    
    make_header(header, buf, header_length);

    memcpy(buf + header_length, p_buf, body_length);

    return header_length + body_length;
}

// make rsp
int make_rsp(message_head_t *header, ::google::protobuf::Message* rsp,
        connection_t* con)
{
    buffer_t* sndbuf = con->sndbuf;
    char* sbuf = sndbuf->get_write_ptr(sndbuf);
    int flen = sndbuf->get_free_size(sndbuf);

    int packet_len = make_rsp(header, rsp, sbuf, flen);

    if (packet_len <= 0) 
    {
        LOG_ERROR("make_rsp failed.\n");
        return -1;
    }
    sndbuf->set_write_size(sndbuf, packet_len);
    return 0;
}

// make rsp
int make_rsp(message_head_t *header, ::google::protobuf::Message* rsp,
        char* buf, int flen)
{
    char p_buf[MAX_PACKET_LEN] = {0};
    rsp->SerializeToArray(p_buf, MAX_PACKET_LEN);

    int body_length = rsp->ByteSize();

    if(header->command % 2 != 0) 
    {
        header->command++;
    }

    header->length = get_header_len() + body_length;

    int header_length = PROTOCOL_HEADER_LENGTH;
    
    if(flen < (header_length + body_length))
        return -1;
    
    if (CHECK_IS_DEBUG()) 
    {
        if ( !(header->command == CMD_HEARTBEAT_REQ
                || header->command == CMD_HEARTBEAT_RSP) ) 
        {
            LOG_DEBUG("rsp packet:\n");
            dump(header, rsp);
        }
    }
        
    make_header(header, buf, header_length);

    memcpy(buf + header_length, p_buf, body_length);
    
    return header_length + body_length;
}

//
void dump(::google::protobuf::Message* msg)
{
    if (CHECK_IS_DEBUG()) 
    {
        if (msg != NULL) 
        {
            std::string debug = msg->DebugString();
            LOG_DEBUG("%s\n", debug.c_str());
        }
    }
}

void dump(const char* buf, int len)
{
    if (CHECK_IS_DEBUG()) 
    {
        
        message_head_t hdr;

        LOG_DEBUG("===HEADER========================\n");
      
        if (parse_header(buf, len, &hdr) != 0) 
        {
            LOG_DEBUG("parse_header failed.\n");
            return;
        }
            
        dump(&hdr);

        LOG_DEBUG("===PACKET========================\n");
       
        ::google::protobuf::Message* msg = NULL;
        switch (hdr.command) 
        {
        case CMD_HEARTBEAT_REQ:  //0x00010001 心跳请求
            msg = new HeartBeatReq;
            break;
        case CMD_HEARTBEAT_RSP: //0x00010002 心跳应答
            msg = new HeartBeatRsp;
            break;
        case CMD_SVR_REG_REQ:  //0x00010003 服务注册请求
            msg = new SvrRegReq;
            break;
        case CMD_SVR_REG_RSP: //0x00010004 服务注册应答
            msg = new SvrRegRsp;
            break;
        case CMD_CHANNEL_MGR_REQ:  //0x00020001 通道管理请求
            msg = new ChannelMgrReq;
            break;
        case CMD_CHANNEL_MGR_RSP: //0x00020002 通道管理应答
            msg = new ChannelMgrRsp;
            break;
        case CMD_CHANNEL_INFO_REQ:  //0x00020003 通道连接信息请求 
            msg = new ChannelInfoReq;
            break;
        case CMD_CHANNEL_INFO_RSP: //0x00020004 通道连接信息应答 
            msg = new ChannelInfoRsp;
            break;
        case CMD_GATEWAY_MSG_SEND_REQ:  //0x00020005 信息发送请求
            msg = new GateWayMsgSendReq;
            break;
        case CMD_GATEWAY_MSG_SEND_RSP: //0x00020006 信息发送应答
            msg = new GateWayMsgSendRsp;
            break;
        default:
            LOG_DEBUG("unknown command code: 0x%x.\n", hdr.command);
            break;
        }
        if (msg != NULL) 
        {
            msg->ParseFromArray(buf + PROTOCOL_HEADER_LENGTH,
                len - PROTOCOL_HEADER_LENGTH);
            dump(msg);
            delete msg;
        }
    }
}

// dump header
void dump(message_head_t *header)
{
    if (CHECK_IS_DEBUG()) 
    {
        if (header) 
        {
            LOG_DEBUG("version  [%u]\n", header->version);
            LOG_DEBUG("length   [%u]\n", header->length);
            LOG_DEBUG("command  [0x%x]\n", header->command);
            LOG_DEBUG("vender_id[%u]\n", header->vender_id);
            LOG_DEBUG("market   [%u]\n", header->market);
            LOG_DEBUG("is_cksum [%u]\n", header->is_cksum);
            LOG_DEBUG("check_sum[%u]\n", header->check_sum);
            LOG_DEBUG("extend   [%u]\n", header->extend);
        }
    }
}

// dump
void dump(message_head_t *header, ::google::protobuf::Message* msg)
{
    if (CHECK_IS_DEBUG()) 
    {
        if (header && msg) 
        {
            LOG_DEBUG("===HEADER========================\n");
            dump(header);
            LOG_DEBUG("===PACKET========================\n");
            dump(msg);
        }
    }
}

