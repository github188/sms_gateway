#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "cmpp3.h"
#include "gateway_util.h"

Cmpp3::Cmpp3()
{
}
Cmpp3::~Cmpp3()
{
}

uint32_t Cmpp3::get_header_len()
{
    return CMPP3_HEADER_LENGTH;
}

int Cmpp3::parse_header(const char* buf, int len, cmpp_header_t* header)
{
    if ( buf == NULL || header == NULL )
    {
        return -1;
    }

    uint32_t TotalLength = 0;
    uint32_t CommandId = 0;
    uint32_t SequenceId = 0;

    int offset = 0;

    memcpy(&TotalLength, buf + offset, sizeof(uint32_t));
    header->TotalLength = ntohl(TotalLength);

    offset += sizeof(uint32_t);
    memcpy(&CommandId, buf + offset, sizeof(uint32_t));
    header->CommandId = ntohl(CommandId);

    offset += sizeof(uint32_t);
    memcpy(&SequenceId, buf + offset, sizeof(uint32_t));
    header->SequenceId = ntohl(SequenceId);

    return 0;
}

int Cmpp3::make_header(cmpp_header_t* header, char* buf, int len)
{
    if ( buf == NULL || header == NULL )
    {
        return -1;
    }
    if(len < CMPP3_HEADER_LENGTH)
    {
        return -1;
    }

    uint32_t TotalLength = 0;
    uint32_t CommandId = 0;
    uint32_t SequenceId = 0;

    uint32_t offset = 0;

    TotalLength = htonl(header->TotalLength);
    memcpy(buf + offset, &TotalLength, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    CommandId = htonl(header->CommandId);
    memcpy(buf + offset, &CommandId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    SequenceId = htonl(header->SequenceId);
    memcpy(buf + offset, &SequenceId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    return offset;
}

int Cmpp3::make_connect_req(char *buf, cmpp_body_connect_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferString(ptr, body.SourceAddr, sizeof(body.SourceAddr)-1);
    SetBufferByte(ptr, body.AuthenticatorSource, sizeof(body.AuthenticatorSource));
    SetBufferChar(ptr, body.Version);
    SetBufferLong(ptr, body.Timestamp);

    return (ptr - buf);
}

int Cmpp3::make_connect_rsp(char *buf, cmpp_body_connect_resp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferChar(ptr, body.Status);
    SetBufferByte(ptr, body.AuthenticatorISMG, sizeof(body.AuthenticatorISMG));
    SetBufferChar(ptr, body.Version);

    return (ptr - buf);
}

int Cmpp3::parse_connect_req(char *buf, cmpp_body_connect_t & body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferString(ptr, body.SourceAddr, sizeof(body.SourceAddr));
    GetBufferByte(ptr, body.AuthenticatorSource, sizeof(body.AuthenticatorSource));
    GetBufferChar(ptr, body.Version);
    GetBufferLong(ptr, body.Timestamp);

    return (ptr - buf);
}

int Cmpp3::parse_connect_rsp(char *buf, cmpp_body_connect_resp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferLong(ptr, body.Status);
    GetBufferByte(ptr, body.AuthenticatorISMG, sizeof(body.AuthenticatorISMG));
    GetBufferChar(ptr, body.Version);
    
    return (ptr - buf);
}

int Cmpp3::make_submit_req(char *buf, cmpp_body_submit_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferLongLong(ptr, body.MsgId);
    SetBufferChar(ptr, body.Pktotal);
    SetBufferChar(ptr, body.Pknumber);
    SetBufferChar(ptr, body.RegisteredDelivery);
    SetBufferChar(ptr, body.MsgLevel);
    SetBufferString(ptr, body.ServiceId, sizeof(body.ServiceId)-1);
    SetBufferChar(ptr, body.FeeUserType);
    SetBufferByte(ptr, body.FeeTerminalId, sizeof(body.FeeTerminalId));
    SetBufferChar(ptr, body.FeeTerminalType);
    SetBufferChar(ptr, body.TPPId);
    SetBufferChar(ptr, body.TPUdhi);
    SetBufferChar(ptr, body.MsgFmt);
    SetBufferString(ptr, body.MsgSrc, sizeof(body.MsgSrc)-1);
    SetBufferString(ptr, body.FeeType, sizeof(body.FeeType)-1);
    SetBufferString(ptr, body.FeeCode, sizeof(body.FeeCode)-1);
    SetBufferString(ptr, body.ValIdTime, sizeof(body.ValIdTime)-1);
    SetBufferString(ptr, body.AtTime, sizeof(body.AtTime)-1);
    SetBufferString(ptr, body.SrcId, sizeof(body.SrcId)-1);
    SetBufferChar(ptr, body.DestUsrtl);
    for (unsigned short i=0; i<body.DestUsrtl; i++)
        SetBufferString(ptr, body.DestTerminalId[i], sizeof(body.DestTerminalId[i])-1);
    SetBufferChar(ptr, body.DestTerminalType);
    SetBufferChar(ptr, body.MsgLength);
    SetBufferString(ptr, body.MsgContent, (size_t)body.MsgLength);
    SetBufferString(ptr, body.LinkID, sizeof(body.LinkID) - 1);

    return (ptr - buf);
}

int Cmpp3::make_submit_rsp(char *buf, cmpp_body_submit_resp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferLongLong(ptr, body.MsgId);
    SetBufferLong(ptr, body.Result);

    return (ptr - buf);
}

int Cmpp3::parse_submit_req(char *buf, cmpp_body_submit_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferLongLong(ptr, body.MsgId);
    GetBufferChar(ptr, body.Pktotal);
    GetBufferChar(ptr, body.Pknumber);
    GetBufferChar(ptr, body.RegisteredDelivery);
    GetBufferChar(ptr, body.MsgLevel);
    GetBufferString(ptr, body.ServiceId, sizeof(body.ServiceId));
    GetBufferChar(ptr, body.FeeUserType);
    GetBufferByte(ptr, body.FeeTerminalId, sizeof(body.FeeTerminalId));
    GetBufferChar(ptr, body.FeeTerminalType);
    GetBufferChar(ptr, body.TPPId);
    GetBufferChar(ptr, body.TPUdhi);
    GetBufferChar(ptr, body.MsgFmt);
    GetBufferString(ptr, body.MsgSrc, sizeof(body.MsgSrc));
    GetBufferString(ptr, body.FeeType, sizeof(body.FeeType));
    GetBufferString(ptr, body.FeeCode, sizeof(body.FeeCode));
    GetBufferString(ptr, body.ValIdTime, sizeof(body.ValIdTime));
    GetBufferString(ptr, body.AtTime, sizeof(body.AtTime));
    GetBufferString(ptr, body.SrcId, sizeof(body.SrcId));
    GetBufferChar(ptr, body.DestUsrtl);
    for (unsigned short i = 0; i<body.DestUsrtl; i++)
        GetBufferString(ptr, body.DestTerminalId[i], sizeof(body.DestTerminalId[i]));
    GetBufferChar(ptr, body.DestTerminalType);
    GetBufferChar(ptr, body.MsgLength);
    if (body.MsgContent <= 0) return 0;
    GetBufferString(ptr, body.MsgContent, (size_t)body.MsgLength + 1);
    GetBufferString(ptr, body.LinkID, sizeof(body.LinkID));

    return (ptr - buf);
}

int Cmpp3::parse_submit_rsp(char *buf, cmpp_body_submit_resp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferLongLong(ptr,body.MsgId);
    GetBufferLong(ptr, body.Result);
    
    return (ptr - buf);
}

int Cmpp3::make_deliver_req(char *buf, cmpp_body_deliver_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferLongLong(ptr, body.MsgId);
    SetBufferString(ptr, body.DestId, sizeof(body.DestId) - 1);
    SetBufferString(ptr, body.ServiceId, sizeof(body.ServiceId) - 1);
    SetBufferChar(ptr, body.TPPid);
    SetBufferChar(ptr, body.TPUdhi);
    SetBufferChar(ptr, body.MsgFmt);
    SetBufferString(ptr, body.SrcTerminalId, sizeof(body.SrcTerminalId) - 1);
    SetBufferChar(ptr, body.SrcTerminalType);
    SetBufferChar(ptr, body.RegisteredDelivery);
    SetBufferChar(ptr, body.MsgLength);
    if (body.RegisteredDelivery == 0)  // 消息为非状态报告
    {
        if (body.MsgFmt == 0x08)    // 消息内容为UCS2编码
            SetBufferString(ptr, (const char *)body.WMsgContent, (size_t)body.MsgLength*sizeof(unsigned short));
        else
            SetBufferString(ptr, (const char *)body.MsgContent, (size_t)body.MsgLength);
    }
    else    // 消息为状态报告
    {
        SetBufferLongLong(ptr, body.MsgId);
        SetBufferString(ptr, body.deliverMessage.Stat, sizeof(body.deliverMessage.Stat)-1);
        SetBufferString(ptr, body.deliverMessage.SubmitTime, sizeof(body.deliverMessage.SubmitTime)-1);
        SetBufferString(ptr, body.deliverMessage.DoneTime, sizeof(body.deliverMessage.DoneTime)-1);
        SetBufferString(ptr, body.deliverMessage.DestTerminalId, sizeof(body.deliverMessage.DestTerminalId)-1);
        SetBufferLong(ptr, body.deliverMessage.SMSCSequence);
    }
    SetBufferString(ptr, body.LinkID, sizeof(body.LinkID) - 1);

    return (ptr - buf);
}

int Cmpp3::make_deliver_rsp(char *buf, cmpp_body_deliver_resp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferLongLong(ptr, body.MsgId);
    SetBufferLong(ptr, body.Result);

    return (ptr - buf);
}

int Cmpp3::parse_deliver_req(char *buf, cmpp_body_deliver_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferLongLong(ptr, body.MsgId);
    GetBufferString(ptr, body.DestId, sizeof(body.DestId));
    GetBufferString(ptr, body.ServiceId, sizeof(body.ServiceId));
    GetBufferChar(ptr, body.TPPid);
    GetBufferChar(ptr, body.TPUdhi);
    GetBufferChar(ptr, body.MsgFmt);
    GetBufferString(ptr, body.SrcTerminalId, sizeof(body.SrcTerminalId));
    GetBufferChar(ptr, body.SrcTerminalType);
    GetBufferChar(ptr, body.RegisteredDelivery);
    GetBufferChar(ptr, body.MsgLength);
    if (body.RegisteredDelivery == 0)  // 消息为非状态报告
    {
        if (body.MsgFmt == 0x08)
            GetBufferWString(ptr, body.WMsgContent, (size_t)body.MsgLength);
        else
            GetBufferString(ptr, body.MsgContent, (size_t)body.MsgLength + 1);
    }
    else    // 消息为状态报告
    {
        GetBufferLongLong(ptr, body.deliverMessage.MsgId);
        GetBufferString(ptr, body.deliverMessage.Stat, sizeof(body.deliverMessage.Stat));
        GetBufferString(ptr, body.deliverMessage.SubmitTime, sizeof(body.deliverMessage.SubmitTime));
        GetBufferString(ptr, body.deliverMessage.DoneTime, sizeof(body.deliverMessage.DoneTime));
        GetBufferString(ptr, body.deliverMessage.DestTerminalId, sizeof(body.deliverMessage.DestTerminalId));
        GetBufferLong(ptr, body.deliverMessage.SMSCSequence);
    }
    GetBufferString(ptr, body.LinkID, sizeof(body.LinkID));

    return (ptr - buf);
}

int Cmpp3::parse_deliver_rsp(char *buf, cmpp_body_deliver_resp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferLongLong(ptr, body.MsgId);
    GetBufferLong(ptr, body.Result);

    return (ptr - buf);
}

int Cmpp3::make_terminal_req(char *buf,uint32_t seq_id)
{
    cmpp_header_t header;
    header.TotalLength = CMPP3_HEADER_LENGTH;
    header.CommandId = CMPP3_TERMINATE;
    header.SequenceId = seq_id;

    make_header(&header,buf,CMPP3_HEADER_LENGTH);

    return CMPP3_HEADER_LENGTH;
}

int Cmpp3::make_terminal_rsp(char *buf,uint32_t seq_id)
{
    cmpp_header_t header;
    header.TotalLength = CMPP3_HEADER_LENGTH;
    header.CommandId = CMPP3_TERMINATE_RESP;
    header.SequenceId = seq_id;

    make_header(&header,buf,CMPP3_HEADER_LENGTH);

    return CMPP3_HEADER_LENGTH;
}

int Cmpp3::make_activeTest_req( char *buf,uint32_t seq_id )
{
    cmpp_header_t header;
    header.TotalLength = CMPP3_HEADER_LENGTH;
    header.CommandId = CMPP3_ACTIVE_TEST;
    header.SequenceId = seq_id;

    make_header(&header,buf,CMPP3_HEADER_LENGTH);

    return CMPP3_HEADER_LENGTH;
}

int Cmpp3::make_activeTest_rsp(char *buf,uint32_t seq_id,unsigned char Reserved)
{
    cmpp_header_t header;
    header.TotalLength = CMPP3_HEADER_LENGTH + sizeof(unsigned char);
    header.CommandId = CMPP3_ACTIVE_TEST_RESP;
    header.SequenceId = seq_id;

    make_header(&header,buf,CMPP3_HEADER_LENGTH);

    memcpy(buf + CMPP3_HEADER_LENGTH, &Reserved, sizeof(unsigned char));

    return header.TotalLength;
}
