#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "sgip.h"
#include "gateway_util.h"

Sgip::Sgip()
{
}
Sgip::~Sgip()
{
}

uint32_t Sgip::get_header_len()
{
    return SGIP_HEADER_LENGTH;
}

int Sgip::parse_header(const char* buf, int len, sgip_header_t* header)
{
    if ( buf == NULL || header == NULL )
    {
        return -1;
    }

    uint32_t MessageLength = 0;
    uint32_t CommandId = 0;
    uint32_t SequenceId = 0;

    int offset = 0;

    memcpy(&MessageLength, buf + offset, sizeof(uint32_t));
    header->MessageLength = ntohl(MessageLength);

    offset += sizeof(uint32_t);
    memcpy(&CommandId, buf + offset, sizeof(uint32_t));
    header->CommandId = ntohl(CommandId);

    offset += sizeof(uint32_t);
    memcpy(&SequenceId, buf + offset, sizeof(uint32_t));
    header->SequenceId[0] = ntohl(SequenceId);

    offset += sizeof(uint32_t);
    memcpy(&SequenceId, buf + offset, sizeof(uint32_t));
    header->SequenceId[1] = ntohl(SequenceId);

    offset += sizeof(uint32_t);
    memcpy(&SequenceId, buf + offset, sizeof(uint32_t));
    header->SequenceId[2] = ntohl(SequenceId);

    return 0;
}

int Sgip::make_header(sgip_header_t* header, char* buf, int len)
{
    if ( buf == NULL || header == NULL )
    {
        return -1;
    }
    if(len < SGIP_HEADER_LENGTH)
    {
        return -1;
    }

    uint32_t MessageLength = 0;
    uint32_t CommandId = 0;
    uint32_t SequenceId = 0;

    uint32_t offset = 0;

    MessageLength = htonl(header->MessageLength);
    memcpy(buf + offset, &MessageLength, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    CommandId = htonl(header->CommandId);
    memcpy(buf + offset, &CommandId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    SequenceId = htonl(header->SequenceId[0]);
    memcpy(buf + offset, &SequenceId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    SequenceId = htonl(header->SequenceId[1]);
    memcpy(buf + offset, &SequenceId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    SequenceId = htonl(header->SequenceId[2]);
    memcpy(buf + offset, &SequenceId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    return offset;
}

int Sgip::make_bind_req(char *buf, sgip_body_bind_req_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferChar(ptr, body.LoginType);
    SetBufferString(ptr, body.LoginName, sizeof(body.LoginName)-1);
    SetBufferString(ptr, body.LoginPassword, sizeof(body.LoginPassword)-1);
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve)-1);

    return (ptr - buf);
}

int Sgip::make_bind_rsp(char *buf, sgip_body_bind_rsp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferChar(ptr, body.Result);
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve)-1);

    return (ptr - buf);
}

int Sgip::parse_bind_req(char *buf, sgip_body_bind_req_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    GetBufferChar(ptr, body.LoginType);
    GetBufferString(ptr, body.LoginName, sizeof(body.LoginName));
    GetBufferString(ptr, body.LoginPassword, sizeof(body.LoginPassword));
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));

    return (ptr - buf);
}

int Sgip::parse_bind_rsp(char *buf, sgip_body_bind_rsp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    GetBufferChar(ptr, body.Result);
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));

    return (ptr - buf);
}

int Sgip::make_submit_req(char *buf, sgip_body_submit_req_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    SetBufferString(ptr, body.SPNumber, sizeof(body.SPNumber)-1);
    SetBufferString(ptr, body.ChargeNumber, sizeof(body.ChargeNumber)-1);
    SetBufferChar(ptr, body.UserCount);
    for (unsigned short i=0; i<body.UserCount; i++)
        SetBufferString(ptr, body.UserNumber[i], sizeof(body.UserNumber[i])-1);
    SetBufferString(ptr, body.CorpId, sizeof(body.CorpId)-1);
    SetBufferString(ptr, body.ServiceType, sizeof(body.ServiceType)-1);
    SetBufferChar(ptr, body.FeeType);
    SetBufferString(ptr, body.FeeValue, sizeof(body.FeeValue)-1);
    SetBufferString(ptr, body.GivenValue, sizeof(body.GivenValue)-1);
    SetBufferChar(ptr, body.AgentFlag);
    SetBufferChar(ptr, body.MorelatetoMTFlag);
    SetBufferChar(ptr, body.Priority);
    SetBufferString(ptr, body.ExpireTime, sizeof(body.ExpireTime)-1);
    SetBufferString(ptr, body.ScheduleTime, sizeof(body.ScheduleTime)-1);
    SetBufferChar(ptr, body.ReportFlag);
    SetBufferChar(ptr, body.TPPid);
    SetBufferChar(ptr, body.TPUdhi);
    SetBufferChar(ptr, body.MessageCoding);
    SetBufferChar(ptr, body.MessageType);
    SetBufferLong(ptr, body.MessageLength);
    SetBufferString(ptr, body.MessageContent, (size_t)body.MessageLength);
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve)-1);

    return (ptr - buf);
}

int Sgip::parse_submit_rsp(char *buf, sgip_body_submit_rsp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferChar(ptr, body.Result);
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));
    
    return (ptr - buf);
}

int Sgip::make_deliver_rsp(char *buf, sgip_body_deliver_rsp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    SetBufferChar(ptr, body.Result);
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve)-1);

    return (ptr - buf);
}

int Sgip::parse_deliver_req(char *buf, sgip_body_deliver_req_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    GetBufferString(ptr, body.UserNumber, sizeof(body.UserNumber));
    GetBufferString(ptr, body.SPNumber, sizeof(body.SPNumber));
    GetBufferChar(ptr, body.TPPid);
    GetBufferChar(ptr, body.TPUdhi);
    GetBufferChar(ptr, body.MessageCoding);
    GetBufferLong(ptr, body.MessageLength);
    if (body.MessageCoding == 0x08)
        GetBufferWString(ptr, body.WMsgContent, (size_t)body.MessageLength);
    else
        GetBufferString(ptr, body.MessageContent, (size_t)body.MessageLength+1);
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));

    return (ptr - buf);
}

int Sgip::make_report_rsp(char *buf, sgip_body_report_rsp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    SetBufferChar(ptr, body.Result);
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve)-1);

    return (ptr - buf);
}

int Sgip::parse_report_req(char *buf, sgip_body_report_req_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    GetBufferLong(ptr, body.SubmitSequenceNumber[0]);
    GetBufferLong(ptr, body.SubmitSequenceNumber[1]);
    GetBufferLong(ptr, body.SubmitSequenceNumber[2]);
    GetBufferChar(ptr, body.ReportType);
    GetBufferString(ptr, body.UserNumber, sizeof(body.UserNumber));
    GetBufferChar(ptr, body.State);
    GetBufferChar(ptr, body.ErrorCode);
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));

    return (ptr - buf);
}

int Sgip::make_unbind_req(char *buf, uint32_t seq_id[3])
{
    sgip_header_t header;
    header.MessageLength = SGIP_HEADER_LENGTH;
    header.CommandId = SGIP_UNBIND;
    header.SequenceId[0] = seq_id[0];
    header.SequenceId[1] = seq_id[1];
    header.SequenceId[2] = seq_id[2];

    make_header(&header,buf,SGIP_HEADER_LENGTH);

    return SGIP_HEADER_LENGTH;
}

int Sgip::make_unbind_rsp(char *buf, uint32_t seq_id[3])
{
    sgip_header_t header;
    header.MessageLength = SGIP_HEADER_LENGTH;
    header.CommandId = SGIP_UNBIND_RESP;
    header.SequenceId[0] = seq_id[0];
    header.SequenceId[1] = seq_id[1];
    header.SequenceId[2] = seq_id[2];

    make_header(&header,buf,SGIP_HEADER_LENGTH);

    return SGIP_HEADER_LENGTH;
}

int Sgip::make_trace_req(char *buf, sgip_body_trace_req_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    SetBufferLong(ptr, body.SubmitSequenceNumber[0]);
    SetBufferLong(ptr, body.SubmitSequenceNumber[1]);
    SetBufferLong(ptr, body.SubmitSequenceNumber[2]);
    SetBufferString(ptr, body.UserNumber, sizeof(body.UserNumber));
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve));

    return (ptr - buf);
}

int Sgip::parse_trace_rsp(char *buf, sgip_body_trace_rsp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    GetBufferChar(ptr, body.Count);
    GetBufferChar(ptr, body.Result);
    GetBufferString(ptr, body.NodeId, sizeof(body.NodeId));
    GetBufferString(ptr, body.ReceiveTime, sizeof(body.ReceiveTime));
    GetBufferString(ptr, body.SendTime, sizeof(body.SendTime));
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));

    return (ptr - buf);
}
