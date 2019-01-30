#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "smgp.h"
#include "sim_util.h"

Smgp::Smgp()
{
}
Smgp::~Smgp()
{
}

uint32_t Smgp::get_header_len()
{
    return SMGP_HEADER_LENGTH;
}

int Smgp::parse_header(const char* buf, int len, smgp_header_t* header)
{
    if ( buf == NULL || header == NULL )
    {
        return -1;
    }

    uint32_t PacketLength = 0;
    uint32_t RequestId = 0;
    uint32_t SequenceId = 0;

    int offset = 0;

    memcpy(&PacketLength, buf + offset, sizeof(uint32_t));
    header->PacketLength = ntohl(PacketLength);

    offset += sizeof(uint32_t);
    memcpy(&RequestId, buf + offset, sizeof(uint32_t));
    header->RequestId = ntohl(RequestId);

    offset += sizeof(uint32_t);
    memcpy(&SequenceId, buf + offset, sizeof(uint32_t));
    header->SequenceId = ntohl(SequenceId);

    return 0;
}

int Smgp::make_header(smgp_header_t* header, char* buf, int len)
{
    if ( buf == NULL || header == NULL )
    {
        return -1;
    }
    if(len < SMGP_HEADER_LENGTH)
    {
        return -1;
    }

    uint32_t PacketLength = 0;
    uint32_t RequestId = 0;
    uint32_t SequenceId = 0;

    uint32_t offset = 0;

    PacketLength = htonl(header->PacketLength);
    memcpy(buf + offset, &PacketLength, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    RequestId = htonl(header->RequestId);
    memcpy(buf + offset, &RequestId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    SequenceId = htonl(header->SequenceId);
    memcpy(buf + offset, &SequenceId, sizeof(uint32_t));

    offset += sizeof(uint32_t);
    return offset;
}

int Smgp::make_login_req(char *buf, smgp_body_login_req_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    SetBufferString(ptr, body.ClientId, sizeof(body.ClientId)-1);
    SetBufferString(ptr, body.AuthenticatorClient, sizeof(body.AuthenticatorClient)-1);
    SetBufferChar(ptr, body.LoginMode);
    SetBufferLong(ptr, body.Timestamp);
    SetBufferChar(ptr, body.ClientVersion);

    return (ptr - buf);
}

int Smgp::parse_login_rsp(char *buf, smgp_body_login_rsp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 消息体
    GetBufferLong(ptr, body.Status);
    GetBufferString(ptr, body.AuthenticatorServer, sizeof(body.AuthenticatorServer));
    GetBufferChar(ptr, body.ServerVersion);

    return (ptr - buf);
}

int Smgp::make_submit_req(char *buf, smgp_body_submit_req_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    SetBufferChar(ptr, body.MsgType);
    SetBufferChar(ptr, body.NeedReport);
    SetBufferChar(ptr, body.Priority);
    SetBufferString(ptr, body.ServiceId, sizeof(body.ServiceId)-1);
    SetBufferString(ptr, body.FeeType, sizeof(body.FeeType)-1);
    SetBufferString(ptr, body.FeeCode, sizeof(body.FeeCode)-1);
    SetBufferString(ptr, body.FixedFee, sizeof(body.FixedFee)-1);
    SetBufferChar(ptr, body.MsgFormat);
    SetBufferString(ptr, body.ValidTime, sizeof(body.ValidTime)-1);
    SetBufferString(ptr, body.AtTime, sizeof(body.AtTime)-1);
    SetBufferString(ptr, body.SrcTermId, sizeof(body.SrcTermId)-1);
    SetBufferString(ptr, body.ChargeTermId, sizeof(body.ChargeTermId)-1);
    SetBufferChar(ptr, body.DestTermIdCount);
    for (uint32_t i=0; i<body.DestTermIdCount; i++)
        SetBufferString(ptr, body.DestTermId[i], sizeof(body.DestTermId[i])-1);
    SetBufferChar(ptr, body.MsgLength);
    SetBufferString(ptr, body.MsgContent, (size_t)body.MsgLength);
    SetBufferString(ptr, body.Reserve, sizeof(body.Reserve)-1);

    if (body.bIsLongSms)
    {
        // 设置TP_Udhi
        SetBufferShort(ptr, SMGP_TAG_TP_UDHI);
        SetBufferShort(ptr, 0x0001);
        SetBufferChar(ptr, body.TPUdhi);
        // 设置PkTotal
        SetBufferShort(ptr, SMGP_TAG_PKTOTAL);
        SetBufferShort(ptr, 0x0001);
        SetBufferChar(ptr, body.PkTotal);
        // 设置PkNumber
        SetBufferShort(ptr, SMGP_TAG_PKNUMBER);
        SetBufferShort(ptr, 0x0001);
        SetBufferChar(ptr, body.PkNumber);
    }

    return (ptr - buf);
}

int Smgp::parse_submit_rsp(char *buf, smgp_body_submit_rsp_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferByte(ptr,body.MsgId,sizeof(body.MsgId));
    GetBufferLong(ptr, body.Status);
    
    return (ptr - buf);
}

int Smgp::make_deliver_rsp(char *buf, smgp_body_deliver_rsp_t body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    SetBufferByte(ptr,body.MsgId,sizeof(body.MsgId));
    SetBufferLong(ptr, body.Status);

    return (ptr - buf);
}

int Smgp::parse_deliver_req(char *buf,uint32_t body_len,smgp_body_deliver_req_t &body)
{
    if (buf == NULL)  return -1;
    char *ptr = buf;

    // 解析消息体
    GetBufferByte(ptr, body.MsgId, sizeof(body.MsgId));
    GetBufferChar(ptr, body.IsReport);
    GetBufferChar(ptr, body.MsgFormat);
    GetBufferString(ptr, body.RecvTime, sizeof(body.RecvTime));
    GetBufferString(ptr, body.SrcTermId, sizeof(body.SrcTermId));
    GetBufferString(ptr, body.DestTermId, sizeof(body.DestTermId));
    GetBufferChar(ptr, body.MsgLength);
    if (body.IsReport == 0x00)    // 消息为状态报告
    {
        if (body.MsgFormat == 0x08)
            GetBufferWString(ptr, body.WMsgContent, (size_t)body.MsgLength);
        else
            GetBufferString(ptr, body.MsgContent, (size_t)body.MsgLength+1);
    }
    else
    {
        GetBufferString(ptr, body.MsgContent, (size_t)body.MsgLength+1);
        // 解释MessageContent为状态报告
        char *pMsgContent = body.MsgContent;
        pMsgContent += strlen("id:");
        GetBufferByte(pMsgContent, body.deliverMessage.MsgId, sizeof(body.deliverMessage.MsgId));
        pMsgContent += strlen(" sub:");
        GetBufferString(pMsgContent, body.deliverMessage.Sub, sizeof(body.deliverMessage.Sub));
        pMsgContent += strlen(" dlvrd:");
        GetBufferString(pMsgContent, body.deliverMessage.Dlvrd, sizeof(body.deliverMessage.Dlvrd));
        pMsgContent += strlen(" submit date:");
        GetBufferString(pMsgContent, body.deliverMessage.SubmitDate, sizeof(body.deliverMessage.SubmitDate));
        pMsgContent += strlen(" done date:");
        GetBufferString(pMsgContent, body.deliverMessage.DoneDate, sizeof(body.deliverMessage.DoneDate));
        pMsgContent += strlen(" stat:");
        GetBufferString(pMsgContent, body.deliverMessage.Stat, sizeof(body.deliverMessage.Stat));
        pMsgContent += strlen(" err:");
        GetBufferString(pMsgContent, body.deliverMessage.Err, sizeof(body.deliverMessage.Err));
        pMsgContent += strlen(" text:");
        GetBufferString(pMsgContent, body.deliverMessage.Txt, sizeof(body.deliverMessage.Txt));
    }
    GetBufferString(ptr, body.Reserve, sizeof(body.Reserve));
    // 解释可变参数TLV
    int lVariableLength =  body_len - (ptr - buf);
    if (lVariableLength > 0)
    {
        smgp_tlv_t bodyTlv;
        if (parse_tlv(ptr, lVariableLength, bodyTlv) == lVariableLength)
        {
            memcpy(&body.tppid, &bodyTlv.TPPid, sizeof(smgp_common_tlv_t));
            memcpy(&body.tpudhi, &bodyTlv.TPUdhi, sizeof(smgp_common_tlv_t));
            memcpy(&body.linkId, &bodyTlv.LinkId, sizeof(smgp_variable_tlv_t));
        }
    }

    return (ptr - buf);
}

int Smgp::make_terminal_req(char *buf,uint32_t seq_id)
{
    smgp_header_t header;
    header.PacketLength = SMGP_HEADER_LENGTH;
    header.RequestId = SMGP_EXIT;
    header.SequenceId = seq_id;

    make_header(&header,buf,SMGP_HEADER_LENGTH);

    return SMGP_HEADER_LENGTH;
}

int Smgp::make_terminal_rsp(char *buf,uint32_t seq_id)
{
    smgp_header_t header;
    header.PacketLength = SMGP_HEADER_LENGTH;
    header.RequestId = SMGP_EXIT_RESP;
    header.SequenceId = seq_id;

    make_header(&header,buf,SMGP_HEADER_LENGTH);

    return SMGP_HEADER_LENGTH;
}

int Smgp::make_activeTest_req( char *buf,uint32_t seq_id )
{
    smgp_header_t header;
    header.PacketLength = SMGP_HEADER_LENGTH;
    header.RequestId = SMGP_ACTIVE_TEST;
    header.SequenceId = seq_id;

    make_header(&header,buf,SMGP_HEADER_LENGTH);

    return SMGP_HEADER_LENGTH;
}

int Smgp::make_activeTest_rsp(char *buf,uint32_t seq_id)
{
    smgp_header_t header;
    header.PacketLength = SMGP_HEADER_LENGTH;
    header.RequestId = SMGP_ACTIVE_TEST_RESP;
    header.SequenceId = seq_id;

    make_header(&header,buf,SMGP_HEADER_LENGTH);

    return SMGP_HEADER_LENGTH;
}

int Smgp::parse_tlv(char *&buf, uint32_t tlvLength, smgp_tlv_t &tlv)
{
    if (!buf)   return 0;

    char *ptr = buf;
    unsigned short uTag=0x0, uLength=0x0;
    while (tlvLength > (ptr - buf))
    {
        GetBufferShort(ptr, uTag);
        GetBufferShort(ptr, uLength);
        if (uTag == SMGP_TAG_TP_PID)
        {
            tlv.TPPid.Tag = uTag;
            tlv.TPPid.Length = uLength;
            GetBufferChar(ptr, tlv.TPPid.Value);
        }
        else if (uTag == SMGP_TAG_TP_UDHI)
        {
            tlv.TPUdhi.Tag = uTag;
            tlv.TPUdhi.Length = uLength;
            GetBufferChar(ptr, tlv.TPUdhi.Value);
        }
        else if (uTag == SMGP_TAG_LINKID)
        {
            tlv.LinkId.Tag = uTag;
            tlv.LinkId.Length = uLength;
            GetBufferString(ptr, tlv.LinkId.Value, uLength+1);
        }
        else if (uTag == SMGP_TAG_CHARGEUSERTYPE)
        {
            tlv.ChargeUserType.Tag = uTag;
            tlv.ChargeUserType.Length = uLength;
            GetBufferChar(ptr, tlv.ChargeUserType.Value);
        }
        else if (uTag == SMGP_TAG_CHARGETERMTYPE)
        {
            tlv.ChargeTermType.Tag = uTag;
            tlv.ChargeTermType.Length = uLength;
            GetBufferChar(ptr, tlv.ChargeTermType.Value);
        }
        else if (uTag == SMGP_TAG_CHARGETERMPSEUDO)
        {
            tlv.ChargeTermPseudo.Tag = uTag;
            tlv.ChargeTermPseudo.Length = uLength;
            GetBufferString(ptr, tlv.ChargeTermPseudo.Value, uLength+1);
        }
        else if (uTag == SMGP_TAG_DESTTERMTYPE)
        {
            tlv.DestTermType.Tag = uTag;
            tlv.DestTermType.Length = uLength;
            GetBufferChar(ptr, tlv.DestTermType.Value);
        }
        else if (uTag == SMGP_TAG_DESTTERMPSEUDO)
        {
            tlv.DestTermPseudo.Tag = uTag;
            tlv.DestTermPseudo.Length = uLength;
            GetBufferString(ptr, tlv.DestTermPseudo.Value, uLength+1);
        }
        else if (uTag == SMGP_TAG_PKTOTAL)
        {
            tlv.PkTotal.Tag = uTag;
            tlv.PkTotal.Length = uLength;
            GetBufferChar(ptr, tlv.PkTotal.Value);
        }
        else if (uTag == SMGP_TAG_PKNUMBER)
        {
            tlv.PkNumber.Tag = uTag;
            tlv.PkNumber.Length = uLength;
            GetBufferChar(ptr, tlv.PkNumber.Value);
        }
        else if (uTag == SMGP_TAG_SUBMITMSGTYPE)
        {
            tlv.SubmitMsgType.Tag = uTag;
            tlv.SubmitMsgType.Length = uLength;
            GetBufferChar(ptr, tlv.SubmitMsgType.Value);
        }
        else if (uTag == SMGP_TAG_SPDEALRESLT)
        {
            tlv.SPDealResult.Tag = uTag;
            tlv.SPDealResult.Length = uLength;
            GetBufferChar(ptr, tlv.SPDealResult.Value);
        }
        else if (uTag == SMGP_TAG_SRCTERMTYPE)
        {
            tlv.SrcTermType.Tag = uTag;
            tlv.SrcTermType.Length = uLength;
            GetBufferChar(ptr, tlv.SrcTermType.Value);
        }
        else if (uTag == SMGP_TAG_SRCTERMPSEUDO)
        {
            tlv.SrcTermPseudo.Tag = uTag;
            tlv.SrcTermPseudo.Length = uLength;
            GetBufferString(ptr, tlv.SrcTermPseudo.Value, uLength+1);
        }
        else if (uTag == SMGP_TAG_NODESCOUNT)
        {
            tlv.NodesCount.Tag = uTag;
            tlv.NodesCount.Length = uLength;
            GetBufferChar(ptr, tlv.NodesCount.Value);
        }
        else if (uTag == SMGP_TAG_MSGSRC)
        {
            tlv.MsgSrc.Tag = uTag;
            tlv.MsgSrc.Length = uLength;
            GetBufferString(ptr, tlv.MsgSrc.Value, uLength+1);
        }
        else if (uTag == SMGP_TAG_SRCTYPE)
        {
            tlv.SrcType.Tag = uTag;
            tlv.SrcType.Length = uLength;
            GetBufferChar(ptr, tlv.SrcType.Value);
        }
        else if (uTag == SMGP_TAG_MSERVICEID)
        {
            tlv.MServiceId.Tag = uTag;
            tlv.MServiceId.Length = uLength;
            GetBufferString(ptr, tlv.MServiceId.Value, uLength+1);
        }
        else    break;
    }
    int parserLen = (ptr - buf);
    buf = ptr;
    return parserLen;
}
