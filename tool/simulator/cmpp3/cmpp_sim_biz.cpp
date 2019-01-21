#include "cmpp_sim_biz.h"
#include "sim_util.h"

extern long     g_cnt;
extern dlist_t *g_phonelist;

int is_packet_complete(const char* buf, unsigned len)
{
    if( len <= CMPP3_HEADER_LENGTH )
    {
        return 0;
    }

    cmpp3_header_t header;
    int ret = g_cmpp3.parse_header(buf, len, &header);
    if( ret != 0 )
    {
        return -1;
    }

    if( len < header.TotalLength )
    {
        return 0;
    }

    return header.TotalLength;
}

int handle_packet( connection_t *con )
{
    // 1. 参数合法性检查
	if ( con == NULL )
    {
        LOG_ERROR("parameters are illegal.\n");
        return -1;
    }

    int ret = 0;
    
	// 2. 从读缓存中读出数据
    buffer_t *rcvbuf = con->rcvbuf;
    if (rcvbuf == NULL)
    {
        LOG_ERROR("rcvbuf is null!\n");
        return -1;
    }
    const char* readptr = rcvbuf->get_read_ptr(rcvbuf);
    int datalen = rcvbuf->get_data_size(rcvbuf);

    // 3. 解析报文头
    cmpp3_header_t hdr;
    if (g_cmpp3.parse_header(readptr, datalen, &hdr) != 0)
    {
        LOG_ERROR("parse_header failed.\n");
        return -1;
    }

    char buff[MAX_PACKET_LEN];
    memcpy(buff, readptr, hdr.TotalLength);
    rcvbuf->set_read_size(rcvbuf, hdr.TotalLength);

    // 4. 根据命令码，处理各种报文
    switch(hdr.CommandId)
    {
    case CMPP3_ACTIVE_TEST:// 心跳请求
        {
            ret = handle_heartbeat_req(&hdr, 
                                       buff + CMPP3_HEADER_LENGTH, 
                                       hdr.TotalLength - CMPP3_HEADER_LENGTH,
                                       con);
        }
        break;
    case CMPP3_CONNECT: //注册请求
        {
            ret = handle_svr_reg_req(&hdr, 
                                     buff + CMPP3_HEADER_LENGTH, 
                                     hdr.TotalLength - CMPP3_HEADER_LENGTH,
                                     con);
        }
        break;
	case CMPP3_SUBMIT: //信息发送请求
		{
			ret = handle_gateway_msg_send_req(&hdr, 
                                              buff + CMPP3_HEADER_LENGTH, 
                                              hdr.TotalLength - CMPP3_HEADER_LENGTH,
                                              con);
		}
		break;
    case CMPP3_DELIVER_RESP: //状态报告应答
		{
			ret = handle_gateway_report_rsp(&hdr, 
                                              buff + CMPP3_HEADER_LENGTH, 
                                              hdr.TotalLength - CMPP3_HEADER_LENGTH);
		}
		break;
	default:
	    {
    		LOG_ERROR("unknown command : 0x%x\n", hdr.CommandId);
    	    ret = -1;
    		break;
        }
    }
    
    return ret;
}

// 处理心跳请求包
int handle_heartbeat_req(cmpp3_header_t* hdr, const char* data, int len, connection_t *pcon)
{
    if( g_cnt > 1 )
    {
        LOG_INFO("recv submit.total[%ld]\n",g_cnt);
        g_cnt = 1;
    }

    LOG_INFO("recv heartbeat.seq[%u]\n",hdr->SequenceId);

    buffer_t* pbuffer = pcon->sndbuf;
    char* writeptr = pbuffer->get_write_ptr(pbuffer);
    pbuffer->get_free_size(pbuffer);

    int packet_len = g_cmpp3.make_activeTest_rsp(writeptr,hdr->SequenceId,0x00);

    pbuffer->set_write_size(pbuffer, packet_len);

    return 0;
}

//处理注册请求包
int handle_svr_reg_req(cmpp3_header_t* hdr, const char* data, int len, connection_t *pcon)
{
    LOG_INFO("recv connect_req.seq[%u]\n",hdr->SequenceId);

    buffer_t * pbuffer = pcon->sndbuf;
    int freesize = pbuffer->get_free_size(pbuffer);
    char* writeptr = pbuffer->get_write_ptr(pbuffer);

    //返回应答报文
    cmpp3_body_connect_resp_t rsp;
    rsp.Status = 0;

    char outbuf[MAX_PACKET_LEN];
    int body_len = g_cmpp3.make_connect_rsp(outbuf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_connect_rsp fail.\n");
        return -1;
    }
    if( ( body_len + CMPP3_HEADER_LENGTH ) > freesize )
    {
        return -1;
    }

    //报文头
    cmpp3_header_t head;
    head.CommandId = CMPP3_CONNECT_RESP;
    head.SequenceId = hdr->SequenceId;
    head.TotalLength = body_len + CMPP3_HEADER_LENGTH;
    g_cmpp3.make_header(&head,writeptr,CMPP3_HEADER_LENGTH);

    //拷贝报文体
    memcpy(writeptr + CMPP3_HEADER_LENGTH, outbuf, body_len);

    //设置缓冲区游标
    pbuffer->set_write_size(pbuffer, head.TotalLength);
    
    return 0;
}

time_t g_recv_time = 0;
long g_one_second = 0L;
uint32_t g_seq = 0;
//信息发送请求
int handle_gateway_msg_send_req(cmpp3_header_t* hdr, const char* data, int len, connection_t *pcon)
{
    cmpp3_body_submit_t req;

    int tmp_len = g_cmpp3.parse_submit_req(const_cast<char *>(data),req);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_submit_req fail.\n");
        return -1;
    }

    //生成msgid
    char msgid[64] ={0};
    char date_time[11] = {0};
    get_datetime(date_time,sizeof(date_time));
    snprintf(msgid,sizeof(msgid),"%s%04u",date_time,g_seq);

    for( int i = 0 ; i < req.DestUsrtl; i++ )
    {
        char msgid_tmp[64] = {0};
        snprintf(msgid_tmp,sizeof(msgid_tmp),"%s%04u",date_time,g_seq);
        phone_info_t *pInfo = new phone_info_t;
        pInfo->msg_id = msgid_tmp;
        pInfo->src_phone = req.SrcId;
        pInfo->dest_phone = req.DestTerminalId[i];
        dlist_insert_tail(g_phonelist, pInfo);
        g_seq++;
    }

    ++g_one_second;
    ++g_cnt;
    time_t now = time(NULL);
	if( ( now - g_recv_time ) >= 1 )
	{
		g_recv_time = now;
		LOG_INFO("recv submit.total[%ld]second[%ld]time[%ld]\n",g_cnt,g_one_second,now);
		g_one_second = 0;
	}

    buffer_t * pbuffer = pcon->sndbuf;
    int freesize = pbuffer->get_free_size(pbuffer);
    char* writeptr = pbuffer->get_write_ptr(pbuffer);

    //返回应答报文
    cmpp3_body_submit_resp_t rsp;
    rsp.MsgId = atol(msgid);
    rsp.Result = 0;

    char outbuf[MAX_PACKET_LEN];
    int body_len = g_cmpp3.make_submit_rsp(outbuf, rsp);
    if( body_len <= 0 )
    {
        LOG_ERROR("make_submit_rsp fail.\n");
        return -1;
    }
    if( ( body_len + CMPP3_HEADER_LENGTH ) > freesize )
    {
        return -1;
    }

    //报文头
    cmpp3_header_t head;
    head.CommandId = CMPP3_SUBMIT_RESP;
    head.SequenceId = hdr->SequenceId;
    head.TotalLength = body_len + CMPP3_HEADER_LENGTH;
    g_cmpp3.make_header(&head,writeptr,CMPP3_HEADER_LENGTH);

    //拷贝报文体
    memcpy(writeptr + CMPP3_HEADER_LENGTH, outbuf, body_len);

    //设置缓冲区游标
    pbuffer->set_write_size(pbuffer, head.TotalLength);
    
	return 0;
}

//信息发送应答
int handle_gateway_report_rsp(cmpp3_header_t* hdr, const char* data, int len)
{
    cmpp3_body_deliver_resp_t rsp;

    int tmp_len = g_cmpp3.parse_deliver_rsp(const_cast<char *>(data),rsp);
    if( tmp_len != len )
    {
        LOG_ERROR("parse_deliver_rsp fail.\n");
        return -1;
    }

    //LOG_INFO("recv deliver_rsp.seq[%u]\n",hdr->SequenceId);

	return 1;
}
