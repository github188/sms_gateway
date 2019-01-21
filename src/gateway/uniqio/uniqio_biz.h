#ifndef __UNIQIO_BIZ_H__
#define __UNIQIO_BIZ_H__

#include "uniqio_struct.h"
#include "protocol.h"

// 处理数据包
int handle_packet(connection_t *con);

// 处理心跳请求包
int handle_heartbeat_req(message_head_t* hdr, const char* data, int len,connection_t *pcon);

//处理注册请求包
int handle_svr_reg_req(message_head_t* hdr, const char* data, int len,connection_t *pcon);

//信息发送请求
int handle_gateway_msg_send_req(message_head_t* hdr, const char* data, int len, connection_t *pcon);

//信息发送应答
int handle_gateway_msg_send_rsp(message_head_t* hdr, const char* data, int len);

//网关不可用，保存数据到redis
int save_msg( GateWayMsgSendReq *req );

#endif