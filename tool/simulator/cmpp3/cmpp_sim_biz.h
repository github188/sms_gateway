#ifndef __CMPP_SIM_BIZ_H__
#define __CMPP_SIM_BIZ_H__

#include "sim_struct.h"

//是否完整报文
int is_packet_complete(const char* buf, unsigned len);

// 处理数据包
int handle_packet(connection_t *con);

// 处理心跳请求包
int handle_heartbeat_req(cmpp3_header_t* hdr, const char* data, int len,connection_t *pcon);

//处理注册请求包
int handle_svr_reg_req(cmpp3_header_t* hdr, const char* data, int len,connection_t *pcon);

//信息发送请求
int handle_gateway_msg_send_req(cmpp3_header_t* hdr, const char* data, int len, connection_t *pcon);

//状态应答
int handle_gateway_report_rsp(cmpp3_header_t* hdr, const char* data, int len);


#endif