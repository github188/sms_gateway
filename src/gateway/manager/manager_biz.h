#ifndef __MANAGER_BIZ_H__
#define __MANAGER_BIZ_H__

#include "manager_struct.h"
#include "protocol.h"

// 处理数据包
int handle_packet(connection_t *con);

// 处理心跳请求包
int handle_heartbeat_req(message_head_t* hdr, const char* data, int len,connection_t *pcon);

//处理注册请求包
int handle_svr_reg_req(message_head_t* hdr, const char* data, int len,connection_t *pcon);

//通道参数变更应答包
int handle_channel_update_rsp(message_head_t* hdr, const char* data, int len);

// 增加通道
int add_channel(string channel_id,string channel_info);

//更新通道
int update_channel(string channel_id,dlist_t *write);

// 删除通道
int delete_channel(string channel_id,dlist_t *write);

//程序异常退出告警信息
int send_exit_alarm_msg(int pid,string channel);

#endif