#ifndef __GATEWAY_BIZ_H__
#define __GATEWAY_BIZ_H__

#include "gateway_struct.h"

// 处理通道数据包
int handle_channel_packet( connection_t** pcon );

// 处理内部数据包
int handle_gateway_packet( connection_t** pcon );

// 处理心跳应答包
int handle_heartbeat_rsp(message_head_t* hdr, const char* data, int len);

//处理注册应答包
int handle_svr_reg_rsp(message_head_t* hdr, const char* data, int len, connection_t *pcon);

// 通道参数变更请求
int handle_channel_mgr_req(message_head_t* hdr, const char* data, int len, connection_t *pcon);

//信息发送请求
int handle_gateway_msg_send_req(message_head_t* hdr, const char* data, int len, connection_t *pcon);

int msg_to_json( GateWayMsgSendReq *req,string &msg_json );

int get_phone_packet(map<string,sms_attribute_t> *plist,GateWayMsgSendReq *req,int num);

//处理信息发送请求
int msg_send(message_head_t* hdr,GateWayMsgSendReq *req);

int json_to_msg(string msg_json,GateWayMsgSendReq *req,map<string,sms_attribute_t> &phonelist);

//加载通道参数
int load_channel_info(const char* channel_id);

//fork发送子进程
int fork_proc();

//程序异常退出告警信息
int send_exit_alarm_msg(int pid);

//处理MQ数据
int handle_mq_msg();

//处理子进程退出
int handle_child_exit();

#endif