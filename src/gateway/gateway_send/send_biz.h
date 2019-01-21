#ifndef __SEND_BIZ_H__
#define __SEND_BIZ_H__

#include "send_struct.h"

//解析msg
bool parse_message(const char *buf,int data_len,message_packet_t *msgPacket);

//扣减发送量
bool deduct_remaining( uint32_t cnt );

//签名校验
void do_sign(uint32_t uSignType, string &msg);

//处理网络报文
int handle_packet(connection_t *con,int datalen, dict* wq);

//处理通道注册
int handle_channel_login(dlist_t *write);

//读取通道参数
int load_channel_info(const char* channel_id);

//处理通道定时任务
int handle_channel_timer_process(dlist_t *write, dict* wq);

//处理消息发送
int handle_send_msg(dlist_t *write,message_packet_t *packet, dict* wq);


#endif