#ifndef __SEND_UTIL_H__
#define __SEND_UTIL_H__
#include <send_struct.h>

channel_reserved_t* get_channel_reserved_data(dict* wq,int key);

int delete_channel_reserved_data(dict* wq,int key);

int insert_channel_reserved_data(dict* wq,channel_reserved_t &data);

//保存通道状态
int handle_channel_status(string channel_id,int status);

#endif
