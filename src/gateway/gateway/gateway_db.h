#ifndef __GATEWAY_DB_H__
#define __GATEWAY_DB_H__

#include "gateway_struct.h"


int init_db(void *conf);
void uninit_db();

bool reconnect_db();

int query_channel_info(const char *channel_id,string &info);

int query_httpchannel_info(const char *interface_id,uint32_t &http_type);

int get_channel_msg(const char *key,string &value);

int save_channel_msg(const char *key,string value);

int save_alarm_msg(string value);

#endif