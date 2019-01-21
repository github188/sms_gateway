#ifndef __SEND_DB_H__
#define __SEND_DB_H__

#include "send_struct.h"


int init_db(void *conf);
void uninit_db();

bool reconnect_db();

int query_channel_info(const char *channel_id,string &info);

int query_httpchannel_info(const char *interface_id,uint32_t &http_type);

int save_channel_remaining(const char *channel_id,int cnt,int &resultValue);

int save_channel_status(string value);

#endif