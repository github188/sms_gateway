#ifndef __CHANNEL_DB_H__
#define __CHANNEL_DB_H__

#include <string>
#include <string.h>
#include "public.h"

using namespace std;

int init_db( const char* conf );
void uninit_db();

bool reconnect_db();

int query_channel_info(const char *channel_id,string &info);

int save_channel_status(string value);

int query_channel_msg(const char *key,string &value);

int save_channel_msg(const char *key,string value);

int query_channel_template(const char *channel_id,string &info);

int save_channel_rsp(string value);

int save_channel_rsp_remaining(const char *channel_id,int cnt);

int save_channel_report(string value);

int save_channel_report_remaining(const char *channel_id,int cnt);

int save_channel_uplink(string value);

//保存通道状态
int handle_channel_status(string channel_id,int status);

#endif