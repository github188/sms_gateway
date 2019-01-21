#ifndef __MANAGER_DB_H__
#define __MANAGER_DB_H__

#include "manager_struct.h"


int init_db(void* conf);
void uninit_db();

bool reconnect_db();

int query_all_channel(unsigned int uCount, 
                      unsigned int &uCursor, 
                      map<string,string> &mFieldValue);

int query_channel_info(const char *channel_id,string &info);

int get_channel_update(string &value);

int save_alarm_msg(string value);

#endif