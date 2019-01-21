#ifndef __UNIQIO_DB_H__
#define __UNIQIO_DB_H__

#include "uniqio_struct.h"


int init_db(void* conf);
void uninit_db();

bool reconnect_db();

int save_channel_msg(const char *key,string value);

#endif