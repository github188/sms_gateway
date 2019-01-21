#ifndef __GATEWAY_TASK_H__
#define __GATEWAY_TASK_H__
#include "gateway_struct.h"

//读网络报文任务
int read_net_task(dlist_t *read);

//处理任务
int process_task(dlist_t *read, dlist_t *write);

//写网络报文任务
int write_net_task(dlist_t *write);

//超时任务
int timeout_task(dlist_t *read, dlist_t *write);

//数据库任务
int db_task();

//mq任务
int mq_task();

#endif
