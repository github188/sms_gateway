#ifndef __SEND_TASK_H__
#define __SEND_TASK_H__
#include "send_struct.h"

//读MQ报文任务
int read_mq_task(dlist_t *read, dlist_t *write, dict* wq);

//http拉去状态任务
int http_pull_task(dlist_t *read, dlist_t *write, dict* wq);

//读网络报文任务
int read_net_task(dlist_t *read);

//处理任务
int process_task(dlist_t *read, dlist_t *write, dict* wq);

//写网络报文任务
int write_net_task(dlist_t *write);

//超时任务
int timeout_task(dlist_t *read, dlist_t *write, dict* wq);

//定时任务
int time_task(dlist_t *write, dict* wq);

#endif
