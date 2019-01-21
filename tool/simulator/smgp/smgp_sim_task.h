#ifndef __SMGP_SIM_TASK_H__
#define __SMGP_SIM_TASK_H__

#include "sim_struct.h"

//读网络报文任务
int read_net_task(dlist_t *read);

//处理任务
int process_task(dlist_t *read, dlist_t *write);

//写网络报文任务
int write_net_task(dlist_t *write);

//定时任务
int time_task(dlist_t *write);

#endif
