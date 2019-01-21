#ifndef __MANAGER_STRUCT_H__
#define __MANAGER_STRUCT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/msg.h>
#include <arpa/inet.h>
#include <list>
#include <map>
#include <dlfcn.h>
#include <sys/epoll.h>
#include <sys/wait.h>

#include "public.h"

using namespace std;

typedef struct channel_info_s
{
    int fd;
    pid_t pid;
    time_t heartbeat_time;
    string channel_type;
    string channel_id;
    string channel_name;
}channel_info_t;

typedef struct manager_conf_s
{
    char prog_name[MAX_PATH_LEN]; //程序名
    char conf_file[MAX_PATH_LEN]; //配置文件名

    char log_path[MAX_PATH_LEN];
    char log_hdr[MAX_LOG_HDR_LEN];
    int log_file_lvl;
    int log_term_lvl;
    int log_buf;
    int log_switch_time;
    
    //需要监听的ip
    char local_ip[MAX_IP_LEN];
    int port;
    
    //是否启动智能管理通道模块
    int isAuto;

    //通道心跳超时时间
    time_t channel_time_out;

    time_t timing_task_time;
    time_t timing_task_interval;

    char exe_name[MAX_PATH_LEN]; //执行程序名
    char exe_conf[MAX_PATH_LEN]; //程序配置文件

    //告警短信模板ID
    char template_id[MAX_PATH_LEN];
    
}manager_conf_t;

extern manager_conf_t g_conf;
extern int g_exit;
extern dlist_t *g_channel_info;

#endif
