#ifndef __UNIQIO_STRUCT_H__
#define __UNIQIO_STRUCT_H__

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

typedef struct gateway_info_s
{
    char        channel_id[MAX_PATH_LEN]; //key
    int         fd;
    int64_t     last_send_time;
    char        channel_type[MAX_PATH_LEN];
    long        count;
}gateway_info_t;

typedef struct uniqio_conf_s
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

    //心跳超时时间
    time_t heartbeat_interval;

    // 报文缓存大小配置
	int package_buff_size;

}uniqio_conf_t;

extern uniqio_conf_t g_conf;
extern int g_exit;
extern dict *g_gateway_dict;

#endif
