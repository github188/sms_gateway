#ifndef __SEND_STRUCT_H__
#define __SEND_STRUCT_H__

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
#include <dlfcn.h>
#include <sys/epoll.h>

#include <json/json.h>
#include "public.h"
#include "biz.h"
#include "msgque.h"
#include "protocol.h"

using namespace std;

typedef struct channel_reserved_s
{
    int fd;                           // key
    char sid[MAX_SID_LEN];            // 流水号
    int len;                          // 流水号长度
    time_t fd_begin_time;
    
    channel_reserved_s()
    {
        memset(this, 0, sizeof(channel_reserved_s));
    }
}channel_reserved_t;

typedef struct send_conf_s
{
    char prog_name[MAX_PATH_LEN]; //程序名
    char conf_file[MAX_PATH_LEN]; //配置文件名

    char log_path[MAX_PATH_LEN];
    char log_hdr[MAX_LOG_HDR_LEN];
    int log_file_lvl;
    int log_term_lvl;
    int log_buf;
    int log_switch_time;

    //通道dll
    char channel_dll[MAX_PATH_LEN];

    //通道启动参数
    char channel_type[MAX_PATH_LEN];
    char channel_id[MAX_PATH_LEN];

    //mq
    char mq_file[MAX_PATH_LEN];

    //重连时间隔(秒)
    time_t reconnect_interval;
    //上次连接时间
    time_t last_connect_time;
    //重连次数
    int reconnect_times;

    time_t last_heartbeat_time;
    
    // 报文缓存大小配置
	int package_buff_size;

    //是否启用多连接
    int is_need_multi_conn;

    //上次和redis交互时间
    time_t last_opr_redis_time;
}send_conf_t;

extern send_conf_t      g_conf;
extern int              g_exit;
extern IChannelBiz*     g_biz;
extern int              g_is_login_success;
extern int              g_connect_fd;
extern msgque           g_mq;
extern channel_conf_t   g_channel_conf;
extern bool             g_breload;
extern dict*            g_channel_dict;
extern uint32_t         g_phone_size;
extern int              g_reconnect_times;

#endif
