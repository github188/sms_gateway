#ifndef __GATEWAY_STRUCT_H__
#define __GATEWAY_STRUCT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/msg.h>
#include <arpa/inet.h>
#include <list>
#include <vector>
#include <dlfcn.h>
#include <sys/epoll.h>

#include "public.h"
#include "biz.h"
#include "msgque.h"
#include "protocol.h"

using namespace std;

typedef struct server_info_s
{
    char server_name[MAX_SECTION_LEN];
    char ip[MAX_IP_LEN];
    int port;
    int reconnect_interval; //重连时间隔 秒
    int heartbeat_interval; //心跳时间隔 秒
    int fd;
    time_t last_connect_time;
    bool is_reg;
}server_info_t;

typedef struct gateway_conf_s
{
    char prog_name[MAX_PATH_LEN]; //程序名
    char conf_file[MAX_PATH_LEN]; //配置文件名

    char log_path[MAX_PATH_LEN];
    char log_hdr[MAX_LOG_HDR_LEN];
    int log_file_lvl;
    int log_term_lvl;
    int log_buf;
    int log_switch_time;
    
    //监听本地IP和端口
    char local_ip[MAX_IP_LEN];
    int local_port;

    //连接管理和统一接入信息
    vector<server_info_t> server_info;

    //通道dll
    char channel_dll[MAX_PATH_LEN];

    //通道启动参数
    char channel_type[MAX_PATH_LEN];
    char channel_id[MAX_PATH_LEN];

    //是否启用多连接
    int is_need_multi_conn;

    //mq
    char mq_file[MAX_PATH_LEN];

    //发送子进程路径
    char exe_name[MAX_PATH_LEN];

    //定时扫描数据库
    time_t db_interval;
    time_t db_last_read_time;

    // 报文缓存大小配置
	int package_buff_size;
    
    //告警短信模板ID
    char template_id[MAX_PATH_LEN];
    
}gateway_conf_t;

extern gateway_conf_t   g_conf;
extern int              g_exit;
extern IChannelBiz*     g_biz;
extern msgque           g_mq;
extern vector<pid_t>    g_send_pid;
extern channel_conf_t   g_channel_conf;
extern msgform_t*       g_msgform;
extern int              g_ready_to_send;
#endif
