#ifndef __SIM_STRUCT_H__
#define __SIM_STRUCT_H__

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
#include <vector>
#include <dlfcn.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include "tsbase.h"
#include "cmpp2.h"
#include "cmpp3.h"
#include "sgip.h"
#include "smgp.h"

using namespace std;

#ifndef _MSC_VER
//信号处理
#define REGISTER_SIGNAL(type, func/*, interupt*/)         \
    do{                                                   \
        if(register_signal(type, func/*, interupt*/) ==   \
                SIG_ERR){                                 \
            printf("register signal %d failed: %s\n",     \
                    type, strerror(errno));               \
            return -1;                                    \
        }                                                 \
    }while(0)

#define READ_CONF_INT_MUST(s, k, v)                       \
    do{                                                   \
        const char* t = get_value(s, k);                  \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->sec, k);     \
            return -1;                                    \
        }else{                                            \
            v = atoi(t);                                  \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_INT_OPT(s, k, v)                        \
    do{                                                   \
        const char* t = get_value(s, k);                  \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->sec, k);     \
        }else{                                            \
            v = atoi(t);                                  \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STR_MUST(s, k, v)                       \
    do{                                                   \
        const char* t = get_value(s, k);                  \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->sec, k);     \
            return -1;                                    \
        }else{                                            \
            /*必须确保V比T空间大*/                           \
            strcpy(v, t);                                 \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STR_OPT(s, k, v)                        \
    do{                                                   \
        const char* t = get_value(s, k);                  \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->sec, k);     \
        }else{                                            \
            /*必须确保V比T空间大*/                           \
            strcpy(v, t);                                 \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STDSTR_MUST(s, k, v)                    \
    do{                                                   \
        const char* t = get_value(s, k);                  \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->sec, k);     \
            return -1;                                    \
        }else{                                            \
            v = t;                                        \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STDSTR_OPT(s, k, v)                     \
    do{                                                   \
        const char* t = get_value(s, k);                  \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->sec, k);     \
        }else{                                            \
            v = t;                                        \
        }                                                 \
    }while(0)                                             \

#else
//R5_LOG
#define READ_CONF_INT_MUST(s, k, v)                       \
    do{                                                   \
        const char* t = s->getValue(k);                   \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->getSession(), k);     \
            return -1;                                    \
        }else{                                            \
            v = atoi(t);                                  \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_INT_OPT(s, k, v)                        \
    do{                                                   \
        const char* t = s->getValue(k);                   \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->getSession(), k);     \
        }else{                                            \
            v = atoi(t);                                  \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STR_MUST(s, k, v)                       \
    do{                                                   \
        const char* t = s->getValue(k);                   \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->getSession(), k);     \
            return -1;                                    \
        }else{                                            \
         /*必须确保V比T空间大*/                           \
            v = t;                                        \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STR_OPT(s, k, v)                        \
    do{                                                   \
        const char* t = s->getValue(k);                   \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->getSession(), k);     \
        }else{                                            \
         /*必须确保V比T空间大*/                           \
            v = t;                                        \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STDSTR_MUST(s, k, v)                    \
    do{                                                   \
        const char* t = s->getValue(k);                   \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->getSession(), k);     \
            return -1;                                    \
        }else{                                            \
            v = t;                                        \
        }                                                 \
    }while(0)                                             \

#define READ_CONF_STDSTR_OPT(s, k, v)                     \
    do{                                                   \
        const char* t = s->getValue(k);                   \
        if(NULL == t){                                    \
            printf("fail to obtain configuration item."   \
              " section: %s, item: %s\n", s->getSession(), k);     \
        }else{                                            \
            v = t;                                        \
        }                                                 \
    }while(0)                                             \

#endif

// 长度定义
enum 
{
    MAX_SID_LEN                         = 64,
    MAX_SECTION_LEN                     = 64,
    MAX_KEY_LEN                         = 128,
    MAX_PATH_LEN                        = 256,
    MAX_LOG_HDR_LEN                     = 128,
    MAX_IP_LEN                          = 32,
    MAX_DB_USER_LEN                     = 128,
    MAX_DB_PSW_LEN                      = 64,
    MAX_DB_CONN_LEN                     = 256,
    MAX_DB_DOMAIN_LEN                   = 64,
    MAX_MSG_LEN                         = 1024,
    MAX_PACKET_LEN                      = 1024*64,   //64k
};

typedef struct phone_info_s
{
    string msg_id;
    string src_phone;
    string dest_phone;
}phone_info_t;

typedef struct sim_conf_s
{
    char prog_name[MAX_PATH_LEN]; //程序名
    char conf_file[MAX_PATH_LEN]; //配置文件名

    char log_path[MAX_PATH_LEN];
    char log_hdr[MAX_LOG_HDR_LEN];
    int log_file_lvl;
    int log_term_lvl;
    int log_buf;
    int log_switch_time;
    
    char exe_name[MAX_PATH_LEN];
    //需要监听的ip
    char local_ip[MAX_IP_LEN];
    int port;

}sim_conf_t;

extern sim_conf_t       g_conf;
extern int              g_exit;
extern Cmpp2            g_cmpp2;
extern Cmpp3            g_cmpp3;
extern Sgip             g_sgip;
extern Smgp             g_smgp;

#endif
