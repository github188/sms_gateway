#ifndef __PUBLIC_H__
#define __PUBLIC_H__

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include "tsbase.h"

// 长度定义
enum {
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
    MAX_PACKET_LEN                      = 1024*128,   //128k
};

// 心跳类型
enum {
    HEARTBEAT_TYPE_ACTIVE               = 1,           // 主动模式
    HEARTBEAT_TYPE_PASSIVE              = 2,           // 被动模式
};

#define CMPP2_CHANNEL_TYPE              "cmpp2"    // 移动cmpp2
#define CMPP3_CHANNEL_TYPE              "cmpp3"    // 移动cmpp3
#define SGIP_CHANNEL_TYPE               "sgip"    // 联通
#define SMGP_CHANNEL_TYPE               "smgp"    // 电信
#define HTTP_CHANNEL_TYPE               "http"    // HTTP


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

#endif
