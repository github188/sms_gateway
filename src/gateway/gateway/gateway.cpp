#include "gateway.h"
#include "gateway_struct.h"
#include "gateway_task.h"
#include "gateway_db.h"
#include "gateway_biz.h"
#include "gateway_util.h"

#define PROGRAM_VERSION "1.0"

poller_t *cur_poller = &epoll_poller;   // epoll多路复用
fd_list_t *g_con;                       // connection_t*数组
int g_fd_size;                          // 最大连接数
gateway_conf_t g_conf;                  // 配置信息
IChannelBiz*  g_biz = NULL;             // 业务dll的指针
void* g_hm  = NULL;                     // dlopen打开的业务库
msgque      g_mq;                       //消息队列
int g_need_to_listen = 0;               //是否需要监听服务
vector<pid_t> g_send_pid;               //发送子进程pid
channel_conf_t  g_channel_conf;         //通道参数
msgform_t *g_msgform = NULL;            //消息队列指针
int g_ready_to_send = 1;                //网关是否连接成功

int main(int argc, char* argv[])
{
    //解析命令行参数
    extern char* optarg;
    int optch;
    char optstring[] = "hvt:i:c:";

    int ret = 0;
    strncpy(g_conf.prog_name, argv[0], MAX_PATH_LEN - 1);   	
    while ((optch = getopt(argc, argv, optstring)) != -1) 
    {
        switch (optch) 
        {
        case 'h':
            usage();
            return 0;
        case 'v':
            version();
            return 0;
        case 't':  //ChannelType
            strncpy(g_conf.channel_type, optarg, MAX_PATH_LEN - 1);
            break;
        case 'i': //ChannelId
            strncpy(g_conf.channel_id, optarg, MAX_PATH_LEN - 1);
            break;
        case 'c': //config
            strncpy(g_conf.conf_file, optarg, MAX_PATH_LEN - 1);
            break;
        default:
            usage();
            return -1;
        }
    }
                                                                                                                                                                          	
    if ( ( strlen(g_conf.channel_type) <= 0 ) || 
         ( strlen(g_conf.channel_id) <= 0 ) || 
         ( strlen(g_conf.conf_file) <= 0 )
        )
    {
        usage();
        exit(-1);
    }

    // 注册信号函数
    if (unlikely((ret = reg_signal()) != 0)) 
    {
        printf("fail to register sign.\n");
        return 0;
    }
    // 加载配置文件
    if (load_config() != 0)
    {
        printf("fail to load config file!\n");
        return 0;
    }

    // 初始化日志
    if (init_log() != 0)
    {
        printf("fail to init logger.\n");
        return 0;
    }
    printf("logger initialize successful.\n");

    // 初始化数据库
    if (init_db(g_conf.conf_file) != 0)
    {
        LOG_ERROR("fail to initialize db.\n");
        return 0;
    }
	LOG_INFO("db initialize successful.\n");
    
    //加载通道参数
    ret = load_channel_info(g_conf.channel_id);
    if( ret != 0)
    {
        LOG_ERROR("load_channel_info failed.\n");
        return -1;
    }
    LOG_INFO("load channel successful.channel_id[%s]channel_type[%s]\n",
                        g_conf.channel_id,
                        g_conf.channel_type);

    //fork发送子进程
    if( fork_proc() != 0 )
    {
        LOG_ERROR("fail to fork_proc!\n");
        return 0;
    }
    // 初始化消息队列
    if (init_mq() != 0)
    {
        LOG_ERROR("fail to initialize mq.\n");
        return 0;
    }
	LOG_INFO("mq initialize successful.\n");
    
    // 初始化业务库
    if (init_biz() != 0)
    {
        LOG_ERROR("fail to initialize biz.\n");
        return 0;
    }
	LOG_INFO("biz initialize successful.\n");

    // 初始化网络
    if (init_net() != 0)
    {
        LOG_ERROR("fail to initialize network.\n");
        return 0;
    }
	LOG_INFO("network initialize successful.\n");
	
    // 主处理过程
    main_process();

    // 释放资源
    uninit_net();
    uninit_biz();
    uninit_db();
    uninit_mq();
    uninit_log();
 
    return 0;
}

// 信号处理
int handler_sigterm()
{
    LOG_WARN("program receive sigterm\n");
    g_exit = 1;
    return 0;
}

int handler_sigchild()
{
    //收到子进程退出信号
    LOG_WARN("program receive sigchild\n");
    bool bsigchld;
    if ( g_exit ) 
    {
      bsigchld = false;
    } 
    else 
    {
      bsigchld = true;
    }
    if ( bsigchld ) 
    {
        pid_t pid = -1;
        int ret = 0;
        while ( (pid = waitpid(-1, &ret, WNOHANG)) > 0 ) 
        {
            vector<pid_t>::iterator it = g_send_pid.begin();
            for(;it!=g_send_pid.end();)
            {
                if( *it == pid )
                {
                    LOG_WARN("child exit, pid=%d, ret=%d\n", pid, ret);
                    it = g_send_pid.erase(it); //从列表删除
                    send_exit_alarm_msg(pid);//发送告警
                }
                else
                {
                    it++;
                }
            }
        }
    }
    //所有子进程都退出，父进程暂停发送数据
    if( g_send_pid.size() == 0 )
    {
        g_ready_to_send = 0;
    }
    
    return 0;
}
int handler_sighup()
{
    return 0;
}
int handler_sigsegv()
{
    return 0;
}
int handler_sigusr2()
{
    //刷日志
    log_flush();
    return 0;
}
int handler_sigpipe()
{
    return 0;
}

void usage()
{
    printf("Usage : %s [hvt:i:n:c:]\n", g_conf.prog_name);
    printf("        -h Show help.\n");
    printf("        -t channel type. [must]\n");
    printf("        -i channel id. [must]\n");
    printf("        -n channel connect count. [must]\n");
    printf("        -c input config file. [must]\n");
    printf("        -v show the version info.\n");
}

void version()
{
    printf("PROGRAM VERSION : %s\n", PROGRAM_VERSION);
    printf("REVISION NUMBER : %s\n", PROGRAM_REVISION);
}

int reg_signal()
{
    REGISTER_SIGNAL(SIGTERM, sigterm);//Kill信号
    REGISTER_SIGNAL(SIGINT, sigterm);//终端CTRL-C信号
    REGISTER_SIGNAL(SIGUSR1, SIG_IGN);//忽略SIGUSR1信号
    REGISTER_SIGNAL(SIGUSR2, sigusr2);//SIGUSR2信号
    REGISTER_SIGNAL(SIGHUP, sighup);//忽略SIGHUP信号
    REGISTER_SIGNAL(SIGCHLD, sigchild);//忽略子进程退出
    REGISTER_SIGNAL(SIGPIPE, SIG_IGN);//忽略SIGPIPE信号
    REGISTER_SIGNAL(SIGALRM, SIG_IGN);//忽略SIGALRM信号
    REGISTER_SIGNAL(SIGSEGV, sigsegv);//CORE信号

    return 0;
}

// 加载配置文件
int load_config()
{
    cfg_t *cfg = cfg_create();
    if (unlikely(cfg == NULL)) 
    {
        printf("cfg_create failed.\n");
        return 0;
    }
    int ret = parse_conf(g_conf.conf_file, cfg);
    if (unlikely(ret < 0))
    {
        printf("parse_config failed.\n");
        cfg_destroy(cfg);
        return 0;
    }
    sec_dict_t *sec = get_section(cfg, "COMMON");
    if (sec != NULL) 
    {
        // 日志
        READ_CONF_STR_MUST(sec, "LOG_DIR",              g_conf.log_path);
        READ_CONF_STR_MUST(sec, "LOG_HEADER",           g_conf.log_hdr);
        READ_CONF_INT_MUST(sec, "LOG_LEVEL_FILE",       g_conf.log_file_lvl);
        READ_CONF_INT_MUST(sec, "LOG_LEVEL_TERM",       g_conf.log_term_lvl);
        READ_CONF_INT_MUST(sec, "LOG_BUFFER",           g_conf.log_buf);
        READ_CONF_INT_MUST(sec, "LOG_SWITCH_TIME",      g_conf.log_switch_time);
        //网络
        READ_CONF_STR_MUST(sec, "LOCAL_IP",             g_conf.local_ip);
        
        READ_CONF_INT_MUST(sec, "PACKAGE_BUFF_SIZE",    g_conf.package_buff_size);
        if (g_conf.package_buff_size < MAX_PACKET_LEN)
        {
            g_conf.package_buff_size = MAX_PACKET_LEN;
        }
        
        //mq
        char mq_path[MAX_PATH_LEN];
        READ_CONF_STR_MUST(sec, "MQ_PATH",              mq_path);
        sprintf(g_conf.mq_file,"%s/%s",mq_path,g_conf.channel_id);

        //告警短信模板ID
        READ_CONF_STR_MUST(sec, "ALARM_SMS_TEMPLATE_ID",    g_conf.template_id);

        //业务库
        if( strcasecmp(g_conf.channel_type,CMPP2_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "CMPP2_CHANNEL_LIB",          g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,CMPP3_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "CMPP3_CHANNEL_LIB",          g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,SGIP_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "SGIP_CHANNEL_LIB",          g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,SMGP_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "SMGP_CHANNEL_LIB",          g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,HTTP_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "HTTP_CHANNEL_LIB",          g_conf.channel_dll);
        }
        else
        {
            printf("read channel lib failed.type[%s]\n",g_conf.channel_type);
            cfg_destroy(cfg);
            return -1;
        }
    }

    sec = get_section(cfg, "GATEWAY");
    if (sec != NULL) 
    {
        int server_cnt = 0;
        READ_CONF_INT_MUST(sec, "SVRCOUNT", server_cnt);
        if( server_cnt < 1 ) 
        {
            printf("SVRCOUNT = %d is less than 1!\n" , server_cnt);
            cfg_destroy(cfg);
            return -1;
        }
         // value example "MANAGER 127.0.0.1 8000 30 60"
        char key[MAX_SECTION_LEN] = {0};
        for(int i = 0; i < server_cnt;i++) 
        {
            char value[MAX_PATH_LEN] = {0};
            snprintf(key, sizeof(key), "SERVER%d", i+1);
            READ_CONF_STR_MUST(sec, key,value);
            
            char list[32][32];
            int count = parse_str_list(value,list);
            if( count != 5 ) 
            {
                printf("error: parse [%s] error!\n",key);
                cfg_destroy(cfg);
                return -1;
            }
            server_info_t info;
            memset(&info,0,sizeof(server_info_t));
            memcpy(info.server_name, list[0], 32);
            memcpy(info.ip, list[1], 32);
            info.port = atoi(list[2]);
            info.heartbeat_interval = atoi(list[3]);
            info.reconnect_interval = atoi(list[4]);
            printf("name[%s]ip[%s]port[%s]heartbeat[%s]reconnect[%s]\n",
                                list[0],
                                list[1],
                                list[2],
                                list[3],
                                list[4]);
            g_conf.server_info.push_back(info);
        }

        READ_CONF_STR_MUST(sec, "EXE_NAME",             g_conf.exe_name);
        READ_CONF_INT_MUST(sec, "DB_INTERVAL",          g_conf.db_interval);
        READ_CONF_INT_MUST(sec, "MULTI_CONN",           g_conf.is_need_multi_conn);
    }
    cfg_destroy(cfg);
    return 0;
}

// 初始化日志对象
int init_log()
{
    if (unlikely(init_log(g_conf.prog_name) != 0)) 
    {
        return 0;
    }
    
    set_log_path(g_conf.log_path);
    set_log_head(g_conf.log_hdr);

    set_file_level(g_conf.log_file_lvl);
    set_term_level(g_conf.log_term_lvl);

    set_cache_size(g_conf.log_buf);
    set_switch_interval(g_conf.log_switch_time);/*in seconds*/
    
    return 0;
}
void uninit_log()
{
    destroy_log();
}

// 初始化网络连接
int init_net()
{
    g_fd_size = SOCK_DEFAULT_FD_SIZE;
    g_con = (fd_list_t*)malloc(sizeof(fd_list_t) * g_fd_size);

    for (int i = 0; i < g_fd_size; i++)
    {
        g_con[i].con = NULL;
        g_con[i].type = -1;
    }
    poller_ev_init();
    
    //判断是否需要监听
    if( g_need_to_listen )
    {
        // 建立监听socket
        int fd = start_listen_ipv4(g_conf.local_ip, g_conf.local_port);
        if (unlikely(fd < 0))
        {
            LOG_ERROR("start_listen_ipv4 failed.\n");
            return 0;
        }
        LOG_INFO("listen local_ip = %s, local_port = %d\n", g_conf.local_ip, g_conf.local_port);

        poller_add_fd(fd, EV_READ);
    }

    return 0;
}

void uninit_net()
{
    for (int i = 0; i < g_fd_size; i++) 
    {
        if (g_con[i].con != NULL) 
        {
            LOG_DEBUG("destroy_fd_con : %d\n", g_con[i].con->fd);
            close(g_con[i].con->fd);
            destroy_fd_con(g_con[i].con->fd);
        }
    }
    poller_ev_term();
    free(g_con);
}

//初始化业务库
int init_biz()
{
    void* func = NULL;
    char err[MAX_PATH_LEN];
    g_hm = dlopen(g_conf.channel_dll , RTLD_LAZY);
    char* error = dlerror();
    if(g_hm == NULL)
    {
        sprintf(err, "%s", error);
        LOG_ERROR("fail to load library: %s, errmsg:%s\n",
                g_conf.channel_dll, err);
        return -1;
    }
    // 加载业务处理库
    func = dlsym(g_hm, "GetBizInterface");
    if ((error = dlerror()) != NULL)
    {
        sprintf(err, "%s", error);
        LOG_ERROR("fail to load function: GetBizInterface, errmsg:%s\n", err);
        dlclose(g_hm);
        return -1;
    }
    GetBizInterfaceFunc bizfun = (GetBizInterfaceFunc)func;
    if( g_channel_conf.uProtoType == 3 )
    {
        g_biz = bizfun( g_channel_conf.uHttpType );
    }
    else
    {
        g_biz = bizfun( g_channel_conf.uProtoType );
    }
    
    if (unlikely(g_biz == NULL)) 
    {
        LOG_ERROR("obtain biz library pointer error!\n");
        return -1;
    }

    //业务库初始化
    if (unlikely(g_biz->init_biz(g_conf.conf_file, 
                                 g_log,
                                 &g_channel_conf) != 0))
    {
        LOG_ERROR("init biz library error!\n");
        return -1;
    }
    //调用业务库判断是否需要监听
    if (unlikely(g_biz->is_need_to_listen(g_need_to_listen,g_conf.local_port) != 0))
    {
        LOG_ERROR("biz library is_need_to_listen error!\n");
        return -1;
    }

    return 0;
}

int uninit_biz()
{
    if (g_biz != NULL)
    {
        g_biz->uninit_biz();
        delete g_biz;
        g_biz = NULL;
    }
	if(g_hm != NULL)
	{
        dlclose(g_hm);
        g_hm = NULL;
	}
    g_hm = NULL;
    return 0;
}

// 初始化消息队列
int init_mq()
{
    //判断文件是否存在
    if (access(g_conf.mq_file, F_OK) != 0)
    {
        //没有则创建一个文件
        FILE* fp = fopen(g_conf.mq_file, "w+");
        if (fp == NULL)
        {
            return -1;
        }
        fclose(fp);
    }
    if( g_mq.attach( g_conf.mq_file )  < 0 )
    {
        if( g_mq.create( g_conf.mq_file )  < 0 )
        {
            return -1;
        }
    }

    return 0;
}

void uninit_mq()
{

}

// 主处理过程
int main_process()
{
    // 创建读队列
    dlist_t *read = dlist_create();
    if (unlikely(read == NULL)) 
    {
        LOG_ERROR("read queue pointer null!\n");
        return -1;
    }
    // 创建写队列
    dlist_t *write = dlist_create();
    if (unlikely(write == NULL)) 
    {
        LOG_ERROR("write queue pointer null!\n");
        dlist_destroy(read);
        return -1;
    }

    g_msgform = new msgform_t;
    if( g_msgform == NULL )
    {
        LOG_ERROR("failed to allocate memory for g_msgform.\n");
        return -1;
    }

    while(true)
    {
        signal_handler();
        //响应kill信号
        if( g_exit )
        {
            //处理子进程退出
            handle_child_exit();
            break;
        }
        
        //客户端超时处理 
        timeout_task(read, write);
        //读取报文
        read_net_task(read);
        //处理报文
        process_task(read, write);
        //发送报文
        write_net_task(write);
        
        if( g_ready_to_send )
        {
            //数据库任务
            db_task();
        }
        else
        {
            //所有发送子进程都退出了
            //判断mq是否有数据
            //有数据，将数据写回redis
            mq_task();
            sleep(1);
        }
    }

    if( g_msgform != NULL )
    {
        delete g_msgform;
        g_msgform = NULL;
    }
    dlist_destroy(read);
    dlist_destroy(write);
    return 0;
}
