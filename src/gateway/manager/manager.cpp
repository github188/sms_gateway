#include "manager.h"
#include "manager_task.h"
#include "manager_db.h"
#include "manager_biz.h"


#define PROGRAM_VERSION "1.0"

poller_t *cur_poller = &epoll_poller;   // epoll多路复用
fd_list_t *g_con;                       // connection_t*数组
int g_fd_size;                          // 最大连接数
manager_conf_t  g_conf;           // 配置信息
dlist_t *g_channel_info = NULL;

int main(int argc, char* argv[])
{
    //解析命令行参数
    extern char* optarg;
    int optch;
    char optstring[] = "hvc:";
    bool daemon = true;

    int ret = 0;
    memset(&g_conf,0,sizeof(g_conf));
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
        case 'c': //config
            strncpy(g_conf.conf_file, optarg, MAX_PATH_LEN - 1);
            break;
        case 'e':
            daemon = false;
            break;
        default:
            usage();
            return -1;
        }
    }
                                                                                                                                                                          	
    if( strlen( g_conf.conf_file ) <= 0 )
    {
        usage();
        exit(-1);
    }
    //建立守护进程
    if (daemon) 
    {
        daemonlize();
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
    // 初始化网络
    if (init_net() != 0)
    {
        LOG_ERROR("fail to initialize network.\n");
        return 0;
    }
	LOG_INFO("network initialize successful.\n");
    // 初始化数据库
    if (init_db(g_conf.conf_file) != 0)
    {
        LOG_ERROR("fail to initialize db.\n");
        return 0;
    }
	LOG_INFO("db initialize successful.\n");
    // 初始化通道数据
    if (init_channel() != 0)
    {
        LOG_ERROR("fail to initialize channel.\n");
        return 0;
    }
	LOG_INFO("channel initialize successful.\n");

    // 主处理过程
    main_process();

    // 释放资源
    uninit_channel();
    uninit_db();
    uninit_net();
    uninit_log();
 
    return 0;
}

//守护进程
void daemonlize()
{
    int pid = 0;
    if((pid = fork()) > 0)
    {
        exit(0);
    }
    setsid();
    if((pid = fork()) > 0)
    {
        exit(0);
    }
}

// 信号处理
int handler_sigterm()
{
    LOG_WARN("program receive sigterm\n");
    g_exit = 1;

    dlist_entry_t *item = NULL;
    list_for_each(item, g_channel_info->head, g_channel_info->tail)
    {
        channel_info_t  *info = (channel_info_t*)item->data;
        if(info == NULL)
        {
            LOG_ERROR("info is null\n");
            continue;
        }
        if( info->pid > 0 )
        {
            //杀死子进程
            kill(info->pid, SIGTERM);
            //等待子进程退出，防止僵尸进程
            waitpid(info->pid, NULL, 0);
        }
    }

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
            dlist_entry_t *item = NULL;
            list_for_each(item, g_channel_info->head, g_channel_info->tail)
            {
                channel_info_t  *info = (channel_info_t*)item->data;
                if(info == NULL)
                {
                    LOG_ERROR("info is null\n");
                    continue;
                }
                if( info->pid == pid )
                {
                    LOG_WARN("child exit, pid=%d, ret=%d\n", pid, ret);
                    info->pid = 0;
                    //发送告警信息
                    send_exit_alarm_msg(pid,info->channel_name);
                    break;
                }
            }
        }
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
    log_flush();
    return 0;
}
int handler_sigpipe()
{
    return 0;
}

void usage()
{
    printf("Usage : %s [hvc:e]\n", g_conf.prog_name);
    printf("        -h Show help.\n");
    printf("        -v show the version info.\n");
    printf("        -c input config file. [must]\n");
    printf("        -e don't start as daemon process.\n");
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
    REGISTER_SIGNAL(SIGCHLD, sigchild);//子进程退出
    REGISTER_SIGNAL(SIGPIPE, SIG_IGN);//忽略SIGPIPE信号
    REGISTER_SIGNAL(SIGALRM, SIG_IGN);//忽略SIGALRM信号
    REGISTER_SIGNAL(SIGSEGV, sigsegv);//CORE信号

    return 0;
}

// 加载配置文件
int load_config()
{
    cfg_t *cfg = cfg_create();
    if (unlikely(NULL == cfg)) 
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
    if (NULL != sec) 
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
        READ_CONF_INT_MUST(sec, "PORT",                 g_conf.port);

        //是否启动自动管理通道程序
        READ_CONF_INT_MUST(sec, "AUTO_MANAGER",         g_conf.isAuto);

        //心跳
        READ_CONF_INT_MUST(sec, "CHANNEL_TIME_OUT",     g_conf.channel_time_out);
        
        READ_CONF_INT_MUST(sec, "TIMING_TASK_INTERVAL", g_conf.timing_task_interval);

        //告警短信模板ID
        READ_CONF_STR_MUST(sec, "ALARM_SMS_TEMPLATE_ID",g_conf.template_id);

        //通道进程
        READ_CONF_STR_MUST(sec, "EXE_NAME",             g_conf.exe_name);
        READ_CONF_STR_MUST(sec, "EXE_CONF",             g_conf.exe_conf);
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
    
    // 建立监听socket
    int fd = start_listen_ipv4(g_conf.local_ip, g_conf.port);
    if (unlikely(fd < 0))
    {
        LOG_ERROR("start_listen_ipv4 failed.\n");
        return -1;
    }
    LOG_DEBUG("listen local_ip = %s, local_port = %d\n", g_conf.local_ip, g_conf.port);

    poller_add_fd(fd, EV_READ);
    
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

//初始化通道
int init_channel()
{
    g_channel_info = dlist_create();
    if (unlikely(g_channel_info == NULL)) 
    {
        LOG_ERROR("g_channel_info queue pointer null!\n");
        return -1;
    }

    int ret = 0;
    unsigned int uScanCursor = 0;
    map<std::string, std::string> mSmsChannel;

    do
    {
        ret = query_all_channel(100,uScanCursor,mSmsChannel);
    } while (ret == 0 && uScanCursor != 0);

    if( ret < 0 ) return -1;

    LOG_INFO("query_all_channel ok. size[%d]\n", mSmsChannel.size());
    
    map<std::string, std::string>::iterator itSmsChannel;
    for (itSmsChannel = mSmsChannel.begin(); itSmsChannel != mSmsChannel.end(); itSmsChannel++)
    {
        add_channel(itSmsChannel->first,itSmsChannel->second);
    }

    return 0;
}

void uninit_channel()
{
    dlist_destroy(g_channel_info);
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

    while(true)
    {
        signal_handler();

        //响应kill信号
        if( g_exit )  break;
        
        //读取报文
        read_net_task(read);
        //处理报文
        process_task(read, write);
        //应答报文
        write_net_task(write);
        //通道超时处理 
        timeout_task();
        //定时任务
        time_task(write);
        sleep(1);
    }
    
    dlist_destroy(read);
    dlist_destroy(write);
    
    return 0;
}
