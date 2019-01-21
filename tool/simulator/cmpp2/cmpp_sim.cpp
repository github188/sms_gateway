#include "cmpp_sim.h"
#include "cmpp_sim_task.h"

#define PROGRAM_VERSION "1.0"

poller_t *cur_poller = &epoll_poller;   // epoll多路复用
fd_list_t *g_con;                       // connection_t*数组
int g_fd_size;                          // 最大连接数
sim_conf_t  g_conf;                  // 配置信息
Cmpp2   g_cmpp2;
long g_cnt = 0;
int g_client_fd = 0;
int g_pid = 0;

dlist_t *g_phonelist = NULL;

int main(int argc, char* argv[])
{
    //解析命令行参数
    extern char* optarg;
    int optch;
    char optstring[] = "hvs:c:";

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
        case 's': //socket
            g_client_fd = atoi(optarg);
            break;
        case 'c': //config
            strncpy(g_conf.conf_file, optarg, MAX_PATH_LEN - 1);
            break;
        default:
            usage();
            return -1;
        }
    }
                                                                                                                                                                          	
    if( g_client_fd == 0 || strlen( g_conf.conf_file ) <= 0 )
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
    // 初始化网络
    if (init_net() != 0)
    {
        printf("fail to initialize network.\n");
        return 0;
    }
	printf("network initialize successful.\n");

    g_phonelist = dlist_create();
    if (unlikely(g_phonelist == NULL)) 
    {
        LOG_ERROR("g_phonelist queue pointer null!\n");
        return -1;
    }

    g_pid = getpid();

    // 主处理过程
    main_process();

    // 释放资源
    dlist_destroy(g_phonelist);
    uninit_net();
    uninit_log();
 
    return 0;
}

// 信号处理
int handler_sigterm()
{
    g_exit = 1;
    return 0;
}
int handler_sigchild()
{
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
    printf("Usage : %s [hvs:c:]\n", g_conf.prog_name);
    printf("        -h Show help.\n");
    printf("        -v show the version info.\n");
    printf("        -s accept fd. [must]\n");
    printf("        -c input config file. [must]\n");
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
    //set_log_head(g_conf.log_hdr);

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

    create_fd_con_buffsize(g_client_fd, BUF_DEFAULT_SIZE);

    connection_t *cli = g_con[g_client_fd].con;
    cli->con_type = CON_T_SERVER;
    cli->con_status = CON_S_CONNECTED;
    cli->proto.type = AF_INET;
    cli->connected_time = time(NULL);
    cli->heartbeat_time = cli->connected_time;
    g_con[g_client_fd].type = CON_T_SERVER;
    set_nonblock(g_client_fd);
    poller_add_fd(g_client_fd, EV_READ);
    
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
        //定时任务
        time_task(write);
        //读取报文
        read_net_task(read);
        //处理报文
        process_task(read, write);
        //应答报文
        write_net_task(write);
    }
    
    dlist_destroy(read);
    dlist_destroy(write);
    
    return 0;
}
