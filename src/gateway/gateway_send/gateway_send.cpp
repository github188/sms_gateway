#include "gateway_send.h"
#include "send_struct.h"
#include "send_task.h"
#include "send_db.h"
#include "send_biz.h"
#include "send_util.h"

#define PROGRAM_VERSION "1.0"

poller_t *cur_poller = &epoll_poller;   // epoll多路复用
fd_list_t *g_con;                       // connection_t*数组
int g_fd_size;                          // 最大连接数
send_conf_t g_conf;                     // 配置信息
IChannelBiz*  g_biz = NULL;             // 业务dll的指针
void* g_hm  = NULL;                     // dlopen打开的业务库
int g_is_login_success = 0;             //是否注册成功
msgque      g_mq;                       //消息队列
int g_connect_fd = 0;                   //连接channel的fd
channel_conf_t  g_channel_conf;         //通道参数
bool g_breload = false;                 //重读通道参数
dict* g_channel_dict = NULL;            //用于http协议库时的hash
uint32_t g_phone_size = 0;              //累计号码数，写入redis
int g_reconnect_times = 0;              //重连次数

int main(int argc, char* argv[])
{
    //解析命令行参数
    extern char* optarg;
    int optch;
    char optstring[] = "hvt:i:c:";

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

    g_channel_dict = dict_create(NULL);
    if (g_channel_dict == NULL)
    {
        printf("fail to create g_channel_dict.\n");
        return 0;
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
    LOG_INFO("logger initialize successful.\n");
    
    // 初始化数据库
    if (init_db(g_conf.conf_file) != 0)
    {
        LOG_ERROR("fail to initialize db.\n");
        return 0;
    }
	LOG_INFO("db initialize successful.\n");

    ret = load_channel_info(g_conf.channel_id);
    if( ret != 0 )
    {
        LOG_ERROR("load_channel_info failed.\n");
        return -1;
    }
    LOG_INFO("load channel successful.channel_id[%s]channel_type[%s]\n",
                        g_conf.channel_id,
                        g_conf.channel_type);
    // 初始化消息队列
    if (init_mq() != 0)
    {
        LOG_ERROR("fail to initialize mq.\n");
        return 0;
    }
	LOG_INFO("mq initialize successful.\n");
    
    // 初始化网络
    if (init_net() != 0)
    {
        LOG_ERROR("fail to initialize network.\n");
        return 0;
    }
	LOG_INFO("network initialize successful.\n");
    // 初始化业务库
    if (init_biz() != 0)
    {
        LOG_ERROR("fail to initialize biz.\n");
        return 0;
    }
	LOG_INFO("biz initialize successful.\n");
	
    // 主处理过程
    main_process();

    // 释放资源
    dict_release(g_channel_dict);
    uninit_biz();
    uninit_net();
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
    return 0;
}
int handler_sighup()
{
    LOG_WARN("program receive sighup\n");
    g_breload = true;
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
    printf("Usage : %s [hvt:i:c:]\n", g_conf.prog_name);
    printf("        -h Show help.\n");
    printf("        -t channel type. [must]\n");
    printf("        -i channel id. [must]\n");
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

        //重连时间隔
        READ_CONF_INT_MUST(sec, "RECONNECT_INTERVAL",   g_conf.reconnect_interval);
        //重连次数
        READ_CONF_INT_MUST(sec, "RECONNECT_TIMES",      g_conf.reconnect_times);

        READ_CONF_INT_MUST(sec, "PACKAGE_BUFF_SIZE",    g_conf.package_buff_size);
        if (g_conf.package_buff_size < MAX_PACKET_LEN)
        {
            g_conf.package_buff_size = MAX_PACKET_LEN;
        }

        //mq
        char mq_path[MAX_PATH_LEN];
        READ_CONF_STR_MUST(sec, "MQ_PATH", mq_path);
        sprintf(g_conf.mq_file,"%s/%s",mq_path,g_conf.channel_id);

        //业务库
        if( strcasecmp(g_conf.channel_type,CMPP2_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "CMPP2_CHANNEL_LIB", g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,CMPP3_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "CMPP3_CHANNEL_LIB", g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,SGIP_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "SGIP_CHANNEL_LIB", g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,SMGP_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "SMGP_CHANNEL_LIB", g_conf.channel_dll);
        }else if( strcasecmp(g_conf.channel_type,HTTP_CHANNEL_TYPE) == 0 )
        {
            READ_CONF_STR_MUST(sec, "HTTP_CHANNEL_LIB", g_conf.channel_dll);
        }
        else
        {
            printf("read channel lib failed.type[%s]\n",g_conf.channel_type);
        }
    }

    sec = get_section(cfg, "GATEWAY");
    if (sec != NULL) 
    {
        READ_CONF_INT_OPT(sec, "MULTI_CONN",           g_conf.is_need_multi_conn);
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
        //http协议默认状态为连接成功
        handle_channel_status(g_conf.channel_id,0);
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
    
    if (unlikely(g_biz->init_biz(g_conf.conf_file, 
                                 g_log,
                                 &g_channel_conf) != 0))
    {
        LOG_ERROR("init biz library error!\n");
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
    if( g_mq.attach( g_conf.mq_file )  < 0 )
    {
        return -1;
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
    // 等待队列
    dict* wq = dict_create(NULL);
    if(unlikely(NULL == wq)) 
    {
        dlist_destroy(read);
        dlist_destroy(write);
        LOG_ERROR("Fail to create wait queue.\n");
        return -1;
    }

    while(true)
    {
        //超时任务
        timeout_task(read, write, wq);
        //接收网络报文
        read_net_task(read);
        //处理网络报文
        process_task(read, write,wq);
        
        //处理信号
        signal_handler();
        //响应kill信号 或者超过登录次数
        if( g_exit || g_reconnect_times > g_conf.reconnect_times )
        {
            //写连接状态
            handle_channel_status(g_conf.channel_id,-1);
            break;
        }
        //重读通道参数信号
        if( g_breload )
        {
            g_breload = false;
            int ret = load_channel_info(g_conf.channel_id);
            if( ret != 0 )
            {
                LOG_ERROR("load_channel_info failed.\n");
                break;
            }
            //业务库用最新的配置
            g_biz->reload_channel( &g_channel_conf );
            //关闭掉与通道连接
            close( g_connect_fd );
            g_connect_fd = 0;
        }

        if( g_is_login_success && g_connect_fd > 0 )
        {
            //发送短信任务
            read_mq_task(read, write, wq);
        }
        //定时任务
        time_task(write, wq);
        //发送报文
        write_net_task(write);
        sleep(1);
    }

    dict_release(wq);
    dlist_destroy(read);
    dlist_destroy(write);
    return 0;
}
