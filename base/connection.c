#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

#include "connection.h"
#include "compiler.h"
#include "logger.h"
#include "sock_stream.h"
#include "poller.h"

int sock_err = 0;

#define TSBASE_PORT_SAME_ERR 0x0010


inline static void check_sock_err(connection_t *con);
static int wait_noblock_connect_ready(int fd);
static int sock_connect_block(connection_t* con);


int create_fd_con_buffsize(int fd, int buffsize)
{
    fd_list_t *plist = &(g_con[fd]);
    connection_t *pcon = plist->con;
    if(NULL != pcon)
    {
        pcon->rcvbuf->data_len = 0;
        pcon->rcvbuf->ptr = 0;

        pcon->sndbuf->data_len = 0;
        pcon->sndbuf->ptr = 0;

        return 0;
    }
    else
    {
        pcon = (connection_t*)malloc(sizeof(connection_t));
        if(unlikely(NULL == pcon))
        {
            LOG_ERROR("in create_fd_con malloc failed.\n");
            return -1;
        }

        pcon->fd = fd;
        pcon->rcvbuf = create_buffer(buffsize);
        pcon->sndbuf = create_buffer(buffsize);
        if(NULL == pcon->rcvbuf || NULL == pcon->sndbuf)
        {
            LOG_ERROR("in create_fd_con create_buffer failed.\n");
            free(pcon);
            return -1;
        }

        plist->con = pcon;
    }

    return 0;

}

int create_fd_con(int fd)
{
    return create_fd_con_buffsize(fd, BUF_DEFAULT_SIZE);
}

void destroy_fd_con(int fd)
{ 
    fd_list_t *plist = &(g_con[fd]);
    connection_t *pcon = plist->con;
    if(NULL != pcon)
    {
        if(NULL != pcon->rcvbuf)
        {
            destroy_buffer(pcon->rcvbuf);
            pcon->rcvbuf = NULL;    
        }       

        if(NULL != pcon->sndbuf)
        {
            destroy_buffer(pcon->sndbuf);
            pcon->sndbuf = NULL;
        }

        free(pcon);
        pcon = NULL;
        plist->con = NULL;
    }

    return;
}

int set_ipv4_addr(const char *ip, const short port, connection_t *con, int direction)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in set_ipv4_addr pointer is NULL.\n");
        return -1;
    }

    sock_addr_t *addr = NULL;
    if(IP_DIRECTION_LOCAL == direction)
        addr = &(con->proto.local_addr);
    else
        addr = &(con->proto.remote_addr);

    struct sockaddr_in *in = &(addr->addr.ipv4);
    memset(in, 0, sizeof(*in));

    in->sin_family = AF_INET;
    if(NULL != ip && ip[0] != '\0')
        inet_pton(AF_INET, ip, &(in->sin_addr));
    else
        in->sin_addr.s_addr = htonl(INADDR_ANY);

    in->sin_port = htons(port);

    con->proto.type = AF_INET;

    return 0;
}

struct sockaddr_in *get_ipv4_addr(connection_t *con, int direction)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in get_ipv4_addr pointer is NULL.\n");
        return NULL;
    }

    if(IP_DIRECTION_LOCAL == direction)
        return &(con->proto.local_addr.addr.ipv4);
    else
        return &(con->proto.remote_addr.addr.ipv4);

}

int set_un_addr(const char *path, connection_t *con, int direction)
{
    if(unlikely(NULL == path || NULL == con))
    {
        LOG_ERROR("in set_un_addr pointer is NULL.\n");
        return -1;
    }

    sock_addr_t *addr = NULL;
    if(IP_DIRECTION_LOCAL == direction)
        addr = &(con->proto.local_addr);
    else
        addr = &(con->proto.remote_addr);

    struct sockaddr_un *un = &(addr->addr.un);
    memset(un, 0, sizeof(*un));

    un->sun_family = AF_LOCAL;
    strncpy(un->sun_path, path, sizeof(un->sun_path) -1);

    con->proto.type = AF_LOCAL;

    return 0;
}

struct sockaddr_un *get_un_addr(connection_t *con, int direction)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in get_un_addr pointer is NULL.\n");
        return NULL;
    }

    if(IP_DIRECTION_LOCAL == direction)
        return &(con->proto.local_addr.addr.un);
    else
        return &(con->proto.remote_addr.addr.un);

}

int sock_listen(connection_t *con)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in sock_listen, pointer is NULL.\n");
        return -1;
    }

    int type = con->proto.type;
    int fd = con->fd;

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(int));

    if(AF_INET == type)
    {
        struct sockaddr_in *in = &(con->proto.local_addr.addr.ipv4);

        if(bind(fd, (struct sockaddr*)in, sizeof(struct sockaddr)) < 0)
        {
            LOG_ERROR("bind ipv4 failed, err = %s\n", strerror(errno));
            return -1;
        }

        if(listen(fd, 5) < 0)
        {
            LOG_ERROR("listen failed, err = %s\n", strerror(errno));
            return -1;
        }

        return 0;
    }
    else if(AF_LOCAL == type)
    {
        struct sockaddr_un *un = &(con->proto.local_addr.addr.un);
        if(bind(fd, (struct sockaddr*)un, sizeof(*un)) < 0)
        {
            LOG_ERROR("bind un failed, err = %s\n", strerror(errno));
            return -1;
        }

        if(listen(fd, 5) < 0)
        {
            LOG_ERROR("listen failed, err = %s\n", strerror(errno));
        }

        return 0;
    }

    return -1;
}

int wait_noblock_connect_ready(int fd)
{
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);

    static int radix = 1;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 20000 * radix; /*max 600 miliseconds by now*/

    int time_origin = tv.tv_usec;

    int sret = select(fd + 1, NULL, &wset, NULL, &tv);
    if(sret < 0)
    {
        LOG_ERROR("select faield, err = %s\n", strerror(errno)); 
        return -1;
    }

    if(sret == 0)
    {
        LOG_ERROR("connect timeout failed, time = %d\n", tv.tv_usec);
        radix++;
        if(radix > 30)
            radix = 30;

        return -1;
    }

    LOG_DEBUG("origin time:%d time remain:%d\n", time_origin, tv.tv_usec);

    if(!FD_ISSET(fd, &wset))
    {   
        LOG_ERROR("connect3 faield, err = %s\n", strerror(errno)); 
        return -1;
    }

    int err = 0;     
    socklen_t errlen = sizeof(err);  
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1)
    {
        LOG_ERROR("getsockopt failed, err = %s\n", strerror(errno));
        return -1;
    }

    if (err) 
    {
        LOG_ERROR("connect failed, err = %d\n", err);
        return -1;
    }

    return 0;
}

int sock_connect(connection_t *con)
{
    if(unlikely(NULL == con)) 
    {
        LOG_ERROR("in sock_connect, pointer is NULL.\n");
        return -1;
    }

    int fd = con->fd;
    int type = con->proto.type;

    if(AF_INET == type)
    {
        struct sockaddr_in *in = &(con->proto.remote_addr.addr.ipv4);
        if(connect(fd, (struct sockaddr*)in, sizeof(struct sockaddr)) < 0)
        {
            /*do not use on winsock*/
            if(errno != EINPROGRESS)
            {
                LOG_ERROR("connect faield, err = %s\n", strerror(errno));
                return -1;
            }
            
            if(wait_noblock_connect_ready(fd) != 0)
            {
                LOG_ERROR("wait_noblock_connect_ready failed.\n");
                return -1;
            }
        }

        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        unsigned int local_len = sizeof(local);

        if(getsockname(fd, (struct sockaddr *)&local, &local_len) < 0)
        {
            LOG_ERROR("getsockname failed, err = %s\n", strerror(errno));
            return -1;
        }

        /*the local port and the remote port are the same
         *if the local and the remote are the same machine,
         *this will be a self-connect, loop connection!
         *we prevente this happen!
         */

        if(unlikely(CHECK_IS_DEBUG()))
        {
            char local_ip[32] = {0};
            char remote_ip[32] = {0};
            inet_ntop(AF_INET, (void*)&(local.sin_addr), local_ip, sizeof(local_ip));
            inet_ntop(AF_INET, (void*)&(in->sin_addr), remote_ip, sizeof(remote_ip));

            LOG_DEBUG("local ip:%s port:%d, remote ip:%s port:%d\n", 
                    local_ip, ntohs(local.sin_port), remote_ip, ntohs(in->sin_port));
        }

        if(local.sin_port == in->sin_port)
        {
            LOG_WARN("in sock_connect, local port and the remore port are the same!\n"); 
            return TSBASE_PORT_SAME_ERR;
        }


        con->con_status = CON_S_CONNECTED;
        return 0;
    }
    else if(AF_LOCAL == type)
    {
        struct sockaddr_un *un = &(con->proto.remote_addr.addr.un);
        if(connect(fd, (struct sockaddr*)un, sizeof(*un)) < 0)
        {
            LOG_ERROR("connect failed, err = %s\n", strerror(errno));
            LOG_DEBUG("path = %s\n", un->sun_path);
            return -1;
        }

        con->con_status = CON_S_CONNECTED;
        return 0;
    }

    return -1;
}

int sock_connect_block(connection_t *con)
{
    if(unlikely(NULL == con)) 
    {
        LOG_ERROR("in sock_connect, pointer is NULL.\n");
        return -1;
    }

    int fd = con->fd;
    int type = con->proto.type;

    if(AF_INET == type)
    {
        struct sockaddr_in *in = &(con->proto.remote_addr.addr.ipv4);
        if(connect(fd, (struct sockaddr*)in, sizeof(struct sockaddr)) < 0)
        {
            LOG_ERROR("connect faield, err = %s\n", strerror(errno));
            return -1;
        }

        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        unsigned int local_len = sizeof(local);

        if(getsockname(fd, (struct sockaddr *)&local, &local_len) < 0)
        {
            LOG_ERROR("getsockname failed, err = %s\n", strerror(errno));
            return -1;
        }

        /*the local port and the remote port are the same
         *if the local and the remote are the same machine,
         *this will be a self-connect, loop connection!
         *we prevente this happen!
         */

        if(unlikely(CHECK_IS_DEBUG()))
        {
            char local_ip[32] = {0};
            char remote_ip[32] = {0};
            inet_ntop(AF_INET, (void*)&(local.sin_addr), local_ip, sizeof(local_ip));
            inet_ntop(AF_INET, (void*)&(in->sin_addr), remote_ip, sizeof(remote_ip));

            LOG_DEBUG("local ip:%s port:%d, remote ip:%s port:%d\n", 
                    local_ip, ntohs(local.sin_port), remote_ip, ntohs(in->sin_port));
        }

        if(local.sin_port == in->sin_port)
        {
            LOG_WARN("in sock_connect, local port and the remore port are the same!\n"); 
            return TSBASE_PORT_SAME_ERR;
        }


        con->con_status = CON_S_CONNECTED;
        return 0;
    }
    else if(AF_LOCAL == type)
    {
        struct sockaddr_un *un = &(con->proto.remote_addr.addr.un);
        if(connect(fd, (struct sockaddr*)un, sizeof(*un)) < 0)
        {
            LOG_ERROR("connect failed, err = %s\n", strerror(errno));
            LOG_DEBUG("path = %s\n", un->sun_path);
            return -1;
        }

        con->con_status = CON_S_CONNECTED;
        return 0;
    }

    return -1;
}

int sock_accept(connection_t *con)
{
    return sock_accept_buffsize(con, BUF_DEFAULT_SIZE);
}

int sock_accept_buffsize(connection_t *con, int buffsize)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in sock_accept, pointer is NULL.\n");
        return -1;
    }

    int fd = con->fd;
    int type = con->proto.type;

    if(AF_INET == type)
    {
        struct sockaddr_in in;
        unsigned int len = sizeof(in);

        int accfd = accept(fd, (struct sockaddr*)&in, &len);
        if(accfd < 0)
        {
            LOG_ERROR("accept failed, err = %s\n", strerror(errno));
            return -1;
        }

        create_fd_con_buffsize(accfd, buffsize);
        if(NULL != g_con[accfd].con)
            memcpy(&(g_con[accfd].con->proto.remote_addr.addr.ipv4), &in, sizeof(in));

        return accfd;
    }
    else if(AF_LOCAL == type)
    {
        struct sockaddr_un un;
        unsigned int len = sizeof(un);

        int accfd = accept(fd, (struct sockaddr*)&un, &len);
        if(accfd < 0)
        {
            LOG_ERROR("accept failed, err = %s\n", strerror(errno));
            return -1;
        }

        create_fd_con_buffsize(accfd, buffsize);
        if(NULL != g_con[accfd].con)
            memcpy(&(g_con[accfd].con->proto.remote_addr.addr.un), &un, sizeof(un));

        return accfd;
    }

    return -1;
}

int recv_data(connection_t *con)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in recv_data, pointer is NULL.\n");
        return -1;
    }

    int fd = con->fd;

    if (((con->con_status & CON_S_CONNECTED) == 0) && ((con->con_status & CON_S_CONNECTING) == 0))
    {
        LOG_ERROR("recv_data:con status illegal, fd = %d status = 0x%x\n",
                fd, con->con_status);
        return -1;
    }

    buffer_t *pbuf = con->rcvbuf;
    if (0 != pbuf->is_full(pbuf))
    {
        LOG_WARN("recv buffer is full, fd = %d\n", fd);
        return 0;
    }

    int free_size = pbuf->get_free_size(pbuf);
    char *writeptr = pbuf->get_write_ptr(pbuf);

    int ret = tcp_recv(fd, writeptr, free_size);
    if (ret < 0)
    {
        LOG_ERROR("tcp_recv failed.\n");
        return -1;
    }

    check_sock_err(con);

    /* 
       if(CON_S_BROKEN == con->con_status)
       ret = -1;
       */

    if (ret > 0)
    {
        pbuf->set_write_size(pbuf, ret);
        con->recv_time = time(NULL);
    }

    if(CHECK_IS_DEBUG())
    {
        /*
           char ip[16] = { 0 };
           inet_ntop(AF_INET, (void *) &(pcon->addr.sin_addr), ip, sizeof(ip));
           LOG_INFO
           ("from [%s]:[%d] to fd:[%d] buffer length:[%d], recv data length:[%d] succ.\n",
           ip, ntohs(pcon->addr.sin_port), fd, free_size, ret);
           */
    }

    return ret;
}

/*
 * send data in the send buffer
 *  
 * retrun: 0:success   -1:fatal error    1:send blocked
 *
 */
int send_data(connection_t *con)
{
    if(unlikely(NULL == con))
    {
        LOG_ERROR("in send_data pointer is NULL.\n");
        return -1;
    }

    int fd = con->fd;
    if (((CON_S_CONNECTED & con->con_status) == 0) && ((CON_S_CONNECTING & con->con_status) == 0))
    {
        LOG_ERROR("send_data: con status illegel, status = 0x%x, fd = %d\n",
                con->con_status, fd);
        return -1;
    }

    buffer_t *pbuf = con->sndbuf;
    const char *readptr = pbuf->get_read_ptr(pbuf);
    int send_len = pbuf->get_data_size(pbuf);

    int ret = tcp_send(fd, (char *) readptr, send_len);
    if (ret < 0)
    {
        LOG_ERROR("tcp_send failed.\n");
        return -1;
    }

    check_sock_err(con);

    if (ret > 0)
    {
        pbuf->set_read_size(pbuf, ret);
        con->send_time = time(NULL);

   }
   if(ret != send_len) //if EAGAIN (ret == 0) return blocked
   {
       return 1;
   }
 
    if(CHECK_IS_DEBUG())
    {
        /*
           char ip[16] = { 0 };
           inet_ntop(AF_INET, (void *) &(pcon->addr.sin_addr), ip, sizeof(ip));
           LOG_INFO("from fd:[%d] to [%s]:[%d] buffer length:[%d] send [%d] succ.\n",
           fd, ip, ntohs(pcon->addr.sin_port), send_len, ret);
           */
    }

    return 0;
}


inline void set_con_status(connection_t *con, int status)
{
    con->con_status = status;
}


inline static void check_sock_err(connection_t *con)
{
    if(sock_err == SOCK_ERR_BROKEN || sock_err == SOCK_ERR_OTHER || sock_err == SOCK_ERR_PIPE)
        set_con_status(con, CON_S_BROKEN);

    sock_err = SOCK_ERR_NONE;
}

int start_listen_ipv4(const char* ip, const unsigned short port)
{
    int fd = create_ipv4_socket();
    if(unlikely(fd > g_fd_size))
    {
        LOG_ERROR("in start_listen_ip too many socket.\n");
        close(fd);
        return -1;
    }

    /*let listen socket use default buffsize*/
    if(unlikely(create_fd_con(fd) < 0))
    {
        LOG_ERROR("create_fd_con failed.\n");
        close(fd);
        return -1;
    }

    connection_t *con = g_con[fd].con;
    if(unlikely(set_ipv4_addr(ip, port, con, IP_DIRECTION_LOCAL) < 0))
    {
        LOG_ERROR("set_ipv4_addr failed.\n");
        close(fd);
        return -1;
    }

    if(unlikely(sock_listen(con) < 0))
    {
        LOG_ERROR("sock_listen failed.\n");
        close(fd);
        return -1;
    }

    g_con[fd].type = CON_T_LISTEN;
    con->con_type = CON_T_LISTEN;
    con->con_status = CON_S_LISTENED;

    return fd;
}   

int start_listen_un(const char* path)
{
    int fd = create_un_socket();
    if(unlikely(fd > g_fd_size))
    {
        LOG_ERROR("in start_listen_deamon too many socket.\n");
        close(fd);
        return -1;
    }

    /*let listen socket use default buffsize*/
    if(unlikely(create_fd_con(fd) < 0))
    {
        LOG_ERROR("create_fd_con failed.\n");
        close(fd);
        return -1;
    }

    connection_t *con = g_con[fd].con;
    if(unlikely(set_un_addr(path, con, IP_DIRECTION_LOCAL) < 0))
    {
        LOG_ERROR("set_ipv4_addr failed.\n");
        close(fd);
        return -1;
    }

    unlink(path);

    if(unlikely(sock_listen(con) < 0))
    {
        LOG_ERROR("sock_listen failed.\n");
        close(fd);
        return -1;
    }

    g_con[fd].type = CON_T_LISTEN;
    con->con_type = CON_T_LISTEN;
    con->con_status = CON_S_LISTENED;

    return fd;
}

int accept_client(connection_t *con)
{
    return accept_client_buffsize(con, BUF_DEFAULT_SIZE);
}

int accept_client_buffsize(connection_t *con, int buffsize)
{
    int accfd = sock_accept_buffsize(con, buffsize);
    if(unlikely(accfd < 0))
    {
        LOG_ERROR("sock_accept failed.\n");
        return -1;
    }

    if(unlikely(accfd > g_fd_size))
    {
        LOG_WARN("too many fds, fd limitation is = %d\n", g_fd_size);
        close(accfd);
        return -1;
    }

    connection_t *cli = g_con[accfd].con;
    cli->con_type = CON_T_SERVER;
    cli->con_status = CON_S_CONNECTED;
    cli->proto.type = con->proto.type;
    cli->connected_time = time(NULL);
    cli->heartbeat_time = cli->connected_time;
    g_con[accfd].type = CON_T_SERVER;
    set_nonblock(accfd);
    poller_add_fd(accfd, EV_READ);

    if(unlikely(CHECK_IS_DEBUG()))
    {
        struct sockaddr_in *remote = get_ipv4_addr(cli, IP_DIRECTION_REMOTE);
        char ip[32] = { 0 };
        inet_ntop(AF_INET, (void *) &(remote->sin_addr), ip, sizeof(ip)); 
        LOG_DEBUG("accept a client from %s fd = %d\n", ip, accfd);
    }

    return accfd;
}

int connect_ipv4_serv(const char* ip, const unsigned short port)
{
    return connect_ipv4_serv_buffsize(ip, port, BUF_DEFAULT_SIZE);
}


int connect_ipv4_serv_block(const char* ip, const unsigned short port)
{
    return connect_ipv4_serv_buffsize_block(ip, port, BUF_DEFAULT_SIZE);
}


int connect_ipv4_serv_buffsize_block(const char* ip, const unsigned short port, int buffsize)
{
TSBAE_RECON:    
    int fd = create_ipv4_socket();
    if(fd < 0)
    {
        LOG_ERROR("create_ipv4_socket failed.\n");
        return -1;
    }

    if(fd >= g_fd_size)
    {
        LOG_ERROR("too many fd opened, fd_max = %d\n", g_fd_size);
        close(fd);
        return -1;
    }

    if(create_fd_con_buffsize(fd, buffsize) < 0)
    {
        LOG_ERROR("in connect_ipv4_serv, create_fd_con failed.\n");
        close(fd);
        return -1;
    }

    connection_t *con = g_con[fd].con;
    int ret = 0;

    ret = set_ipv4_addr(ip, port, con, IP_DIRECTION_REMOTE);
    if(ret < 0)
    {
        LOG_ERROR("in connect_ipv4_serv_block, set_ipv4_addr failed.\n");
        close(fd);
        return -1;
    }

    ret = sock_connect(con);
    if(ret < 0)
    {
        LOG_ERROR("in connect_ipv4_serv_block, sock_connect failed.\n");
        close(fd);
        return -1;
    }

    if(ret == TSBASE_PORT_SAME_ERR)
    {
        LOG_WARN("port same, close fd and reconnect.\n");
        close(fd);
        goto TSBAE_RECON; 
    }


    if(set_nonblock(fd) < 0)
    {
        LOG_ERROR("socket set nonblock failed, fd = %d err = %s\n", fd, strerror(errno));
        close(fd);
        return -1;
    }

    poller_add_fd(fd, EV_READ);   

    g_con[fd].type = CON_T_CLIENT;
    con->con_type = CON_T_CLIENT;

    return fd;
}


int connect_ipv4_serv_buffsize(const char* ip, const unsigned short port, int buffsize)
{
TSBAE_RECON:    
    int fd = create_ipv4_socket();
    if(fd < 0)
    {
        LOG_ERROR("create_ipv4_socket failed.\n");
        return -1;
    }

    if(fd >= g_fd_size)
    {
        LOG_ERROR("too many fd opened, fd_max = %d\n", g_fd_size);
        close(fd);
        return -1;
    }

    if(create_fd_con_buffsize(fd, buffsize) < 0)
    {
        LOG_ERROR("in connect_ipv4_serv, create_fd_con failed.\n");
        close(fd);
        return -1;
    }

    connection_t *con = g_con[fd].con;
    int ret = 0;

    ret = set_ipv4_addr(ip, port, con, IP_DIRECTION_REMOTE);
    if(ret < 0)
    {
        LOG_ERROR("in connect_ipv4_serv, set_ipv4_addr failed.\n");
        close(fd);
        return -1;
    }

    if(set_nonblock(fd) < 0)
    {
        LOG_ERROR("socket set nonblock failed, fd = %d err = %s\n", fd, strerror(errno));
        close(fd);
        return -1;
    }

    ret = sock_connect(con);
    if(ret < 0)
    {
        LOG_ERROR("in connect_ipv4_serv, sock_connect failed.\n");
        close(fd);
        return -1;
    }

    if(ret == TSBASE_PORT_SAME_ERR)
    {
        LOG_WARN("port same, close fd and reconnect.\n");
        close(fd);
        goto TSBAE_RECON; 
    }

    poller_add_fd(fd, EV_READ);   

    g_con[fd].type = CON_T_CLIENT;
    con->con_type = CON_T_CLIENT;

    return fd;
}

int connect_un_serv(const char* path)
{
    return connect_un_serv_buffsize(path, BUF_DEFAULT_SIZE);
}

int connect_un_serv_buffsize(const char* path, int buffsize)
{
    int fd = create_un_socket();
    if(fd < 0)
    {
        LOG_ERROR("create_ipv4_socket failed.\n");
        return -1;
    }

    if(fd >= g_fd_size)
    {
        LOG_ERROR("too many fd opened, fd_max = %d\n", g_fd_size);
        close(fd);
        return -1;
    }

    if(create_fd_con_buffsize(fd, buffsize) < 0)
    {
        LOG_ERROR("in connect_un_serv, create_fd_con failed.\n");
        close(fd);
        return -1;
    }

    connection_t *con = g_con[fd].con;
    int ret = 0;

    ret = set_un_addr(path, con, IP_DIRECTION_REMOTE);
    if(ret < 0)
    {
        LOG_ERROR("in connect_un_serv, set_un_addr failed.\n");
        close(fd);
        return -1;
    }

    ret = sock_connect(con);
    if(ret < 0)
    {
        LOG_ERROR("in connect_un_serv, sock_connect failed.\n");
        close(fd);
        return -1;
    }

    set_nonblock(fd); 
    poller_add_fd(fd, EV_READ);   

    g_con[fd].type = CON_T_CLIENT;
    con->con_type = CON_T_CLIENT;

    return fd;
}

