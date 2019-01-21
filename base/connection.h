#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    CON_NAME_LEN = 31,
};

enum
{
    CON_S_CONNECTING    = 0x00000001,
    CON_S_CONNECTED     = 0x00000002,
    CON_S_DISCONNECTING = 0x00000004,
    CON_S_DISCONNECTED  = 0x00000008,
    CON_S_BROKEN        = 0x00000010,
    CON_S_LISTENING     = 0x00000020,
    CON_S_LISTENED      = 0x00000040,
    CON_S_BLOCKED       = 0x00000080,
};


enum
{
    CON_T_LISTEN = 1,
    CON_T_SERVER = 2,
    CON_T_CLIENT = 3,
};

enum
{
    FD_T_LINTENER = 1,
    FD_T_COMMON   = 2,
};


enum
{
    IP_DIRECTION_LOCAL  = 1,
    IP_DIRECTION_REMOTE = 2,
};

enum
{
    SOCK_MIN_FD_SIZE = 1024,
    SOCK_DEFAULT_FD_SIZE = 4096,
    SOCK_MAX_FD_SIZE = 10240,
};

typedef struct connection_s connection_t;

typedef struct fd_list_s fd_list_t;

struct fd_list_s
{
    int type;
    connection_t *con;
};


typedef struct sock_addr_s sock_addr_t;

typedef struct ip_proto_s ip_proto_t;

struct sock_addr_s
{
    union{
        struct sockaddr_in ipv4;
        struct sockaddr_un un;
    }addr;
};


struct ip_proto_s
{
    int type;   /* AF_INET or AF_LOCAL */
    sock_addr_t local_addr;
    sock_addr_t remote_addr;
};


struct connection_s
{
    char con_name[CON_NAME_LEN + 1];
    ip_proto_t proto;
    int fd;
    int con_status;
    int con_type;
    int con_reg_status;
    void *owner;
    time_t connected_time;
    time_t send_time; 
    time_t recv_time;
    time_t heartbeat_time;
    buffer_t *rcvbuf;
    buffer_t *sndbuf;
};

int create_fd_con_buffsize(int fd, int buffsize);
int create_fd_con(int fd);
void destroy_fd_con(int fd);


int set_ipv4_addr(const char *ip, const short port, connection_t *con, int direction);
struct sockaddr_in *get_ipv4_addr(connection_t *con, int direction);

int set_un_addr(const char *path, connection_t *con, int direction);
struct sockaddr_un *get_un_addr(connection_t *con, int direction);


int sock_listen(connection_t *con);
int sock_connect(connection_t *con);

int sock_accept_buffsize(connection_t *con, int buffsize);
int sock_accept(connection_t *con);

int start_listen_ipv4(const char* ip, const unsigned short port);
int start_listen_un(const char* path);

int accept_client_buffsize(connection_t *con, int buffsize);
int accept_client(connection_t *con);

int connect_ipv4_serv_buffsize(const char* ip, const unsigned short port, int buffsize);
int connect_ipv4_serv(const char *ip, const unsigned short port);

int connect_ipv4_serv_block(const char* ip, const unsigned short port);
int connect_ipv4_serv_buffsize_block(const char* ip, const unsigned short port, int buffsize);


int connect_un_serv_buffsize(const char* path, int buffsize);
int connect_un_serv(const char *path);


int recv_data(connection_t *con);
int send_data(connection_t *con);

extern void set_con_status(connection_t *con, int status);

extern fd_list_t *g_con;
extern int g_fd_size;

#ifdef __cplusplus
}
#endif

#endif

