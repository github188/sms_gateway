#ifndef __H_SOCK_STREAM_H__
#define __H_SOCK_STREAM_H__

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    SOCK_ERR_NONE   = 0,
    SOCK_ERR_BROKEN = 1,
    SOCK_ERR_BLOCK  = 2,
    SOCK_ERR_PIPE   = 3,
    SOCK_ERR_OTHER  = 4,
};


int create_ipv4_socket();
int create_un_socket();

int tcp_send(int fd, char *buf, int len);
int tcp_recv(int fd, char *buf, int len);

int set_nonblock(int fd);

#ifdef __cplusplus
}
#endif

#endif

