
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdio.h>

#include "sock_stream.h"
#include "logger.h"
#include "compiler.h"


extern int sock_err;

int create_ipv4_socket()
{
    return socket(AF_INET, SOCK_STREAM, 0);
}

int create_un_socket()
{
    return socket(AF_LOCAL, SOCK_STREAM, 0);
}

int tcp_recv(int fd, char *buf, int len)
{
    int ret = 0, rlen;
    if (len < 0)
        return 0;

    while (1)
    {
        rlen = recv(fd, buf + ret, len - ret, 0);
        if (rlen == 0)
        {
            LOG_WARN("recv data lenth = 0, connection closed, fd:%d.\n", fd);
            sock_err = SOCK_ERR_BROKEN;
            break;
        }
        else if (rlen < 0)
        {
            int err = errno;
            if (err == EINTR)
                continue;
            else if (err == EAGAIN || err == EWOULDBLOCK)
            {
                LOG_DEBUG("tcp_recv:EAGAIN\n");
                break;
            }
            else
            {
                LOG_ERROR("recv data error: ret = %d, err = %s, fd:%d\n", rlen,
                          strerror(err), fd);
                sock_err = SOCK_ERR_OTHER;
                break;
            }
        }

        ret += rlen;
        if (ret == len)
            break;
    }

    if(CHECK_IS_DEBUG())
    {
        LOG_DEBUG("recv, fd = %d data datalen = %d\n", fd, ret);
    }

    return ret;
}

int tcp_send(int fd, char *buf, int len)
{
    int ret = 0;
    if (len <= 0)
        return 0;

    while (1)
    {

        int slen = send(fd, buf + ret, len - ret, 0);
        if (slen < 0)
        {
            if (errno == EINTR)
                continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                LOG_WARN("tcp_send:EAGAIN, fd = %d len = %d\n", fd, len);
                break;
            }
            else
            {
                int err = errno;
                LOG_ERROR("send data error: ret = %d, err = %s, fd = %d\n",
                          slen, strerror(err), fd);
                sock_err = SOCK_ERR_OTHER;
                break;
            }
        }

        ret += slen;
        if (ret == len)
            break;
    }

    if(CHECK_IS_DEBUG())
    {
        LOG_DEBUG("send, fd = %d len = %d\n", fd, ret);
    }

    return ret;
}


int set_nonblock(int fd)
{
    int opts;
    opts = fcntl(fd, F_GETFL);
    if (opts < 0)
    {
        LOG_WARN("fcntl F_GETFL failed, fd = %d\n", fd);
        return -1;
    }

    opts = opts | O_NONBLOCK;
    if (fcntl(fd, F_SETFL, opts) < 0)
    {
        LOG_WARN("fcntl F_SETFL failed, fd = %d\n", fd);
        return -1;
    }

    return 0;
}

