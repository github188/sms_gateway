#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "compiler.h"
#include "poller.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EPOLL_MAX_FD 10000

struct ev_data_s
{
    int fd;
    void *ptr;
};
typedef struct ev_data_s ev_data_t;

static int epoll_fd;
static int nevents;
static struct epoll_event *epoll_list;

static ev_data_t *ev_data;

static int epoll_max_events;

static int __epoll_ev_init(poller_t *p);
static void __epoll_ev_term(poller_t *p);
static int __epoll_add_fd(poller_t *p, const int fd, int events, void* ptr);
static int __epoll_del_fd(poller_t *p, const int fd);
static int __epoll_do_poll(poller_t *p);
static ev_events_t* __epoll_get_events(poller_t *p);
static int __epoll_alter_ev(poller_t *p, const int fd, int events);
static void __pool_set_timeout(poller_t *p, int timeout);

poller_t epoll_poller = {
    __epoll_add_fd,
    __epoll_del_fd,
    __epoll_alter_ev,
    __epoll_do_poll,
    __epoll_get_events,
    __epoll_ev_init,
    __epoll_ev_term,
    __pool_set_timeout,
    NULL,
    "epoll",
    300,
    POLL_DEFAULT_TIME_OUT,
    NULL
};


static int __epoll_ev_init(poller_t *p)
{
    nevents = 0;

    epoll_max_events = EPOLL_MAX_FD;

    epoll_fd = epoll_create(epoll_max_events);
    if (epoll_fd < 0)
    {
        LOG_ERROR("epoll_create failed.\n");
        return -1;
    }

    size_t ev_size = epoll_max_events * sizeof(ev_events_t);
    p->ev = (ev_events_t *) malloc(ev_size);
    if (NULL == p->ev)
    {
        LOG_ERROR("malloc p->ev failed.\n");
        return -1;
    }
    memset(p->ev, 0, ev_size);

    size_t list_size = sizeof(struct epoll_event) * epoll_max_events;
    epoll_list = (struct epoll_event *) malloc(list_size);
    if (NULL == epoll_list)
    {
        free(p->ev);
        LOG_ERROR("malloc epoll_list failed.\n");
        return -1;
    }
    memset(epoll_list, 0, list_size);

    size_t ev_data_size = sizeof(ev_data_t) * epoll_max_events;
    ev_data = (ev_data_t*) malloc(ev_data_size);
    if(ev_data == NULL)
    {
        free(p->ev);
        free(epoll_list);
        LOG_ERROR("malloc ev_data failed.\n");
        return -1;
    }
    memset(ev_data, 0, ev_data_size);

    return 0;
}

static void __epoll_ev_term(poller_t *p)
{
    close(epoll_fd);
    epoll_fd = -1;

    if (p->ev)
    {
        free(p->ev);
        p->ev = NULL;
    }

    if (epoll_list)
    {
        free(epoll_list);
        epoll_list = NULL;
    }

    if(ev_data)
    {
        free(ev_data);
        ev_data = NULL;
    }
}

static int __epoll_add_fd(poller_t *p, const int fd, int events, void* ptr)
{
    int local_event = 0;
    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));

    if (events & EV_READ)
        local_event |= EPOLLIN;
    if (events & EV_WRITE)
        local_event |= EPOLLOUT;
    if (events & EV_ERROR)
        local_event |= EPOLLERR;

    ee.events = local_event;

    ev_data[fd].fd = fd;
    ev_data[fd].ptr = ptr;
    ee.data.ptr = &(ev_data[fd]);

    int ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ee);
    if (ret < 0)
    {
        LOG_WARN("__epoll_add_fd:epoll_ctl failed, err = %s\n",
                 strerror(errno));
        return -1;
    }

    nevents++;

    return 0;
}

static int __epoll_del_fd(poller_t *p, const int fd)
{
    struct epoll_event ee;

    ee.events = 0;
    ee.data.ptr = &(ev_data[fd]);

    int ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ee);
    if (ret < 0)
    {
        LOG_WARN("__epoll_del_fd:epoll_ctl failed, err = %s\n",
                 strerror(errno));
        return -1;
    }

    nevents--;

    return 0;
}

static int __epoll_do_poll(poller_t *p)
{
    int ret = epoll_wait(epoll_fd, epoll_list, nevents, p->time_out);
    if (ret < 0)
    {
        /*LOG_ERROR("__epoll_do_poll:epoll_ctl failed, err = %s\n",
                  strerror(errno));
          This may cause errno alter when write log failed.
        */

        return -1;
    }

    /*LOG_DEBUG("ret = %d nevents = %d\n", ret, nevents); */

    if (ret == 0)
    {
        /*TODO time out ... */
    }

    for (int i = 0; i < ret; ++i)
    {
        ev_events_t *ev = &(p->ev[i]);
        ev_data_t *d = (ev_data_t *)epoll_list[i].data.ptr;

        ev->fd = d->fd;
        ev->ptr = d->ptr;

        ev->events = 0;

        if (epoll_list[i].events & EPOLLIN)
            ev->events |= EV_READ;
        if (epoll_list[i].events & EPOLLOUT)
            ev->events |= EV_WRITE;
        if (epoll_list[i].events & EPOLLERR)
            ev->events |= EV_ERROR;
        
        if(CHECK_IS_DEBUG())
            LOG_DEBUG("epoll:fd = %d events = %x\n", ev->fd, ev->events);
    }

    return ret;
}

static ev_events_t *__epoll_get_events(poller_t *p)
{
    return p->ev;
}

static int __epoll_alter_ev(poller_t *p, const int fd, int events)
{
    int local_event = 0;
    if (events & EV_READ)
        local_event |= EPOLLIN;
    if (events & EV_WRITE)
        local_event |= EPOLLOUT;
    if (events & EV_ERROR)
        local_event |= EPOLLERR;

    struct epoll_event ee;
    ee.events = local_event;
    ee.data.ptr = &(ev_data[fd]);

    int ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ee);
    if (ret < 0)
    {
        LOG_WARN("__epoll_alter_ev:epoll_ctl failed, err = %s.\n",
                 strerror(errno));
        return -1;
    }

    return 0;
}

static void __pool_set_timeout(poller_t *p, int timeout)
{
    p->time_out = timeout;
}

#ifdef __cplusplus
}
#endif

