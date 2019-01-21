#ifndef __POLLER_H__
#define __POLLER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define EV_READ    0X0001
#define EV_WRITE   0X0010
#define EV_ERROR   0X0100

/*millisecond*/
#define POLL_DEFAULT_TIME_OUT 10

typedef struct ev_events_s ev_events_t;

struct ev_events_s {
    int fd;
    int events;
    void *ptr;     /*epoll_event.data.ptr*/
};

typedef struct poller_s poller_t;

struct poller_s {
    int (*add_fd) (poller_t *p, const int fd, int events, void *ptr);
    int (*del_fd) (poller_t *p, const int fd);
    int (*alter_events) (poller_t *p, const int fd, int events);
    int (*do_poll) (poller_t *p);
    ev_events_t* (*get_events)(poller_t *p);
    int (*ev_init) (poller_t *p);
    void (*ev_term) (poller_t *p);
    void (*set_timeout) (poller_t *p, int timeout);
    void *private_data;
    const char *name;
    int pref;
    int time_out; /*in milliseconds*/ 
    ev_events_t *ev;
};

extern poller_t *cur_poller;    /* the current poller */

extern poller_t epoll_poller;

#define poller_add_fd(fd, events)\
        cur_poller->add_fd(cur_poller, fd, events, NULL)

#define poller_add_fd_ptr(fd, events, ptr)\
        cur_poller->add_fd(cur_poller, fd, events, ptr)

#define poller_del_fd(fd)\
        cur_poller->del_fd(cur_poller, fd)

#define poller_alter_events(fd, events)\
        cur_poller->alter_events(cur_poller, fd, events)       

#define poller_do_poll()\
        cur_poller->do_poll(cur_poller)

#define poller_get_events()\
        cur_poller->get_events(cur_poller)

#define poller_ev_init()\
        cur_poller->ev_init(cur_poller)

#define poller_ev_term()\
        cur_poller->ev_term(cur_poller)

#define poller_set_timeout(timeout)\
        cur_poller->set_timeout(cur_poller, timeout)


#ifdef __cplusplus
}
#endif

#endif

