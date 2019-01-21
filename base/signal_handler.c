
#define _POSIX_SOURCE

#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "signal_handler.h"
#include "logger.h"

extern int reload_conf();

static int s_signal_term = 0;
/*static int s_signal_segv = 1;*/
static int s_signal_child = 0;
static int s_signal_hup = 0;
static int s_signal_usr2 = 0;
static int s_signal_pipe = 0;

int g_exit = 0;

sigfunc *register_signal(int signo, sigfunc * func)
{
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    if (sigaction(signo, &act, &oact) < 0)
        return SIG_ERR;

    return oact.sa_handler;
}

int signal_handler()
{
    int retval = 0;

    if (s_signal_term == 1)
    {
        s_signal_term = 0;
        retval = handler_sigterm();
    }

    if (s_signal_hup == 1)
    {
        s_signal_hup = 0;
        retval = handler_sighup();
    }

    if (s_signal_child == 1)
    {
        s_signal_child = 0;
        retval = handler_sigchild();
    }

    if (s_signal_usr2 == 1)
    {
        s_signal_usr2 = 0;
        retval = handler_sigusr2();
    }

    if(s_signal_pipe == 1)
    {
        s_signal_pipe = 0;
        retval = handler_sigpipe();
    }

    return retval;
}

void sigterm(int signo)
{
    s_signal_term = 1;
}

void sigsegv(int signo)
{
    handler_sigsegv();
    signal(signo, SIG_DFL);
    raise(signo);
}

void sigchild(int signo)
{
    s_signal_child = 1;
}

void sighup(int signo)
{
    s_signal_hup = 1;
}

void sigusr2(int signo)
{
    s_signal_usr2 = 1;
}

void sigpipe(int signo)
{
    s_signal_pipe = 1;
}

