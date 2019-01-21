
#ifndef __SIGNAL_HANDLER_H__
#define __SIGNAL_HANDLER_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef void sigfunc(int);

sigfunc *register_signal(int signo, sigfunc * func);

int handler_sigterm();

int handler_sigsegv();

int handler_sigchild();

int handler_sighup();

int handler_sigusr2();

int handler_sigpipe();

int signal_handler();

void sigterm(int signo);
void sigsegv(int signo);
void sigchild(int signo);
void sighup(int signo);
void sigusr2(int signo);
void sigpipe(int signo);

extern int g_exit;

#ifdef __cplusplus
}
#endif


#endif
