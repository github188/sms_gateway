#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include "msgque.h"

using namespace std;

#define PROGRAM_VERSION "1.0"

int         g_create = 0;
msgque      g_mq;
string      g_ipc_file;

void print_usage()
{
    printf("Usage: ipc_tool [-h][-c ipcfile][-s ipcfile][-d ipcfile]\n");
    printf("       -h show help\n");
    printf("       -c create ipc\n");
    printf("       -s show msgid\n");
    printf("       -d destroy ipc\n");
}

int main(int argc, char* argv[])
{
    //解析命令行参数
    extern char* optarg;
    int optch;
    char optstring[] = "hc:s:d:";

    while ((optch = getopt(argc, argv, optstring)) != -1) 
    {
        switch (optch) 
        {
        case 'h':
            print_usage();
            return 0;
        case 'c': 
            g_create = 1;
            g_ipc_file = optarg;
            break;
        case 's': 
            g_create = 2;
            g_ipc_file = optarg;
            break;
        case 'd': 
            g_create = -1;
            g_ipc_file = optarg;
            break;
        default:
            print_usage();
            return -1;
        }
    }

    if ( g_create == 0 )
    {
        print_usage();
        exit(0);
    }
    if ( g_ipc_file.empty() )
    {
        print_usage();
        exit(0);
    }

    if ( g_create == 1 )
    {
        int msgid = g_mq.create(g_ipc_file.c_str());
        if ( msgid >= 0 )
        {
            printf("create ipc ok.msgid=[%d]\n",msgid);
        }
        else
        {
            printf("create ipc failed:%s\n",strerror(errno));
        }
    }
    else if ( g_create == 2 )
    {
        int msgid = g_mq.attach(g_ipc_file.c_str());
        if ( msgid >= 0 )
        {
            printf("show ipc ok.msgid=[%d]\n",msgid);
        }
        else
        {
            printf("create ipc failed:%s\n",strerror(errno));
        }
    }
    else if ( g_create == -1 )
    {
        printf("destroy ipc: %s\n",g_ipc_file.c_str());
        if (g_mq.attach(g_ipc_file.c_str()) >= 0)
        {
            printf("attach ipc ok\n");
            if (g_mq.destroy() >= 0)
            {
                printf("destroy ipc ok\n");
            }
            else
            {
                printf("destroy ipc faild:%s\n",strerror(errno));
            }
        }
        else
        {
            printf("attach ipc faild:%s\n",strerror(errno));
        }
    }
 
    return 0;
}
