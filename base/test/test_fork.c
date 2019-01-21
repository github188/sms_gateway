#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "tsbase.h"

int main(int argc, char* argv[])
{
    init_log(argv[0]);
    set_log_path("/home/lqb/tsbase/logs");

    LOG_INFO("before fork.\n");

    log_flush();

    int ret = -1;
    
    ret = fork();
    if(ret == 0)
    {
        /*child process*/
        log_only_close(g_log);
        init_log("aaaaaa");
        
        set_log_path("/home/lqb/tsbase/logs");

        LOG_INFO("child process.\n");

        LOG_INFO("log_file:%s\n", g_log->file_name);

        sleep(10);
        destroy_log();
    }
    else if(ret > 0)
    {
        sleep(1);
        /*parent process*/

        LOG_INFO("parent process.\n");
        
        LOG_INFO("log_file:%s\n", g_log->file_name);

        destroy_log();
    }


    return 0;
}
