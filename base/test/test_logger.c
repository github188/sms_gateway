#include <stdio.h>
#include <string.h>

#include "compiler.h"
#include "logger.h"

int test_init(const char* arg)
{
    init_log(arg);

    set_cache_size(10485760);
    
    return 0;
}

int test_write_log()
{
    LOG_INFO("TEST LOG info level 1\n");
    LOG_WARN("TEST LOG warn level 1\n");
    LOG_ERROR("TEST LOG error level 1\n");
    LOG_FATAL("TEST LOG fatal level 1\n");
    LOG_DEBUG("TEST LOG debug level 1\n");
    set_file_level(LOG_LEVEL_DEBUG);
    set_term_level(LOG_LEVEL_DEBUG);
    LOG_DEBUG("TEST LOG debug level 2\n");

    set_file_level(LOG_LEVEL_FATAL);
    set_term_level(LOG_LEVEL_FATAL);
    LOG_INFO("TEST LOG info level 3\n");
    LOG_WARN("TEST LOG warn level 3\n");
    LOG_ERROR("TEST LOG error level 3\n");
    LOG_FATAL("TEST LOG fatal level 3\n");
    LOG_DEBUG("TEST LOG debug level 3\n");

    set_str_file_level("debug");
    set_str_term_level("debug");
    LOG_INFO("TEST LOG info level 4\n");
    LOG_WARN("TEST LOG warn level 4\n");
    LOG_ERROR("TEST LOG error level 4\n");
    LOG_FATAL("TEST LOG fatal level 4\n");
    LOG_DEBUG("TEST LOG debug level 4\n");

    set_file_level(LOG_LEVEL_INFO);
    set_term_level(LOG_LEVEL_INFO);

    LOG_DEBUG("TEST LOG debug level 5\n");
    LOG_INFO("TEST LOG info level 5\n");

    return 0;
}

int test_change_path()
{

    const char* path2 = "/home/lqb/tsbase/logs";
    if(set_log_path(path2) != 0)
    {
        printf("set_log_path failed. path = %s\n", path2);
        return -1;
    }


    const char* path1 = "abc/def";
    if(set_log_path(path1) != 0)
    {
        printf("set_log_path failed. path = %s\n", path1);
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[])
{
    if(0 != test_init(argv[0]))
    {
        printf("test_init failed.\n");
        return -1;
    }
    
    //g_log->max_line = 10;

    test_write_log();

    test_change_path();

    set_log_head("aaaaaaaaaaaaa");
    
    char hex[] = "ABCabcdefghijklmnopqrstxyz0123456789NDJGLTS";

    HEX_LOG(hex, strlen(hex));


    for(int i = 0; i < 100; i++)
    {
        LOG_ERROR("I = %d\n", i);
    }

    set_term_level(100);
    set_cache_size(LOG_MAX_CACHE_SIZE - 1);

    for(int i = 0; i < 1000000; i++)
    {
        LOG_INFO("DKFDDDDDDfdlkfldkfdlfkdlfkdlfkdlfkdlkfdlkfdlkfdlkfdfjisurfmgfksrjiejfkdfndksjriawjrkmvdsfasjdkjfidajfdjfkfjdkj\n");
    }


    destroy_log();

    return 0;
}

