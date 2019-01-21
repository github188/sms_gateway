#include <stdio.h>

#include "tslimits.h"
#include "dict.h"
#include "dlist.h"
#include "cfgparse.h"
#include "logger.h"

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("param error!\n");
        printf("usage:./test_cfg cfg_file_name\n");
        return -1;
    }

    cfg_t *cfg = cfg_create();
    if(NULL == cfg)
    {   
        printf("cfg_create failed.\n");
        return -1;
    }   

    int ret = 0;
    ret = parse_conf(argv[1], cfg);
    if(ret < 0)
    {
        printf("parse_config failed.\n");
        return -1;
    }

    sec_dict_t *sec = get_section(cfg, "global");
    if(NULL != sec)
    {
        char *val = get_value(sec, "LOG_FILE_LEVEL");
        if(NULL != val)
            printf("LOG_FILE_LEVEL:%s\n", val);
        else
            printf("get LOG_FILE_LEVEL failed.\n");


        val = get_value(sec, "LOG_TREM_LEVEL");
        if(NULL != val)
            printf("LOG_TREM_LEVEL:%s\n", val);
        else
            printf("get LOG_TREM_LEVEL failed.\n");

        val = get_value(sec, "LOG_PATH");
        if(NULL != val)
            printf("LOG_PATH:%s\n", val);
        else
            printf("get LOG_PATH failed.\n");

    }

    sec = get_section(cfg, "backend");
    if(NULL != sec)
    {
        char* val = get_value(sec, "FILE_COUNT");
        if(NULL != val)
            printf("FILE_COUNT:%s\n", val);
        else
            printf("get FILE_COUNT failed.\n");

        val = get_value(sec, "USER_ID");
        if(NULL != val)
            printf("USER_ID:%s\n", val);
        else
            printf("get USER_ID failed.\n");


        val = get_value(sec, "SID");
        if(NULL != val)
            printf("SID:%s\n", val);
        else
            printf("get SID failed.\n");


       val = get_value(sec, "NOT_FOUND");
       if(NULL != val)
           printf("NOT_FOUND:%s\n", val);
       else
           printf("NOT_FOUND is NOT_FOUND.\n");



    }

    sec = get_section(cfg, "NO_SUCH_SEC");
    if(NULL != sec)
    {
        printf("get a NO_SUCH_SEC.\n");
    }
    else
    {
        printf("NO_SUCH_SEC is NO_SUCH_SEC.\n");
    }

    cfg_destroy(cfg);

    return 0;
}
