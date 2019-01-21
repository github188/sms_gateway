#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>

#include "logger.h"
#include "compiler.h"
#include "util.h"


#define STR_LOG_LEVEL_SIZE 8
static int stderr_noblocking = 0;

char str_log_level[][STR_LOG_LEVEL_SIZE] = 
    {
        "debug", "20",
        "info", "40",
        "warn", "60",
        "error", "80",
        "fatal", "100"
    };

logger_t *g_log = NULL;

static int path_is_ok(const char* path);
static int str_log_level_translate(const char* str_level);


#define TS_SBUFFER_LEN 1024

void warning(const char *fmt, ...)
{
    static char sbuffer[TS_SBUFFER_LEN];
    va_list argp;
    struct timeval tv;
    struct tm now;

    gettimeofday(&tv, NULL);

    localtime_r(&tv.tv_sec, &now);

    va_start(argp, fmt);
    if(unlikely(stderr_noblocking == 0))
    {
        int opts = 0;
        opts = fcntl(STDERR_FILENO, F_GETFL);
        if(opts < 0)
        {
            fprintf(stderr, "in warning fcntl get failed.\n");
        }
        else
        {
            opts = opts | O_NONBLOCK;
            if(fcntl(STDERR_FILENO, F_SETFL, opts) < 0)
            {
                fprintf(stderr, "in warning fcntl set failed.\n");
            }
            else
            {
                stderr_noblocking = 1;
            }
        }
    }

    sbuffer[0] = '\0';
    int time_len = 0;
    time_len = snprintf(sbuffer, TS_SBUFFER_LEN, "[%02d%02d%02d:%06ld]",
            now.tm_hour, now.tm_min, now.tm_sec, tv.tv_usec);

    if(unlikely(time_len < 0))
    {
        fprintf(stderr, "snprintf failed, ret = %d\n", time_len);
        return;
    }


    int varlen = vsnprintf(&sbuffer[time_len], TS_SBUFFER_LEN - time_len,  fmt, argp);
    if(unlikely(varlen < 0))
    {
        fprintf(stderr, "2.vsnprintf failed, ret = %d\n", varlen);
        return;
    }
    
    va_end(argp);

    write(STDERR_FILENO, sbuffer, time_len + varlen);
}

/*All configurations are default.*/
int init_log(const char* proc_name)
{
    if (NULL != g_log)
    {
        destroy_log();
    }

    g_log = (logger_t*) malloc(sizeof(logger_t));
    if (NULL == g_log)
    {
        warning("malloc failed.\n");
        return -1;
    }

    memset(g_log, 0, sizeof(logger_t));

    g_log->file_level = LOG_LEVEL_INFO;
    g_log->term_level = LOG_LEVEL_INFO;

    char filename[TS_MAX_FILENAME_LEN + 1] = {0};
    const char *last = rindex(proc_name, '/');
    if(NULL == last)
        strncpy(filename, proc_name, TS_MAX_FILENAME_LEN);
    else
        strncpy(filename, last + 1, TS_MAX_FILENAME_LEN);

    snprintf(g_log->log_path, TS_MAX_PATH_LEN, "/tmp");

    if(path_is_ok(g_log->log_path) < 0)
    {
        destroy_log();
        return -1;
    }

    strncpy(g_log->log_head, filename, TS_MAX_PATH_LEN);

    g_log->file_counts = 0;
    g_log->is_open = 0;
    g_log->is_set_path = 0;
    g_log->switch_interval = 24*60*60;

    g_log->max_line = LOG_DEFAULT_LINE;
    g_log->cache_size = LOG_DEFAULT_CACHE_SIZE;
    if (g_log->cache_size > 0)
    {
        g_log->cache = (char*)malloc(g_log->cache_size);
    }

    return 0;
}

void destroy_log()
{
    if (NULL == g_log)
    {
        return;
    }

    log_close(g_log);

    if (g_log->cache)
        free(g_log->cache);

    free(g_log);
    g_log = NULL;
}

int log_open(logger_t *log)
{
    if (!log)
    {
        warning("log is null\n");
        return -1;
    }
    if (log->is_open && log->flog)
    {
        warning("log is opend, file:%s\n", log->file_name);
        return 0;
    }

    char file[TS_MAX_FILENAME_LEN + 1] = { 0 };

    struct timeval tv;
    gettimeofday(&tv, NULL);

    localtime_r(&tv.tv_sec, &log->date);
    struct tm *ptm = &log->date;

    snprintf(file, TS_MAX_FILENAME_LEN, "%s_%d_%04d%02d%02d_%d.log",
             log->log_head, getpid(), ptm->tm_year + 1900, ptm->tm_mon + 1,
             ptm->tm_mday, log->file_counts);

    snprintf(log->file_name, TS_MAX_FILENAME_LEN, "%s%s%s",
             log->log_path, "/", file);
    memset(file, 0, sizeof(file));
    snprintf(file, TS_MAX_FILENAME_LEN, "%s.tmp", log->file_name);

    log->flog = fopen(file, "w");
    if (NULL == log->flog)
    {
        warning("fopen failed, file = %s err = %s\n", file, strerror(errno));
        return -1;
    }

    if (log->cache)
    {
        if (setvbuf(log->flog, log->cache, _IOFBF, log->cache_size) < 0)
        {
            LOG_WARN("setvbuf failed.\n");
        }
    }

    log->is_open = 1;
    log->file_counts++;
    log->cur_line = 0;
    log->last_switch_time = time(NULL);

    return 0;
}

int log_close(logger_t *log)
{
    if (!log || !log->is_open)
    {
        //warning("no open file.");
        return -1;
    }

    fflush(log->flog);
    fclose(log->flog);
    log->is_open = 0;

    char file[TS_MAX_FILENAME_LEN + 1] = { 0 };
    snprintf(file, TS_MAX_FILENAME_LEN, "%s.tmp", log->file_name);

    if (rename(file, log->file_name) < 0)
    {
        warning("reaname failed, %s, tmp:%s, file:%s\n", strerror(errno), file,
                log->file_name);
        return -1;
    }

    return 0;
}

int log_only_close(logger_t *log)
{
    if (!log || !log->is_open)
    {
        warning("no open file.");
        return -1;
    }

    fflush(log->flog);
    fclose(log->flog);
    log->is_open = 0;

    return 0;
}

int write_log(const char *fmt, ...)
{
    logger_t *log = g_log;

    if (!log)
    {
        warning("log param is null.\n");
        return -1;
    }

    if (!log->is_open)
    {
        if(log_open(log) < 0)
        {
            warning("log file not opened.is_open:%d\n", log->is_open);
            return -1;
        }
    }

    struct timeval tv;
    struct tm now;

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &now);
    int next_day = 0;
    if(now.tm_year != log->date.tm_year || now.tm_mon != log->date.tm_mon 
            || now.tm_mday != log->date.tm_mday)
        next_day = 1;

    if (next_day || log->cur_line >= log->max_line
        || (tv.tv_sec - log->switch_interval >= log->last_switch_time))
    {
        log_close(log);
        if(next_day)
            log->file_counts = 0;
       
        if(log_open(log) < 0)
        {
            warning("reopen log file failed, opened.is_open:%d\n", log->is_open);  
            return -1;
        }
    }

    char datebuf[64] = { 0 };
    snprintf(datebuf, sizeof(datebuf), "[%02d%02d%02d:%06ld]", now.tm_hour,
             now.tm_min, now.tm_sec, tv.tv_usec);

    fprintf(log->flog, "%s", datebuf);

    va_list argp;
    va_start(argp, fmt);
    vfprintf(log->flog, fmt, argp);
    va_end(argp);

    log->cur_line++;

    return 0;
}

int write_hex_to_file(const char* data, int len)
{
    logger_t *log = g_log; 

    if (!log)
    {
        warning("in write_hex_log, log param is null.\n");
        return -1;
    }

    if (!log->is_open)
    {
        if(log_open(log) < 0)
        {
            warning("write_hex_log log file not opened.is_open:%d\n", log->is_open);
            return -1;
        }
    }

    fprintf(log->flog, "Begin write hexadecimal log: len = %d\n", len);

    unsigned char* ptr = (unsigned char*)data;
    for(int i = 0; i < len; i++)
    {
        fprintf(log->flog, " %02X", ptr[i]);
        if((i + 1) % 16 == 0)
            fprintf(log->flog, "\n");
    }

    fprintf(log->flog, "\nEnd write hexadecimal log!\n");
    
    return 0;
}

int write_hex_to_term(const char* data, int len)
{
    fprintf(stderr, "Begin write hexadecimal log: len = %d\n", len);

    unsigned char* ptr = (unsigned char*)data;
    for(int i = 0; i < len; i++)
    {
        fprintf(stderr, " %02X", ptr[i]);
        if((i + 1) % 16 == 0)
            fprintf(stderr, "\n");
    }

    fprintf(stderr, "\nEnd write hexadecimal log!\n");
    
    return 0;
}

void log_flush()
{
    if (g_log && g_log->flog)
    {
        fflush(g_log->flog);
    }
}

int set_log_path(const char* log_path)
{
    if(unlikely(NULL == g_log || NULL == log_path))
    {
        LOG_ERROR("set_log_path, log_path is NULL!\n");
        return -1;
    }

    if(path_is_ok(log_path) < 0)
    {
        LOG_ERROR("path_is_ok failed.\n");
        return -1;
    }

    /*if the last character in the log_path is '/', discard it*/
    int len = strlen(log_path);
    if(log_path[len] == '/')
        len--;

    if(len > TS_MAX_PATH_LEN)
    {   
        LOG_ERROR("set_log_path failed, log_path too length, len = %d\n", len);
        return -1;
    }
 
    g_log->is_set_path = 1;

    if(0 == strcmp(g_log->log_path, log_path))
    {
        LOG_INFO("set_log_path, log_path and the old is the same.log_path = %s\n", log_path);
        return 0;
    }

    memset(g_log->log_path, 0, sizeof(g_log->log_path));
    strncpy(g_log->log_path, log_path, len);
    
    /*can,t rename, because the new file and the old file maybe on diffent device
     *and cross-device rename is forbidden. 
     * */
    if(g_log->is_open)
        log_close(g_log);

    return 0;
}

int set_log_head(const char* head)
{
    if(unlikely(NULL == g_log || NULL == head))
    {
        LOG_ERROR("set_log_head or pointer is NULL.\n");
        return -1;
    }   

    if(0 != is_valid_path_character(head))   
    {
        LOG_WARN("is_valid_path_character failed, str = %s\n", head);
        return -1;
    }

    if(0 == strcmp(head, g_log->log_head))
    {
        LOG_INFO("set_log_head, head and the old is equal. head = %s\n", head);
        return 0;
    }

    memset(g_log->log_head, 0, sizeof(g_log->log_head));
    strncpy(g_log->log_head, head, TS_MAX_PATH_LEN);
    
    if(g_log->is_open)
    {
        char *file_name = strrchr(g_log->file_name, '/');
        if(NULL == file_name)
        {
            LOG_ERROR("log file name error. file = %s\n", g_log->file_name);
            return -1;
        }

        char *after_head = strchr(file_name, '_');
        if(NULL == after_head)
        {
            LOG_ERROR("log file name error, file = %s\n", g_log->file_name);
            return -1;
        }   

        char new_file[TS_MAX_PATH_LEN + 1] = {0};
        int new_len = snprintf(new_file, TS_MAX_PATH_LEN, "%s/%s%s", g_log->log_path,
                g_log->log_head, after_head);

        char old_tmp_name[TS_MAX_PATH_LEN + 1] = {0};
        char new_tmp_name[TS_MAX_PATH_LEN + 1] = {0};
        snprintf(old_tmp_name, TS_MAX_PATH_LEN, "%s.tmp", g_log->file_name);
        snprintf(new_tmp_name, TS_MAX_PATH_LEN, "%s.tmp", new_file);

        rename(old_tmp_name, new_tmp_name);

        strncpy(g_log->file_name, new_file, new_len);    
    }

    return 0;
}

int set_term_level(const int level)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    if(level < LOG_LEVEL_MIN || level > LOG_LEVEL_MAX)
    {
        LOG_WARN("set_term_level failed, level = %d\n", level);
        return -1;
    }   

    g_log->term_level = level;

    return 0;
}

int set_file_level(const int level)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    if(level < LOG_LEVEL_MIN || level > LOG_LEVEL_MAX)
    {
        LOG_WARN("set_file_level failed, level = %d\n", level);
        return -1;
    }   

    g_log->file_level = level;

    return 0;
}

int set_str_file_level(const char* file_level)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    if(unlikely(NULL == file_level))
    {
        LOG_ERROR("set_str_file_level failed, file_level is NULL.\n");
        return -1;
    }

    int level = str_log_level_translate(file_level);
    if(unlikely(level < 0))
    {
        LOG_ERROR("str_log_level_translate error! level = %d\n", level);
        return -1;
    }

    g_log->file_level = level;

    return 0;
}

int set_str_term_level(const char* term_level)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    if(unlikely(NULL == term_level))
    {
        LOG_ERROR("set_str_term_level, term_level is NULL.\n");
        return -1;
    }

    int level = str_log_level_translate(term_level);
    if(unlikely(level < 0))
    {
        LOG_ERROR("str_log_level_translate error, level = %d\n", level);
        return -1;
    }

    g_log->term_level = level;

    return 0;
}

int set_max_line(const int max_line)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    if(max_line < LOG_MIN_LINE || max_line > LOG_MAX_LINE)
        g_log->max_line = LOG_DEFAULT_LINE;
    else
        g_log->max_line = max_line;

    return 0;
}

int set_cache_size(const int cache_size)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    int old_size = g_log->cache_size;
    int use_cache = g_log->cache ? 1:0;

    if(cache_size < LOG_MIN_CACHE_SIZE || cache_size > LOG_MAX_CACHE_SIZE)
        g_log->cache_size = LOG_DEFAULT_CACHE_SIZE;
    else
        g_log->cache_size = cache_size;

    if(old_size != g_log->cache_size)
    {
        log_flush();
        if(g_log->cache)
        {
            free(g_log->cache);
            g_log->cache = NULL;
        }

        g_log->cache = (char*)malloc(g_log->cache_size);
    }

    if(g_log->is_open && use_cache)
    {
        if (g_log->cache)
        {
            if (setvbuf(g_log->flog, g_log->cache, _IOFBF, g_log->cache_size) < 0)
                LOG_WARN("setvbuf failed.\n");
            else
                setvbuf(g_log->flog, (char *) NULL, _IOLBF, 0);
        }
        else
            setvbuf(g_log->flog, (char *) NULL, _IOLBF, 0);
    }
    
    return 0;
}

int set_switch_interval(const int switch_interval)
{
    if(unlikely(NULL == g_log))
    {
        return -1;
    }

    if(switch_interval < 10*60 || switch_interval > 24 * 60 * 60)
    {
        g_log->switch_interval = 24 * 60 * 60;
        return 0;
    }

    g_log->switch_interval = switch_interval;

    return 0;
}

int str_log_level_translate(const char* str_level)
{
    int size = sizeof(str_log_level) / STR_LOG_LEVEL_SIZE;

    for(int i = 0; i < size;)
    {
        if(strcmp(str_log_level[i], str_level) == 0)
        {
            return atoi(str_log_level[i + 1]);
        }

        i += 2;
    }

    return -1;
}

int path_is_ok(const char* path)
{
    if(unlikely(NULL == path))
    {
        LOG_ERROR("in path_is_ok, path is NULL.\n");
        return -1;
    }

    if(access(path, R_OK|W_OK) < 0)
    {
        if(errno == ENOENT)
            mkdir(path, 0777);

        chmod(path, 0777);
        if(access(path, W_OK) < 0)
        {
            LOG_ERROR("log path error! path = %s\n", path);
            return -1;
        }
    }

   return 0;
}

void print_log_cfgs()
{
    if(NULL == g_log)
    {
        warning("print_log_cfgs, g_log is NULL.\n");
        return ;
    }

    warning("log_path:%s\n", g_log->log_path);
    warning("log_head:%s\n", g_log->log_head);
    warning("file_level:%d\n", g_log->file_level);
    warning("term_level:%d\n", g_log->term_level);
    warning("max_line:%d\n", g_log->max_line);
    warning("cache_size:%d\n", g_log->cache_size);
    warning("file_counts:%d\n", g_log->file_counts);
}


