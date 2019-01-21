#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <time.h>
#include <stdio.h>

#include "tslimits.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    LOG_MIN_LINE = 10000,
    LOG_DEFAULT_LINE = 1000000,
    LOG_MAX_LINE = 1 << 30, /*1073741824*/
};

enum {
    LOG_MIN_CACHE_SIZE = 64 * 1024,
    LOG_DEFAULT_CACHE_SIZE = 2048 * 1024,
    LOG_MAX_CACHE_SIZE = 16 * 1024 * 1024,
};

enum {
    LOG_LEVEL_MIN = 0,
    LOG_LEVEL_ALL = 0,
    LOG_LEVEL_DEBUG = 20,
    LOG_LEVEL_INFO = 40,
    LOG_LEVEL_WARN = 60,
    LOG_LEVEL_ERROR = 80,
    LOG_LEVEL_FATAL = 100,
    LOG_LEVEL_MAX = 100
};

#define WRITE_LOG(log, le, X) \
    do{\
        if(unlikely(NULL == log || log->is_set_path == 0)) \
        { \
            warning X;\
        }else \
        { \
            if ( log->file_level <= le)\
            {\
                write_log X;\
            }\
            if ( log->term_level <= le )\
            {\
                warning X;\
            }\
        }\
    }while(0)


#define HEX_LOG(data, len)\
    do{\
        if(unlikely(NULL == g_log || g_log->is_set_path == 0))\
        {\
            write_hex_to_term(data, len);\
        }\
        else\
        {\
            write_hex_to_file(data, len);\
            write_hex_to_term(data, len);\
        }\
    }while(0)

#define XLOG_DEBUG(log, X)\
    WRITE_LOG(log, LOG_LEVEL_DEBUG, X)

#define XLOG_INFO(log, X)\
    WRITE_LOG(log, LOG_LEVEL_INFO, X)

#define XLOG_WARN(log, X)\
    WRITE_LOG(log, LOG_LEVEL_WARN, X)

#define XLOG_ERROR(log, X)\
    WRITE_LOG(log, LOG_LEVEL_ERROR, X)

#define XLOG_FATAL(log, X)\
    WRITE_LOG(log, LOG_LEVEL_FATAL, X)

#define LOG_DEBUG(...) \
        XLOG_DEBUG((g_log), ("[D] " __VA_ARGS__))

#define LOG_INFO(...)\
        XLOG_INFO((g_log), ("[I] " __VA_ARGS__))

#define LOG_WARN(...)\
        XLOG_WARN((g_log), ("[W] " __VA_ARGS__))

#define LOG_ERROR(...)\
        XLOG_ERROR((g_log), ("[E] " __VA_ARGS__))

#define LOG_FATAL(...)\
        XLOG_FATAL((g_log), ("[F] " __VA_ARGS__))

#define CHECK_IS_DEBUG()\
        unlikely(g_log && (g_log->file_level <= LOG_LEVEL_DEBUG || g_log->term_level <= LOG_LEVEL_DEBUG))

struct logger_s {
    int file_level;
    int term_level;
    int max_line;
    int cur_line;
    int is_open;
    int is_set_path;
    int file_counts;
    int cache_size;
    struct tm date;
    FILE *flog;
    char log_path[TS_MAX_PATH_LEN + 1];
    char log_head[TS_MAX_PATH_LEN + 1];
    char file_name[TS_MAX_FILENAME_LEN + 1];
    char *cache;
    int switch_interval;
    int last_switch_time;
};

typedef struct logger_s logger_t;

int init_log(const char* proc_name);

void destroy_log();

int log_open(logger_t *log);

int log_close(logger_t *log);
int log_only_close(logger_t *log);

int write_log(const char *fmt, ...);

void warning(const char *fmt, ...);

void log_flush();

/*set configurations*/
int set_log_path(const char* path);
int set_log_head(const char* head);

int set_file_level(const int level);
int set_term_level(const int level);

int set_str_file_level(const char* file_level);
int set_str_term_level(const char* term_level);


int set_max_line(const int max_line);
int set_cache_size(const int cache_size);/*in byte*/
int set_switch_interval(const int switch_interval);/*in seconds*/

void print_log_cfgs();

int write_hex_to_file(const char* data, int len);
int write_hex_to_term(const char* data, int len);


extern logger_t *g_log;

#ifdef __cplusplus
}
#endif


#endif
