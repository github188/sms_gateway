#include <string.h>
#include <stdio.h>

#include "ts_time.h"

enum
{
    TS_1970_TO_1900 = 2208988800U,
};

time_t get_utc_seconds()
{
    return time(NULL) + TS_1970_TO_1900;
}

int64_t get_utc_miliseconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)((tv.tv_sec + TS_1970_TO_1900) * 1000 + tv.tv_usec / 1000);
}

int64_t get_utc_microseconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)((tv.tv_sec + TS_1970_TO_1900)* 1000000 + tv.tv_usec );
}

time_t get_1970_seconds()
{
    return time(NULL);
}

int64_t timestap_to_utc_microseconds(struct timeval *tv)
{
    if(NULL == tv)
        return -1;

    return (int64_t)((tv->tv_sec + TS_1970_TO_1900)* 1000000 + tv->tv_usec );
}

int microseconds_to_str(int64_t microsec, char* dest, int dest_len)
{
    if(dest == NULL || dest_len < 20)
        return -1;

    memset(dest, 0, dest_len);

    time_t sec = microsec / 1000000;
    sec -= TS_1970_TO_1900;
    struct tm result;
    localtime_r(&sec, &result);
    snprintf(dest, dest_len, "%04d-%02d-%02d %02d:%02d:%02d", result.tm_year + 1900, result.tm_mon + 1, 
            result.tm_mday, result.tm_hour, result.tm_min, result.tm_sec);
    
    return 0;
}

