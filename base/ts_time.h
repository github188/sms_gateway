#ifndef __TS_DATE_H__
#define __TS_DATE_H__

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

time_t get_utc_seconds();
int64_t get_utc_microseconds();
int64_t get_utc_miliseconds();


time_t get_1970_seconds();

int64_t timestap_to_utc_microseconds(struct timeval *tv);

int microseconds_to_str(int64_t microsec, char* dest, int dest_len);

#ifdef __cplusplus
}
#endif

#endif

