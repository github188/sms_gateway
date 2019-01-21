#ifndef __TS_SID_H__
#define __TS_SID_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


struct ts_sid_s
{
    int64_t sid_first;
    int64_t sid_second;
};

typedef struct ts_sid_s ts_sid_t;

/*
 * when loginid is unknown, use "0" instand of.
 */
int get_sid_one(int loginid, ts_sid_t* sid);
int get_sid_two(int loginid, int64_t *sid_first, int64_t *sid_second);

int get_sid_str(int loginid, char* dest, int dest_len);

#ifdef __cplusplus
}
#endif

#endif

