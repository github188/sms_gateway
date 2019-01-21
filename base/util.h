#ifndef __TSBASE_UTIL_H__
#define __TSBASE_UTIL_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*the path can only contains a~z/A~Z/0~9/_  */
int is_valid_path_character(const char* str);

int64_t htonl64(int64_t host64);

int64_t ntohl64(int64_t net64);


#ifdef __cplusplus
}
#endif


#endif

