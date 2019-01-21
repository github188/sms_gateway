#ifndef __UNIQIO_UTIL_H__
#define __UNIQIO_UTIL_H__
#include <uniqio_struct.h>


gateway_info_t* get_gateway_data(dict* wq,const char *key);

int delete_gateway_data(dict* wq,const char *key);

int insert_gateway_data(dict* wq,gateway_info_t &data);

#endif
