#include "gateway_crypt.h"

// 将十六进制字符串转化为十进制字符串
void to_decimal_str(const char* src, int src_len, char* dest, int& dest_len) 
{
    int src_index, dest_index;
    char left = '\0', right = '\0';
    
    for ( src_index = 0, dest_index = 0; src_index < src_len; src_index += 2 ) {

        if ( '0' <= src[src_index]   && src[src_index]   <= '9' ) left  = src[src_index]   - '0';
        if ( 'A' <= src[src_index]   && src[src_index]   <= 'Z' ) left  = src[src_index]   - 'A' + 10;
        if ( '0' <= src[src_index+1] && src[src_index+1] <= '9' ) right = src[src_index+1] - '0';
        if ( 'A' <= src[src_index+1] && src[src_index+1] <= 'Z' ) right = src[src_index+1] - 'A' + 10;

        dest[dest_index++] = left * 16 + right;
    }
    dest_len = dest_index;

    return ;
}

int my_compute_md5(const char* buf,int buf_len,char* md5, int md5_len)
{
    if( md5 == NULL || md5_len < 32 ) return -1;
    unsigned char MD5result[16] = {0};
    MD5((const unsigned char*)buf,buf_len,MD5result);
    for (int i = 0; i < 16; i++)
    {
        snprintf(md5 + i*2, md5_len -1, "%02x", MD5result[i]);
    }
    return 0;
}

