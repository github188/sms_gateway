#include <string.h>
#ifdef __MINGW32__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "util.h"

/*the path can only contains a~z/A~Z/0~9/_  */
int is_valid_path_character(const char* str)
{
    char* p = (char*)str;

    while(*p != '\0')
    {
        if(!((*p >= 48 && *p <= 57) || (*p >= 65 && *p <= 90) || (*p >= 97 && *p <= 122) || *p == '_'))
        {
            return -1;
        }
        p++;
    }

    return 0;
}

int64_t htonl64(int64_t host64)
{
    static int big_endian = -1;
    if ( big_endian == -1 )
    {
        int16_t magic = 0x0102;
        char magicbuf[2] = {0};
        memcpy(magicbuf, (char*)&magic, 2);

        if(magicbuf[0] == 0x01)
        {
            big_endian = 1;
        }
        else
        {
            big_endian = 0;
        }
    }

    int64_t net64 = host64;

    if(big_endian == 0)
    {
        int32_t *i1 = (int32_t*)&net64;
        int32_t *i2 = i1 + 1;

        *i1 = htonl(*i1);
        *i2 = htonl(*i2);

        int32_t i3 = *i1;
        *i1 = *i2;
        *i2 = i3;
    }

    return net64;
}


int64_t ntohl64(int64_t net64)
{
    static int big_endian = -1;
    if ( big_endian == -1 )
    {
        int16_t magic = 0x0102;
        char magicbuf[2] = {0};
        memcpy(magicbuf, (char*)&magic, 2);

        if(magicbuf[0] == 0x01)
        {
            big_endian = 1;
        }
        else
        {
            big_endian = 0;
        }
    }

    int64_t host64 = net64;
    if(big_endian == 0)
    {
        int32_t *i1 = (int32_t*)&host64;
        int32_t *i2 = i1 + 1;

        *i1 = ntohl(*i1);
        *i2 = ntohl(*i2);

        int32_t i3 = *i1;
        *i1 = *i2;
        *i2 = i3;
    }

    return host64;
}





