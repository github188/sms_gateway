#include "sim_util.h"


uint64_t htonl64(uint64_t host)
{
	static int big_endian = -1;
    if ( big_endian == -1 )
    {
        uint16_t magic = 0x0102;
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
    uint64_t ret = host;
	if(big_endian == 0)
    {
		uint32_t high,low;
		low = host & 0xFFFFFFFF;
		high = (host & 0xFFFFFFFF00000000) >> 32;
		low = htonl(low);
		high = htonl(high);
		ret = ( (uint64_t)low << 32 ) | high;
	}
    return ret;
}

uint64_t ntohl64(uint64_t host)
{
	static int big_endian = -1;
    if ( big_endian == -1 )
    {
        uint16_t magic = 0x0102;
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
    uint64_t ret = host;
	if(big_endian == 0)
    {
		uint32_t high,low;
		low = host & 0xFFFFFFFF;
		high = (host & 0xFFFFFFFF00000000) >> 32;
		low = ntohl(low);
		high = ntohl(high);
		ret = ( (uint64_t)low << 32 ) | high;
	}
    return ret;
}

void SetBufferString(char *&ptr, const char *pValue, size_t length)
{
    if (!ptr || !pValue)        return ;

    size_t len = length;
    memcpy(ptr, pValue, len);
    ptr += len;
}

void SetBufferByte(char *&ptr, const unsigned char *pValue, size_t length)
{
    if (!ptr || !pValue)        return ;

    size_t len = length;
    memcpy(ptr, pValue, len);
    ptr += len;
}

void SetBufferZero(char *&ptr, size_t length)
{
    if (!ptr || length==0)       return ;

    memset(ptr, 0x0, length);
    ptr += length;
}

void SetBufferChar(char *&ptr, unsigned char value)
{
    if (!ptr)       return ;

    memcpy(ptr, &value, 1);
    ptr ++;
}

void SetBufferShort(char *&ptr, unsigned short value)
{
    if (!ptr)       return ;
    size_t len = sizeof(unsigned short);
    unsigned short temp = htons(value);
    memcpy(ptr, &temp, len);
    ptr += len;
}

void SetBufferLong(char *&ptr, unsigned int value)
{
    if (!ptr)       return ;
    size_t len = sizeof(unsigned int);
    unsigned int temp = htonl(value);
    memcpy(ptr, &temp, len);
    ptr += len;
}

void SetBufferLongLong(char *&ptr, uint64_t value)
{
    if (!ptr)       return ;
    size_t len = sizeof(uint64_t);
    uint64_t temp = htonl64(value);
    memcpy(ptr, &temp, len);
    ptr += len;
}

bool GetBufferWString(char *&ptr, unsigned short *pValue, size_t length)
{
    if (!ptr || !pValue)    return false;
    
    size_t len = length;
    memcpy(pValue, ptr, len);
    pValue[len] = 0x0;
    ptr += len;
    return true;
}

bool GetBufferString(char *&ptr, char *pValue, size_t length)
{
    if (!ptr || !pValue)    return false;

    size_t len = length - 1;
    memcpy(pValue, ptr, len);
    pValue[len] = 0x0;
    ptr += len;
    return true;
}

bool GetBufferByte(char *&ptr, unsigned char *pValue, size_t length)
{
    if (!ptr || !pValue)    return false;

    size_t len = length;
    memcpy(pValue, ptr, len);
    ptr += len;
    return true;
}

bool GetBufferChar(char *&ptr, unsigned char &value)
{
    if (!ptr)       return false;

    memcpy(&value, ptr, 1);
    ptr ++;
    return true;
}

bool GetBufferShort(char *&ptr, unsigned short &value)
{
    if (!ptr)       return false;

    size_t len = sizeof(unsigned short);
    unsigned short temp = 0;
    memcpy(&temp, ptr, len);
    value = ntohs(temp);
    ptr += len;

    return true;
}

bool GetBufferLong(char *&ptr, unsigned int &value)
{
    if (!ptr)       return false;

    size_t len = sizeof(unsigned int);
    unsigned int temp = 0;
    memcpy(&temp, ptr, len);
    value = ntohl(temp);
    ptr += len;

    return true;
}

bool GetBufferLongLong(char *&ptr, uint64_t &value)
{
    if (!ptr)       return false;

    size_t len = sizeof(uint64_t);
    uint64_t temp = 0;
    memcpy(&temp, ptr, len);
    value = ntohl64(temp);
    ptr += len;

    return true;
}

int get_datetime(char* buf, int size)
{
    if ( buf == NULL || size <= 10 ) 
    {
        return -1;
    }
    time_t t;
    struct tm ts;
    time(&t);
    localtime_r(&t, &ts);

    int ret = snprintf(buf, size, "%02d%02d%02d%02d%02d",
                                ts.tm_mon + 1, 
                                ts.tm_mday,
                                ts.tm_hour,
                                ts.tm_min,
                                ts.tm_sec);                           
    buf[ret] = 0;
    return 0;
}
