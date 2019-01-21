#ifndef __SIM_UTIL_H__
#define __SIM_UTIL_H__

#include <sim_struct.h>


uint64_t htonl64(uint64_t host);
uint64_t ntohl64(uint64_t host);

void SetBufferString(char *&ptr, const char *pValue, size_t length);
void SetBufferByte(char *&ptr, const unsigned char *pValue, size_t length);
void SetBufferZero(char *&ptr, size_t length);
void SetBufferChar(char *&ptr, const unsigned char value);
void SetBufferShort(char *&ptr, const unsigned short value);
void SetBufferLong(char *&ptr, const unsigned int value);
void SetBufferLongLong(char *&ptr, const uint64_t value);

bool GetBufferWString(char *&ptr, unsigned short *pValue, size_t length);
bool GetBufferString(char *&ptr, char *pValue, size_t length);
bool GetBufferByte(char *&ptr, unsigned char *pValue, size_t length);
bool GetBufferChar(char *&ptr, unsigned char &value);
bool GetBufferShort(char *&ptr, unsigned short &value);
bool GetBufferLong(char *&ptr, unsigned int &value);
bool GetBufferLongLong(char *&ptr, uint64_t &value);

//MMDDHHMMSS，即月日时分秒，10位
int get_datetime(char* buf, int size);

#endif
