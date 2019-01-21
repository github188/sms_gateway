#ifndef __GATEWAY_UTIL_H__
#define __GATEWAY_UTIL_H__
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "biz.h"

int parse_str_list(const char *str, char list[32][32]);

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

//YYYYMMDDHHMMSS，即年月日时分秒，14位
int get_date_time(char* buf, int size);

//%04d-%02d-%02d %02d:%02d:%02d
std::string MakeDateTime();

unsigned int GetUtf8TextLength(std::string sTextContent);

unsigned int GetSmsCount(std::string sMessageContent);

bool TransCodeToUnicodeLE(unsigned short *wText, unsigned int &wSize, std::string text);

bool TransCodeToUnicodeBE(unsigned short *wText, unsigned int &wSize, std::string text);

bool TransCodeFromUnicodeLE(std::string &text,unsigned short *wText, unsigned int wSize);

bool TransCodeFromUnicodeBE(std::string &text,unsigned short *wText, unsigned int wSize);

std::string http_get_field(const char *haystack, const char *needle);

int hex_pair_value(const char * code);

int url_decode(const char *source, char *dest);

int url_encode(const char *source, char *dest, unsigned max);

int parse_http_hdr(const char* buf, int size, int req_flag,
		char* bodybuf, int& bodylen);

int parse_http_chunked_data(const char* buf, int size,
		char* bodybuf, int& bodylen);

int insert_wait_cache(dict* wq, http_wait_cache_t& wi);

http_wait_cache_t* get_wait_cache(dict* wq, const char* sid);

int delete_wait_cache(dict* wq, const char* sid);

void SplitString(std::vector<std::string> &vStrItem, std::string sStrText, std::string sStrDelim);


#endif
