#include "gateway_util.h"
#include "public.h"
#include <iconv.h>

int parse_str_list(const char *str, char list[32][32])
{
    if(str == NULL)
    {
        printf("[E] parse_str_list null param.\n");
        return -1;   
    }
    
    char c;
    char c_black = ' ';
    int blank_char = 1;
    int i = 0;
    int name_idx = 0;
    int item_count = 0;
    char item_name[32];

    while( (c = str[i]) != '\0')
    {
        if ( (c_black == c)  && (!blank_char))
        {
            blank_char = 1;
            item_name[name_idx] = '\0';
            strcpy(list[item_count], item_name);
            name_idx = 0;
            ++item_count;
        }
        else
        {
            if (blank_char)
            {
                if (item_count == 32)
                {
                    return -1;
                }
                blank_char = 0;
            }
            if (32 - 1 <= name_idx)
            {
                return -1;
            }
            item_name[name_idx] = c;
            ++name_idx;
        }
        ++i;
    }
    if (!blank_char)
    {
        item_name[name_idx] = '\0';
        strcpy(list[item_count], item_name);
        ++item_count;
    }
    return item_count;
}

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

int get_date_time(char* buf, int size)
{
    if ( buf == NULL || size <= 14 )
    {
        return -1;
    }
    time_t t;
    struct tm ts;
    time(&t);
    localtime_r(&t, &ts);

    int ret = snprintf(buf, size, "%04d%02d%02d%02d%02d%02d",
                                ts.tm_year + 1900,
                                ts.tm_mon + 1, 
                                ts.tm_mday,
                                ts.tm_hour,
                                ts.tm_min,
                                ts.tm_sec);                           
    buf[ret] = 0;
    return 0;
}

std::string MakeDateTime()
{
    time_t t;
    struct tm ts;
    time(&t);
    localtime_r(&t, &ts);

    char sDateTime[20]={0};
    int ret = snprintf(sDateTime, sizeof(sDateTime), "%04d-%02d-%02d %02d:%02d:%02d",
                                ts.tm_year + 1900,
                                ts.tm_mon + 1,
                                ts.tm_mday,
                                ts.tm_hour,
                                ts.tm_min,
                                ts.tm_sec);
    sDateTime[ret] = 0;
    return std::string(sDateTime);
}

unsigned int GetUtf8TextLength(std::string sTextContent)
{
    if (sTextContent.empty())       return 0;

    unsigned int uResultLength = 0;
    for (std::string::iterator itStr = sTextContent.begin(); itStr != sTextContent.end();)
    {
        char cUtf8 = *itStr;
        if (((cUtf8 >> 3) & 0x1E) == 0x1E)
        {
            ++itStr; cUtf8 = *itStr;
            if (((cUtf8 >> 6) & 0x02) != 0x02) continue;
            ++itStr; cUtf8 = *itStr;
            if (((cUtf8 >> 6) & 0x02) != 0x02) continue;
            ++itStr; cUtf8 = *itStr;
            if (((cUtf8 >> 6) & 0x02) != 0x02) continue;
            ++itStr; uResultLength++; uResultLength++;
        }
        else if (((cUtf8 >> 4) & 0x0E) == 0x0E)
        {
            ++itStr; cUtf8 = *itStr;
            if (((cUtf8 >> 6) & 0x02) != 0x02) continue;
            ++itStr; cUtf8 = *itStr;
            if (((cUtf8 >> 6) & 0x02) != 0x02) continue;
            ++itStr; uResultLength++;
        }
        else if (((cUtf8 >> 5) & 0x06) == 0x06)
        {
            ++itStr; cUtf8 = *itStr;
            if (((cUtf8 >> 6) & 0x02) != 0x02) continue;
            ++itStr; uResultLength++;
        }
        else if ((cUtf8 >> 7) == 0x00)
        {
            ++itStr; uResultLength++;
        }
        else
        {
            ++itStr; continue;
        }
    }
    return uResultLength;
}

unsigned int GetSmsCount(std::string sMessageContent)
{
    if (sMessageContent.empty())        return 0;

    unsigned int uResult = 1;
    unsigned int uTextLen = GetUtf8TextLength(sMessageContent);
    if (uTextLen > 70)
    {
        unsigned int uLastLen = uTextLen % 67;
        if (uLastLen == 0)
            uResult = uTextLen / 67;
        else
            uResult = uTextLen / 67 + 1;
    }
    return uResult;
}

bool TransCodeToUnicodeLE(unsigned short *wText, unsigned int &wSize, std::string text)
{
    // UTF-8 -> UCS-2
    unsigned short *p = wText;
    for (std::string::iterator itStr = text.begin(); itStr != text.end();)
    {
        unsigned short cUtf8 = (unsigned short)(*itStr);
        if (((cUtf8 >> 3) & 0x1E) == 0x1E)
        {
            ++itStr; cUtf8 = (unsigned short)(*itStr);
            if (((cUtf8 >> 6) & 0x02) == 0x02) { ++itStr; cUtf8 = (unsigned short)(*itStr); }
            if (((cUtf8 >> 6) & 0x02) == 0x02) { ++itStr; cUtf8 = (unsigned short)(*itStr); }
            if (((cUtf8 >> 6) & 0x02) == 0x02) { ++itStr; cUtf8 = (unsigned short)(*itStr); }
            *p = 0x25A1; ++p; *p = 0x25A1; ++p;
        }
        else if (((cUtf8 >> 4) & 0x0E) == 0x0E)
        {
            *p = (cUtf8 & 0x0F) << 12; ++itStr; cUtf8 = (unsigned short)(*itStr);
            if (((cUtf8 >> 6) & 0x02) == 0x02) { *p |= (cUtf8 & 0x3F) << 6; ++itStr; cUtf8 = (unsigned short)(*itStr); }
            if (((cUtf8 >> 6) & 0x02) == 0x02) { *p |= (cUtf8 & 0x3F); ++p; ++itStr; }
        }
        else if (((cUtf8 >> 5) & 0x06) == 0x06)
        {
            *p = (cUtf8 & 0x1F) << 6; ++itStr; cUtf8 = (unsigned short)(*itStr);
            if (((cUtf8 >> 6) & 0x02) == 0x02) { *p |= (cUtf8 & 0x3F); ++p; ++itStr; }
        }
        else if ((cUtf8 >> 7) == 0x00)
        {
            *p = (cUtf8 & 0x7F); ++p; ++itStr;
        }
        else
        {
            ++itStr; continue;
        }
    }
    wSize = p - wText;
    return true;
}

bool TransCodeToUnicodeBE(unsigned short *wText, unsigned int &wSize, std::string text)
{
    if (!TransCodeToUnicodeLE(wText,wSize,text))
        return false;
    // convert LE to BE
    for (unsigned int index=0; index<wSize; index++)
        wText[index] = htons(wText[index]);

    return true;
}

bool TransCodeFromUnicodeLE(std::string &text,unsigned short *wText, unsigned int wSize)
{
    // UCS2 -> UTF-8
    for (unsigned int szIndex = 0; szIndex < wSize; szIndex++)
    {
        unsigned short wUcs2 = wText[szIndex];
        if (wUcs2 <= 0x007F)
        {
            char cUtf8 = wUcs2 & 0x7F;
            text.append(&cUtf8, sizeof(char));
        }
        else if (wUcs2 <= 0x07FF)
        {
            char cUtf8 = (wUcs2 >> 6) | 0xC0;
            text.append(&cUtf8, sizeof(char));
            cUtf8 = (wUcs2 & 0x3F) | 0x80;
            text.append(&cUtf8, sizeof(char));
        }
        else if (wUcs2 <= 0xFFFF)
        {
            char cUtf8 = (wUcs2 >> 12) | 0xE0;
            text.append(&cUtf8, sizeof(char));
            cUtf8 = ((wUcs2 >> 6) & 0x3F) | 0x80;
            text.append(&cUtf8, sizeof(char));
            cUtf8 = (wUcs2 & 0x3F) | 0x80;
            text.append(&cUtf8, sizeof(char));
        }
    }

    return true;
}

bool TransCodeFromUnicodeBE(std::string &text,unsigned short *wText, unsigned int wSize)
{
    // convert BE to LE
    for (unsigned int index=0; index<wSize; index++)
        wText[index] = ntohs(wText[index]);

    if (!TransCodeFromUnicodeLE(text,wText,wSize))
        return false;
        
    return true;
}


std::string http_get_field(const char *haystack, const char *needle)
{
    std::string s1;
    char field_with_equal[128] = {0};
    snprintf(field_with_equal, sizeof (field_with_equal), "%s=", needle);

    const char *pos0 = strstr(haystack, field_with_equal);
    if (pos0 == NULL) 
    {
        LOG_ERROR("Cannot Found %s\n", field_with_equal);
        return "";
    }

    const char *pos1 = strstr(pos0 + strlen(field_with_equal), "&");
    if (pos1 == NULL)
    {
        s1.assign(pos0 + strlen(field_with_equal), strlen(pos0) - strlen(field_with_equal));
    }
    else
    {
        s1.assign(pos0 + strlen(field_with_equal), strlen(pos0) - strlen(pos1) - strlen(field_with_equal));
    }

    return s1;
}


int hex_pair_value(const char * code)
{
    int value = 0;
    const char * pch = code;
    for (;;)
    {
        int digit = *pch++;
        if (digit >= '0' && digit <= '9')
        {
            value += digit - '0';
        }
        else if (digit >= 'A' && digit <= 'F')
        {
            value += digit - 'A' + 10;
        }
        else if (digit >= 'a' && digit <= 'f')
        {
            value += digit - 'a' + 10;
        }
        else
        {
            return -1;
        }
        if (pch == code + 2)
        {
            return value;
        }
        value <<= 4;
    }
    return 0;
}

int url_decode(const char *source, char *dest)
{
    char * start = dest;
    while (*source)
    {
        switch (*source)
        {
        case '+':
            *(dest++) = ' ';
            break;
        case '%':
            if (source[1] && source[2])
            {
                int value = hex_pair_value(source + 1);
                if (value >= 0)
                {
                    *(dest++) = value;
                    source += 2;
                }
                else
                {
                    *dest++ = '?';
                }
            }
            else
            {
                *dest++ = '?';
            }
            break;
        default:
            *dest++ = *source;
            break;
        }
        source++;
    }
    *dest = 0;
    return dest - start;
}

int url_encode(const char *source, char *dest, unsigned max)
{
    static const char *digits = "0123456789ABCDEF";
    unsigned char ch;
    unsigned len = 0;
    char *start = dest;

    while (len < max - 4 && *source)
    {
        ch = (unsigned char)*source;
        if (*source == ' ')
        {
            *dest++ = '+';
        }
        else if (isalnum(ch) || strchr("-_.!~*'()", ch))
        {
            *dest++ = *source;
        }
        else
        {
            *dest++ = '%';
            *dest++ = digits[(ch >> 4) & 0x0F];
            *dest++ = digits[       ch & 0x0F];
        }
        source++;
    }
    *dest = 0;
    return start - dest;
}


int parse_http_hdr(const char* buf, int size, int req_flag,
		char* bodybuf, int& bodylen)
{
	const char* pos_head = strstr(buf, "\r\n\r\n") + strlen("\r\n\r\n");
	int hdr_len = pos_head - buf;

	if(req_flag) 
    {
	    if(strstr(buf, "POST") == NULL || strstr(buf, "GET"))
        {
	        LOG_ERROR("not post/get packet.\n");
	        return -1;
	    }
	}
    else
    {
        if(strstr(buf, "HTTP/1.1 200 OK\r\n") == NULL) 
        {
            LOG_ERROR("HTTP Error:\n%s\n", buf);
            return -1;
        }
    }

    const char* pos_conn = strstr(buf, "Keep-Alive");
    if( pos_conn == NULL  )
    {
        memcpy(bodybuf, buf + hdr_len, size - hdr_len);
		bodylen = size - hdr_len;
        return 0;
    }

	const char* pos_tmp = strstr(buf, "Content-Length:");
	if(pos_tmp != NULL) 
    {
		memcpy(bodybuf, buf + hdr_len, size - hdr_len);
		bodylen = size - hdr_len;
		return 0;
	}
	pos_tmp = strstr(buf, "Transfer-Encoding: chunked");
	if(pos_tmp != NULL) 
    {
		int ret = parse_http_chunked_data(buf + hdr_len, size - hdr_len, bodybuf, bodylen);
		if(ret <= 0) 
        {
			LOG_ERROR("parse_http_chunked_data failed\n");
			return -1;
		}
		return 0;
	}

	LOG_ERROR("unknown transfer len.\n");

	return -1;
}

int parse_http_chunked_data(const char* buf, int size,
		char* bodybuf, int& bodylen)
{
	const char *occurrence = NULL;
	const char *haystack = buf;
	const char *needle = "\r\n";
	int needle_len = strlen(needle);

	int outlen = 0;
	int cntlen = 0;
	do {
		occurrence = strstr(haystack, needle);
		if (occurrence != NULL && occurrence + needle_len - buf <= size) 
        {
			char hex_str[128] = { 0 };
			int dec_num = 0;
			strncpy(hex_str, haystack, occurrence - haystack);
			sscanf(hex_str, "%x", &dec_num);
			if (dec_num == 0) 
            {
				// complete
				outlen = (int) (occurrence + 2*needle_len - buf);
				LOG_DEBUG("chunked finish, len = %d\n", outlen);
				break;
			}
			if (bodybuf) 
            {
				if (cntlen + dec_num >= bodylen) 
                {
					LOG_ERROR("parse_http_chunked_data outbuf too small.\n");
					return -1;
				}
				memcpy(bodybuf + cntlen, occurrence + needle_len, dec_num);
				cntlen += dec_num;
			}
			haystack = occurrence + needle_len + dec_num + needle_len;
		} 
        else 
        {
			// not complete
			outlen = 0;
			break;
		}
	} while (1);

	if(outlen > 0) 
    {
		// complete
		if(bodybuf) 
        {
			bodylen = cntlen;
		}
	}
	return outlen;
}

int insert_wait_cache(dict* wq, http_wait_cache_t& wi)
{
    char* d_key = (char*) alloc_key(wq, sizeof(wi.sid));
    http_wait_cache_t* d_val = (http_wait_cache_t*) alloc_val(wq, sizeof(wi));

    memcpy(d_key, wi.sid, sizeof(wi.sid));
    memcpy(d_val, &wi, sizeof(wi));

    d_val->uptime = get_utc_miliseconds();

    int ret = DICT_OK;

    ret = dict_add(wq, d_key, sizeof(wi.sid),
            d_val, sizeof(http_wait_cache_t*));

    if (ret != DICT_OK) 
    {
        LOG_ERROR("dict_add 1 failed.\n");
    }

    return ret;
}

http_wait_cache_t* get_wait_cache(dict* wq, const char* sid)
{
    if(sid == NULL)
    {
        return NULL;
    }

    int len = strlen(sid);
    if(len >= MAX_SID_LEN)
    {
        return NULL;
    }

    char thesid[MAX_SID_LEN] = {0};
    strcpy(thesid, sid);

    return (http_wait_cache_t*)dict_fetch_value(wq, sid, sizeof(thesid));
}

int delete_wait_cache(dict* wq, const char* sid)
{
    int ret = DICT_OK;
    http_wait_cache_t* the_wi = NULL;
    the_wi = get_wait_cache(wq, sid);
    if(the_wi != NULL)
    {
        ret = dict_delete(wq, the_wi->sid, sizeof(the_wi->sid));
        if (ret != DICT_OK) 
        {
            LOG_ERROR("dict_delete failed.\n");
        }
    }
    return ret;
}

void SplitString(std::vector<std::string> &vStrItem, std::string sStrText, std::string sStrDelim)
{
    if (sStrText.empty() || sStrDelim.empty())      return;
    std::string sAddedStr;
    size_t pos = sStrText.find(sStrDelim);
    while (pos != std::string::npos)
    {
        sAddedStr = sStrText.substr(0, pos);
        if (!sAddedStr.empty())
            vStrItem.push_back(sAddedStr);
        sStrText.erase(sStrText.begin(), sStrText.begin() + pos + sStrDelim.length());
        pos = sStrText.find(sStrDelim);
    }
    sAddedStr = sStrText;
    if (!sAddedStr.empty())
        vStrItem.push_back(sAddedStr);
}
