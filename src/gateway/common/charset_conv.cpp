#include "charset_conv.h"
#include "public.h"
#include <iconv.h>

#define MAX_CONV_LEN   1024

static int _my_convert(const char* fromcode, const char* tocode,
        std::string from, std::string& to)
{
    iconv_t ic = iconv_open(tocode, fromcode);

    if(ic == (iconv_t)-1 ) 
    {
        return -1;
    }

    char src[MAX_CONV_LEN] = {0};
    char dest[MAX_CONV_LEN] = {0};

    strcpy(src, from.c_str());

    char* tmp_src = src;
    char* tmp_dest = dest;

    size_t len_src = from.length();
    size_t len_dest = MAX_CONV_LEN;
    
    size_t ret = iconv(ic, &tmp_src, &len_src, &tmp_dest, &len_dest);
    if( ret == (size_t)-1) 
    {
        iconv_close(ic);
        return -1;
    }

    iconv_close(ic);
    to.clear();
    to = dest;

    return 0;
}

int utf8_to_ascii(std::string utf8, std::string& ascii)
{
    int len = utf8.length();

    if (len <=0 || len >= MAX_CONV_LEN)
    {
        return -1;
    }

    return _my_convert("utf-8", "GBK", utf8, ascii);
}

int ascii_to_utf8(std::string ascii, std::string& utf8)
{
    int len = ascii.length();

    if (len <=0 || len >= MAX_CONV_LEN)
    {
        return -1;
    }
    
    return _my_convert("GBK", "utf-8", ascii, utf8);
}
