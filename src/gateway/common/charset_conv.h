#ifndef __CHARSET_CONV_H__
#define __CHARSET_CONV_H__

#include <string>

int utf8_to_ascii(std::string utf8, std::string& ascii);
int ascii_to_utf8(std::string ascii, std::string& utf8);

#endif