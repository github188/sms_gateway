#ifndef __GATEWAY_CRYPT_H__
#define __GATEWAY_CRYPT_H__

#include <string>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/des.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/md5.h>


void to_decimal_str(const char* src, int src_len, char* dest, int& dest_len);

int my_compute_md5(const char* buf,int buf_len,char* md5, int md5_len);

#endif 
