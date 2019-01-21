
#include <math.h>
#include <stdlib.h>

#include "ts_enc_helper.h"
#include "cipher.h"
#include "base64.h"
#include <stdio.h>
//#include "tsbase.h"


static int ts_get_db_key(char* out, int* outlen);

int ts_db_enc(const char* in, int inlen, char* out, int* outlen)
{
    if(*outlen < inlen + 16)
    {
        return -1;
    }

    char key[32];
    int keylen = sizeof(key);

    const cipher_info_t* cipher = cipher_info_from_type(CAYMAN_CIPHER_DES_CBC);
    if(cipher == NULL)
    {
        return -1;
    }

    int ret = 0;

    cipher_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    ret = cipher_init_ctx(&ctx, cipher);
    if(ret != 0)
    {
        return -1;
    }

    if(ts_get_db_key(key, &keylen) != 0)
    {
        return -1;
    }

    const char*p = (const char*)key;
    if(cipher_setkey(&ctx, (const unsigned char*)p, keylen, CAYMAN_ENCRYPT) != 0)
    {
        return -1;
    }

    int enclen = cipher_get_block_size(&ctx) * (1 + inlen / cipher_get_block_size(&ctx));
    if(enclen <= 0)
    {
        return -1;
    }

    size_t middle_len = inlen + 8;
    unsigned char* middle = (unsigned char*)malloc(middle_len);
    if(middle == NULL)
    {
        return -1;
    }
    do{

        if(cipher_update(&ctx, (unsigned char*)in, (unsigned int)inlen, middle, &middle_len) != 0)
        {
            ret = -1;
            break;
        }

        if(cipher_finish(&ctx, middle + middle_len, &middle_len) != 0)
        {
            ret = -1;
            break;
        }

        if(base64_encode(middle, enclen, (unsigned char *)out, outlen) < 0)
        {
            ret = -1;
            break;
        }
        ret = 0;

    }while(0);

    free(middle);

    return ret;
}


int ts_db_dec(const char* in, int inlen, char* out, int* outlen)
{
    if(*outlen < inlen + 16)
    {
        return -1;
    }

    int baselen = inlen + 8;
    unsigned char* baseout = (unsigned char*)malloc(baselen);
    if(baseout == NULL)
    {
        return -1;
    }

    int ret = 0;

    do
    {
        if(base64_decode((unsigned char*)in, inlen, baseout, &baselen) < 0)
        {
            ret = -1;
            break;
        }

        char key[32];
        int keylen = sizeof(key);

        const cipher_info_t* cipher = cipher_info_from_type(CAYMAN_CIPHER_DES_CBC);
        if(cipher == NULL)
        {
            ret = -1;
            break;
        }

        int ret = 0;

        cipher_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));

        ret = cipher_init_ctx(&ctx, cipher);
        if(ret != 0)
        {
            ret = -1;
            break;
        }

        if(ts_get_db_key(key, &keylen) != 0)
        {
            ret = -1;
            break;
        }

        const char*p = (const char*)key;
        if(cipher_setkey(&ctx, (const unsigned char*)p, keylen, CAYMAN_DECRYPT) != 0)
        {
            ret = -1;
            break;
        }

        int enclen = cipher_get_block_size(&ctx) * (1 + baselen / cipher_get_block_size(&ctx));
        if(enclen <= 0)
        {
            ret = -1;
            break;
        }

        size_t middle_len = 0;

        if(cipher_update(&ctx, (unsigned char*)baseout, (unsigned int)baselen, (unsigned char*)out, &middle_len) != 0)
        {
            ret = -1;
            break;
        }

        if(cipher_finish(&ctx, (unsigned char*)out + middle_len, &middle_len) != 0)
        {
            ret = -1;
            break;
        }

        int datalen = baselen - cipher_get_block_size (&ctx) + middle_len;
        out[datalen] = '\0';

        *outlen = datalen;

        ret = 0;

    }while(0);

    free(baseout);

    return ret;
}


static int ts_get_db_key(char* out, int* outlen)
{
    if(*outlen < 32)
        return -1;

    double r = 17.0;
    double s = sqrt(r);

    snprintf(out, *outlen, "%.22f", s);

    *outlen = strlen(out);

    return 0;
}


