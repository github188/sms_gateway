#include <stdio.h>
#include "base64.h"

struct sr_s
{
    int a;
    int b;
    int c;
};

typedef sr_s sr_t;

int main()
{
//    char before[128] = {0};
    sr_t aaa;

    aaa.a = 100;
    aaa.b = 200;
    aaa.c = 300;
    int srclen = sizeof(aaa);

    //int srclen = snprintf(before, sizeof(before), "%s%d%d%s", "aaaaaaaaaa", 1000000, 9999999, "bbbbbbbbbbbb");
    

    char dest[256] = {0};
    int dlen = sizeof(dest);
    base64_encode((unsigned char*)&aaa, srclen, (unsigned char*)dest, &dlen);

    printf("srclen = %d dest:%s dlen:%d\n", srclen, dest, dlen);
    
    char decode[256] = {0};
    int decodelen = sizeof(decode);

    base64_decode((unsigned char*)dest, dlen, (unsigned char*)decode, &decodelen);

    sr_t *bbb = (sr_t*)decode;

    printf("a = %d b = %d c = %d\n", bbb->a, bbb->b, bbb->c);


    return 0;
}
