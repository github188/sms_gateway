#ifndef __base64_h__
#define __base64_h__

#ifdef __cplusplus
extern "C" {
#endif

int base64_decode(unsigned char *src,int srclen,unsigned char *dst, int *dstlen);
int base64_encode(unsigned char *src,int srclen,unsigned char *dst,int *dstlen);

//  Base64 code table
//  0-63 : A-Z(25) a-z(51), 0-9(61), +(62), /(63)
char  base_2_chr( unsigned char n );

unsigned char chr_2_base( char c );

#ifdef __cplusplus
}
#endif

#endif

