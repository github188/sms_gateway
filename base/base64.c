#include "base64.h"

int base64_encode(unsigned char *src,int srclen,unsigned char *dst,int *dstlen)
{
	if(*dstlen < 2*srclen)
		return -1;
	int i;
	unsigned char t=0;
	unsigned char *p = dst;
    unsigned char *s = src;

	for ( i = 0; i < srclen; i++ )
	{
		switch ( i % 3 )
		{
		case 0 :
			*p++ = base_2_chr( *s >> 2 );
			t = ( *s++ << 4 ) & 0x3F;
			break;
		case 1 :
			*p++ = base_2_chr( t | ( *s >> 4 ) );
			t = ( *s++ << 2 ) & 0x3F;
			break;
		case 2 :
			*p++ = base_2_chr( t | ( *s>> 6 ) );
			*p++ = base_2_chr( *s++ );
			break;
		}
	}
	if ( srclen % 3 != 0 )
	{
		*p++ = base_2_chr( t );
		if ( srclen % 3 == 1 )
			*p++ = '=';
			*p++ = '=';
	}
	*p = 0;  //  aDest is an ASCIIZ string
	*dstlen = p - dst;
	return 0;  //  exclude the end of zero
	
}

int base64_decode(unsigned char *src,int srclen,unsigned char *dst, int *dstlen)
{
	if(*dstlen<srclen + 2)
		return -1;
    unsigned char *s = src;
	unsigned char *p = dst;
	int  i, n = srclen;
	unsigned char   c=0, t=0;
	
	for ( i = 0; i < n; i++ )
	{
		if ( *s == '=' )
			break;
		do 
		{
			if ( *s )
			c = chr_2_base( *s++ );
			else
			c = 65;  
		} while ( c == 64 );  
		if ( c == 65 )
			break;
		switch ( i % 4 )
		{
		case 0 :
			t = c << 2;
			break;
		case 1 :
			*p++ = ( unsigned char )( t | ( c >> 4 ) );
			t = ( unsigned char )( c << 4 );
			break;
		case 2 :
			*p++ = ( unsigned char )( t | ( c >> 2 ) );
			t = ( unsigned char )( c << 6 );
			break;
		case 3 :
			*p++ = ( unsigned char )( t | c );
			break;
		}
	}
	*dstlen = p - dst;
    	return 0;
	
}

//  Base64 code table
//  0-63 : A-Z(25) a-z(51), 0-9(61), +(62), /(63)
char  base_2_chr( unsigned char n )
{
    n &= 0x3F;
    if ( n < 26 )
        return ( char )( n + 'A' );
    else if ( n < 52 )
        return ( char )( n - 26 + 'a' );
    else if ( n < 62 )
        return ( char )( n - 52 + '0' );
    else if ( n == 62 )
        return '+';
    else
        return '/';
}

unsigned char chr_2_base( char c )
{
    if ( c >= 'A' && c <= 'Z' )
        return ( unsigned char )( c - 'A' );
    else if ( c >= 'a' && c <= 'z' )
        return ( unsigned char )( c - 'a' + 26 );
    else if ( c >= '0' && c <= '9' )
        return ( unsigned char )( c - '0' + 52 );
    else if ( c == '+' )
        return 62;
    else if ( c == '/' )
        return 63;
    else
        return 64; 
}

