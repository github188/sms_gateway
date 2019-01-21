/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 */
#ifndef CAYMAN_CONFIG_H
#define CAYMAN_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#define CAYMAN_HAVE_LONGLONG

/**
 * \def CAYMAN_HAVE_ASM
 *
 * The compiler has support for asm()
 *
 * Uncomment to enable the use of assembly code.
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      library/timing.c
 *      library/padlock.c
 *      include/polarssl/bn_mul.h
 *
 */
#define CAYMAN_HAVE_ASM

#define CAYMAN_CIPHER_MODE_CFB
#define CAYMAN_CIPHER_MODE_CTR

#define CAYMAN_ERROR_STRERROR_DUMMY

#define CAYMAN_GENPRIME

#define CAYMAN_FS_IO

#define CAYMAN_PKCS1_V21

#define CAYMAN_SELF_TEST

#define CAYMAN_SSL_ALERT_MESSAGES

#define CAYMAN_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO

/*
#define CAYMAN_AES_C

#define CAYMAN_ARC4_C

#define CAYMAN_ASN1_PARSE_C

#define CAYMAN_ASN1_WRITE_C

#define CAYMAN_BASE64_C

#define CAYMAN_BIGNUM_C

#define CAYMAN_BLOWFISH_C

#define CAYMAN_CAMELLIA_C
*/

#define CAYMAN_CERTS_C

#define CAYMAN_CIPHER_C

#define CAYMAN_CTR_DRBG_C

#define CAYMAN_DEBUG_C

#define CAYMAN_DES_C

#define CAYMAN_DHM_C

#define CAYMAN_ENTROPY_C

#define CAYMAN_ERROR_C

#define CAYMAN_GCM_C

#define CAYMAN_MD_C

#define CAYMAN_MD5_C

#define CAYMAN_NET_C

/*#define CAYMAN_PADLOCK_C*/
/*
#define CAYMAN_PEM_C

#define CAYMAN_PKCS5_C

#define CAYMAN_PKCS12_C

#define CAYMAN_RSA_C

#define CAYMAN_SHA1_C

#define CAYMAN_SHA2_C

#define CAYMAN_SHA4_C

#define CAYMAN_SSL_CACHE_C

#define CAYMAN_SSL_CLI_C

#define CAYMAN_SSL_SRV_C

#define CAYMAN_SSL_TLS_C

#define CAYMAN_TIMING_C

#define CAYMAN_VERSION_C

#define CAYMAN_X509_PARSE_C

#define CAYMAN_X509_WRITE_C

#define CAYMAN_XTEA_C

*/

#endif /* config.h */
