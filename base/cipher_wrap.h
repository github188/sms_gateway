#ifndef CAYMAN_CIPHER_WRAP_H
#define CAYMAN_CIPHER_WRAP_H

#include "cayman_config.h"
#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CAYMAN_AES_C)

extern const cipher_info_t aes_128_cbc_info;
extern const cipher_info_t aes_192_cbc_info;
extern const cipher_info_t aes_256_cbc_info;

#if defined(CAYMAN_CIPHER_MODE_CFB)
extern const cipher_info_t aes_128_cfb128_info;
extern const cipher_info_t aes_192_cfb128_info;
extern const cipher_info_t aes_256_cfb128_info;
#endif /* CAYMAN_CIPHER_MODE_CFB */

#if defined(CAYMAN_CIPHER_MODE_CTR)
extern const cipher_info_t aes_128_ctr_info;
extern const cipher_info_t aes_192_ctr_info;
extern const cipher_info_t aes_256_ctr_info;
#endif /* CAYMAN_CIPHER_MODE_CTR */

#endif /* defined(CAYMAN_AES_C) */

#if defined(CAYMAN_CAMELLIA_C)

extern const cipher_info_t camellia_128_cbc_info;
extern const cipher_info_t camellia_192_cbc_info;
extern const cipher_info_t camellia_256_cbc_info;

#if defined(CAYMAN_CIPHER_MODE_CFB)
extern const cipher_info_t camellia_128_cfb128_info;
extern const cipher_info_t camellia_192_cfb128_info;
extern const cipher_info_t camellia_256_cfb128_info;
#endif /* CAYMAN_CIPHER_MODE_CFB */

#if defined(CAYMAN_CIPHER_MODE_CTR)
extern const cipher_info_t camellia_128_ctr_info;
extern const cipher_info_t camellia_192_ctr_info;
extern const cipher_info_t camellia_256_ctr_info;
#endif /* CAYMAN_CIPHER_MODE_CTR */

#endif /* defined(CAYMAN_CAMELLIA_C) */

#if defined(CAYMAN_DES_C)

extern const cipher_info_t des_cbc_info;
extern const cipher_info_t des_ede_cbc_info;
extern const cipher_info_t des_ede3_cbc_info;

#endif /* defined(CAYMAN_DES_C) */

#if defined(CAYMAN_BLOWFISH_C)
extern const cipher_info_t blowfish_cbc_info;

#if defined(CAYMAN_CIPHER_MODE_CFB)
extern const cipher_info_t blowfish_cfb64_info;
#endif /* CAYMAN_CIPHER_MODE_CFB */

#if defined(CAYMAN_CIPHER_MODE_CTR)
extern const cipher_info_t blowfish_ctr_info;
#endif /* CAYMAN_CIPHER_MODE_CTR */
#endif /* defined(CAYMAN_BLOWFISH_C) */

#if defined(CAYMAN_CIPHER_NULL_CIPHER)
extern const cipher_info_t null_cipher_info;
#endif /* defined(CAYMAN_CIPHER_NULL_CIPHER) */

#ifdef __cplusplus
}
#endif

#endif /* CAYMAN_CIPHER_WRAP_H */
