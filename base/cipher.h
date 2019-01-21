#ifndef CAYMAN_CIPHER_H
#define CAYMAN_CIPHER_H

#include <string.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#define CAYMAN_ERR_CIPHER_FEATURE_UNAVAILABLE            -0x6080  /**< The selected feature is not available. */
#define CAYMAN_ERR_CIPHER_BAD_INPUT_DATA                 -0x6100  /**< Bad input parameters to function. */
#define CAYMAN_ERR_CIPHER_ALLOC_FAILED                   -0x6180  /**< Failed to allocate memory. */
#define CAYMAN_ERR_CIPHER_INVALID_PADDING                -0x6200  /**< Input data contains invalid padding and is rejected. */
#define CAYMAN_ERR_CIPHER_FULL_BLOCK_EXPECTED            -0x6280  /**< Decryption of block requires a full block. */

typedef enum {
    CAYMAN_CIPHER_ID_NONE = 0,
    CAYMAN_CIPHER_ID_NULL,
    CAYMAN_CIPHER_ID_AES,
    CAYMAN_CIPHER_ID_DES,
    CAYMAN_CIPHER_ID_3DES,
    CAYMAN_CIPHER_ID_CAMELLIA,
    CAYMAN_CIPHER_ID_BLOWFISH,
} cipher_id_t;

typedef enum {
    CAYMAN_CIPHER_NONE = 0,
    CAYMAN_CIPHER_NULL,
    CAYMAN_CIPHER_AES_128_CBC,
    CAYMAN_CIPHER_AES_192_CBC,
    CAYMAN_CIPHER_AES_256_CBC,
    CAYMAN_CIPHER_AES_128_CFB128,
    CAYMAN_CIPHER_AES_192_CFB128,
    CAYMAN_CIPHER_AES_256_CFB128,
    CAYMAN_CIPHER_AES_128_CTR,
    CAYMAN_CIPHER_AES_192_CTR,
    CAYMAN_CIPHER_AES_256_CTR,
    CAYMAN_CIPHER_CAMELLIA_128_CBC,
    CAYMAN_CIPHER_CAMELLIA_192_CBC,
    CAYMAN_CIPHER_CAMELLIA_256_CBC,
    CAYMAN_CIPHER_CAMELLIA_128_CFB128,
    CAYMAN_CIPHER_CAMELLIA_192_CFB128,
    CAYMAN_CIPHER_CAMELLIA_256_CFB128,
    CAYMAN_CIPHER_CAMELLIA_128_CTR,
    CAYMAN_CIPHER_CAMELLIA_192_CTR,
    CAYMAN_CIPHER_CAMELLIA_256_CTR,
    CAYMAN_CIPHER_DES_CBC,
    CAYMAN_CIPHER_DES_EDE_CBC,
    CAYMAN_CIPHER_DES_EDE3_CBC,
    CAYMAN_CIPHER_BLOWFISH_CBC,
    CAYMAN_CIPHER_BLOWFISH_CFB64,
    CAYMAN_CIPHER_BLOWFISH_CTR,
} cipher_type_t;

typedef enum {
    CAYMAN_MODE_NONE = 0,
    CAYMAN_MODE_NULL,
    CAYMAN_MODE_CBC,
    CAYMAN_MODE_CFB,
    CAYMAN_MODE_OFB,
    CAYMAN_MODE_CTR,
} cipher_mode_t;

typedef enum {
    CAYMAN_OPERATION_NONE = -1,
    CAYMAN_DECRYPT = 0,
    CAYMAN_ENCRYPT,
} operation_t;

enum {
    /** Undefined key length */
    CAYMAN_KEY_LENGTH_NONE = 0,
    /** Key length, in bits (including parity), for DES keys */
    CAYMAN_KEY_LENGTH_DES  = 64,
    /** Key length, in bits (including parity), for DES in two key EDE */
    CAYMAN_KEY_LENGTH_DES_EDE = 128,
    /** Key length, in bits (including parity), for DES in three-key EDE */
    CAYMAN_KEY_LENGTH_DES_EDE3 = 192,
    /** Maximum length of any IV, in bytes */
    CAYMAN_MAX_IV_LENGTH = 16,
};

/**
 * Base cipher information. The non-mode specific functions and values.
 */
typedef struct {

    /** Base Cipher type (e.g. CAYMAN_CIPHER_ID_AES) */
    cipher_id_t cipher;

    /** Encrypt using CBC */
    int (*cbc_func)( void *ctx, operation_t mode, size_t length, unsigned char *iv,
            const unsigned char *input, unsigned char *output );

    /** Encrypt using CFB (Full length) */
    int (*cfb_func)( void *ctx, operation_t mode, size_t length, size_t *iv_off,
            unsigned char *iv, const unsigned char *input, unsigned char *output );

    /** Encrypt using CTR */
    int (*ctr_func)( void *ctx, size_t length, size_t *nc_off, unsigned char *nonce_counter,
            unsigned char *stream_block, const unsigned char *input, unsigned char *output );

    /** Set key for encryption purposes */
    int (*setkey_enc_func)( void *ctx, const unsigned char *key, unsigned int key_length);

    /** Set key for decryption purposes */
    int (*setkey_dec_func)( void *ctx, const unsigned char *key, unsigned int key_length);

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

} cipher_base_t;

/**
 * Cipher information. Allows cipher functions to be called in a generic way.
 */
typedef struct {
    /** Full cipher identifier (e.g. CAYMAN_CIPHER_AES_256_CBC) */
    cipher_type_t type;

    /** Cipher mode (e.g. CAYMAN_MODE_CBC) */
    cipher_mode_t mode;

    /** Cipher key length, in bits (default length for variable sized ciphers)
     *  (Includes parity bits for ciphers like DES) */
    unsigned int key_length;

    /** Name of the cipher */
    const char * name;

    /** IV size, in bytes */
    unsigned int iv_size;

    /** block size, in bytes */
    unsigned int block_size;

    /** Base cipher information and functions */
    const cipher_base_t *base;

} cipher_info_t;

/**
 * Generic cipher context.
 */
typedef struct {
    /** Information about the associated cipher */
    const cipher_info_t *cipher_info;

    /** Key length to use */
    int key_length;

    /** Operation that the context's key has been initialised for */
    operation_t operation;

    /** Buffer for data that hasn't been encrypted yet */
    unsigned char unprocessed_data[CAYMAN_MAX_IV_LENGTH];

    /** Number of bytes that still need processing */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode */
    unsigned char iv[CAYMAN_MAX_IV_LENGTH];

    /** Cipher-specific context */
    void *cipher_ctx;
} cipher_context_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Returns the list of ciphers supported by the generic cipher module.
 *
 * \return              a statically allocated array of ciphers, the last entry
 *                      is 0.
 */
const int *cipher_list( void );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher name.
 *
 * \param cipher_name   Name of the cipher to search for.
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_name, or NULL if not found.
 */
const cipher_info_t *cipher_info_from_string( const char *cipher_name );

/**
 * \brief               Returns the cipher information structure associated
 *                      with the given cipher type.
 *
 * \param cipher_type   Type of the cipher to search for.
 *
 * \return              the cipher information structure associated with the
 *                      given cipher_type, or NULL if not found.
 */
const cipher_info_t *cipher_info_from_type( const cipher_type_t cipher_type );

/**
 * \brief               Initialises and fills the cipher context structure with
 *                      the appropriate values.
 *
 * \param ctx           context to initialise. May not be NULL.
 * \param cipher_info   cipher to use.
 *
 * \return              \c 0 on success,
 *                      \c CAYMAN_ERR_CIPHER_BAD_INPUT_DATA on parameter failure,
 *                      \c CAYMAN_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context failed.
 */
int cipher_init_ctx( cipher_context_t *ctx, const cipher_info_t *cipher_info );

/**
 * \brief               Free the cipher-specific context of ctx. Freeing ctx
 *                      itself remains the responsibility of the caller.
 *
 * \param ctx           Free the cipher-specific context
 *
 * \returns             0 on success, CAYMAN_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails.
 */
int cipher_free_ctx( cipher_context_t *ctx );

/**
 * \brief               Returns the block size of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              size of the cipher's blocks, or 0 if ctx has not been
 *                      initialised.
 */
static inline unsigned int cipher_get_block_size( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->block_size;
}

/**
 * \brief               Returns the mode of operation for the cipher.
 *                      (e.g. CAYMAN_MODE_CBC)
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              mode of operation, or CAYMAN_MODE_NONE if ctx
 *                      has not been initialised.
 */
static inline cipher_mode_t cipher_get_cipher_mode( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return CAYMAN_MODE_NONE;

    return ctx->cipher_info->mode;
}

/**
 * \brief               Returns the size of the cipher's IV.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              size of the cipher's IV, or 0 if ctx has not been
 *                      initialised.
 */
static inline int cipher_get_iv_size( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->iv_size;
}

/**
 * \brief               Returns the type of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              type of the cipher, or CAYMAN_CIPHER_NONE if ctx has
 *                      not been initialised.
 */
static inline cipher_type_t cipher_get_type( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return CAYMAN_CIPHER_NONE;

    return ctx->cipher_info->type;
}

/**
 * \brief               Returns the name of the given cipher, as a string.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              name of the cipher, or NULL if ctx was not initialised.
 */
static inline const char *cipher_get_name( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 0;

    return ctx->cipher_info->name;
}

/**
 * \brief               Returns the key length of the cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              cipher's key length, in bits, or
 *                      CAYMAN_KEY_LENGTH_NONE if ctx has not been
 *                      initialised.
 */
static inline int cipher_get_key_size ( const cipher_context_t *ctx )
{
    if( NULL == ctx )
        return CAYMAN_KEY_LENGTH_NONE;

    return ctx->key_length;
}

/**
 * \brief               Returns the operation of the given cipher.
 *
 * \param ctx           cipher's context. Must have been initialised.
 *
 * \return              operation (CAYMAN_ENCRYPT or CAYMAN_DECRYPT),
 *                      or CAYMAN_OPERATION_NONE if ctx has not been
 *                      initialised.
 */
static inline operation_t cipher_get_operation( const cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return CAYMAN_OPERATION_NONE;

    return ctx->operation;
}

/**
 * \brief               Set the key to use with the given context.
 *
 * \param ctx           generic cipher context. May not be NULL. Must have been
 *                      initialised using cipher_context_from_type or
 *                      cipher_context_from_string.
 * \param key           The key to use.
 * \param key_length    key length to use, in bits.
 * \param operation     Operation that the key will be used for, either
 *                      CAYMAN_ENCRYPT or CAYMAN_DECRYPT.
 *
 * \returns             0 on success, CAYMAN_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails or a cipher specific
 *                      error code.
 */
int cipher_setkey( cipher_context_t *ctx, const unsigned char *key, int key_length,
        const operation_t operation );

/**
 * \brief               Reset the given context, setting the IV to iv
 *
 * \param ctx           generic cipher context
 * \param iv            IV to use or NONCE_COUNTER in the case of a CTR-mode cipher
 *
 * \returns             0 on success, CAYMAN_ERR_CIPHER_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int cipher_reset( cipher_context_t *ctx, const unsigned char *iv );

/**
 * \brief               Generic cipher update function. Encrypts/decrypts
 *                      using the given cipher context. Writes as many block
 *                      size'd blocks of data as possible to output. Any data
 *                      that cannot be written immediately will either be added
 *                      to the next block, or flushed when cipher_final is
 *                      called.
 *
 * \param ctx           generic cipher context
 * \param input         buffer holding the input data
 * \param ilen          length of the input data
 * \param output        buffer for the output data. Should be able to hold at
 *                      least ilen + block_size. Cannot be the same buffer as
 *                      input!
 * \param olen          length of the output data, will be filled with the
 *                      actual number of bytes written.
 *
 * \returns             0 on success, CAYMAN_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails,
 *                      CAYMAN_ERR_CIPHER_FEATURE_UNAVAILABLE on an
 *                      unsupported mode for a cipher or a cipher specific
 *                      error code.
 */
int cipher_update( cipher_context_t *ctx, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen );

/**
 * \brief               Generic cipher finalisation function. If data still
 *                      needs to be flushed from an incomplete block, data
 *                      contained within it will be padded with the size of
 *                      the last block, and written to the output buffer.
 *
 * \param ctx           Generic cipher context
 * \param output        buffer to write data to. Needs block_size data available.
 * \param olen          length of the data written to the output buffer.
 *
 * \returns             0 on success, CAYMAN_ERR_CIPHER_BAD_INPUT_DATA if
 *                      parameter verification fails,
 *                      CAYMAN_ERR_CIPHER_FULL_BLOCK_EXPECTED if decryption
 *                      expected a full block but was not provided one,
 *                      CAYMAN_ERR_CIPHER_INVALID_PADDING on invalid padding
 *                      while decrypting or a cipher specific error code.
 */
int cipher_finish( cipher_context_t *ctx, unsigned char *output, size_t *olen);



#ifdef __cplusplus
}
#endif

#endif /* CAYMAN_MD_H */
