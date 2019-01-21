#include "cayman_config.h"


#include "cipher.h"
#include "cipher_wrap.h"

#include <stdlib.h>

#if defined _MSC_VER && !defined strcasecmp
#define strcasecmp _stricmp
#endif

static const int supported_ciphers[] = {

#if defined(CAYMAN_AES_C)
        CAYMAN_CIPHER_AES_128_CBC,
        CAYMAN_CIPHER_AES_192_CBC,
        CAYMAN_CIPHER_AES_256_CBC,

#if defined(CAYMAN_CIPHER_MODE_CFB)
        CAYMAN_CIPHER_AES_128_CFB128,
        CAYMAN_CIPHER_AES_192_CFB128,
        CAYMAN_CIPHER_AES_256_CFB128,
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
        CAYMAN_CIPHER_AES_128_CTR,
        CAYMAN_CIPHER_AES_192_CTR,
        CAYMAN_CIPHER_AES_256_CTR,
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */

#endif /* defined(CAYMAN_AES_C) */

#if defined(CAYMAN_CAMELLIA_C)
        CAYMAN_CIPHER_CAMELLIA_128_CBC,
        CAYMAN_CIPHER_CAMELLIA_192_CBC,
        CAYMAN_CIPHER_CAMELLIA_256_CBC,

#if defined(CAYMAN_CIPHER_MODE_CFB)
        CAYMAN_CIPHER_CAMELLIA_128_CFB128,
        CAYMAN_CIPHER_CAMELLIA_192_CFB128,
        CAYMAN_CIPHER_CAMELLIA_256_CFB128,
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
        CAYMAN_CIPHER_CAMELLIA_128_CTR,
        CAYMAN_CIPHER_CAMELLIA_192_CTR,
        CAYMAN_CIPHER_CAMELLIA_256_CTR,
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */

#endif /* defined(CAYMAN_CAMELLIA_C) */

#if defined(CAYMAN_DES_C)
        CAYMAN_CIPHER_DES_CBC,
        CAYMAN_CIPHER_DES_EDE_CBC,
        CAYMAN_CIPHER_DES_EDE3_CBC,
#endif /* defined(CAYMAN_DES_C) */

#if defined(CAYMAN_BLOWFISH_C)
        CAYMAN_CIPHER_BLOWFISH_CBC,

#if defined(CAYMAN_CIPHER_MODE_CFB)
        CAYMAN_CIPHER_BLOWFISH_CFB64,
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
        CAYMAN_CIPHER_BLOWFISH_CTR,
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */

#endif /* defined(CAYMAN_BLOWFISH_C) */

#if defined(CAYMAN_CIPHER_NULL_CIPHER)
        CAYMAN_CIPHER_NULL,
#endif /* defined(CAYMAN_CIPHER_NULL_CIPHER) */

        0
};

const int *cipher_list( void )
{
    return supported_ciphers;
}

const cipher_info_t *cipher_info_from_type( const cipher_type_t cipher_type )
{
    /* Find static cipher information */
    switch ( cipher_type )
    {
#if defined(CAYMAN_AES_C)
        case CAYMAN_CIPHER_AES_128_CBC:
            return &aes_128_cbc_info;
        case CAYMAN_CIPHER_AES_192_CBC:
            return &aes_192_cbc_info;
        case CAYMAN_CIPHER_AES_256_CBC:
            return &aes_256_cbc_info;

#if defined(CAYMAN_CIPHER_MODE_CFB)
        case CAYMAN_CIPHER_AES_128_CFB128:
            return &aes_128_cfb128_info;
        case CAYMAN_CIPHER_AES_192_CFB128:
            return &aes_192_cfb128_info;
        case CAYMAN_CIPHER_AES_256_CFB128:
            return &aes_256_cfb128_info;
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
        case CAYMAN_CIPHER_AES_128_CTR:
            return &aes_128_ctr_info;
        case CAYMAN_CIPHER_AES_192_CTR:
            return &aes_192_ctr_info;
        case CAYMAN_CIPHER_AES_256_CTR:
            return &aes_256_ctr_info;
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */

#endif

#if defined(CAYMAN_CAMELLIA_C)
        case CAYMAN_CIPHER_CAMELLIA_128_CBC:
            return &camellia_128_cbc_info;
        case CAYMAN_CIPHER_CAMELLIA_192_CBC:
            return &camellia_192_cbc_info;
        case CAYMAN_CIPHER_CAMELLIA_256_CBC:
            return &camellia_256_cbc_info;

#if defined(CAYMAN_CIPHER_MODE_CFB)
        case CAYMAN_CIPHER_CAMELLIA_128_CFB128:
            return &camellia_128_cfb128_info;
        case CAYMAN_CIPHER_CAMELLIA_192_CFB128:
            return &camellia_192_cfb128_info;
        case CAYMAN_CIPHER_CAMELLIA_256_CFB128:
            return &camellia_256_cfb128_info;
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
        case CAYMAN_CIPHER_CAMELLIA_128_CTR:
            return &camellia_128_ctr_info;
        case CAYMAN_CIPHER_CAMELLIA_192_CTR:
            return &camellia_192_ctr_info;
        case CAYMAN_CIPHER_CAMELLIA_256_CTR:
            return &camellia_256_ctr_info;
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */

#endif

#if defined(CAYMAN_DES_C)
        case CAYMAN_CIPHER_DES_CBC:
            return &des_cbc_info;
        case CAYMAN_CIPHER_DES_EDE_CBC:
            return &des_ede_cbc_info;
        case CAYMAN_CIPHER_DES_EDE3_CBC:
            return &des_ede3_cbc_info;
#endif

#if defined(CAYMAN_BLOWFISH_C)
        case CAYMAN_CIPHER_BLOWFISH_CBC:
            return &blowfish_cbc_info;

#if defined(CAYMAN_CIPHER_MODE_CFB)
        case CAYMAN_CIPHER_BLOWFISH_CFB64:
            return &blowfish_cfb64_info;
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
        case CAYMAN_CIPHER_BLOWFISH_CTR:
            return &blowfish_ctr_info;
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */

#endif

#if defined(CAYMAN_CIPHER_NULL_CIPHER)
        case CAYMAN_CIPHER_NULL:
            return &null_cipher_info;
#endif /* defined(CAYMAN_CIPHER_NULL_CIPHER) */

        default:
            return NULL;
    }
}

const cipher_info_t *cipher_info_from_string( const char *cipher_name )
{
    if( NULL == cipher_name )
        return NULL;

    /* Get the appropriate cipher information */
#if defined(CAYMAN_CAMELLIA_C)
    if( !strcasecmp( "CAMELLIA-128-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_128_CBC );
    if( !strcasecmp( "CAMELLIA-192-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_192_CBC );
    if( !strcasecmp( "CAMELLIA-256-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_256_CBC );

#if defined(CAYMAN_CIPHER_MODE_CFB)
    if( !strcasecmp( "CAMELLIA-128-CFB128", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_128_CFB128 );
    if( !strcasecmp( "CAMELLIA-192-CFB128", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_192_CFB128 );
    if( !strcasecmp( "CAMELLIA-256-CFB128", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_256_CFB128 );
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
    if( !strcasecmp( "CAMELLIA-128-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_128_CTR );
    if( !strcasecmp( "CAMELLIA-192-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_192_CTR );
    if( !strcasecmp( "CAMELLIA-256-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_CAMELLIA_256_CTR );
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */
#endif

#if defined(CAYMAN_AES_C)
    if( !strcasecmp( "AES-128-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_128_CBC );
    if( !strcasecmp( "AES-192-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_192_CBC );
    if( !strcasecmp( "AES-256-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_256_CBC );

#if defined(CAYMAN_CIPHER_MODE_CFB)
    if( !strcasecmp( "AES-128-CFB128", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_128_CFB128 );
    if( !strcasecmp( "AES-192-CFB128", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_192_CFB128 );
    if( !strcasecmp( "AES-256-CFB128", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_256_CFB128 );
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
    if( !strcasecmp( "AES-128-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_128_CTR );
    if( !strcasecmp( "AES-192-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_192_CTR );
    if( !strcasecmp( "AES-256-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_AES_256_CTR );
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */
#endif

#if defined(CAYMAN_DES_C)
    if( !strcasecmp( "DES-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_DES_CBC );
    if( !strcasecmp( "DES-EDE-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_DES_EDE_CBC );
    if( !strcasecmp( "DES-EDE3-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_DES_EDE3_CBC );
#endif

#if defined(CAYMAN_BLOWFISH_C)
    if( !strcasecmp( "BLOWFISH-CBC", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_BLOWFISH_CBC );

#if defined(CAYMAN_CIPHER_MODE_CFB)
    if( !strcasecmp( "BLOWFISH-CFB64", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_BLOWFISH_CFB64 );
#endif /* defined(CAYMAN_CIPHER_MODE_CFB) */

#if defined(CAYMAN_CIPHER_MODE_CTR)
    if( !strcasecmp( "BLOWFISH-CTR", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_BLOWFISH_CTR );
#endif /* defined(CAYMAN_CIPHER_MODE_CTR) */
#endif

#if defined(CAYMAN_CIPHER_NULL_CIPHER)
    if( !strcasecmp( "NULL", cipher_name ) )
        return cipher_info_from_type( CAYMAN_CIPHER_NULL );
#endif /* defined(CAYMAN_CIPHER_NULL_CIPHER) */

    return NULL;
}

int cipher_init_ctx( cipher_context_t *ctx, const cipher_info_t *cipher_info )
{
    if( NULL == cipher_info || NULL == ctx )
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;

    memset( ctx, 0, sizeof( cipher_context_t ) );

    if( NULL == ( ctx->cipher_ctx = cipher_info->base->ctx_alloc_func() ) )
        return CAYMAN_ERR_CIPHER_ALLOC_FAILED;

    ctx->cipher_info = cipher_info;

    return 0;
}

int cipher_free_ctx( cipher_context_t *ctx )
{
    if( ctx == NULL || ctx->cipher_info == NULL )
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;

    ctx->cipher_info->base->ctx_free_func( ctx->cipher_ctx );

    return 0;
}

int cipher_setkey( cipher_context_t *ctx, const unsigned char *key,
        int key_length, const operation_t operation )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;

    ctx->key_length = key_length;
    ctx->operation = operation;

#if defined(CAYMAN_CIPHER_NULL_CIPHER)
    if( ctx->cipher_info->mode == CAYMAN_MODE_NULL )
        return 0;
#endif /* defined(CAYMAN_CIPHER_NULL_CIPHER) */

    /*
     * For CFB and CTR mode always use the encryption key schedule
     */
    if( CAYMAN_ENCRYPT == operation ||
        CAYMAN_MODE_CFB == ctx->cipher_info->mode ||
        CAYMAN_MODE_CTR == ctx->cipher_info->mode )
    {
        return ctx->cipher_info->base->setkey_enc_func( ctx->cipher_ctx, key,
                ctx->key_length );
    }

    if( CAYMAN_DECRYPT == operation )
        return ctx->cipher_info->base->setkey_dec_func( ctx->cipher_ctx, key,
                ctx->key_length );

    return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;
}

int cipher_reset( cipher_context_t *ctx, const unsigned char *iv )
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == iv )
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;

    ctx->unprocessed_len = 0;

    memcpy( ctx->iv, iv, cipher_get_iv_size( ctx ) );

    return 0;
}

int cipher_update( cipher_context_t *ctx, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen )
{
    int ret;
    size_t copy_len = 0;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen ||
        input == output )
    {
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *olen = 0;

#if defined(CAYMAN_CIPHER_NULL_CIPHER)
    if( ctx->cipher_info->mode == CAYMAN_MODE_NULL )
    {
        memcpy( output, input, ilen );
        *olen = ilen;
        return 0;
    }
#endif /* defined(CAYMAN_CIPHER_NULL_CIPHER) */

    if( ctx->cipher_info->mode == CAYMAN_MODE_CBC )
    {
        /*
         * If there is not enough data for a full block, cache it.
         */
        if( ( ctx->operation == CAYMAN_DECRYPT &&
                ilen + ctx->unprocessed_len <= cipher_get_block_size( ctx ) ) ||
             ( ctx->operation == CAYMAN_ENCRYPT &&
                ilen + ctx->unprocessed_len < cipher_get_block_size( ctx ) ) )
        {
            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    ilen );

            ctx->unprocessed_len += ilen;
            return 0;
        }

        /*
         * Process cached data first
         */
        if( ctx->unprocessed_len != 0 )
        {
            copy_len = cipher_get_block_size( ctx ) - ctx->unprocessed_len;

            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    copy_len );

            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, cipher_get_block_size( ctx ), ctx->iv,
                    ctx->unprocessed_data, output ) ) )
            {
                return ret;
            }

            *olen += cipher_get_block_size( ctx );
            output += cipher_get_block_size( ctx );
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }

        /*
         * Cache final, incomplete block
         */
        if( 0 != ilen )
        {
            copy_len = ilen % cipher_get_block_size( ctx );
            if( copy_len == 0 && ctx->operation == CAYMAN_DECRYPT )
                copy_len = cipher_get_block_size(ctx);

            memcpy( ctx->unprocessed_data, &( input[ilen - copy_len] ),
                    copy_len );

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if( ilen )
        {
            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, ilen, ctx->iv, input, output ) ) )
            {
                return ret;
            }
            *olen += ilen;
        }

        return 0;
    }

    if( ctx->cipher_info->mode == CAYMAN_MODE_CFB )
    {
        if( 0 != ( ret = ctx->cipher_info->base->cfb_func( ctx->cipher_ctx,
                ctx->operation, ilen, &ctx->unprocessed_len, ctx->iv,
                input, output ) ) )
        {
            return ret;
        }

        *olen = ilen;

        return 0;
    }

    if( ctx->cipher_info->mode == CAYMAN_MODE_CTR )
    {
        if( 0 != ( ret = ctx->cipher_info->base->ctr_func( ctx->cipher_ctx,
                ilen, &ctx->unprocessed_len, ctx->iv,
                ctx->unprocessed_data, input, output ) ) )
        {
            return ret;
        }

        *olen = ilen;

        return 0;
    }

    return CAYMAN_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

static void add_pkcs_padding( unsigned char *output, size_t output_len,
        size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    for( i = 0; i < padding_len; i++ )
        output[data_len + i] = (unsigned char) padding_len;
}

static int get_pkcs_padding( unsigned char *input, unsigned int input_len,
        size_t *data_len)
{
    unsigned int i, padding_len = 0;

    if( NULL == input || NULL == data_len )
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;

    padding_len = input[input_len - 1];

    if( padding_len > input_len )
        return CAYMAN_ERR_CIPHER_INVALID_PADDING;

    for( i = input_len - padding_len; i < input_len; i++ )
        if( input[i] != padding_len )
            return CAYMAN_ERR_CIPHER_INVALID_PADDING;

    *data_len = input_len - padding_len;

    return 0;
}

int cipher_finish( cipher_context_t *ctx, unsigned char *output, size_t *olen)
{
    int ret = 0;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen )
        return CAYMAN_ERR_CIPHER_BAD_INPUT_DATA;

    *olen = 0;

    if( CAYMAN_MODE_CFB == ctx->cipher_info->mode ||
        CAYMAN_MODE_CTR == ctx->cipher_info->mode ||
        CAYMAN_MODE_NULL == ctx->cipher_info->mode )
    {
        return 0;
    }

    if( CAYMAN_MODE_CBC == ctx->cipher_info->mode )
    {
        if( CAYMAN_ENCRYPT == ctx->operation )
        {
            add_pkcs_padding( ctx->unprocessed_data, cipher_get_iv_size( ctx ),
                    ctx->unprocessed_len );
        }
        else if ( cipher_get_block_size( ctx ) != ctx->unprocessed_len )
        {
            /* For decrypt operations, expect a full block */
            return CAYMAN_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        /* cipher block */
        if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                ctx->operation, cipher_get_block_size( ctx ), ctx->iv,
                ctx->unprocessed_data, output ) ) )
        {
            return ret;
        }

        /* Set output size for decryption */
        if( CAYMAN_DECRYPT == ctx->operation )
            return get_pkcs_padding( output, cipher_get_block_size( ctx ), olen );

        /* Set output size for encryption */
        *olen = cipher_get_block_size( ctx );
        return 0;
    }

    return CAYMAN_ERR_CIPHER_FEATURE_UNAVAILABLE;
}



