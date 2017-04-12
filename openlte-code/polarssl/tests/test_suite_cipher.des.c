#include <polarssl/config.h>

#ifdef POLARSSL_CIPHER_C

#include <polarssl/cipher.h>

#if defined(POLARSSL_GCM_C)
#include <polarssl/gcm.h>
#endif
#endif /* POLARSSL_CIPHER_C */


#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#include "polarssl/memory.h"
#endif

#if defined(WANT_NOT_RND_MPI)
#if defined(POLARSSL_BIGNUM_C)
#include "polarssl/bignum.h"
#else
#error "not_rnd_mpi() need bignum.c"
#endif
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 * 
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4];

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += (((info->v1 << 4) ^ (info->v1 >> 5)) + info->v1) ^ (sum + k[sum & 3]);
            sum += delta;
            info->v1 += (((info->v0 << 4) ^ (info->v0 >> 5)) + info->v0) ^ (sum + k[(sum>>11) & 3]);
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( output, result, use_len );
        len -= use_len;
    }

    return( 0 );
}

#if defined(WANT_NOT_RND_MPI)
/**
 * NOT random function, to match test vectors.
 *
 * The following are equivalent:
 *   mpi_fill_random( x, strlen( str ) / 2, not_rnd, str );
 *   mpi_read_string( x, 16, str );
 * Warning: no other use is supported!
 */
#define ciL    (sizeof(t_uint))         /* chars in limb  */
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1) / ciL)
static int not_rnd_mpi( void *in, unsigned char *out, size_t len )
{
    char *str = (char *) in;
    mpi X;

    /*
     * The 'in' pointer we get is from an MPI prepared by mpi_fill_random(),
     * just reconstruct the rest in order to be able to call mpi_read_string()
     */
    X.s = 1;
    X.p = (t_uint *) out;
    X.n = CHARS_TO_LIMBS( len );

    /*
     * If str is too long, mpi_read_string() will try to allocate a new buffer
     * for X.p, which we want to avoid at all costs.
     */
    assert( strlen( str ) / 2 == len );

    return( mpi_read_string( &X, 16, str ) );
}
#endif /* WANT_NOT_RND_MPI */


#include <stdio.h>
#include <string.h>

static int test_errors = 0;

#ifdef POLARSSL_CIPHER_C

#define TEST_SUITE_ACTIVE

static int test_assert( int correct, const char *test )
{
    if( correct )
        return( 0 );

    test_errors++;
    if( test_errors == 1 )
        printf( "FAILED\n" );
    printf( "  %s\n", test );

    return( 1 );
}

#define TEST_ASSERT( TEST )                         \
        do { test_assert( (TEST) ? 1 : 0, #TEST );  \
             if( test_errors) return;               \
        } while (0)

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        printf( "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    (*str)++;
    (*str)[strlen( *str ) - 1] = '\0';

    return( 0 );
}

int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && str[i] == 'x' )
        {
            hex = 1;
            continue;
        }

        if( str[i] < '0' || str[i] > '9' )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    if( strcmp( str, "POLARSSL_PADDING_ONE_AND_ZEROS" ) == 0 )
    {
        *value = ( POLARSSL_PADDING_ONE_AND_ZEROS );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_PADDING_ZEROS_AND_LEN" ) == 0 )
    {
        *value = ( POLARSSL_PADDING_ZEROS_AND_LEN );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_CIPHER_DES_EDE3_CBC" ) == 0 )
    {
        *value = ( POLARSSL_CIPHER_DES_EDE3_CBC );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_CIPHER_DES_EDE_CBC" ) == 0 )
    {
        *value = ( POLARSSL_CIPHER_DES_EDE_CBC );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_PADDING_NONE" ) == 0 )
    {
        *value = ( POLARSSL_PADDING_NONE );
        return( 0 );
    }
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_CIPHER_DES_CBC" ) == 0 )
    {
        *value = ( POLARSSL_CIPHER_DES_CBC );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_PADDING_ZEROS" ) == 0 )
    {
        *value = ( POLARSSL_PADDING_ZEROS );
        return( 0 );
    }


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_enc_dec_buf( int cipher_id, char *cipher_string, int key_len,
                  int length_val, int pad_mode )
{
    size_t length = length_val, outlen, total_len, i;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char ad[13];
    unsigned char tag[16];
    unsigned char inbuf[64];
    unsigned char encbuf[64];
    unsigned char decbuf[64];

    const cipher_info_t *cipher_info;
    cipher_context_t ctx_dec;
    cipher_context_t ctx_enc;

    /*
     * Prepare contexts
     */
    memset( &ctx_dec, 0, sizeof( ctx_dec ) );
    memset( &ctx_enc, 0, sizeof( ctx_enc ) );

    memset( key, 0x2a, sizeof( key ) );

    /* Check and get info structures */
    cipher_info = cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );
    TEST_ASSERT( cipher_info_from_string( cipher_string ) == cipher_info );

    /* Initialise enc and dec contexts */
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );

    TEST_ASSERT( 0 == cipher_setkey( &ctx_dec, key, key_len, POLARSSL_DECRYPT ) );
    TEST_ASSERT( 0 == cipher_setkey( &ctx_enc, key, key_len, POLARSSL_ENCRYPT ) );

#if defined(POLARSSL_CIPHER_MODE_WITH_PADDING)
    if( -1 != pad_mode )
    {
        TEST_ASSERT( 0 == cipher_set_padding_mode( &ctx_dec, pad_mode ) );
        TEST_ASSERT( 0 == cipher_set_padding_mode( &ctx_enc, pad_mode ) );
    }
#else
    (void) pad_mode;
#endif /* POLARSSL_CIPHER_MODE_WITH_PADDING */

    /*
     * Do a few encode/decode cycles
     */
    for( i = 0; i < 3; i++ )
    {
    memset( iv , 0x00 + i, sizeof( iv ) );
    memset( ad, 0x10 + i, sizeof( ad ) );
    memset( inbuf, 0x20 + i, sizeof( inbuf ) );

    memset( encbuf, 0, sizeof( encbuf ) );
    memset( decbuf, 0, sizeof( decbuf ) );
    memset( tag, 0, sizeof( tag ) );

    TEST_ASSERT( 0 == cipher_set_iv( &ctx_dec, iv, sizeof( iv ) ) );
    TEST_ASSERT( 0 == cipher_set_iv( &ctx_enc, iv, sizeof( iv ) ) );

    TEST_ASSERT( 0 == cipher_reset( &ctx_dec ) );
    TEST_ASSERT( 0 == cipher_reset( &ctx_enc ) );

#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_update_ad( &ctx_dec, ad, sizeof( ad ) - i ) );
    TEST_ASSERT( 0 == cipher_update_ad( &ctx_enc, ad, sizeof( ad ) - i ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* encode length number of bytes from inbuf */
    TEST_ASSERT( 0 == cipher_update( &ctx_enc, inbuf, length, encbuf, &outlen ) );
    total_len = outlen;

    TEST_ASSERT( total_len == length ||
                 ( total_len % cipher_get_block_size( &ctx_enc ) == 0 &&
                   total_len < length &&
                   total_len + cipher_get_block_size( &ctx_enc ) > length ) );

    TEST_ASSERT( 0 == cipher_finish( &ctx_enc, encbuf + outlen, &outlen ) );
    total_len += outlen;

#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_write_tag( &ctx_enc, tag, sizeof( tag ) ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    TEST_ASSERT( total_len == length ||
                 ( total_len % cipher_get_block_size( &ctx_enc ) == 0 &&
                   total_len > length &&
                   total_len <= length + cipher_get_block_size( &ctx_enc ) ) );

    /* decode the previously encoded string */
    TEST_ASSERT( 0 == cipher_update( &ctx_dec, encbuf, total_len, decbuf, &outlen ) );
    total_len = outlen;

    TEST_ASSERT( total_len == length ||
                 ( total_len % cipher_get_block_size( &ctx_dec ) == 0 &&
                   total_len < length &&
                   total_len + cipher_get_block_size( &ctx_dec ) >= length ) );

    TEST_ASSERT( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
    total_len += outlen;

#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_check_tag( &ctx_dec, tag, sizeof( tag ) ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* check result */
    TEST_ASSERT( total_len == length );
    TEST_ASSERT( 0 == memcmp(inbuf, decbuf, length) );
    }

    /*
     * Done
     */
    TEST_ASSERT( 0 == cipher_free_ctx( &ctx_dec ) );
    TEST_ASSERT( 0 == cipher_free_ctx( &ctx_enc ) );
}

void test_suite_enc_fail( int cipher_id, int pad_mode, int key_len,
               int length_val, int ret )
{
    size_t length = length_val;
    unsigned char key[32];
    unsigned char iv[16];

    const cipher_info_t *cipher_info;
    cipher_context_t ctx;

    unsigned char inbuf[64];
    unsigned char encbuf[64];

    size_t outlen = 0;

    memset( key, 0, 32 );
    memset( iv , 0, 16 );

    memset( &ctx, 0, sizeof( ctx ) );

    memset( inbuf, 5, 64 );
    memset( encbuf, 0, 64 );

    /* Check and get info structures */
    cipher_info = cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );

    /* Initialise context */
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx, cipher_info ) );
    TEST_ASSERT( 0 == cipher_setkey( &ctx, key, key_len, POLARSSL_ENCRYPT ) );
#if defined(POLARSSL_CIPHER_MODE_WITH_PADDING)
    TEST_ASSERT( 0 == cipher_set_padding_mode( &ctx, pad_mode ) );
#else
    (void) pad_mode;
#endif /* POLARSSL_CIPHER_MODE_WITH_PADDING */
    TEST_ASSERT( 0 == cipher_set_iv( &ctx, iv, 16 ) );
    TEST_ASSERT( 0 == cipher_reset( &ctx ) );
#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_update_ad( &ctx, NULL, 0 ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* encode length number of bytes from inbuf */
    TEST_ASSERT( 0 == cipher_update( &ctx, inbuf, length, encbuf, &outlen ) );
    TEST_ASSERT( ret == cipher_finish( &ctx, encbuf + outlen, &outlen ) );

    /* done */
    TEST_ASSERT( 0 == cipher_free_ctx( &ctx ) );
}

void test_suite_dec_empty_buf()
{
    unsigned char key[32];
    unsigned char iv[16];

    cipher_context_t ctx_dec;
    const cipher_info_t *cipher_info;

    unsigned char encbuf[64];
    unsigned char decbuf[64];

    size_t outlen = 0;

    memset( key, 0, 32 );
    memset( iv , 0, 16 );
    
    memset( &ctx_dec, 0, sizeof( ctx_dec ) );
    
    memset( encbuf, 0, 64 );
    memset( decbuf, 0, 64 );

    /* Initialise context */
    cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
    TEST_ASSERT( NULL != cipher_info);
    
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );

    TEST_ASSERT( 0 == cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT ) );

    TEST_ASSERT( 0 == cipher_set_iv( &ctx_dec, iv, 16 ) );

    TEST_ASSERT( 0 == cipher_reset( &ctx_dec ) );

#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_update_ad( &ctx_dec, NULL, 0 ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* decode 0-byte string */
    TEST_ASSERT( 0 == cipher_update( &ctx_dec, encbuf, 0, decbuf, &outlen ) );
    TEST_ASSERT( 0 == outlen );
    TEST_ASSERT( POLARSSL_ERR_CIPHER_FULL_BLOCK_EXPECTED == cipher_finish(
                 &ctx_dec, decbuf + outlen, &outlen ) );
    TEST_ASSERT( 0 == outlen );

    TEST_ASSERT( 0 == cipher_free_ctx( &ctx_dec ) );
}

void test_suite_enc_dec_buf_multipart( int cipher_id, int key_len, int first_length_val,
                            int second_length_val )
{
    size_t first_length = first_length_val;
    size_t second_length = second_length_val;
    size_t length = first_length + second_length;
    unsigned char key[32];
    unsigned char iv[16];

    cipher_context_t ctx_dec;
    cipher_context_t ctx_enc;
    const cipher_info_t *cipher_info;

    unsigned char inbuf[64];
    unsigned char encbuf[64];
    unsigned char decbuf[64];

    size_t outlen = 0;
    size_t totaloutlen = 0;

    memset( key, 0, 32 );
    memset( iv , 0, 16 );
    
    memset( &ctx_dec, 0, sizeof( ctx_dec ) );
    memset( &ctx_enc, 0, sizeof( ctx_enc ) );
        
    memset( inbuf, 5, 64 );
    memset( encbuf, 0, 64 );
    memset( decbuf, 0, 64 );

    /* Initialise enc and dec contexts */
    cipher_info = cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info);
    
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx_dec, cipher_info ) );
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx_enc, cipher_info ) );
    
    TEST_ASSERT( 0 == cipher_setkey( &ctx_dec, key, key_len, POLARSSL_DECRYPT ) );
    TEST_ASSERT( 0 == cipher_setkey( &ctx_enc, key, key_len, POLARSSL_ENCRYPT ) );

    TEST_ASSERT( 0 == cipher_set_iv( &ctx_dec, iv, 16 ) );
    TEST_ASSERT( 0 == cipher_set_iv( &ctx_enc, iv, 16 ) );

    TEST_ASSERT( 0 == cipher_reset( &ctx_dec ) );
    TEST_ASSERT( 0 == cipher_reset( &ctx_enc ) );

#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_update_ad( &ctx_dec, NULL, 0 ) );
    TEST_ASSERT( 0 == cipher_update_ad( &ctx_enc, NULL, 0 ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* encode length number of bytes from inbuf */
    TEST_ASSERT( 0 == cipher_update( &ctx_enc, inbuf, first_length, encbuf, &outlen ) );
    totaloutlen = outlen;
    TEST_ASSERT( 0 == cipher_update( &ctx_enc, inbuf + first_length, second_length, encbuf + totaloutlen, &outlen ) );
    totaloutlen += outlen;
    TEST_ASSERT( totaloutlen == length ||
                 ( totaloutlen % cipher_get_block_size( &ctx_enc ) == 0 &&
                   totaloutlen < length &&
                   totaloutlen + cipher_get_block_size( &ctx_enc ) > length ) );

    TEST_ASSERT( 0 == cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen ) );
    totaloutlen += outlen;
    TEST_ASSERT( totaloutlen == length ||
                 ( totaloutlen % cipher_get_block_size( &ctx_enc ) == 0 &&
                   totaloutlen > length &&
                   totaloutlen <= length + cipher_get_block_size( &ctx_enc ) ) );

    /* decode the previously encoded string */
    TEST_ASSERT( 0 == cipher_update( &ctx_dec, encbuf, totaloutlen, decbuf, &outlen ) );
    totaloutlen = outlen;

    TEST_ASSERT( totaloutlen == length ||
                 ( totaloutlen % cipher_get_block_size( &ctx_dec ) == 0 &&
                   totaloutlen < length &&
                   totaloutlen + cipher_get_block_size( &ctx_dec ) >= length ) );

    TEST_ASSERT( 0 == cipher_finish( &ctx_dec, decbuf + outlen, &outlen ) );
    totaloutlen += outlen;

    TEST_ASSERT( totaloutlen == length );

    TEST_ASSERT( 0 == memcmp(inbuf, decbuf, length) );

    TEST_ASSERT( 0 == cipher_free_ctx( &ctx_dec ) );
    TEST_ASSERT( 0 == cipher_free_ctx( &ctx_enc ) );
}

void test_suite_decrypt_test_vec( int cipher_id, int pad_mode,
                       char *hex_key, char *hex_iv,
                       char *hex_cipher, char *hex_clear,
                       char *hex_ad, char *hex_tag,
                       int finish_result, int tag_result )
{
    unsigned char key[50];
    unsigned char iv[50];
    unsigned char cipher[200];
    unsigned char clear[200];
    unsigned char ad[200];
    unsigned char tag[20];
    size_t key_len, iv_len, cipher_len, clear_len;
#if defined(POLARSSL_CIPHER_MODE_AEAD)
    size_t ad_len, tag_len;
#endif
    cipher_context_t ctx;
    unsigned char output[200];
    size_t outlen, total_len;

    memset( key, 0x00, sizeof( key ) );
    memset( iv, 0x00, sizeof( iv ) );
    memset( cipher, 0x00, sizeof( cipher ) );
    memset( clear, 0x00, sizeof( clear ) );
    memset( ad, 0x00, sizeof( ad ) );
    memset( tag, 0x00, sizeof( tag ) );
    memset( output, 0x00, sizeof( output ) );

    key_len = unhexify( key, hex_key );
    iv_len = unhexify( iv, hex_iv );
    cipher_len = unhexify( cipher, hex_cipher );
    clear_len = unhexify( clear, hex_clear );
#if defined(POLARSSL_CIPHER_MODE_AEAD)
    ad_len = unhexify( ad, hex_ad );
    tag_len = unhexify( tag, hex_tag );
#else
    ((void) hex_ad);
    ((void) hex_tag);
#endif

    /* Prepare context */
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx,
                                       cipher_info_from_type( cipher_id ) ) );
    TEST_ASSERT( 0 == cipher_setkey( &ctx, key, 8 * key_len, POLARSSL_DECRYPT ) );
#if defined(POLARSSL_CIPHER_MODE_WITH_PADDING)
    if( pad_mode != -1 )
        TEST_ASSERT( 0 == cipher_set_padding_mode( &ctx, pad_mode ) );
#else
    (void) pad_mode;
#endif /* POLARSSL_CIPHER_MODE_WITH_PADDING */
    TEST_ASSERT( 0 == cipher_set_iv( &ctx, iv, iv_len ) );
    TEST_ASSERT( 0 == cipher_reset( &ctx ) );
#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( 0 == cipher_update_ad( &ctx, ad, ad_len ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* decode buffer and check tag */
    total_len = 0;
    TEST_ASSERT( 0 == cipher_update( &ctx, cipher, cipher_len, output, &outlen ) );
    total_len += outlen;
    TEST_ASSERT( finish_result == cipher_finish( &ctx, output + outlen,
                                                 &outlen ) );
    total_len += outlen;
#if defined(POLARSSL_CIPHER_MODE_AEAD)
    TEST_ASSERT( tag_result == cipher_check_tag( &ctx, tag, tag_len ) );
#endif /* POLARSSL_CIPHER_MODE_AEAD */

    /* check plaintext only if everything went fine */
    if( 0 == finish_result && 0 == tag_result )
    {
        TEST_ASSERT( total_len == clear_len );
        TEST_ASSERT( 0 == memcmp( output, clear, clear_len ) );
    }

    cipher_free_ctx( &ctx );
}

void test_suite_test_vec_ecb( int cipher_id, int operation, char *hex_key,
                   char *hex_input, char *hex_result,
                   int finish_result )
{
    unsigned char key[50];
    unsigned char input[16];
    unsigned char result[16];
    size_t key_len;
    cipher_context_t ctx;
    unsigned char output[32];
    size_t outlen;

    memset( key, 0x00, sizeof( key ) );
    memset( input, 0x00, sizeof( input ) );
    memset( result, 0x00, sizeof( result ) );
    memset( output, 0x00, sizeof( output ) );

    /* Prepare context */
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx,
                                       cipher_info_from_type( cipher_id ) ) );

    key_len = unhexify( key, hex_key );
    TEST_ASSERT( unhexify( input, hex_input ) ==
                 (int) cipher_get_block_size( &ctx ) );
    TEST_ASSERT( unhexify( result, hex_result ) ==
                 (int) cipher_get_block_size( &ctx ) );

    TEST_ASSERT( 0 == cipher_setkey( &ctx, key, 8 * key_len, operation ) );

    TEST_ASSERT( 0 == cipher_update( &ctx, input,
                                     cipher_get_block_size( &ctx ),
                                     output, &outlen ) );
    TEST_ASSERT( outlen == cipher_get_block_size( &ctx ) );
    TEST_ASSERT( finish_result == cipher_finish( &ctx, output + outlen,
                                                 &outlen ) );
    TEST_ASSERT( 0 == outlen );

    /* check plaintext only if everything went fine */
    if( 0 == finish_result )
        TEST_ASSERT( 0 == memcmp( output, result,
                                  cipher_get_block_size( &ctx ) ) );

    cipher_free_ctx( &ctx );
}

#ifdef POLARSSL_CIPHER_MODE_WITH_PADDING
void test_suite_set_padding( int cipher_id, int pad_mode, int ret )
{
    const cipher_info_t *cipher_info;
    cipher_context_t ctx;

    cipher_info = cipher_info_from_type( cipher_id );
    TEST_ASSERT( NULL != cipher_info );
    TEST_ASSERT( 0 == cipher_init_ctx( &ctx, cipher_info ) );

    TEST_ASSERT( ret == cipher_set_padding_mode( &ctx, pad_mode ) );

    TEST_ASSERT( 0 == cipher_free_ctx( &ctx ) );
}
#endif /* POLARSSL_CIPHER_MODE_WITH_PADDING */

#ifdef POLARSSL_CIPHER_MODE_CBC
void test_suite_check_padding( int pad_mode, char *input_str, int ret, int dlen_check )
{
    cipher_info_t cipher_info;
    cipher_context_t ctx;
    unsigned char input[16];
    size_t ilen, dlen;

    /* build a fake context just for getting access to get_padding */
    memset( &ctx, 0, sizeof( ctx ) );
    cipher_info.mode = POLARSSL_MODE_CBC;
    ctx.cipher_info = &cipher_info;

    TEST_ASSERT( 0 == cipher_set_padding_mode( &ctx, pad_mode ) );

    ilen = unhexify( input, input_str );

    TEST_ASSERT( ret == ctx.get_padding( input, ilen, &dlen ) );
    if( 0 == ret )
        TEST_ASSERT( dlen == (size_t) dlen_check );
}
#endif /* POLARSSL_CIPHER_MODE_CBC */

#ifdef POLARSSL_SELF_TEST
void test_suite_cipher_selftest()
{
    TEST_ASSERT( cipher_self_test( 0 ) == 0 );
}
#endif /* POLARSSL_SELF_TEST */


#endif /* POLARSSL_CIPHER_C */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_CIPHER_MODE_CBC" ) == 0 )
    {
#if defined(POLARSSL_CIPHER_MODE_CBC)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_CIPHER_PADDING_PKCS7" ) == 0 )
    {
#if defined(POLARSSL_CIPHER_PADDING_PKCS7)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_DES_C" ) == 0 )
    {
#if defined(POLARSSL_DES_C)
        return( 0 );
#else
        return( 1 );
#endif
    }


    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "enc_dec_buf" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_enc_dec_buf( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "enc_fail" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_enc_fail( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "dec_empty_buf" ) == 0 )
    {


        if( cnt != 1 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_dec_empty_buf(  );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "enc_dec_buf_multipart" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        int param4;

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );

        test_suite_enc_dec_buf_multipart( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "decrypt_test_vec" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;
        int param10;

        if( cnt != 11 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );

        test_suite_decrypt_test_vec( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "test_vec_ecb" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        int param6;

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );

        test_suite_test_vec_ecb( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "set_padding" ) == 0 )
    {
    #ifdef POLARSSL_CIPHER_MODE_WITH_PADDING

        int param1;
        int param2;
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_set_padding( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_CIPHER_MODE_WITH_PADDING */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "check_padding" ) == 0 )
    {
    #ifdef POLARSSL_CIPHER_MODE_CBC

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );

        test_suite_check_padding( param1, param2, param3, param4 );
        return ( 0 );
    #endif /* POLARSSL_CIPHER_MODE_CBC */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "cipher_selftest" ) == 0 )
    {
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_cipher_selftest(  );
        return ( 0 );
    #endif /* POLARSSL_SELF_TEST */

        return ( 3 );
    }
    else

    {
        fprintf( stdout, "FAILED\nSkipping unknown test function '%s'\n", params[0] );
        fflush( stdout );
        return( 1 );
    }
#else
    return( 3 );
#endif
    return( ret );
}

int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;

    ret = fgets( buf, len, f );
    if( ret == NULL )
        return( -1 );

    if( strlen( buf ) && buf[strlen(buf) - 1] == '\n' )
        buf[strlen(buf) - 1] = '\0';
    if( strlen( buf ) && buf[strlen(buf) - 1] == '\r' )
        buf[strlen(buf) - 1] = '\0';

    return( 0 );
}

int parse_arguments( char *buf, size_t len, char *params[50] )
{
    int cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < buf + len )
    {
        if( *p == '\\' )
        {
           *p++;
           *p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        *p++;
    }

    // Replace newlines, question marks and colons in strings
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *(p + 1) == 'n' )
            {
                p += 2;
                *(q++) = '\n';
            }
            else if( *p == '\\' && *(p + 1) == ':' )
            {
                p += 2;
                *(q++) = ':';
            }
            else if( *p == '\\' && *(p + 1) == '?' )
            {
                p += 2;
                *(q++) = '?';
            }
            else
                *(q++) = *(p++);
        }
        *q = '\0';
    }

    return( cnt );
}

int main()
{
    int ret, i, cnt, total_errors = 0, total_tests = 0, total_skipped = 0;
    const char *filename = "suites/test_suite_cipher.des.data";
    FILE *file;
    char buf[5000];
    char *params[50];

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[1000000];
    memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    file = fopen( filename, "r" );
    if( file == NULL )
    {
        fprintf( stderr, "Failed to open\n" );
        return( 1 );
    }

    while( !feof( file ) )
    {
        int skip = 0;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        fprintf( stdout, "%s%.66s", test_errors ? "\n" : "", buf );
        fprintf( stdout, " " );
        for( i = strlen( buf ) + 1; i < 67; i++ )
            fprintf( stdout, "." );
        fprintf( stdout, " " );
        fflush( stdout );

        total_tests++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        cnt = parse_arguments( buf, strlen(buf), params );

        if( strcmp( params[0], "depends_on" ) == 0 )
        {
            for( i = 1; i < cnt; i++ )
                if( dep_check( params[i] ) != 0 )
                    skip = 1;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen(buf), params );
        }

        if( skip == 0 )
        {
            test_errors = 0;
            ret = dispatch_test( cnt, params );
        }

        if( skip == 1 || ret == 3 )
        {
            total_skipped++;
            fprintf( stdout, "----\n" );
            fflush( stdout );
        }
        else if( ret == 0 && test_errors == 0 )
        {
            fprintf( stdout, "PASS\n" );
            fflush( stdout );
        }
        else if( ret == 2 )
        {
            fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
            fclose(file);
            exit( 2 );
        }
        else
            total_errors++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        if( strlen(buf) != 0 )
        {
            fprintf( stderr, "Should be empty %d\n", (int) strlen(buf) );
            return( 1 );
        }
    }
    fclose(file);

    fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        fprintf( stdout, "PASSED" );
    else
        fprintf( stdout, "FAILED" );

    fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#if defined(POLARSSL_MEMORY_DEBUG)
    memory_buffer_alloc_status();
#endif
    memory_buffer_alloc_free();
#endif

    return( total_errors != 0 );
}


