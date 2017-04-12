#include <polarssl/config.h>

#ifdef POLARSSL_BIGNUM_C

#include <polarssl/x509_crt.h>
#include <polarssl/x509_crl.h>
#include <polarssl/pem.h>
#include <polarssl/oid.h>

int verify_none( void *data, x509_crt *crt, int certificate_depth, int *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags |= BADCERT_OTHER;

    return 0;
}

int verify_all( void *data, x509_crt *crt, int certificate_depth, int *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags = 0;

    return 0;
}

#endif /* POLARSSL_BIGNUM_C */


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

#ifdef POLARSSL_BIGNUM_C

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

#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_INVALID_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, " 1" ) == 0 )
    {
        *value = (  1 );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, " 1" ) == 0 )
    {
        *value = (  1 );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_CERT_VERIFY_FAILED" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_CERT_VERIFY_FAILED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_SIG_ALG + POLARSSL_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG + POLARSSL_ERR_OID_NOT_FOUND );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_SIG_ALG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( BADCRL_EXPIRED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCRL_EXPIRED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_VERSION );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_UNKNOWN_VERSION );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCRL_EXPIRED | BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCRL_EXPIRED | BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_NAME + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_ALG + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_SIG_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_SIG_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_SIG_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_SIG_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_KEY_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED | BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_REVOKED | BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_INVALID_LENGTH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_OTHER" ) == 0 )
    {
        *value = ( BADCERT_OTHER );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( BADCERT_CN_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_INVALID_PUBKEY" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_INVALID_PUBKEY );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_CN_MISMATCH + BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( BADCERT_CN_MISMATCH + BADCERT_NOT_TRUSTED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_EXTENSIONS + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_PK_UNKNOWN_PK_ALG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_PK_UNKNOWN_PK_ALG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ASN1_INVALID_LENGTH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_INVALID_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_INVALID_LENGTH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SIGNATURE + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA " ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_SERIAL + POLARSSL_ERR_ASN1_OUT_OF_DATA  );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_DATE + POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( BADCERT_NOT_TRUSTED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "BADCERT_REVOKED" ) == 0 )
    {
        *value = ( BADCERT_REVOKED );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
#endif // POLARSSL_X509_CRT_PARSE_C
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_OUT_OF_DATA );
        return( 0 );
    }
#endif // POLARSSL_X509_CRL_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_FORMAT + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRT_PARSE_C
    if( strcmp( str, "POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( POLARSSL_ERR_X509_INVALID_VERSION + POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
        return( 0 );
    }
#endif // POLARSSL_X509_CRT_PARSE_C


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_cert_info( char *crt_file, char *result_str )
{
    x509_crt   crt;
    char buf[2000];
    int res;

    x509_crt_init( &crt );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    res = x509_crt_info( buf, 2000, "", &crt );

    x509_crt_free( &crt );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509_crl_info( char *crl_file, char *result_str )
{
    x509_crl   crl;
    char buf[2000];
    int res;

    x509_crl_init( &crl );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crl_parse_file( &crl, crl_file ) == 0 );
    res = x509_crl_info( buf, 2000, "", &crl );

    x509_crl_free( &crl );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509_verify( char *crt_file, char *ca_file, char *crl_file,
                  char *cn_name_str, int result, int flags_result,
                  char *verify_callback )
{
    x509_crt   crt;
    x509_crt   ca;
    x509_crl    crl;
    int         flags = 0;
    int         res;
    int (*f_vrfy)(void *, x509_crt *, int, int *) = NULL;
    char *      cn_name = NULL;

    x509_crt_init( &crt );
    x509_crt_init( &ca );
    x509_crl_init( &crl );

    if( strcmp( cn_name_str, "NULL" ) != 0 )
        cn_name = cn_name_str;

    if( strcmp( verify_callback, "NULL" ) == 0 )
        f_vrfy = NULL;
    else if( strcmp( verify_callback, "verify_none" ) == 0 )
        f_vrfy = verify_none;
    else if( strcmp( verify_callback, "verify_all" ) == 0 )
        f_vrfy = verify_all;
    else
        TEST_ASSERT( "No known verify callback selected" == 0 );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    TEST_ASSERT( x509_crt_parse_file( &ca, ca_file ) == 0 );
    TEST_ASSERT( x509_crl_parse_file( &crl, crl_file ) == 0 );

    res = x509_crt_verify( &crt, &ca, &crl, cn_name, &flags, f_vrfy, NULL );

    x509_crt_free( &crt );
    x509_crt_free( &ca );
    x509_crl_free( &crl );

    TEST_ASSERT( res == ( result ) );
    TEST_ASSERT( flags == ( flags_result ) );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_USE_C
void test_suite_x509_dn_gets( char *crt_file, char *entity, char *result_str )
{
    x509_crt   crt;
    char buf[2000];
    int res = 0;

    x509_crt_init( &crt );
    memset( buf, 0, 2000 );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );
    if( strcmp( entity, "subject" ) == 0 )
        res =  x509_dn_gets( buf, 2000, &crt.subject );
    else if( strcmp( entity, "issuer" ) == 0 )
        res =  x509_dn_gets( buf, 2000, &crt.issuer );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

    x509_crt_free( &crt );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_USE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_USE_C
void test_suite_x509_time_expired( char *crt_file, char *entity, int result )
{
    x509_crt   crt;

    x509_crt_init( &crt );

    TEST_ASSERT( x509_crt_parse_file( &crt, crt_file ) == 0 );

    if( strcmp( entity, "valid_from" ) == 0 )
        TEST_ASSERT( x509_time_expired( &crt.valid_from ) == result );
    else if( strcmp( entity, "valid_to" ) == 0 )
        TEST_ASSERT( x509_time_expired( &crt.valid_to ) == result );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

    x509_crt_free( &crt );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_USE_C */

#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509parse_crt( char *crt_data, char *result_str, int result )
{
    x509_crt   crt;
    unsigned char buf[2000];
    unsigned char output[2000];
    int data_len, res;

    x509_crt_init( &crt );
    memset( buf, 0, 2000 );
    memset( output, 0, 2000 );

    data_len = unhexify( buf, crt_data );

    TEST_ASSERT( x509_crt_parse( &crt, buf, data_len ) == ( result ) );
    if( ( result ) == 0 )
    {
        res = x509_crt_info( (char *) output, 2000, "", &crt );

        TEST_ASSERT( res != -1 );
        TEST_ASSERT( res != -2 );

        TEST_ASSERT( strcmp( (char *) output, result_str ) == 0 );
    }

    x509_crt_free( &crt );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_X509_CRL_PARSE_C
void test_suite_x509parse_crl( char *crl_data, char *result_str, int result )
{
    x509_crl   crl;
    unsigned char buf[2000];
    unsigned char output[2000];
    int data_len, res;

    x509_crl_init( &crl );
    memset( buf, 0, 2000 );
    memset( output, 0, 2000 );

    data_len = unhexify( buf, crl_data );

    TEST_ASSERT( x509_crl_parse( &crl, buf, data_len ) == ( result ) );
    if( ( result ) == 0 )
    {
        res = x509_crl_info( (char *) output, 2000, "", &crl );

        TEST_ASSERT( res != -1 );
        TEST_ASSERT( res != -2 );

        TEST_ASSERT( strcmp( (char *) output, result_str ) == 0 );
    }

    x509_crl_free( &crl );
}
#endif /* POLARSSL_X509_CRL_PARSE_C */

#ifdef POLARSSL_FS_IO
#ifdef POLARSSL_X509_CRT_PARSE_C
void test_suite_x509_crt_parse_path( char *crt_path, int ret, int nb_crt )
{
    x509_crt chain, *cur;
    int i;

    x509_crt_init( &chain );

    TEST_ASSERT( x509_crt_parse_path( &chain, crt_path ) == ret );

    /* Check how many certs we got */
    for( i = 0, cur = &chain; cur != NULL; cur = cur->next )
        if( cur->raw.p != NULL )
            i++;

    TEST_ASSERT( i == nb_crt );

    x509_crt_free( &chain );
}
#endif /* POLARSSL_FS_IO */
#endif /* POLARSSL_X509_CRT_PARSE_C */

#ifdef POLARSSL_X509_CRT_PARSE_C
#ifdef POLARSSL_SELF_TEST
void test_suite_x509_selftest()
{
    TEST_ASSERT( x509_self_test( 0 ) == 0 );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */
#endif /* POLARSSL_SELF_TEST */


#endif /* POLARSSL_BIGNUM_C */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_PKCS1_V15" ) == 0 )
    {
#if defined(POLARSSL_PKCS1_V15)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SHA1_C" ) == 0 )
    {
#if defined(POLARSSL_SHA1_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_RSA_C" ) == 0 )
    {
#if defined(POLARSSL_RSA_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3" ) == 0 )
    {
#if defined(POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_MD4_C" ) == 0 )
    {
#if defined(POLARSSL_MD4_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECDSA_C" ) == 0 )
    {
#if defined(POLARSSL_ECDSA_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP384R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP256R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_PEM_PARSE_C" ) == 0 )
    {
#if defined(POLARSSL_PEM_PARSE_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SHA256_C" ) == 0 )
    {
#if defined(POLARSSL_SHA256_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_MD5_C" ) == 0 )
    {
#if defined(POLARSSL_MD5_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP192R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SHA512_C" ) == 0 )
    {
#if defined(POLARSSL_SHA512_C)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_C" ) == 0 )
    {
#if defined(POLARSSL_ECP_C)
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
    if( strcmp( params[0], "x509_cert_info" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_x509_cert_info( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crl_info" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_x509_crl_info( param1, param2 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_verify" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        int param5;
        int param6;
        char *param7 = params[7];

        if( cnt != 8 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );

        test_suite_x509_verify( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_dn_gets" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );

        test_suite_x509_dn_gets( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_USE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_time_expired" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_time_expired( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_USE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509parse_crt" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509parse_crt( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509parse_crl" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509parse_crl( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_X509_CRL_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_crt_parse_path" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO
    #ifdef POLARSSL_X509_CRT_PARSE_C

        char *param1 = params[1];
        int param2;
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_x509_crt_parse_path( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */
    #endif /* POLARSSL_X509_CRT_PARSE_C */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "x509_selftest" ) == 0 )
    {
    #ifdef POLARSSL_X509_CRT_PARSE_C
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_x509_selftest(  );
        return ( 0 );
    #endif /* POLARSSL_X509_CRT_PARSE_C */
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
    const char *filename = "suites/test_suite_x509parse.data";
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


