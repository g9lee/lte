#include <polarssl/config.h>

#ifdef POLARSSL_PKCS1_V21
#ifdef POLARSSL_RSA_C
#ifdef POLARSSL_BIGNUM_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_GENPRIME

#include <polarssl/rsa.h>
#include <polarssl/md.h>
#include <polarssl/md2.h>
#include <polarssl/md4.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/sha256.h>
#include <polarssl/sha512.h>
#endif /* POLARSSL_PKCS1_V21 */
#endif /* POLARSSL_RSA_C */
#endif /* POLARSSL_BIGNUM_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_GENPRIME */


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

#ifdef POLARSSL_PKCS1_V21
#ifdef POLARSSL_RSA_C
#ifdef POLARSSL_BIGNUM_C
#ifdef POLARSSL_SHA1_C
#ifdef POLARSSL_GENPRIME

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

    if( strcmp( str, "POLARSSL_MD_SHA1" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_MD_SHA512" ) == 0 )
    {
        *value = ( POLARSSL_MD_SHA512 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_RSA_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
        return( 0 );
    }


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_pkcs1_rsaes_oaep_encrypt( int mod, int radix_N, char *input_N, int radix_E,
                               char *input_E, int hash,
                               char *message_hex_string, char *seed,
                               char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    unsigned char rnd_buf[1000];
    rsa_context ctx;
    size_t msg_len;
    rnd_buf_info info;

    info.length = unhexify( rnd_buf, seed );
    info.buf = rnd_buf;

    rsa_init( &ctx, RSA_PKCS_V21, hash );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    ctx.len = mod / 8 + ( ( mod % 8 ) ? 1 : 0 );
    TEST_ASSERT( mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    TEST_ASSERT( rsa_pkcs1_encrypt( &ctx, &rnd_buffer_rand, &info, RSA_PUBLIC, msg_len, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

    rsa_free( &ctx );
}

void test_suite_pkcs1_rsaes_oaep_decrypt( int mod, int radix_P, char *input_P,
                               int radix_Q, char *input_Q, int radix_N,
                               char *input_N, int radix_E, char *input_E,
                               int hash, char *result_hex_str, char *seed,
                               char *message_hex_string, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    rsa_context ctx;
    mpi P1, Q1, H, G;
    size_t output_len;
    rnd_pseudo_info rnd_info;
    ((void) seed);

    mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
    rsa_init( &ctx, RSA_PKCS_V21, hash );

    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    ctx.len = mod / 8 + ( ( mod % 8 ) ? 1 : 0 );
    TEST_ASSERT( mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
    TEST_ASSERT( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
    TEST_ASSERT( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
    TEST_ASSERT( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
    TEST_ASSERT( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );

    TEST_ASSERT( rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );

    TEST_ASSERT( rsa_pkcs1_decrypt( &ctx, &rnd_pseudo_rand, &rnd_info, RSA_PRIVATE, &output_len, message_str, output, 1000 ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strncasecmp( (char *) output_str, result_hex_str, strlen( result_hex_str ) ) == 0 );
    }

    mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
    rsa_free( &ctx );
}

void test_suite_pkcs1_rsassa_pss_sign( int mod, int radix_P, char *input_P, int radix_Q,
                            char *input_Q, int radix_N, char *input_N,
                            int radix_E, char *input_E, int digest, int hash,
                            char *message_hex_string, char *salt,
                            char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    unsigned char rnd_buf[1000];
    rsa_context ctx;
    mpi P1, Q1, H, G;
    size_t msg_len;
    rnd_buf_info info;

    info.length = unhexify( rnd_buf, salt );
    info.buf = rnd_buf;

    mpi_init( &P1 ); mpi_init( &Q1 ); mpi_init( &H ); mpi_init( &G );
    rsa_init( &ctx, RSA_PKCS_V21, hash );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    ctx.len = mod / 8 + ( ( mod % 8 ) ? 1 : 0 );
    TEST_ASSERT( mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mpi_sub_int( &P1, &ctx.P, 1 ) == 0 );
    TEST_ASSERT( mpi_sub_int( &Q1, &ctx.Q, 1 ) == 0 );
    TEST_ASSERT( mpi_mul_mpi( &H, &P1, &Q1 ) == 0 );
    TEST_ASSERT( mpi_gcd( &G, &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mpi_inv_mod( &ctx.D , &ctx.E, &H  ) == 0 );
    TEST_ASSERT( mpi_mod_mpi( &ctx.DP, &ctx.D, &P1 ) == 0 );
    TEST_ASSERT( mpi_mod_mpi( &ctx.DQ, &ctx.D, &Q1 ) == 0 );
    TEST_ASSERT( mpi_inv_mod( &ctx.QP, &ctx.Q, &ctx.P ) == 0 );

    TEST_ASSERT( rsa_check_privkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    if( md_info_from_type( digest ) != NULL )
        TEST_ASSERT( md( md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( rsa_pkcs1_sign( &ctx, &rnd_buffer_rand, &info, RSA_PRIVATE, digest, 0, hash_result, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len);

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

    mpi_free( &P1 ); mpi_free( &Q1 ); mpi_free( &H ); mpi_free( &G );
    rsa_free( &ctx );
}

void test_suite_pkcs1_rsassa_pss_verify( int mod, int radix_N, char *input_N, int radix_E,
                              char *input_E, int digest, int hash,
                              char *message_hex_string, char *salt,
                              char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    rsa_context ctx;
    size_t msg_len;
    ((void) salt);

    rsa_init( &ctx, RSA_PKCS_V21, hash );
    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    ctx.len = mod / 8 + ( ( mod % 8 ) ? 1 : 0 );
    TEST_ASSERT( mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );

    TEST_ASSERT( rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( md_info_from_type( digest ) != NULL )
        TEST_ASSERT( md( md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( rsa_pkcs1_verify( &ctx, NULL, NULL, RSA_PUBLIC, digest, 0, hash_result, result_str ) == result );

    rsa_free( &ctx );
}


#endif /* POLARSSL_PKCS1_V21 */
#endif /* POLARSSL_RSA_C */
#endif /* POLARSSL_BIGNUM_C */
#endif /* POLARSSL_SHA1_C */
#endif /* POLARSSL_GENPRIME */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );



    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "pkcs1_rsaes_oaep_encrypt" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        char *param9 = params[9];
        int param10;

        if( cnt != 11 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );

        test_suite_pkcs1_rsaes_oaep_encrypt( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pkcs1_rsaes_oaep_decrypt" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        char *param12 = params[12];
        char *param13 = params[13];
        int param14;

        if( cnt != 15 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_string( &param11 ) != 0 ) return( 2 );
        if( verify_string( &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );
        if( verify_int( params[14], &param14 ) != 0 ) return( 2 );

        test_suite_pkcs1_rsaes_oaep_decrypt( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pkcs1_rsassa_pss_sign" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        int param11;
        char *param12 = params[12];
        char *param13 = params[13];
        char *param14 = params[14];
        int param15;

        if( cnt != 16 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 16 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_int( params[10], &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );
        if( verify_string( &param12 ) != 0 ) return( 2 );
        if( verify_string( &param13 ) != 0 ) return( 2 );
        if( verify_string( &param14 ) != 0 ) return( 2 );
        if( verify_int( params[15], &param15 ) != 0 ) return( 2 );

        test_suite_pkcs1_rsassa_pss_sign( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14, param15 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "pkcs1_rsassa_pss_verify" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        int param7;
        char *param8 = params[8];
        char *param9 = params[9];
        char *param10 = params[10];
        int param11;

        if( cnt != 12 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 12 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );
        if( verify_string( &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );

        test_suite_pkcs1_rsassa_pss_verify( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11 );
        return ( 0 );

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
    const char *filename = "suites/test_suite_pkcs1_v21.data";
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


