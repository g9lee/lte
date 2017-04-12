#include <polarssl/config.h>

#ifdef POLARSSL_ECP_C

#include <polarssl/ecp.h>

#define POLARSSL_ECP_PF_UNKNOWN     -1
#endif /* POLARSSL_ECP_C */


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

#ifdef POLARSSL_ECP_C

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

    if( strcmp( str, "POLARSSL_ECP_PF_UNCOMPRESSED" ) == 0 )
    {
        *value = ( POLARSSL_ECP_PF_UNCOMPRESSED );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_PF_COMPRESSED" ) == 0 )
    {
        *value = ( POLARSSL_ECP_PF_COMPRESSED );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_ECP_INVALID_KEY" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ECP_INVALID_KEY );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_PF_UNKNOWN" ) == 0 )
    {
        *value = ( POLARSSL_ECP_PF_UNKNOWN );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_BP384R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_BP384R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP256R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP256R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_ECP_BUFFER_TOO_SMALL" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_M255" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_M255 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP192R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP192R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_BP256R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_BP256R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP224R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP224R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP521R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP521R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP384R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP384R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_ECP_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
        return( 0 );
    }
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_BP512R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_BP512R1 );
        return( 0 );
    }


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_ecp_curve_info( int id, int tls_id, int size, char *name )
{
    const ecp_curve_info *by_id, *by_tls, *by_name;

    TEST_ASSERT( ( by_id   = ecp_curve_info_from_grp_id( id     ) ) != NULL );
    TEST_ASSERT( ( by_tls  = ecp_curve_info_from_tls_id( tls_id ) ) != NULL );
    TEST_ASSERT( ( by_name = ecp_curve_info_from_name(   name   ) ) != NULL );

    TEST_ASSERT( by_id == by_tls  );
    TEST_ASSERT( by_id == by_name );

    TEST_ASSERT( by_id->size == size );
}

void test_suite_ecp_small_add( int a_zero, char *x_a, char *y_a, int b_zero, char *x_b,
                    char *y_b, int c_zero, int x_c, int y_c )
{
    ecp_group grp;
    ecp_point A, B, C;

    ecp_group_init( &grp );
    ecp_point_init( &A ); ecp_point_init( &B ); ecp_point_init( &C );

    TEST_ASSERT( ecp_group_read_string( &grp, 10,
                "47", "4", "17", "42", "13" ) == 0 );

    if( a_zero )
        ecp_set_zero( &A );
    else
        TEST_ASSERT( ecp_point_read_string( &A, 10, x_a, y_a ) == 0 );

    if( b_zero )
        ecp_set_zero( &B );
    else
        TEST_ASSERT( ecp_point_read_string( &B, 10, x_b, y_b ) == 0 );

    TEST_ASSERT( ecp_add( &grp, &C, &A, &B ) == 0 );

    if( c_zero )
        TEST_ASSERT( mpi_cmp_int( &C.Z, 0 ) == 0 );
    else
    {
        TEST_ASSERT( mpi_cmp_int( &C.X, x_c ) == 0 );
        TEST_ASSERT( mpi_cmp_int( &C.Y, y_c ) == 0 );
    }

    TEST_ASSERT( ecp_add( &grp, &C, &B, &A ) == 0 );

    if( c_zero )
        TEST_ASSERT( mpi_cmp_int( &C.Z, 0 ) == 0 );
    else
    {
        TEST_ASSERT( mpi_cmp_int( &C.X, x_c ) == 0 );
        TEST_ASSERT( mpi_cmp_int( &C.Y, y_c ) == 0 );
    }

    ecp_group_free( &grp );
    ecp_point_free( &A ); ecp_point_free( &B ); ecp_point_free( &C );
}

void test_suite_ecp_small_sub( int a_zero, char *x_a, char *y_a, int b_zero, char *x_b,
                    char *y_b, int c_zero, int x_c, int y_c )
{
    ecp_group grp;
    ecp_point A, B, C;

    ecp_group_init( &grp );
    ecp_point_init( &A ); ecp_point_init( &B ); ecp_point_init( &C );

    TEST_ASSERT( ecp_group_read_string( &grp, 10,
                "47", "4", "17", "42", "13" ) == 0 );

    if( a_zero )
        ecp_set_zero( &A );
    else
        TEST_ASSERT( ecp_point_read_string( &A, 10, x_a, y_a ) == 0 );

    if( b_zero )
        ecp_set_zero( &B );
    else
        TEST_ASSERT( ecp_point_read_string( &B, 10, x_b, y_b ) == 0 );

    TEST_ASSERT( ecp_sub( &grp, &C, &A, &B ) == 0 );

    if( c_zero )
        TEST_ASSERT( mpi_cmp_int( &C.Z, 0 ) == 0 );
    else
    {
        TEST_ASSERT( mpi_cmp_int( &C.X, x_c ) == 0 );
        TEST_ASSERT( mpi_cmp_int( &C.Y, y_c ) == 0 );
    }

    ecp_group_free( &grp );
    ecp_point_free( &A ); ecp_point_free( &B ); ecp_point_free( &C );
}

void test_suite_ecp_small_mul( int m_str, int r_zero, int x_r, int y_r, int ret )
{
    ecp_group grp;
    ecp_point R;
    mpi m;
    rnd_pseudo_info rnd_info;

    ecp_group_init( &grp );
    ecp_point_init( &R );
    mpi_init( &m );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( ecp_group_read_string( &grp, 10,
                "47", "4", "17", "42", "13" ) == 0 );

    TEST_ASSERT( mpi_lset( &m, m_str ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &m, &grp.G, NULL, NULL ) == ret );

    if( ret == 0 )
    {
        if( r_zero )
            TEST_ASSERT( mpi_cmp_int( &R.Z, 0 ) == 0 );
        else
        {
            TEST_ASSERT( mpi_cmp_int( &R.X, x_r ) == 0 );
            TEST_ASSERT( mpi_cmp_int( &R.Y, y_r ) == 0 );
        }
    }

    /* try again with randomization */
    ecp_point_free( &R );

    TEST_ASSERT( ecp_mul( &grp, &R, &m, &grp.G,
                          &rnd_pseudo_rand, &rnd_info ) == ret );

    if( ret == 0 )
    {
        if( r_zero )
            TEST_ASSERT( mpi_cmp_int( &R.Z, 0 ) == 0 );
        else
        {
            TEST_ASSERT( mpi_cmp_int( &R.X, x_r ) == 0 );
            TEST_ASSERT( mpi_cmp_int( &R.Y, y_r ) == 0 );
        }
    }

    ecp_group_free( &grp );
    ecp_point_free( &R );
    mpi_free( &m );
}

void test_suite_ecp_small_check_pub( int x, int y, int z, int ret )
{
    ecp_group grp;
    ecp_point P;

    ecp_group_init( &grp );
    ecp_point_init( &P );

    TEST_ASSERT( ecp_group_read_string( &grp, 10,
                "47", "4", "17", "42", "13" ) == 0 );

    TEST_ASSERT( mpi_lset( &P.X, x ) == 0 );
    TEST_ASSERT( mpi_lset( &P.Y, y ) == 0 );
    TEST_ASSERT( mpi_lset( &P.Z, z ) == 0 );

    TEST_ASSERT( ecp_check_pubkey( &grp, &P ) == ret );

    ecp_group_free( &grp );
    ecp_point_free( &P );
}

void test_suite_ecp_check_pub_mx( int grp_id, char *key_hex, int ret )
{
    ecp_group grp;
    ecp_point P;

    ecp_group_init( &grp );
    ecp_point_init( &P );

    TEST_ASSERT( ecp_use_known_dp( &grp, grp_id ) == 0 );

    TEST_ASSERT( mpi_read_string( &P.X, 16, key_hex ) == 0 );
    TEST_ASSERT( mpi_lset( &P.Z, 1 ) == 0 );

    TEST_ASSERT( ecp_check_pubkey( &grp, &P ) == ret );

    ecp_group_free( &grp );
    ecp_point_free( &P );
}

void test_suite_ecp_test_vect( int id, char *dA_str, char *xA_str, char *yA_str,
                    char *dB_str, char *xB_str, char *yB_str, char *xZ_str,
                    char *yZ_str )
{
    ecp_group grp;
    ecp_point R;
    mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    rnd_pseudo_info rnd_info;

    ecp_group_init( &grp ); ecp_point_init( &R );
    mpi_init( &dA ); mpi_init( &xA ); mpi_init( &yA ); mpi_init( &dB );
    mpi_init( &xB ); mpi_init( &yB ); mpi_init( &xZ ); mpi_init( &yZ );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    TEST_ASSERT( ecp_check_pubkey( &grp, &grp.G ) == 0 );

    TEST_ASSERT( mpi_read_string( &dA, 16, dA_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &xA, 16, xA_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &yA, 16, yA_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &dB, 16, dB_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &xB, 16, xB_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &yB, 16, yB_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &xZ, 16, xZ_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &yZ, 16, yZ_str ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &dA, &grp.G,
                          &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xA ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.Y, &yA ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( ecp_mul( &grp, &R, &dB, &R, NULL, NULL ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xZ ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.Y, &yZ ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &dB, &grp.G, NULL, NULL ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xB ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.Y, &yB ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( ecp_mul( &grp, &R, &dA, &R,
                          &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xZ ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.Y, &yZ ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );

    ecp_group_free( &grp ); ecp_point_free( &R );
    mpi_free( &dA ); mpi_free( &xA ); mpi_free( &yA ); mpi_free( &dB );
    mpi_free( &xB ); mpi_free( &yB ); mpi_free( &xZ ); mpi_free( &yZ );
}

void test_suite_ecp_test_vec_x( int id, char *dA_hex, char *xA_hex,
                     char *dB_hex, char *xB_hex, char *xS_hex )
{
    ecp_group grp;
    ecp_point R;
    mpi dA, xA, dB, xB, xS;
    rnd_pseudo_info rnd_info;

    ecp_group_init( &grp ); ecp_point_init( &R );
    mpi_init( &dA ); mpi_init( &xA );
    mpi_init( &dB ); mpi_init( &xB );
    mpi_init( &xS );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    TEST_ASSERT( ecp_check_pubkey( &grp, &grp.G ) == 0 );

    TEST_ASSERT( mpi_read_string( &dA, 16, dA_hex ) == 0 );
    TEST_ASSERT( mpi_read_string( &dB, 16, dB_hex ) == 0 );
    TEST_ASSERT( mpi_read_string( &xA, 16, xA_hex ) == 0 );
    TEST_ASSERT( mpi_read_string( &xB, 16, xB_hex ) == 0 );
    TEST_ASSERT( mpi_read_string( &xS, 16, xS_hex ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &dA, &grp.G,
                          &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xA ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &dB, &R,
                          &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xS ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &dB, &grp.G, NULL, NULL ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xB ) == 0 );

    TEST_ASSERT( ecp_mul( &grp, &R, &dA, &R, NULL, NULL ) == 0 );
    TEST_ASSERT( ecp_check_pubkey( &grp, &R ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &R.X, &xS ) == 0 );

    ecp_group_free( &grp ); ecp_point_free( &R );
    mpi_free( &dA ); mpi_free( &xA );
    mpi_free( &dB ); mpi_free( &xB );
    mpi_free( &xS );
}

void test_suite_ecp_fast_mod( int id, char *N_str )
{
    ecp_group grp;
    mpi N, R;

    mpi_init( &N ); mpi_init( &R );
    ecp_group_init( &grp );

    TEST_ASSERT( mpi_read_string( &N, 16, N_str ) == 0 );
    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );
    TEST_ASSERT( grp.modp != NULL );

    /*
     * Store correct result before we touch N
     */
    TEST_ASSERT( mpi_mod_mpi( &R, &N, &grp.P ) == 0 );

    TEST_ASSERT( grp.modp( &N ) == 0 );
    TEST_ASSERT( mpi_msb( &N ) <= grp.pbits + 3 );

    /*
     * Use mod rather than addition/substraction in case previous test fails
     */
    TEST_ASSERT( mpi_mod_mpi( &N, &N, &grp.P ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &N, &R ) == 0 );

    mpi_free( &N ); mpi_free( &R );
    ecp_group_free( &grp );
}

void test_suite_ecp_write_binary( int id, char *x, char *y, char *z, int format,
                       char *out, int blen, int ret )
{
    ecp_group grp;
    ecp_point P;
    unsigned char buf[256], str[512];
    size_t olen;

    memset( buf, 0, sizeof( buf ) );
    memset( str, 0, sizeof( str ) );

    ecp_group_init( &grp ); ecp_point_init( &P );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    TEST_ASSERT( mpi_read_string( &P.X, 16, x ) == 0 );
    TEST_ASSERT( mpi_read_string( &P.Y, 16, y ) == 0 );
    TEST_ASSERT( mpi_read_string( &P.Z, 16, z ) == 0 );

    TEST_ASSERT( ecp_point_write_binary( &grp, &P, format,
                                   &olen, buf, blen ) == ret );

    if( ret == 0 )
    {
        hexify( str, buf, olen );
        TEST_ASSERT( strcasecmp( (char *) str, out ) == 0 );
    }

    ecp_group_free( &grp ); ecp_point_free( &P );
}

void test_suite_ecp_read_binary( int id, char *input, char *x, char *y, char *z,
                      int ret )
{
    ecp_group grp;
    ecp_point P;
    mpi X, Y, Z;
    int ilen;
    unsigned char buf[256];

    memset( buf, 0, sizeof( buf ) );

    ecp_group_init( &grp ); ecp_point_init( &P );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    TEST_ASSERT( mpi_read_string( &X, 16, x ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, 16, y ) == 0 );
    TEST_ASSERT( mpi_read_string( &Z, 16, z ) == 0 );

    ilen = unhexify( buf, input );

    TEST_ASSERT( ecp_point_read_binary( &grp, &P, buf, ilen ) == ret );

    if( ret == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &P.X, &X ) == 0 );
        TEST_ASSERT( mpi_cmp_mpi( &P.Y, &Y ) == 0 );
        TEST_ASSERT( mpi_cmp_mpi( &P.Z, &Z ) == 0 );
    }

    ecp_group_free( &grp ); ecp_point_free( &P );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
}

void test_suite_ecp_tls_read_point( int id, char *input, char *x, char *y, char *z,
                         int ret )
{
    ecp_group grp;
    ecp_point P;
    mpi X, Y, Z;
    size_t ilen;
    unsigned char buf[256];
    const unsigned char *vbuf = buf;

    memset( buf, 0, sizeof( buf ) );

    ecp_group_init( &grp ); ecp_point_init( &P );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    TEST_ASSERT( mpi_read_string( &X, 16, x ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, 16, y ) == 0 );
    TEST_ASSERT( mpi_read_string( &Z, 16, z ) == 0 );

    ilen = unhexify( buf, input );

    TEST_ASSERT( ecp_tls_read_point( &grp, &P, &vbuf, ilen ) == ret );

    if( ret == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &P.X, &X ) == 0 );
        TEST_ASSERT( mpi_cmp_mpi( &P.Y, &Y ) == 0 );
        TEST_ASSERT( mpi_cmp_mpi( &P.Z, &Z ) == 0 );
        TEST_ASSERT( *vbuf == 0x00 );
    }

    ecp_group_free( &grp ); ecp_point_free( &P );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
}

void test_suite_ecp_tls_write_read_point( int id )
{
    ecp_group grp;
    ecp_point pt;
    unsigned char buf[256];
    const unsigned char *vbuf;
    size_t olen;

    ecp_group_init( &grp );
    ecp_point_init( &pt );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( ecp_tls_write_point( &grp, &grp.G,
                    POLARSSL_ECP_PF_COMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( ecp_tls_read_point( &grp, &pt, &vbuf, olen )
                 == POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    TEST_ASSERT( vbuf == buf + olen );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( ecp_tls_write_point( &grp, &grp.G,
                    POLARSSL_ECP_PF_UNCOMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( ecp_tls_read_point( &grp, &pt, &vbuf, olen ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &grp.G.X, &pt.X ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &grp.G.Y, &pt.Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &grp.G.Z, &pt.Z ) == 0 );
    TEST_ASSERT( vbuf == buf + olen );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( ecp_set_zero( &pt ) == 0 );
    TEST_ASSERT( ecp_tls_write_point( &grp, &pt,
                    POLARSSL_ECP_PF_COMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( ecp_tls_read_point( &grp, &pt, &vbuf, olen ) == 0 );
    TEST_ASSERT( ecp_is_zero( &pt ) );
    TEST_ASSERT( vbuf == buf + olen );

    memset( buf, 0x00, sizeof( buf ) ); vbuf = buf;
    TEST_ASSERT( ecp_set_zero( &pt ) == 0 );
    TEST_ASSERT( ecp_tls_write_point( &grp, &pt,
                    POLARSSL_ECP_PF_UNCOMPRESSED, &olen, buf, 256 ) == 0 );
    TEST_ASSERT( ecp_tls_read_point( &grp, &pt, &vbuf, olen ) == 0 );
    TEST_ASSERT( ecp_is_zero( &pt ) );
    TEST_ASSERT( vbuf == buf + olen );

    ecp_group_free( &grp );
    ecp_point_free( &pt );
}

void test_suite_ecp_tls_read_group( char *record, int result, int bits )
{
    ecp_group grp;
    unsigned char buf[10];
    const unsigned char *vbuf = buf;
    int len, ret;

    ecp_group_init( &grp );
    memset( buf, 0x00, sizeof( buf ) );

    len = unhexify( buf, record );

    ret = ecp_tls_read_group( &grp, &vbuf, len );

    TEST_ASSERT( ret == result );
    if( ret == 0)
    {
        TEST_ASSERT( mpi_msb( &grp.P ) == (size_t) bits );
        TEST_ASSERT( *vbuf == 0x00 );
    }

    ecp_group_free( &grp );
}

void test_suite_ecp_tls_write_read_group( int id )
{
    ecp_group grp1, grp2;
    unsigned char buf[10];
    const unsigned char *vbuf = buf;
    size_t len;
    int ret;

    ecp_group_init( &grp1 );
    ecp_group_init( &grp2 );
    memset( buf, 0x00, sizeof( buf ) );

    TEST_ASSERT( ecp_use_known_dp( &grp1, id ) == 0 );

    TEST_ASSERT( ecp_tls_write_group( &grp1, &len, buf, 10 ) == 0 );
    TEST_ASSERT( ( ret = ecp_tls_read_group( &grp2, &vbuf, len ) ) == 0 );

    if( ret == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &grp1.N, &grp2.N ) == 0 );
        TEST_ASSERT( grp1.id == grp2.id );
    }

    ecp_group_free( &grp1 );
    ecp_group_free( &grp2 );
}

void test_suite_ecp_check_privkey( int id, char *key_hex, int ret )
{
    ecp_group grp;
    mpi d;

    ecp_group_init( &grp );
    mpi_init( &d );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );
    TEST_ASSERT( mpi_read_string( &d, 16, key_hex ) == 0 );

    TEST_ASSERT( ecp_check_privkey( &grp, &d ) == ret );

    ecp_group_free( &grp );
    mpi_free( &d );
}

void test_suite_ecp_gen_keypair( int id )
{
    ecp_group grp;
    ecp_point Q;
    mpi d;
    rnd_pseudo_info rnd_info;

    ecp_group_init( &grp );
    ecp_point_init( &Q );
    mpi_init( &d );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );

    TEST_ASSERT( ecp_gen_keypair( &grp, &d, &Q, &rnd_pseudo_rand, &rnd_info )
                 == 0 );

    TEST_ASSERT( ecp_check_pubkey( &grp, &Q ) == 0 );
    TEST_ASSERT( ecp_check_privkey( &grp, &d ) == 0 );

    ecp_group_free( &grp );
    ecp_point_free( &Q );
    mpi_free( &d );
}

void test_suite_ecp_gen_key( int id )
{
    ecp_keypair key;
    rnd_pseudo_info rnd_info;

    ecp_keypair_init( &key );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( ecp_gen_key( id, &key, &rnd_pseudo_rand, &rnd_info ) == 0 );

    TEST_ASSERT( ecp_check_pubkey( &key.grp, &key.Q ) == 0 );
    TEST_ASSERT( ecp_check_privkey( &key.grp, &key.d ) == 0 );

    ecp_keypair_free( &key );
}

#ifdef POLARSSL_SELF_TEST
void test_suite_ecp_selftest()
{
    TEST_ASSERT( ecp_self_test( 0 ) == 0 );
}
#endif /* POLARSSL_SELF_TEST */


#endif /* POLARSSL_ECP_C */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_ECP_DP_SECP256R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP224R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP521R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_BP512R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_BP512R1_ENABLED)
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
    if( strcmp( str, "POLARSSL_ECP_DP_SECP384R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_BP384R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_BP384R1_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_M255_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_M255_ENABLED)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_ECP_DP_BP256R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_BP256R1_ENABLED)
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
    if( strcmp( params[0], "ecp_curve_info" ) == 0 )
    {

        int param1;
        int param2;
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );

        test_suite_ecp_curve_info( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_small_add" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        char *param6 = params[6];
        int param7;
        int param8;
        int param9;

        if( cnt != 10 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_ecp_small_add( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_small_sub" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        char *param6 = params[6];
        int param7;
        int param8;
        int param9;

        if( cnt != 10 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_ecp_small_sub( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_small_mul" ) == 0 )
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

        test_suite_ecp_small_mul( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_small_check_pub" ) == 0 )
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

        test_suite_ecp_small_check_pub( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_check_pub_mx" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_ecp_check_pub_mx( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_test_vect" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];
        char *param8 = params[8];
        char *param9 = params[9];

        if( cnt != 10 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_string( &param9 ) != 0 ) return( 2 );

        test_suite_ecp_test_vect( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_test_vec_x" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_ecp_test_vec_x( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_fast_mod" ) == 0 )
    {

        int param1;
        char *param2 = params[2];

        if( cnt != 3 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );

        test_suite_ecp_fast_mod( param1, param2 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_write_binary" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        int param8;

        if( cnt != 9 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );

        test_suite_ecp_write_binary( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_read_binary" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
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
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );

        test_suite_ecp_read_binary( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_tls_read_point" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
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
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );

        test_suite_ecp_tls_read_point( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_tls_write_read_point" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_ecp_tls_write_read_point( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_tls_read_group" ) == 0 )
    {

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

        test_suite_ecp_tls_read_group( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_tls_write_read_group" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_ecp_tls_write_read_group( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_check_privkey" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_ecp_check_privkey( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_gen_keypair" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_ecp_gen_keypair( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_gen_key" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_ecp_gen_key( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecp_selftest" ) == 0 )
    {
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_ecp_selftest(  );
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
    const char *filename = "suites/test_suite_ecp.data";
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


