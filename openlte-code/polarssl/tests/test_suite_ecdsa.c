#include <polarssl/config.h>

#ifdef POLARSSL_ECDSA_C

#include <polarssl/ecdsa.h>
#define WANT_NOT_RND_MPI
#endif /* POLARSSL_ECDSA_C */


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

#ifdef POLARSSL_ECDSA_C

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

    if( strcmp( str, "POLARSSL_ECP_DP_SECP256R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP256R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP521R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP521R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP192R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP192R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP384R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP384R1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ECP_DP_SECP224R1" ) == 0 )
    {
        *value = ( POLARSSL_ECP_DP_SECP224R1 );
        return( 0 );
    }


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_ecdsa_prim_random( int id )
{
    ecp_group grp;
    ecp_point Q;
    mpi d, r, s;
    rnd_pseudo_info rnd_info;
    unsigned char buf[66];

    ecp_group_init( &grp );
    ecp_point_init( &Q );
    mpi_init( &d ); mpi_init( &r ); mpi_init( &s );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );
    memset( buf, 0, sizeof( buf ) );

    /* prepare material for signature */
    TEST_ASSERT( rnd_pseudo_rand( &rnd_info, buf, sizeof( buf ) ) == 0 );
    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );
    TEST_ASSERT( ecp_gen_keypair( &grp, &d, &Q, &rnd_pseudo_rand, &rnd_info )
                 == 0 );

    TEST_ASSERT( ecdsa_sign( &grp, &r, &s, &d, buf, sizeof( buf ),
                             &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( ecdsa_verify( &grp, buf, sizeof( buf ), &Q, &r, &s ) == 0 );

    ecp_group_free( &grp );
    ecp_point_free( &Q );
    mpi_free( &d ); mpi_free( &r ); mpi_free( &s );
}

void test_suite_ecdsa_prim_test_vectors( int id, char *d_str, char *xQ_str, char *yQ_str,
                              char *k_str, char *hash_str, char *r_str,
                              char *s_str )
{
    ecp_group grp;
    ecp_point Q;
    mpi d, r, s, r_check, s_check;
    unsigned char buf[66];
    size_t len;

    ecp_group_init( &grp );
    ecp_point_init( &Q );
    mpi_init( &d ); mpi_init( &r ); mpi_init( &s );
    mpi_init( &r_check ); mpi_init( &s_check );
    memset( buf, 0, sizeof( buf ) );

    TEST_ASSERT( ecp_use_known_dp( &grp, id ) == 0 );
    TEST_ASSERT( ecp_point_read_string( &Q, 16, xQ_str, yQ_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &d, 16, d_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &r_check, 16, r_str ) == 0 );
    TEST_ASSERT( mpi_read_string( &s_check, 16, s_str ) == 0 );
    len = unhexify(buf, hash_str);

    TEST_ASSERT( ecdsa_sign( &grp, &r, &s, &d, buf, len,
                &not_rnd_mpi, k_str ) == 0 );

    TEST_ASSERT( mpi_cmp_mpi( &r, &r_check ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &s, &s_check ) == 0 );

    TEST_ASSERT( ecdsa_verify( &grp, buf, len, &Q, &r_check, &s_check ) == 0 );

    ecp_group_free( &grp );
    ecp_point_free( &Q );
    mpi_free( &d ); mpi_free( &r ); mpi_free( &s );
    mpi_free( &r_check ); mpi_free( &s_check );
}

void test_suite_ecdsa_write_read_random( int id )
{
    ecdsa_context ctx;
    rnd_pseudo_info rnd_info;
    unsigned char hash[66];
    unsigned char sig[200];
    size_t sig_len, i;

    ecdsa_init( &ctx );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );
    memset( hash, 0, sizeof( hash ) );
    memset( sig, 0x2a, sizeof( sig ) );

    /* prepare material for signature */
    TEST_ASSERT( rnd_pseudo_rand( &rnd_info, hash, sizeof( hash ) ) == 0 );

    /* generate signing key */
    TEST_ASSERT( ecdsa_genkey( &ctx, id, &rnd_pseudo_rand, &rnd_info ) == 0 );

    /* generate and write signature, then read and verify it */
    TEST_ASSERT( ecdsa_write_signature( &ctx, hash, sizeof( hash ),
                 sig, &sig_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) == 0 );

    /* check we didn't write past the announced length */
    for( i = sig_len; i < sizeof( sig ); i++ )
        TEST_ASSERT( sig[i] == 0x2a );

    /* try verification with invalid length */
    TEST_ASSERT( ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len - 1 ) != 0 );
    TEST_ASSERT( ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len + 1 ) != 0 );

    /* try invalid sequence tag */
    sig[0]++;
    TEST_ASSERT( ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) != 0 );
    sig[0]--;

    /* try modifying r */
    sig[10]++;
    TEST_ASSERT( ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) != 0 );
    sig[10]--;

    /* try modifying s */
    sig[sig_len - 1]++;
    TEST_ASSERT( ecdsa_read_signature( &ctx, hash, sizeof( hash ),
                 sig, sig_len ) != 0 );
    sig[sig_len - 1]--;

    ecdsa_free( &ctx );
}


#endif /* POLARSSL_ECDSA_C */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_ECP_DP_SECP521R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
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
    if( strcmp( str, "POLARSSL_ECP_DP_SECP192R1_ENABLED" ) == 0 )
    {
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
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


    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "ecdsa_prim_random" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_ecdsa_prim_random( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecdsa_prim_test_vectors" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        char *param6 = params[6];
        char *param7 = params[7];
        char *param8 = params[8];

        if( cnt != 9 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
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

        test_suite_ecdsa_prim_test_vectors( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "ecdsa_write_read_random" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_ecdsa_write_read_random( param1 );
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
    const char *filename = "suites/test_suite_ecdsa.data";
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


