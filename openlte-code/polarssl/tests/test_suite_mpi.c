#include <polarssl/config.h>

#ifdef POLARSSL_BIGNUM_C

#include <polarssl/bignum.h>
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

    if( strcmp( str, "POLARSSL_ERR_MPI_NOT_ACCEPTABLE" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_NOT_ACCEPTABLE );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_BAD_INPUT_DATA );
        return( 0 );
    }
    if( strcmp( str, "-3" ) == 0 )
    {
        *value = ( -3 );
        return( 0 );
    }
    if( strcmp( str, "+1" ) == 0 )
    {
        *value = ( +1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_MPI_NEGATIVE_VALUE" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_NEGATIVE_VALUE );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_MPI_BUFFER_TOO_SMALL" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_BUFFER_TOO_SMALL );
        return( 0 );
    }
    if( strcmp( str, "-9871232" ) == 0 )
    {
        *value = ( -9871232 );
        return( 0 );
    }
#ifdef POLARSSL_FS_IO
    if( strcmp( str, "POLARSSL_ERR_MPI_FILE_IO_ERROR" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_FILE_IO_ERROR );
        return( 0 );
    }
#endif // POLARSSL_FS_IO
    if( strcmp( str, "-13" ) == 0 )
    {
        *value = ( -13 );
        return( 0 );
    }
    if( strcmp( str, "-2" ) == 0 )
    {
        *value = ( -2 );
        return( 0 );
    }
    if( strcmp( str, "-34" ) == 0 )
    {
        *value = ( -34 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_MPI_INVALID_CHARACTER" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_INVALID_CHARACTER );
        return( 0 );
    }
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_MPI_DIVISION_BY_ZERO" ) == 0 )
    {
        *value = ( POLARSSL_ERR_MPI_DIVISION_BY_ZERO );
        return( 0 );
    }


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_mpi_read_write_string( int radix_X, char *input_X, int radix_A,
                            char *input_A, int output_size, int result_read,
                            int result_write )
{
    mpi X;
    char str[1000];
    size_t len = output_size;

    mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == result_read );
    if( result_read == 0 )
    {
        TEST_ASSERT( mpi_write_string( &X, radix_A, str, &len ) == result_write );
        if( result_write == 0 )
        {
            TEST_ASSERT( strcasecmp( str, input_A ) == 0 );
        }
    }

    mpi_free( &X );
}

void test_suite_mpi_read_binary( char *input_X, int radix_A, char *input_A )
{
    mpi X;
    unsigned char str[1000];
    unsigned char buf[1000];
    size_t len = 1000;
    size_t input_len;

    mpi_init( &X );

    input_len = unhexify( buf, input_X );

    TEST_ASSERT( mpi_read_binary( &X, buf, input_len ) == 0 );
    TEST_ASSERT( mpi_write_string( &X, radix_A, (char *) str, &len ) == 0 );
    TEST_ASSERT( strcmp( (char *) str, input_A ) == 0 );

    mpi_free( &X );
}

void test_suite_mpi_write_binary( int radix_X, char *input_X, char *input_A,
                       int output_size, int result )
{
    mpi X;
    unsigned char str[1000];
    unsigned char buf[1000];
    size_t buflen;

    memset( buf, 0x00, 1000 );
    memset( str, 0x00, 1000 );

    mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    
    buflen = mpi_size( &X );
    if( buflen > (size_t) output_size )
        buflen = (size_t) output_size;

    TEST_ASSERT( mpi_write_binary( &X, buf, buflen ) == result );
    if( result == 0)
    {
        hexify( str, buf, buflen );

        TEST_ASSERT( strcasecmp( (char *) str, input_A ) == 0 );
    }

    mpi_free( &X );
}

#ifdef POLARSSL_FS_IO
void test_suite_mpi_read_file( int radix_X, char *input_file, char *input_A,
                    int result )
{
    mpi X;
    unsigned char str[1000];
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;

    memset( buf, 0x00, 1000 );
    memset( str, 0x00, 1000 );

    mpi_init( &X );

    file = fopen( input_file, "r" );
    TEST_ASSERT( mpi_read_file( &X, radix_X, file ) == result );
    fclose(file);

    if( result == 0 )
    {
        buflen = mpi_size( &X );
        TEST_ASSERT( mpi_write_binary( &X, buf, buflen ) == 0 );

        hexify( str, buf, buflen );

        TEST_ASSERT( strcasecmp( (char *) str, input_A ) == 0 );
    }

    mpi_free( &X );
}
#endif /* POLARSSL_FS_IO */

#ifdef POLARSSL_FS_IO
void test_suite_mpi_write_file( int radix_X, char *input_X, int output_radix,
                     char *output_file )
{
    mpi X, Y;
    FILE *file_out, *file_in;

    mpi_init( &X ); mpi_init( &Y );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );

    file_out = fopen( output_file, "w" );
    TEST_ASSERT( file_out != NULL );
    TEST_ASSERT( mpi_write_file( NULL, &X, output_radix, file_out ) == 0 );
    fclose(file_out);

    file_in = fopen( output_file, "r" );
    TEST_ASSERT( file_in != NULL );
    TEST_ASSERT( mpi_read_file( &Y, output_radix, file_in ) == 0 );
    fclose(file_in);

    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) == 0 );

    mpi_free( &X ); mpi_free( &Y );
}
#endif /* POLARSSL_FS_IO */

void test_suite_mpi_get_bit( int radix_X, char *input_X, int pos, int val )
{
    mpi X;
    mpi_init( &X );
    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_get_bit( &X, pos ) == val );

    mpi_free( &X );
}

void test_suite_mpi_set_bit( int radix_X, char *input_X, int pos, int val, int radix_Y,
                  char *output_Y )
{
    mpi X, Y;
    mpi_init( &X ); mpi_init( &Y );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, output_Y ) == 0 );
    TEST_ASSERT( mpi_set_bit( &X, pos, val ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) == 0 );

    mpi_free( &X ); mpi_free( &Y );
}

void test_suite_mpi_lsb( int radix_X, char *input_X, int nr_bits )
{
    mpi X;
    mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_lsb( &X ) == (size_t) nr_bits );

    mpi_free( &X );
}

void test_suite_mpi_msb( int radix_X, char *input_X, int nr_bits )
{
    mpi X;
    mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_msb( &X ) == (size_t) nr_bits );

    mpi_free( &X );
}

void test_suite_mpi_gcd( int radix_X, char *input_X, int radix_Y, char *input_Y,
              int radix_A, char *input_A )
{
    mpi A, X, Y, Z;
    mpi_init( &A ); mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_gcd( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &A ); mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );
}

void test_suite_mpi_cmp_int( int input_X, int input_A, int result_CMP )
{
    mpi X;
    mpi_init( &X  );

    TEST_ASSERT( mpi_lset( &X, input_X ) == 0);
    TEST_ASSERT( mpi_cmp_int( &X, input_A ) == result_CMP);

    mpi_free( &X );
}

void test_suite_mpi_cmp_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int input_A )
{
    mpi X, Y;
    mpi_init( &X ); mpi_init( &Y );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) == input_A );

    mpi_free( &X ); mpi_free( &Y );
}

void test_suite_mpi_cmp_abs( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int input_A )
{
    mpi X, Y;
    mpi_init( &X ); mpi_init( &Y );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_cmp_abs( &X, &Y ) == input_A );

    mpi_free( &X ); mpi_free( &Y );
}

void test_suite_mpi_copy( int input_X, int input_A )
{
    mpi X, Y, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );

    TEST_ASSERT( mpi_lset( &X, input_X ) == 0 );
    TEST_ASSERT( mpi_lset( &Y, input_A ) == 0 );
    TEST_ASSERT( mpi_lset( &A, input_A ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) != 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Y, &A ) == 0 );
    TEST_ASSERT( mpi_copy( &Y, &X ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Y, &A ) != 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
}

void test_suite_mpi_copy_self( int input_X )
{
    mpi X;
    mpi_init( &X );

    TEST_ASSERT( mpi_lset( &X, input_X ) == 0 );
    TEST_ASSERT( mpi_copy( &X, &X ) == 0 );
    TEST_ASSERT( mpi_cmp_int( &X, input_X ) == 0 );

    mpi_free( &X );
}

void test_suite_mpi_shrink( int before, int used, int min, int after )
{
    mpi X;
    mpi_init( &X );

    TEST_ASSERT( mpi_grow( &X, before ) == 0 );
    TEST_ASSERT( used <= before );
    memset( X.p, 0x2a, used * sizeof( t_uint ) );
    TEST_ASSERT( mpi_shrink( &X, min ) == 0 );
    TEST_ASSERT( X.n == (size_t) after );

    mpi_free( &X );
}

void test_suite_mpi_safe_cond_assign( int x_sign, char *x_str,
                           int y_sign, char *y_str )
{
    mpi X, Y, XX;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &XX );

    TEST_ASSERT( mpi_read_string( &X, 16, x_str ) == 0 );
    X.s = x_sign;
    TEST_ASSERT( mpi_read_string( &Y, 16, y_str ) == 0 );
    Y.s = y_sign;
    TEST_ASSERT( mpi_copy( &XX, &X ) == 0 );

    TEST_ASSERT( mpi_safe_cond_assign( &X, &Y, 0 ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &XX ) == 0 );

    TEST_ASSERT( mpi_safe_cond_assign( &X, &Y, 1 ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &XX );
}

void test_suite_mpi_safe_cond_swap( int x_sign, char *x_str,
                         int y_sign, char *y_str )
{
    mpi X, Y, XX, YY;

    mpi_init( &X ); mpi_init( &Y );
    mpi_init( &XX ); mpi_init( &YY );

    TEST_ASSERT( mpi_read_string( &X, 16, x_str ) == 0 );
    X.s = x_sign;
    TEST_ASSERT( mpi_read_string( &Y, 16, y_str ) == 0 );
    Y.s = y_sign;

    TEST_ASSERT( mpi_copy( &XX, &X ) == 0 );
    TEST_ASSERT( mpi_copy( &YY, &Y ) == 0 );

    TEST_ASSERT( mpi_safe_cond_swap( &X, &Y, 0 ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &XX ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Y, &YY ) == 0 );

    TEST_ASSERT( mpi_safe_cond_swap( &X, &Y, 1 ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Y, &XX ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &YY ) == 0 );

    mpi_free( &X ); mpi_free( &Y );
    mpi_free( &XX ); mpi_free( &YY );
}

void test_suite_mpi_swap( int input_X,  int input_Y )
{
    mpi X, Y, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );

    TEST_ASSERT( mpi_lset( &X, input_X ) == 0 );
    TEST_ASSERT( mpi_lset( &Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_lset( &A, input_X ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) != 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &A ) == 0 );
    mpi_swap( &X, &Y );
    TEST_ASSERT( mpi_cmp_mpi( &X, &Y ) != 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Y, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
}

void test_suite_mpi_add_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mpi X, Y, Z, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_add_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_add_abs( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mpi X, Y, Z, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_add_abs( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_add_abs_add_first( int radix_X, char *input_X, int radix_Y,
                            char *input_Y, int radix_A, char *input_A )
{
    mpi X, Y, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_add_abs( &X, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
}

void test_suite_mpi_add_abs_add_second( int radix_X, char *input_X, int radix_Y,
                             char *input_Y, int radix_A, char *input_A )
{
    mpi X, Y, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_add_abs( &Y, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Y, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
}

void test_suite_mpi_add_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A )
{
    mpi X, Z, A;
    mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_add_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_sub_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mpi X, Y, Z, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_sub_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_sub_abs( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int sub_result )
{
    mpi X, Y, Z, A;
    int res;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    
    res = mpi_sub_abs( &Z, &X, &Y );
    TEST_ASSERT( res == sub_result );
    if( res == 0 )
        TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_sub_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A )
{
    mpi X, Z, A;
    mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_sub_int( &Z, &X, input_Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_mul_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A )
{
    mpi X, Y, Z, A;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_mul_mpi( &Z, &X, &Y ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_mul_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A, char *result_comparison )
{
    mpi X, Z, A;
    mpi_init( &X ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_mul_int( &Z, &X, input_Y ) == 0 );
    if( strcmp( result_comparison, "==" ) == 0 )
        TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );
    else if( strcmp( result_comparison, "!=" ) == 0 )
        TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) != 0 );
    else
        TEST_ASSERT( "unknown operator" == 0 );

    mpi_free( &X ); mpi_free( &Z ); mpi_free( &A );
}

void test_suite_mpi_div_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int radix_B, char *input_B,
                  int div_result )
{
    mpi X, Y, Q, R, A, B;
    int res;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Q ); mpi_init( &R );
    mpi_init( &A ); mpi_init( &B );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_read_string( &B, radix_B, input_B ) == 0 );
    res = mpi_div_mpi( &Q, &R, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &Q, &A ) == 0 );
        TEST_ASSERT( mpi_cmp_mpi( &R, &B ) == 0 );
    }

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Q ); mpi_free( &R );
    mpi_free( &A ); mpi_free( &B );
}

void test_suite_mpi_div_int( int radix_X, char *input_X, int input_Y, int radix_A,
                  char *input_A, int radix_B, char *input_B, int div_result )
{
    mpi X, Q, R, A, B;
    int res;
    mpi_init( &X ); mpi_init( &Q ); mpi_init( &R ); mpi_init( &A );
    mpi_init( &B );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_read_string( &B, radix_B, input_B ) == 0 );
    res = mpi_div_int( &Q, &R, &X, input_Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &Q, &A ) == 0 );
        TEST_ASSERT( mpi_cmp_mpi( &R, &B ) == 0 );
    }

    mpi_free( &X ); mpi_free( &Q ); mpi_free( &R ); mpi_free( &A );
    mpi_free( &B );
}

void test_suite_mpi_mod_mpi( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int div_result )
{
    mpi X, Y, A;
    int res;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    res = mpi_mod_mpi( &X, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &X, &A ) == 0 );
    }

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &A );
}

void test_suite_mpi_mod_int( int radix_X, char *input_X, int input_Y, int input_A,
                  int div_result )
{
    mpi X;
    int res;
    t_uint r;
    mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    res = mpi_mod_int( &r, &X, input_Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( r == (t_uint) input_A );
    }

    mpi_free( &X );
}

void test_suite_mpi_exp_mod( int radix_A, char *input_A, int radix_E, char *input_E,
                  int radix_N, char *input_N, int radix_RR, char *input_RR,
                  int radix_X, char *input_X, int div_result )
{
    mpi A, E, N, RR, Z, X;
    int res;
    mpi_init( &A  ); mpi_init( &E ); mpi_init( &N );
    mpi_init( &RR ); mpi_init( &Z ); mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_read_string( &E, radix_E, input_E ) == 0 );
    TEST_ASSERT( mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );

    if( strlen( input_RR ) )
        TEST_ASSERT( mpi_read_string( &RR, radix_RR, input_RR ) == 0 );

    res = mpi_exp_mod( &Z, &A, &E, &N, &RR );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &Z, &X ) == 0 );
    }

    mpi_free( &A  ); mpi_free( &E ); mpi_free( &N );
    mpi_free( &RR ); mpi_free( &Z ); mpi_free( &X );
}

void test_suite_mpi_inv_mod( int radix_X, char *input_X, int radix_Y, char *input_Y,
                  int radix_A, char *input_A, int div_result )
{
    mpi X, Y, Z, A;
    int res;
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &Y, radix_Y, input_Y ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    res = mpi_inv_mod( &Z, &X, &Y );
    TEST_ASSERT( res == div_result );
    if( res == 0 )
    {
        TEST_ASSERT( mpi_cmp_mpi( &Z, &A ) == 0 );
    }

    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z ); mpi_free( &A );
}

#ifdef POLARSSL_GENPRIME
void test_suite_mpi_is_prime( int radix_X, char *input_X, int div_result )
{
    mpi X;
    int res;
    mpi_init( &X );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    res = mpi_is_prime( &X, rnd_std_rand, NULL );
    TEST_ASSERT( res == div_result );

    mpi_free( &X );
}
#endif /* POLARSSL_GENPRIME */

void test_suite_mpi_shift_l( int radix_X, char *input_X, int shift_X, int radix_A,
                  char *input_A)
{
    mpi X, A;
    mpi_init( &X ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_shift_l( &X, shift_X ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &A ) == 0 );

    mpi_free( &X ); mpi_free( &A );
}

void test_suite_mpi_shift_r( int radix_X, char *input_X, int shift_X, int radix_A,
                  char *input_A )
{
    mpi X, A;
    mpi_init( &X ); mpi_init( &A );

    TEST_ASSERT( mpi_read_string( &X, radix_X, input_X ) == 0 );
    TEST_ASSERT( mpi_read_string( &A, radix_A, input_A ) == 0 );
    TEST_ASSERT( mpi_shift_r( &X, shift_X ) == 0 );
    TEST_ASSERT( mpi_cmp_mpi( &X, &A ) == 0 );

    mpi_free( &X ); mpi_free( &A );
}

#ifdef POLARSSL_SELF_TEST
void test_suite_mpi_selftest()
{
    TEST_ASSERT( mpi_self_test( 0 ) == 0 );
}
#endif /* POLARSSL_SELF_TEST */


#endif /* POLARSSL_BIGNUM_C */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_GENPRIME" ) == 0 )
    {
#if defined(POLARSSL_GENPRIME)
        return( 0 );
#else
        return( 1 );
#endif
    }
    if( strcmp( str, "POLARSSL_SELF_TEST" ) == 0 )
    {
#if defined(POLARSSL_SELF_TEST)
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
    if( strcmp( params[0], "mpi_read_write_string" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        int param6;
        int param7;

        if( cnt != 8 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );

        test_suite_mpi_read_write_string( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_read_binary" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        char *param3 = params[3];

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );

        test_suite_mpi_read_binary( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_write_binary" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;
        int param5;

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_mpi_write_binary( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_read_file" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_string( &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );

        test_suite_mpi_read_file( param1, param2, param3, param4 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_write_file" ) == 0 )
    {
    #ifdef POLARSSL_FS_IO

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );

        test_suite_mpi_write_file( param1, param2, param3, param4 );
        return ( 0 );
    #endif /* POLARSSL_FS_IO */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_get_bit" ) == 0 )
    {

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

        test_suite_mpi_get_bit( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_set_bit" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_set_bit( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_lsb" ) == 0 )
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

        test_suite_mpi_lsb( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_msb" ) == 0 )
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

        test_suite_mpi_msb( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_gcd" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_gcd( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_cmp_int" ) == 0 )
    {

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

        test_suite_mpi_cmp_int( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_cmp_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_mpi_cmp_mpi( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_cmp_abs" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );

        test_suite_mpi_cmp_abs( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_copy" ) == 0 )
    {

        int param1;
        int param2;

        if( cnt != 3 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );

        test_suite_mpi_copy( param1, param2 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_copy_self" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );

        test_suite_mpi_copy_self( param1 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_shrink" ) == 0 )
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

        test_suite_mpi_shrink( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_safe_cond_assign" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );

        test_suite_mpi_safe_cond_assign( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_safe_cond_swap" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );

        test_suite_mpi_safe_cond_swap( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_swap" ) == 0 )
    {

        int param1;
        int param2;

        if( cnt != 3 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_int( params[2], &param2 ) != 0 ) return( 2 );

        test_suite_mpi_swap( param1, param2 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_add_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_add_mpi( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_add_abs" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_add_abs( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_add_abs_add_first" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_add_abs_add_first( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_add_abs_add_second" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_add_abs_add_second( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_add_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );

        test_suite_mpi_add_int( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_sub_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_sub_mpi( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_sub_abs" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );

        test_suite_mpi_sub_abs( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_sub_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );

        test_suite_mpi_sub_int( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_mul_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_mul_mpi( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_mul_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];
        char *param6 = params[6];

        if( cnt != 7 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );

        test_suite_mpi_mul_int( param1, param2, param3, param4, param5, param6 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_div_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );

        test_suite_mpi_div_mpi( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_div_int" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;

        if( cnt != 9 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );
        if( verify_int( params[6], &param6 ) != 0 ) return( 2 );
        if( verify_string( &param7 ) != 0 ) return( 2 );
        if( verify_int( params[8], &param8 ) != 0 ) return( 2 );

        test_suite_mpi_div_int( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_mod_mpi" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );

        test_suite_mpi_mod_mpi( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_mod_int" ) == 0 )
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

        test_suite_mpi_mod_int( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_exp_mod" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;

        if( cnt != 12 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 12 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );
        if( verify_string( &param8 ) != 0 ) return( 2 );
        if( verify_int( params[9], &param9 ) != 0 ) return( 2 );
        if( verify_string( &param10 ) != 0 ) return( 2 );
        if( verify_int( params[11], &param11 ) != 0 ) return( 2 );

        test_suite_mpi_exp_mod( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_inv_mod" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;

        if( cnt != 8 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_string( &param4 ) != 0 ) return( 2 );
        if( verify_int( params[5], &param5 ) != 0 ) return( 2 );
        if( verify_string( &param6 ) != 0 ) return( 2 );
        if( verify_int( params[7], &param7 ) != 0 ) return( 2 );

        test_suite_mpi_inv_mod( param1, param2, param3, param4, param5, param6, param7 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_is_prime" ) == 0 )
    {
    #ifdef POLARSSL_GENPRIME

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

        test_suite_mpi_is_prime( param1, param2, param3 );
        return ( 0 );
    #endif /* POLARSSL_GENPRIME */

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_shift_l" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );

        test_suite_mpi_shift_l( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_shift_r" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( 2 );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );
        if( verify_string( &param5 ) != 0 ) return( 2 );

        test_suite_mpi_shift_r( param1, param2, param3, param4, param5 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "mpi_selftest" ) == 0 )
    {
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_mpi_selftest(  );
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
    const char *filename = "suites/test_suite_mpi.data";
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


