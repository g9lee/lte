# Install script for directory: /home/glee/lte/openlte-code/polarssl/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ssl_cookie.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/pem.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/camellia.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ecjpake.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/cmac.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/memory_buffer_alloc.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/md.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/entropy.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/cipher.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/aes.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/compat-1.3.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/padlock.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/bignum.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/version.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/base64.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/asn1write.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/error.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ecdh.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ssl_cache.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/debug.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/gcm.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/cipher_internal.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ecp.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/aesni.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/pkcs11.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ripemd160.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/net_sockets.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/config.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/threading.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ccm.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/dhm.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/md4.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ssl_internal.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/arc4.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/hmac_drbg.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/sha256.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/x509.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/timing.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/sha1.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/des.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/md_internal.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/xtea.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/x509_crt.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/x509_csr.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/oid.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/asn1.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/net.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/pkcs5.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/bn_mul.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/entropy_poll.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/md5.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/x509_crl.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/md2.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ecdsa.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/sha512.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/pk_internal.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/check_config.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/havege.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/rsa.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/blowfish.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ssl.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/platform.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ssl_ticket.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/pkcs12.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/platform_time.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/pk.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/certs.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ssl_ciphersuites.h"
    "/home/glee/lte/openlte-code/polarssl/include/mbedtls/ctr_drbg.h"
    )
endif()

