/**
 * \file pkcs7.h
 *
 * \brief PKCS7 generic defines and structures
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_X509_H
#define MBEDTLS_X509_H

//#if !defined(MBEDTLS_CONFIG_FILE)
//#include "config.h"
//#else
//#include MBEDTLS_CONFIG_FILE
//#endif

#include "asn1.h"
#include "x509.h"

/**
 * \name PKCS7 Error codes
 * \{
 */
#define MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE              -0x7080  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
#define MBEDTLS_ERR_PKCS7_UNKNOWN_OID                      -0x7180  /**< Requested OID is unknown. */
#define MBEDTLS_ERR_PKCS7_INVALID_FORMAT                   -0x7200  /**< The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define MBEDTLS_ERR_PKCS7_INVALID_VERSION                  -0x7280  /**< The CRT/CRL/CSR version element is invalid. */
#define MBEDTLS_ERR_PKCS7_UNKNOWN_DIGEST_ALG               -0x7300  /**< The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_PKCS7_UNKNOWN_SIG_ALG                  -0x7380  /**< Signature algorithm (oid) is unsupported. */
#define MBEDTLS_ERR_PKCS7_SIG_MISMATCH                     -0x7400  /**< Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
#define MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA                   -0x7480  /**< Input invalid. */
#define MBEDTLS_ERR_PKCS7_ALLOC_FAILED                     -0x7500  /**< Allocation of memory failed. */
#define MBEDTLS_ERR_PKCS7_BUFFER_TOO_SMALL                 -0x7580  /**< Destination buffer is too small. */
#define MBEDTLS_ERR_PKCS7_FATAL_ERROR                      -0x7600  /**< A fatal error occurred, eg the chain is too long or the vrfy callback failed. */
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef mbedtls_asn1_buf mbedtls_pkcs7_buf;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef mbedtls_asn1_named_data mbedtls_pkcs7_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef mbedtls_asn1_sequence mbedtls_pkcs7_sequence;

/**
 * Structure holding PKCS7 signer info 
 */
typedef struct mbedtls_pkcs7_signer_info {
        int version;
        mbedtls_x509_buf serial;
        mbedtls_x509_name issuer;
        mbedtls_x509_buf issuer_raw;
        mbedtls_x509_buf alg_identifier;
        mbedtls_x509_buf sig_alg_identifier;
        mbedtls_x509_buf sig;
        struct mbedtls_pkcs7_signer_info *next;
}
mbedtls_pkcs7_signer_info;

typedef struct mbedtls_pkcs7_data {
        mbedtls_pkcs7_buf oid;
        mbedtls_pkcs7_buf data;
}
mbedtls_pkcs7_data;

typedef struct mbedtls_pkcs7_signed_data {
        int version;
        mbedtls_pkcs7_buf digest_alg_identifiers;
        struct mbedtls_pkcs7_data content;
        mbedtls_x509_crt certs;
        mbedtls_x509_crl crl;
        struct mbedtls_pkcs7_signer_info signers;
}
mbedtls_pkcs7_signed_data;

typedef struct mbedtls_pkcs7 {
        mbedtls_pkcs7_buf content_type_oid;
        struct mbedtls_pkcs7_signed_data signed_data;
}
mbedtls_pkcs7;

#if defined(MBEDTLS_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_x509_self_test( int verbose );

#endif /* MBEDTLS_SELF_TEST */

#define MBEDTLS_X509_SAFE_SNPRINTF                          \
    do {                                                    \
        if( ret < 0 || (size_t) ret >= n )                  \
            return( MBEDTLS_ERR_X509_BUFFER_TOO_SMALL );    \
                                                            \
        n -= (size_t) ret;                                  \
        p += (size_t) ret;                                  \
    } while( 0 )

#ifdef __cplusplus
}
#endif

#endif /* pkcs7.h */
