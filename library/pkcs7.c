/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_PKCS7_USE_C)

#include "mbedtls/x509.h"
#include "mbedtls/asn1.h"
#include "mbedtls/pkcs7.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free      free
#define mbedtls_calloc    calloc
#define mbedtls_printf    printf
#define mbedtls_snprintf  snprintf
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include "mbedtls/platform_util.h"
#include <time.h>
#endif

int pkcs7_get_next_content_len( unsigned char **p, unsigned char *end, size_t *len )
{
   return (mbedtls_asn1_get_tag(p, end, len, MBEDTLS_ASN1_CONSTRUCTED
			    | MBEDTLS_ASN1_CONTEXT_SPECIFIC));
}

/**
 * version Version
 * Version ::= INTEGER
 **/
int pkcs7_get_version( unsigned char **p, unsigned char *end, int *ver )
{
	return ( mbedtls_asn1_get_int(p, end, ver) );
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
int pkcs7_get_content_info_type( unsigned char **p, unsigned char *end, mbedtls_pkcs7_buf *pkcs7 )
{
	size_t len = 0;
	int rc;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					      | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OID);
	if (rc)
		return rc;

	pkcs7->tag = MBEDTLS_ASN1_OID;
	pkcs7->len = len;
	pkcs7->p = *p;

	return rc;
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
int pkcs7_get_digest_algorithm( unsigned char **p, unsigned char *end, mbedtls_x509_buf *alg )
{
	int rc;

	rc = mbedtls_asn1_get_alg_null(p, end, alg);

	return rc;
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
int pkcs7_get_digest_algorithm_set(unsigned char **p, unsigned char *end,
				   mbedtls_x509_buf *alg)
{
	size_t len = 0;
	int rc;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					      | MBEDTLS_ASN1_SET);
	if (rc)
		return rc;

	end = *p + len;

	/** For now, it assumes there is only one digest algorithm specified **/
	rc = mbedtls_asn1_get_alg_null(p, end, alg);
	if (rc)
		return rc;

	return rc;
}

/**
 * certificates :: SET OF ExtendedCertificateOrCertificate,
 * ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate -- x509,
 *      extendedCertificate[0] IMPLICIT ExtendedCertificate }
 **/
int pkcs7_get_certificates(unsigned char **buf, size_t buflen,
		mbedtls_x509_crt *certs)
{
	int rc;

	rc = mbedtls_x509_crt_parse(certs, *buf, buflen);
	if (rc)
		return rc;

	return rc;
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature(unsigned char **p, unsigned char *end,
		mbedtls_pkcs7_buf *signature)
{
	int rc;
	size_t len = 0;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
	if (rc)
		return rc;

	signature->tag = MBEDTLS_ASN1_OCTET_STRING;
	signature->len = len;
	signature->p = *p;

	return rc;
}

/**
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 **/
static int pkcs7_get_signers_info_set(unsigned char **p, unsigned char *end,
			       mbedtls_pkcs7_signer_info *signers_set)
{
	unsigned char *end_set;
	int rc;
	size_t len = 0;

	rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					      | MBEDTLS_ASN1_SET);
	if (rc) {
		printf("failed\n");
		return rc;
	}

	end_set = *p + len;

	rc = mbedtls_asn1_get_tag(p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
						  | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	rc = mbedtls_asn1_get_int(p, end_set, &signers_set->version);
	if (rc)
		return rc;

	rc = mbedtls_asn1_get_tag(p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
						  | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	signers_set->issuer_raw.p = *p;

	rc = mbedtls_asn1_get_tag(p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
						  | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	rc = mbedtls_x509_get_name(p, *p + len, &signers_set->issuer);
	if (rc)
		return rc;

	signers_set->issuer_raw.len =  *p - signers_set->issuer_raw.p;

	rc = mbedtls_x509_get_serial(p, end_set, &signers_set->serial);
	if (rc)
		return rc;

	rc = pkcs7_get_digest_algorithm(p, end_set,
					&signers_set->alg_identifier);
	if (rc) {
		printf("error getting digest algorithms\n");
		return rc;
	}

	rc = pkcs7_get_digest_algorithm(p, end_set,
					&signers_set->sig_alg_identifier);
	if (rc) {
		printf("error getting signature digest algorithms\n");
		return rc;
	}

	rc = pkcs7_get_signature(p, end, &signers_set->sig);
	signers_set->next = NULL;

	return rc;
}

/**
 * SignedData ::= SEQUENCE {
 *      version Version,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      contentInfo ContentInfo,
 *      certificates
 *              [0] IMPLICIT ExtendedCertificatesAndCertificates
 *                  OPTIONAL,
 *      crls
 *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos SignerInfos }
 */
static int pkcs7_get_signed_data(unsigned char *buf, size_t buflen,
			  mbedtls_pkcs7_signed_data *signed_data)
{
	unsigned char *p = buf;
	unsigned char *end = buf + buflen;
	size_t len = 0;
	size_t rc;

	rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
					       | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;

	/* get version of signed data */
	rc = pkcs7_get_version(&p, end, &signed_data->version);
	if (rc)
		return rc;
	printf("version is %d\n", signed_data->version);

	/* if version != 1, return invalid version */
	if (signed_data->version != 1) {
		printf("invalid version\n");
		return ( MBEDTLS_ERR_PKCS7_INVALID_VERSION );
	}

	/* get digest algorithm */
	rc = pkcs7_get_digest_algorithm_set(&p, end,
					    &signed_data->digest_alg_identifiers);
	if (rc) {
		printf("error getting digest algorithms\n");
		return rc;
	}

	if (signed_data->digest_alg_identifiers.len != strlen(PKCS7_SHA256_OID))
		return ( MBEDTLS_ERR_PKCS7_INVALID_ALG );

	if (memcmp(signed_data->digest_alg_identifiers.p, PKCS7_SHA256_OID,
		   signed_data->digest_alg_identifiers.len)) {
		printf("Digest Algorithm other than SHA256 is not supported\n");
		return ( MBEDTLS_ERR_PKCS7_UNSUPPORTED_DIGEST );
	}

	/* do not expect any content */
	rc = pkcs7_get_content_info_type(&p, end, &signed_data->content.oid);
	if (rc)
		return ( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA );

	if (memcmp(signed_data->content.oid.p, PKCS7_DATA_OID,
		   signed_data->content.oid.len)) {
		printf("Invalid PKCS7 data\n");
		return ( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA ) ;
	}

	p = p + signed_data->content.oid.len;

	rc = pkcs7_get_next_content_len(&p, end, &len);
	if (rc)
		return ( MBEDTLS_ERR_PKCS7_INVALID_ALG ); 

	/* get certificates */
	printf("----Loading Signer's certificate----\n");
	printf("\n");

	mbedtls_x509_crt_init(&signed_data->certs);
	rc = pkcs7_get_certificates(&p, len, &signed_data->certs);
	if (rc)
		return ( MBEDTLS_ERR_PKCS7_CERT_UNKNOWN_FORMAT) ;

	p = p + len;

	/* get signers info */
	printf("Loading signer's signature\n");
	rc = pkcs7_get_signers_info_set(&p, end, &signed_data->signers);

	if (rc)
		return ( MBEDTLS_ERR_PKCS7_INVALID_ALG );

	return rc;
}

void pkcs7_printf(const unsigned char *buf, size_t buflen)
{
	unsigned int i;
	char *sbuf;
	int j = 0;

	sbuf = malloc(buflen*2 + 1);
	memset(sbuf, 0, buflen*2 + 1);

	for (i = 0; i < buflen; i++)
		j += snprintf(sbuf+j, sizeof(sbuf), "%02x", buf[i]);

	printf("Length of sbuf is %lu\n", strlen(sbuf));
	printf("%s\n", sbuf);
	printf("\n");

	free(sbuf);
}

int pkcs7_parse_der_core(const unsigned char *buf, const int buflen,
			mbedtls_pkcs7 *pkcs7)
{
	unsigned char *start;
	unsigned char *end;
	size_t len = 0;
	int rc;

	/* use internal buffer for parsing */
	start = (unsigned char *)buf;
	end = start + buflen;

	rc = pkcs7_get_content_info_type(&start, end, &(pkcs7->content_type_oid));
	if ( rc )
		goto out;

	if ((!memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_DATA,
		   pkcs7->content_type_oid.len))
	    || (!memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_ENCRPYTED_DATA,
		   pkcs7->content_type_oid.len))
	    || (!memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_ENVELOPED_DATA,
		   pkcs7->content_type_oid.len))
            || (!memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA,
		   pkcs7->content_type_oid.len))
            || (!memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_DIGESTED_DATA,
		   pkcs7->content_type_oid.len))
	    || (!memcmp(pkcs7->content_type_oid.p, MBEDTLS_OID_PKCS7_ENCRYPTED_DATA,
		   pkcs7->content_type_oid.len))) {
		printf("PKCS7 is not the signed data\n");
		ret =  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
		goto out;
	}

	printf("Content type is signedData, continue...\n");

	start = start + pkcs7->content_type_oid.len;

	rc = pkcs7_get_next_content_len(&start, end, &len);
	if (rc)
		goto out;

	rc = pkcs7_get_signed_data(start, len, &(pkcs7->signed_data));
	if (rc)
		goto out;

out:
	return rc;
}

int pkcs7_signed_data_verify(mbedtls_pkcs7 *pkcs7, mbedtls_x509_crt *cert, char *data, int datalen)
{

       int rc;
       unsigned char hash[32];
       mbedtls_pk_context pk_cxt = cert->pk;
       const mbedtls_md_info_t *md_info =
               mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

       mbedtls_md(md_info, data, datalen, hash);
       rc = mbedtls_pk_verify(&pk_cxt, MBEDTLS_MD_SHA256,hash, 32, pkcs7->signed_data.signers.sig.p, pkcs7->signed_data.signers.sig.len);

       printf("rc is %02x\n", rc);

       return rc;
}

#endif
