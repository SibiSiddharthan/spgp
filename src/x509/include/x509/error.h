/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_ERROR_H
#define X509_ERROR_H

#include <types.h>

typedef enum _asn1_error_t
{
	ASN1_SUCCESS = 0,

	ASN1_INSUFFICIENT_DATA,
	ASN1_FIELD_LENGTH_TOO_BIG,

	ASN1_UNKNOWN_UNIVERSAL_TYPE,
	ASN1_INVALID_LENGTH_SPECIFICATION,
	ASN1_CONTEXT_MISMATCH,
	ASN1_TYPE_MISMATCH,
} asn1_error_t;

typedef enum _x509_error_t
{
	X509_SUCCESS = 0,

	X509_NO_MEMORY,
	X509_INSUFFICIENT_DATA,
	X509_INVALID_CERTIFICATE,

	X509_UNKNOWN_VERSION,
	X509_SERIAL_NUMBER_TOO_BIG,
	X509_INVALID_VALIDITY,

} x509_error_t;

#endif
