/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef ASN1_ERROR_H
#define ASN1_ERROR_H

typedef enum _asn1_error_t
{
	ASN1_SUCCESS = 0,

	ASN1_FIELD_LENGTH_TOO_BIG,
	ASN1_INSUFFICIENT_DATA,

	ASN1_UNKNOWN_UNIVERSAL_TYPE,
	ASN1_INVALID_LENGTH_SPECIFICATION,
	ASN1_CONTEXT_MISMATCH,
} asn1_error_t;

#endif
