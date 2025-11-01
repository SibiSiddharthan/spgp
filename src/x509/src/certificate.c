/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/x509.h>
#include <x509/asn1.h>
#include <buffer.h>

// Refer RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

#define ASN1_PARSE(EXPR)                                \
	{                                                   \
		asn1_error_t __asn1_error = 0;                  \
                                                        \
		__asn1_error = (EXPR);                          \
		pos += remaining;                               \
		in += pos;                                      \
		remaining = *size - pos;                        \
                                                        \
		if (__asn1_error != ASN1_SUCCESS)               \
		{                                               \
			if (__asn1_error == ASN1_INSUFFICIENT_DATA) \
			{                                           \
				return X509_INSUFFICIENT_DATA;          \
			}                                           \
                                                        \
			return X509_INVALID_CERTIFICATE;            \
		}                                               \
	}

x509_error_t x509_certificate_read(x509_certificate **certificate, void *data, size_t *size)
{
	x509_certificate *cert = NULL;
	asn1_field field = {0};

	x509_error_t x509_error = 0;

	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	// Certificate Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// TBS Certificate Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// TBS Certificate Version
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_INTEGER, ASN1_FLAG_CONTEXT_TAG, in, &remaining));

	


	return X509_SUCCESS;
}
