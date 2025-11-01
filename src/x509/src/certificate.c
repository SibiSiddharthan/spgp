/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/x509.h>
#include <x509/asn1.h>
#include <buffer.h>

#include <stdlib.h>
#include <string.h>

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

x509_error_t x509_certificate_read_interntal(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};

	// Certificate Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// TBS Certificate Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// TBS Certificate Version
	ASN1_PARSE(asn1_field_read(&field, 0, 0, ASN1_FLAG_CONTEXT_TAG, in, &remaining));
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_INTEGER, 0, in, &remaining));

	if (field.size > 1)
	{
		return X509_UNKNOWN_VERSION;
	}

	certificate->version = *(byte_t *)field.data;

	if (certificate->version != X509_CERTIFICATE_V1 && certificate->version != X509_CERTIFICATE_V2 &&
		certificate->version != X509_CERTIFICATE_V3)
	{
		return X509_UNKNOWN_VERSION;
	}

	return X509_SUCCESS;
}

x509_error_t x509_certificate_read(x509_certificate **certificate, void *data, size_t *size)
{
	x509_error_t x509_error = 0;

	*certificate = malloc(sizeof(x509_certificate));

	if (*certificate == NULL)
	{
		return X509_NO_MEMORY;
	}

	memset(*certificate, 0, sizeof(x509_certificate));

	x509_error = x509_certificate_read_interntal(*certificate, data, size);

	if (x509_error != X509_SUCCESS)
	{
		free(*certificate);
		return x509_error;
	}

	return X509_SUCCESS;
}
