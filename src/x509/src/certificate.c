/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/x509.h>
#include <x509/asn1.h>
#include <x509/oid.h>

#include <ptr.h>

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

#define X509_PARSE(EXPR)                    \
	{                                       \
		x509_error_t __x509_error = (EXPR); \
                                            \
		if (__x509_error != X509_SUCCESS)   \
		{                                   \
                                            \
			return __x509_error;            \
		}                                   \
	}

static x509_error_t x509_certificate_parse_version(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};

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

	*size = remaining;

	return X509_SUCCESS;
}

static x509_error_t x509_certificate_parse_serial_number(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	byte_t msb = 0;
	byte_t zero[20] = {0};

	asn1_field field = {0};

	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_INTEGER, 0, in, &remaining));

	msb = *(byte_t *)field.data;

	// Check size
	if (field.size > 20)
	{
		return X509_SERIAL_NUMBER_TOO_BIG;
	}

	// Check negative
	if (msb & 0x80)
	{
		return X509_SERIAL_NUMBER_NEGATIVE;
	}

	if (msb == 0)
	{
		memcpy(certificate->serial_number, PTR_OFFSET(field.data, 1), field.size - 1);
		certificate->serial_number_size = field.size - 1;
	}
	else
	{
		memcpy(certificate->serial_number, field.data, field.size);
		certificate->serial_number_size = field.size;
	}

	// Check zero
	if (memcmp(certificate->serial_number, zero, certificate->serial_number_size) == 0)
	{
		return X509_SERIAL_NUMBER_ZERO;
	}

	*size = remaining;

	return X509_SUCCESS;
}

static x509_error_t x509_parse_signature_algorithm(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};

	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_OBJECT_IDENTIFIER, 0, in, &remaining));

	certificate->signature_algorithm = x509_signature_oid_decode(field.data, field.size);

	if (certificate->signature_algorithm == X509_SIG_RESERVED)
	{
		return X509_UNKNOWN_SIGNATURE_ALGORITHM;
	}

	return X509_SUCCESS;
}

static x509_error_t x509_parse_name(x509_rdn **names, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};

	// RDNSequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	while (pos < remaining)
	{
		size_t inner_remaining = 0;
		size_t inner_pos = 0;

		// Relatively Distinguised Name
		ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SET, 0, in, &inner_remaining));

		while (inner_pos < inner_remaining)
		{
			size_t length = 0;

			// Attribute
			ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &length));

			// Type
			ASN1_PARSE(asn1_field_read(&field, 0, ASN1_OBJECT_IDENTIFIER, 0, in, &remaining));

			// Value
			ASN1_PARSE(asn1_field_read(&field, 0, 0, 0, in, &remaining));
		}
	}

	return X509_SUCCESS;
}

#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')
#define TO_DIGIT(x) ((x) - '0')

static uint64_t x509_parse_validity_time(asn1_field *field)
{
	byte_t *data = field->data;
	size_t size = field->size;
	uint32_t offset = 0;

	uint64_t epoch = 0;
	uint32_t year = 0;
	uint32_t month = 0;
	uint32_t day = 0;
	uint32_t hour = 0;
	uint32_t minute = 0;
	uint32_t second = 0;

	for (size_t i = 0; i + 1 < field->size; ++i)
	{
		if (!IS_DIGIT(data[i]))
		{
			return UINT64_MAX;
		}
	}

	if (data[size - 1] != 'Z')
	{
		return UINT64_MAX;
	}

	if (field->tag == ASN1_UTC_TIME)
	{
		if (field->size != 13)
		{
			return UINT64_MAX;
		}

		year = (TO_DIGIT(data[0]) * 10) + TO_DIGIT(data[1]);

		if (year >= 50)
		{
			year += 1900;
		}
		else
		{
			year += 2000;
		}

		offset = 2;
	}

	if (field->tag == ASN1_GENERAL_TIME)
	{
		if (field->size != 15)
		{
			return UINT64_MAX;
		}

		year = (TO_DIGIT(data[0]) * 1000) + (TO_DIGIT(data[1]) * 100) + (TO_DIGIT(data[2]) * 10) + TO_DIGIT(data[3]);
		offset = 4;
	}

	// Start of epoch is 0 AD. Assume leap year
	// Year
	epoch = year * 31536000;
	epoch += ((year / 4) + 1) * 86400;

	// Month
	month = (TO_DIGIT(data[offset + 0]) * 10) + TO_DIGIT(data[offset + 1]);
	offset += 2;

	switch (month)
	{
	case 1:
		break;
	case 2:
		epoch += 31 * 86400;
		break;
	case 3:
		epoch += 59 * 86400;
		break;
	case 4:
		epoch += 90 * 86400;
		break;
	case 5:
		epoch += 120 * 86400;
		break;
	case 6:
		epoch += 151 * 86400;
		break;
	case 7:
		epoch += 181 * 86400;
		break;
	case 8:
		epoch += 212 * 86400;
		break;
	case 9:
		epoch += 243 * 86400;
		break;
	case 10:
		epoch += 273 * 86400;
		break;
	case 11:
		epoch += 304 * 86400;
		break;
	case 12:
		epoch += 334 * 86400;
		break;
	default:
		return UINT64_MAX;
	}

	if (year % 4 == 0)
	{
		if (month > 2)
		{
			epoch += 86400;
		}
	}

	// Day
	day = (TO_DIGIT(data[offset + 0]) * 10) + TO_DIGIT(data[offset + 1]);
	epoch += day * 86400;
	offset += 2;

	if (day == 0)
	{
		return UINT64_MAX;
	}

	if (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12)
	{
		if (day > 31)
		{
			return UINT64_MAX;
		}
	}
	else
	{
		if (month == 2)
		{
			if (year % 4 == 0)
			{
				if (day > 29)
				{
					return UINT64_MAX;
				}
			}
			else
			{
				if (day > 28)
				{
					return UINT64_MAX;
				}
			}
		}
		else
		{
			if (day > 30)
			{
				return UINT64_MAX;
			}
		}
	}

	// Hours
	hour = (TO_DIGIT(data[offset + 0]) * 10) + TO_DIGIT(data[offset + 1]);
	epoch += hour * 3600;
	offset += 2;

	if (hour >= 24)
	{
		return UINT64_MAX;
	}

	// Minutes
	minute = (TO_DIGIT(data[offset + 0]) * 10) + TO_DIGIT(data[offset + 1]);
	epoch += minute * 60;
	offset += 2;

	if (minute >= 60)
	{
		return UINT64_MAX;
	}

	// Seconds
	second = (TO_DIGIT(data[offset + 0]) * 10) + TO_DIGIT(data[offset + 1]);
	epoch += second;
	offset += 2;

	if (second >= 60)
	{
		return UINT64_MAX;
	}

	return epoch;
}

static x509_error_t x509_parse_certificate_validity(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};
	asn1_field start = {0};
	asn1_field end = {0};

	// Validity Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// Validity Start (Not Before)
	ASN1_PARSE(asn1_field_read(&start, 0, 0, 0, in, &remaining));

	// Validity End (Not After)
	ASN1_PARSE(asn1_field_read(&end, 0, 0, 0, in, &remaining));

	if ((start.tag != ASN1_UTC_TIME && start.tag != ASN1_GENERAL_TIME) || (end.tag != ASN1_UTC_TIME && end.tag != ASN1_GENERAL_TIME))
	{
		return X509_INVALID_CERTIFICATE;
	}

	certificate->validity_start = x509_parse_validity_time(&start);
	certificate->validity_end = x509_parse_validity_time(&end);

	if (certificate->validity_start == UINT64_MAX || certificate->validity_end == UINT64_MAX)
	{
		return X509_INVALID_VALIDITY;
	}

	if (certificate->validity_end < certificate->validity_start)
	{
		return X509_INVALID_VALIDITY;
	}

	return X509_SUCCESS;
}

static x509_error_t x509_certificate_parse_tbs_certificate(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};

	// TBS Certificate Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// TBS Certificate Version
	X509_PARSE(x509_certificate_parse_version(certificate, in, &remaining));

	// TBS Certificate Serial Number
	X509_PARSE(x509_certificate_parse_serial_number(certificate, in, &remaining));

	// TBS Signature Algorithm
	X509_PARSE(x509_parse_signature_algorithm(certificate, in, &remaining));

	// TBS Certificate Issuer
	X509_PARSE(x509_parse_name(&certificate->issuer, in, &remaining));

	// TBS Certificate Validity
	X509_PARSE(x509_parse_certificate_validity(certificate, in, &remaining));

	// TBS Certificate Subject
	X509_PARSE(x509_parse_name(&certificate->subject, in, &remaining));

	*size = remaining;

	return X509_SUCCESS;
}

static x509_error_t x509_certificate_read_internal(x509_certificate *certificate, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;
	size_t remaining = *size;

	asn1_field field = {0};

	// Certificate Sequence
	ASN1_PARSE(asn1_field_read(&field, 0, ASN1_SEQUENCE, 0, in, &remaining));

	// TBS Certificate
	X509_PARSE(x509_certificate_parse_tbs_certificate(certificate, data, &remaining));

	// Signature Algorithm
	X509_PARSE(x509_parse_signature_algorithm(certificate, in, &remaining));

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

	x509_error = x509_certificate_read_internal(*certificate, data, size);

	if (x509_error != X509_SUCCESS)
	{
		free(*certificate);
		return x509_error;
	}

	return X509_SUCCESS;
}
