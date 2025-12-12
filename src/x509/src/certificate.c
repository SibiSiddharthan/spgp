/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/x509.h>
#include <x509/asn1.h>
#include <x509/oid.h>
#include <x509/memory.h>

#include <ptr.h>
#include <round.h>
#include <minmax.h>

// Refer RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

#define ASN1_PARSE(EXPR)                                \
	{                                                   \
		asn1_error_t __asn1_error = (EXPR);             \
                                                        \
		if (__asn1_error != ASN1_SUCCESS)               \
		{                                               \
			if (__asn1_error == ASN1_INSUFFICIENT_DATA) \
			{                                           \
				return X509_INSUFFICIENT_DATA;          \
			}                                           \
                                                        \
			if (__asn1_error == ASN1_NO_MEMEORY)        \
			{                                           \
				return X509_NO_MEMORY;                  \
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

static x509_error_t x509_certificate_parse_version(x509_certificate *certificate, asn1_reader *reader)
{
	asn1_error_t error = 0;
	asn1_field field = {0};

	error = asn1_reader_read(reader, &field, 0, 0, ASN1_FLAG_CONTEXT_TAG | ASN1_FLAG_OPTIONAL);

	if (error != ASN1_SUCCESS)
	{
		// Default
		certificate->version = X509_CERTIFICATE_V1;
		return X509_SUCCESS;
	}

	error = asn1_reader_read(reader, &field, ASN1_INTEGER, 0, 0);

	if (error != ASN1_SUCCESS)
	{
		return X509_INVALID_CERTIFICATE;
	}

	if (field.data_size > 1)
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

static x509_error_t x509_certificate_parse_serial_number(x509_certificate *certificate, asn1_reader *reader)
{
	byte_t msb = 0;
	byte_t zero[20] = {0};

	asn1_field field = {0};

	ASN1_PARSE(asn1_reader_read(reader, &field, ASN1_INTEGER, 0, 0));

	msb = *(byte_t *)field.data;

	// Check size
	if (field.data_size > 20)
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
		memcpy(certificate->serial_number, PTR_OFFSET(field.data, 1), field.data_size - 1);
		certificate->serial_number_size = field.data_size - 1;
	}
	else
	{
		memcpy(certificate->serial_number, field.data, field.data_size);
		certificate->serial_number_size = field.data_size;
	}

	// Check zero
	if (memcmp(certificate->serial_number, zero, certificate->serial_number_size) == 0)
	{
		return X509_SERIAL_NUMBER_ZERO;
	}

	return X509_SUCCESS;
}

static x509_error_t x509_name_new(x509_name **name, asn1_field *type, asn1_field *value)
{
	if (value->tag != ASN1_TELETEX_STRING && value->tag != ASN1_PRINTABLE_STRING && value->tag != ASN1_UNIVERSAL_STRING &&
		value->tag != ASN1_UTF8_STRING && value->tag != ASN1_BMP_STRING)
	{
		return X509_UNKNOWN_DIRECTORY_STRING_TYPE;
	}

	*name = zmalloc(sizeof(x509_name) + value->data_size);

	if (*name == NULL)
	{
		return X509_NO_MEMORY;
	}

	(*name)->attribute_type = x509_rdn_oid_decode(type->data, type->data_size);
	(*name)->value_type = value->tag;

	memcpy((*name)->oid, type->data, type->data_size);
	(*name)->oid_size = type->data_size;

	(*name)->value = PTR_OFFSET(*name, sizeof(x509_name));
	(*name)->value_size = value->data_size;
	memcpy((*name)->value, value->data, value->data_size);

	return X509_SUCCESS;
}

static x509_error_t x509_parse_name(x509_name **name, asn1_reader *reader)
{
	asn1_field type = {0};
	asn1_field value = {0};

	// Attribute Start
	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	// Type
	ASN1_PARSE(asn1_reader_read(reader, &type, ASN1_OBJECT_IDENTIFIER, 0, 0));

	// Value
	ASN1_PARSE(asn1_reader_read(reader, &value, 0, 0, 0));

	// Attribute End
	ASN1_PARSE(asn1_reader_pop(reader));

	// Create the name
	X509_PARSE(x509_name_new(name, &type, &value));

	return X509_SUCCESS;
}

static x509_error_t x509_parse_rdn(x509_rdn **names, asn1_reader *reader)
{
	x509_rdn *root = NULL;

	root = zmalloc(sizeof(x509_rdn));

	if (root == NULL)
	{
		return X509_NO_MEMORY;
	}

	*names = root;

	// RDNSequence Start
	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	while (asn1_reader_pending(reader))
	{
		x509_name *level = NULL;
		x509_name *current = NULL;

		// Relatively Distinguised Name Start
		ASN1_PARSE(asn1_reader_push(reader, ASN1_SET, 0, 0));

		while (asn1_reader_pending(reader))
		{
			x509_name *name = NULL;

			X509_PARSE(x509_parse_name(&name, reader));

			if (level == NULL)
			{
				level = name;
				current = level;
			}
			else
			{
				current->next = name;
				current = current->next;
			}
		}

		// Relatively Distinguised Name End
		ASN1_PARSE(asn1_reader_pop(reader));

		root->name = level;
		root->next = zmalloc(sizeof(x509_rdn));

		if (root->next == NULL)
		{
			return X509_NO_MEMORY;
		}

		root = root->next;
	}

	// RDNSequence End
	ASN1_PARSE(asn1_reader_pop(reader));

	return X509_SUCCESS;
}

static asn1_error_t asn1_parse_bit_string(asn1_bitstring **uid, asn1_field *field)
{
	asn1_bitstring *octets = NULL;
	uint32_t unused_bits = ((byte_t *)field->data)[0];
	uint32_t used_bits = ((field->data_size - 1) * 8) - unused_bits;

	if (unused_bits > 8)
	{
		return ASN1_INVALID_OCTET_STRING;
	}

	if (field->data_size < 2)
	{
		return ASN1_INVALID_OCTET_STRING;
	}

	octets = zmalloc(sizeof(asn1_bitstring) + (field->data_size - 1));

	if (octets == NULL)
	{
		return ASN1_NO_MEMEORY;
	}

	octets->bits = used_bits;
	octets->data = PTR_OFFSET(octets, sizeof(asn1_bitstring));

	memcpy(octets->data, PTR_OFFSET(field->data, 1), field->data_size - 1);

	*uid = octets;

	return ASN1_SUCCESS;
}

static x509_error_t x509_parse_uid(x509_certificate *certificate, asn1_bitstring **uid, asn1_reader *reader, uint32_t context)
{
	asn1_error_t error = 0;
	asn1_field field = {0};

	error = asn1_reader_read(reader, &field, 0, context, ASN1_FLAG_IMPLICIT_TAG | ASN1_FLAG_OPTIONAL);

	if (error == ASN1_SUCCESS)
	{
		// The unique identifiers should only present in V2 and V3 certificates.
		if (certificate->version == X509_CERTIFICATE_V1)
		{
			return X509_INVALID_CERTIFICATE;
		}

		error = asn1_parse_bit_string(uid, &field);

		if (error != ASN1_SUCCESS)
		{
			return X509_INVALID_CERTIFICATE;
		}
	}

	return X509_SUCCESS;
}

static x509_error_t x509_parse_public_key(x509_certificate *certificate, asn1_reader *reader)
{
	asn1_field algorithm = {0};
	asn1_field public_key = {0};

	// Public Key Info Sequence Start
	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	// Signature Algorithm
	ASN1_PARSE(asn1_reader_read(reader, &algorithm, ASN1_OBJECT_IDENTIFIER, 0, 0));

	// Public Key
	ASN1_PARSE(asn1_reader_read(reader, &public_key, ASN1_BIT_STRING, 0, 0));

	// Public Key Info Sequence End
	ASN1_PARSE(asn1_reader_pop(reader));

	certificate->certificate_algorithm = x509_algorithm_oid_decode(algorithm.data, algorithm.data_size);

	if (certificate->signature_algorithm == X509_RESERVED)
	{
		return X509_UNKNOWN_SIGNATURE_ALGORITHM;
	}

	ASN1_PARSE(asn1_parse_bit_string(&certificate->public_key, &public_key));

	return X509_SUCCESS;
}

static x509_error_t x509_parse_extensions(x509_certificate *certificate, asn1_reader *reader)
{
	asn1_error_t error = 0;
	asn1_field field = {0};

	error = asn1_reader_read(reader, &field, 0, 3, ASN1_FLAG_OPTIONAL);

	if (error != ASN1_SUCCESS)
	{
		return X509_SUCCESS;
	}

	// Extensions are only allowed in V3 certificates.
	if (certificate->version != X509_CERTIFICATE_V3)
	{
		return X509_INVALID_CERTIFICATE;
	}

	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	while (asn1_reader_pending(reader))
	{
		asn1_field type = {0};
		asn1_field criticial = {0};
		asn1_field octets = {0};

		// Extension Identifier
		error = asn1_reader_read(reader, &type, ASN1_OBJECT_IDENTIFIER, 0, 0);

		if (error != ASN1_SUCCESS)
		{
			return X509_INVALID_CERTIFICATE;
		}

		// Criticality
		error = asn1_reader_read(reader, &criticial, ASN1_BOOLEAN, 0, ASN1_FLAG_OPTIONAL);

		if (error != ASN1_SUCCESS)
		{
		}

		// Extension
		error = asn1_reader_read(reader, &octets, ASN1_OCTET_STRING, 0, 0);

		if (error != ASN1_SUCCESS)
		{
			return X509_INVALID_CERTIFICATE;
		}
	}

	ASN1_PARSE(asn1_reader_pop(reader));

	return X509_SUCCESS;
}

#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')
#define TO_DIGIT(x) ((x) - '0')

static uint64_t x509_parse_validity_time(asn1_field *field)
{
	byte_t *data = field->data;
	size_t size = field->data_size;
	uint32_t offset = 0;

	uint64_t epoch = 0;
	uint32_t year = 0;
	uint32_t month = 0;
	uint32_t day = 0;
	uint32_t hour = 0;
	uint32_t minute = 0;
	uint32_t second = 0;

	for (size_t i = 0; i + 1 < field->data_size; ++i)
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
		if (field->data_size != 13)
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
		if (field->data_size != 15)
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

static x509_error_t x509_parse_certificate_validity(x509_certificate *certificate, asn1_reader *reader)
{
	asn1_field start = {0};
	asn1_field end = {0};

	// Validity Sequence Start
	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	// Validity Start (Not Before)
	ASN1_PARSE(asn1_reader_read(reader, &start, 0, 0, 0));

	// Validity End (Not After)
	ASN1_PARSE(asn1_reader_read(reader, &end, 0, 0, 0));

	// Validity Sequence End
	ASN1_PARSE(asn1_reader_pop(reader));

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

static x509_error_t x509_parse_signature_algorithm(x509_certificate *certificate, asn1_reader *reader)
{
	asn1_field field = {0};

	ASN1_PARSE(asn1_reader_read(reader, &field, ASN1_OBJECT_IDENTIFIER, 0, 0));

	certificate->signature_algorithm = x509_signature_oid_decode(field.data, field.data_size);

	if (certificate->signature_algorithm == X509_SIG_RESERVED)
	{
		return X509_UNKNOWN_SIGNATURE_ALGORITHM;
	}

	return X509_SUCCESS;
}

static x509_error_t x509_parse_signature_value(x509_certificate *certificate, asn1_reader *reader)
{
	asn1_field field = {0};

	ASN1_PARSE(asn1_reader_read(reader, &field, ASN1_BIT_STRING, 0, 0));
	ASN1_PARSE(asn1_parse_bit_string(&certificate->signature, &field));

	return X509_SUCCESS;
}

static x509_error_t x509_certificate_parse_tbs_certificate(x509_certificate *certificate, asn1_reader *reader)
{
	// TBS Certificate Sequence Start
	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	// TBS Certificate Version
	X509_PARSE(x509_certificate_parse_version(certificate, reader));

	// TBS Certificate Serial Number
	X509_PARSE(x509_certificate_parse_serial_number(certificate, reader));

	// TBS Signature Algorithm
	X509_PARSE(x509_parse_signature_algorithm(certificate, reader));

	// TBS Certificate Issuer
	X509_PARSE(x509_parse_rdn(&certificate->issuer_rdn, reader));

	// TBS Certificate Validity
	X509_PARSE(x509_parse_certificate_validity(certificate, reader));

	// TBS Certificate Subject
	X509_PARSE(x509_parse_rdn(&certificate->subject_rdn, reader));

	// TBS Public Key Info
	X509_PARSE(x509_parse_public_key(certificate, reader));

	// TBS Issuer Unique ID
	X509_PARSE(x509_parse_uid(certificate, &certificate->issuer_uid, reader, 1));

	// TBS Subject Unique ID
	X509_PARSE(x509_parse_uid(certificate, &certificate->subject_uid, reader, 2));

	// TBS Extensions
	X509_PARSE(x509_parse_extensions(certificate, reader));

	// TBS Certificate Sequence End
	ASN1_PARSE(asn1_reader_pop(reader));

	return X509_SUCCESS;
}

static x509_error_t x509_certificate_read_internal(x509_certificate *certificate, asn1_reader *reader)
{
	// Certificate Sequence Start
	ASN1_PARSE(asn1_reader_push(reader, ASN1_SEQUENCE, 0, 0));

	// TBS Certificate
	X509_PARSE(x509_certificate_parse_tbs_certificate(certificate, reader));

	// Signature Algorithm
	X509_PARSE(x509_parse_signature_algorithm(certificate, reader));

	// Signature Value
	X509_PARSE(x509_parse_signature_value(certificate, reader));

	// Certificate Sequence End
	ASN1_PARSE(asn1_reader_pop(reader));

	return X509_SUCCESS;
}

x509_error_t x509_certificate_read(x509_certificate **certificate, void *data, size_t size)
{
	x509_error_t x509_error = 0;
	asn1_reader *reader = NULL;

	reader = asn1_reader_new(data, size);
	*certificate = zmalloc(sizeof(x509_certificate));

	if (*certificate == NULL || reader == NULL)
	{
		asn1_reader_delete(reader);
		free(*certificate);

		return X509_NO_MEMORY;
	}

	x509_error = x509_certificate_read_internal(*certificate, reader);

	if (x509_error != X509_SUCCESS)
	{
		asn1_reader_delete(reader);
		free(*certificate);

		return x509_error;
	}

	asn1_reader_delete(reader);

	return X509_SUCCESS;
}

x509_certificate_chain *x509_certificate_chain_new(uint32_t capacity)
{
	x509_certificate_chain *chain = NULL;
	x509_certificate **certificates = NULL;

	// Round to multiple of 4
	capacity = ROUND_UP(MAX(capacity, 1), 4);

	chain = zmalloc(sizeof(x509_certificate_chain));
	certificates = zmalloc(sizeof(void *) * capacity);

	if (chain == NULL || certificates == NULL)
	{
		zfree(chain);
		zfree(certificates);

		return NULL;
	}

	chain->capacity = capacity;
	chain->certificates = certificates;

	return chain;
}

void x509_certificate_chain_delete(x509_certificate_chain *chain)
{
	if (chain == NULL)
	{
		return;
	}

	for (uint32_t i = 0; i < chain->count; ++i)
	{
		chain->certificates[i] = NULL;
	}
}

x509_certificate_chain *x509_certificate_chain_push(x509_certificate_chain *chain, x509_certificate *certificate)
{
	x509_certificate **temp = NULL;

	if (chain == NULL)
	{
		chain = x509_certificate_chain_new(4);

		if (chain == NULL)
		{
			return NULL;
		}
	}

	if (chain->count == chain->capacity)
	{
		chain->capacity *= 2;
		temp = zrealloc(chain->certificates, sizeof(void *) * chain->capacity);

		if (temp == NULL)
		{
			return NULL;
		}

		chain->certificates = temp;
	}

	chain->certificates[chain->count] = certificate;
	chain->count += 1;

	return chain;
}

x509_error_t x509_certificate_chain_read(x509_certificate_chain **chain, void *data, size_t size)
{
	x509_error_t error = X509_NO_MEMORY;
	asn1_reader *reader = NULL;

	*chain = x509_certificate_chain_new(4);
	reader = asn1_reader_new(data, size);

	if (*chain == NULL || reader == NULL)
	{
		goto no_memory;
	}

	while (asn1_reader_pending(reader))
	{
		void *result = NULL;
		x509_certificate *certificate = zmalloc(sizeof(x509_certificate));

		error = 0;

		if (certificate == NULL)
		{
			goto no_memory;
		}

		error = x509_certificate_read_internal(certificate, reader);

		if (error != X509_SUCCESS)
		{
			goto fail;
		}

		result = x509_certificate_chain_push(*chain, certificate);

		if (result == NULL)
		{
			goto no_memory;
		}
	}

	asn1_reader_delete(reader);

	return X509_SUCCESS;

no_memory:
	error = X509_NO_MEMORY;

fail:
	x509_certificate_chain_delete(*chain);
	asn1_reader_delete(reader);

	return error;
}
