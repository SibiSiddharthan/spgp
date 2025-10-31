/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <asn1/tag.h>
#include <string.h>

#include <ptr.h>

static size_t asn1_required_header_size(asn1_field *field)
{
	size_t required_size = 2; // tag, length

	if (field->context)
	{
		if (ASN1_CONSTRUCTED_TAG(field->context))
		{
			required_size += 1; // context tag
		}
	}

	if (field->size > 126)
	{
		size_t size = field->size;

		do
		{
			required_size += 1;
			size >>= 8;

		} while (size != 0);
	}

	return required_size;
}

static byte_t asn1_validate_type(byte_t tag)
{
	switch (tag)
	{
	case ASN1_INTEGER:
	case ASN1_BIT_STRING:
	case ASN1_OCTET_STRING:
	case ASN1_NULL:
	case ASN1_OBJECT_IDENTIFIER:
	case ASN1_UTF8_STRING:
	case ASN1_PRINTABLE_STRING:
	case ASN1_IA5_STRING:
	case ASN1_UTC_TIME:
	case ASN1_GENERAL_TIME:
	case ASN1_SEQUENCE:
	case ASN1_SET:
		return 1;
	default:
		return 0;
	}
}

static size_t asn1_encode_size(void *data, size_t size)
{
	byte_t *out = data;
	byte_t pos = 0;

	byte_t buffer[8] = {0};

	if (size <= 126)
	{
		*out = (byte_t)size;
		return 1;
	}

	do
	{
		buffer[pos++] = size & 0xFF;
		size >>= 8;

	} while (size != 0);

	*out++ = pos;

	for (byte_t i = 0; i < pos; ++i)
	{
		*out++ = buffer[(pos - i) - 1];
	}

	return pos + 1;
}

asn1_error_t asn1_header_read(asn1_field *field, void *data, size_t *size)
{
	byte_t *in = data;
	size_t pos = 0;

	byte_t tag = 0;
	byte_t length = 0;

	memset(field, 0, sizeof(asn1_field));

	if (*size < 2)
	{
		return ASN1_INSUFFICIENT_DATA;
	}

	tag = *in++;
	pos += 1;

	if (ASN1_UNIVERSAL_TAG(tag))
	{
		if (asn1_validate_type(tag) == 0)
		{
			return ASN1_UNKNOWN_UNIVERSAL_TYPE;
		}

		field->type = tag;
	}
	else if (ASN1_CONTEXT_TAG(tag))
	{
		field->context = tag;

		if (ASN1_CONSTRUCTED_TAG(tag))
		{
			tag = *in++;
			pos += 1;

			if (asn1_validate_type(tag) == 0)
			{
				return ASN1_UNKNOWN_UNIVERSAL_TYPE;
			}

			field->type = tag;
		}
	}
	else
	{
		field->type = tag;
	}

	if (pos + 1 > *size)
	{
		return ASN1_INSUFFICIENT_DATA;
	}

	length = *in++;
	pos += 1;

	if (length > 126)
	{
		length = length & 0x7F;

		if (length == 127)
		{
			return ASN1_INVALID_LENGTH_SPECIFICATION;
		}

		if (length > 8)
		{
			return ASN1_FIELD_LENGTH_TOO_BIG;
		}

		if (pos + length > *size)
		{
			return ASN1_INSUFFICIENT_DATA;
		}

		for (byte_t i = 0; i < length; ++i)
		{
			field->size = (field->size << 8) + *in++;
			pos += 1;
		}
	}
	else
	{
		field->size = length;
	}

	*size = pos;

	return ASN1_SUCCESS;
}

static size_t asn1_header_write_checked(asn1_field *field, void *buffer)
{
	byte_t *out = buffer;
	size_t pos = 0;

	// Tag
	if (field->context)
	{
		*out++ = field->context;
		pos += 1;

		if (ASN1_CONSTRUCTED_TAG(field->context))
		{
			*out++ = field->type;
			pos += 1;
		}
	}
	else
	{
		*out++ = field->type;
		pos += 1;
	}

	// Length
	pos += asn1_encode_size(out, field->size);

	return pos;
}

size_t asn1_header_write(asn1_field *field, void *buffer, size_t size)
{
	size_t required_size = asn1_required_header_size(field);

	if (size < required_size)
	{
		return 0;
	}

	return asn1_header_write_checked(field, buffer);
}

asn1_error_t asn1_field_read(asn1_field *field, byte_t context, byte_t type, void *data, size_t *size)
{
	asn1_error_t error = 0;
	size_t pos = *size;

	error = asn1_header_read(field, data, &pos);

	if (error != ASN1_SUCCESS)
	{
		return error;
	}

	if (*size - pos < field->size)
	{
		return ASN1_INSUFFICIENT_DATA;
	}

	if (context != 0)
	{
		if (field->context != context)
		{
			return ASN1_CONTEXT_MISMATCH;
		}
	}

	if (type != 0)
	{
		if (field->type != type)
		{
			return ASN1_TYPE_MISMATCH;
		}
	}

	field->data = PTR_OFFSET(data, pos);
	pos += field->size;

	*size = pos;

	return ASN1_SUCCESS;
}

size_t asn1_field_write(asn1_field *field, void *buffer, size_t size)
{
	size_t required_size = asn1_required_header_size(field) + field->size;
	size_t pos = 0;

	if (size < required_size)
	{
		return 0;
	}

	pos += asn1_header_write_checked(field, buffer);

	switch (field->type)
	{
	case ASN1_INTEGER:
		break;
	case ASN1_NULL:
		break;
	case ASN1_OBJECT_IDENTIFIER:
		break;
	case ASN1_BIT_STRING:
	case ASN1_OCTET_STRING:
	case ASN1_UTF8_STRING:
	case ASN1_PRINTABLE_STRING:
	case ASN1_IA5_STRING:
	{
		memcpy(PTR_OFFSET(buffer, pos), field->data, field->size);
		pos += field->size;
	}
	break;
	case ASN1_UTC_TIME:
	case ASN1_GENERAL_TIME:

		break;
	case ASN1_SEQUENCE:
	case ASN1_SET:
		break;
	default:
	{
		memcpy(PTR_OFFSET(buffer, pos), field->data, field->size);
		pos += field->size;
	}
	break;
	}

	return pos;
}
