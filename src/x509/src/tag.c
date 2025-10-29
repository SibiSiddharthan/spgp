/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <asn1/tag.h>

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
}

size_t asn1_header_write(asn1_field *field, void *data, size_t size)
{
	size_t required_size = asn1_required_header_size(field);
	byte_t *out = data;
	size_t pos = 0;

	if (size < required_size)
	{
		return 0;
	}

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

	pos += asn1_encode_size(out, field->size);

	return pos;
}
