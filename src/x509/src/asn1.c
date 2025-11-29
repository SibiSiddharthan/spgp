/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <x509/asn1.h>
#include <stdlib.h>
#include <string.h>

#include <ptr.h>
#include <minmax.h>

static size_t asn1_required_header_size(asn1_field *field)
{
	size_t required_size = 2; // tag, length

	if (field->data_size > 126)
	{
		size_t size = field->data_size;

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

		field->tag = tag;
	}
	else
	{
		field->tag = tag;
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

		field->header_size = 1 + length;

		for (byte_t i = 0; i < length; ++i)
		{
			field->data_size = (field->data_size << 8) + *in++;
			pos += 1;
		}
	}
	else
	{
		field->header_size = 2;
		field->data_size = length;
	}

	*size = pos;

	return ASN1_SUCCESS;
}

static size_t asn1_header_write_checked(asn1_field *field, void *buffer)
{
	byte_t *out = buffer;
	size_t pos = 0;

	// Tag
	*out++ = field->tag;
	pos += 1;

	// Length
	pos += asn1_encode_size(out, field->data_size);

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

asn1_error_t asn1_field_read(asn1_field *field, byte_t context, byte_t type, byte_t flags, void *data, size_t *size)
{
	asn1_error_t error = 0;
	size_t pos = *size;

	error = asn1_header_read(field, data, &pos);

	if (error != ASN1_SUCCESS)
	{
		return error;
	}

	if (*size - pos < field->data_size)
	{
		return ASN1_INSUFFICIENT_DATA;
	}

	if (flags)
	{
		byte_t tag = (flags & (~ASN1_FLAG_IMPLICIT_TAG)) | context;

		if ((flags & ASN1_FLAG_IMPLICIT_TAG) == 0)
		{
			tag |= ASN1_FLAG_CONSTRUCTED_TAG;
		}

		if (field->tag != tag)
		{
			return ASN1_CONTEXT_MISMATCH;
		}

		if (flags & ASN1_FLAG_IMPLICIT_TAG)
		{
			if (flags & ASN1_FLAG_CONSTRUCTED_TAG)
			{
				// Implicit sequence or set
				goto end;
			}
			else
			{
				// Implicit other types
				field->data = PTR_OFFSET(data, pos);
				pos += field->data_size;

				goto end;
			}
		}

		// Unwrap the other header and return
		goto end;
	}

	if (type != 0)
	{
		if (field->tag != type)
		{
			return ASN1_TYPE_MISMATCH;
		}
	}

	if (ASN1_PRIMITIVE_TAG(field->tag))
	{
		field->data = PTR_OFFSET(data, pos);
		pos += field->data_size;
	}

end:
	*size = pos;

	return ASN1_SUCCESS;
}

size_t asn1_field_write(asn1_field *field, void *buffer, size_t size)
{
	size_t required_size = field->header_size + field->data_size;
	size_t pos = 0;

	if (size < required_size)
	{
		return 0;
	}

	pos += asn1_header_write_checked(field, buffer);

	switch (field->tag)
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
	case ASN1_TELETEX_STRING:
	case ASN1_IA5_STRING:
	case ASN1_UNIVERSAL_STRING:
	case ASN1_BMP_STRING:
	{
		memcpy(PTR_OFFSET(buffer, pos), field->data, field->data_size);
		pos += field->data_size;
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
		memcpy(PTR_OFFSET(buffer, pos), field->data, field->data_size);
		pos += field->data_size;
	}
	break;
	}

	return pos;
}

#define ASN1_STACK_DEPTH 16

typedef struct _asn1_stack
{
	uint32_t top;
	uint32_t size;
	size_t *st;
} asn1_stack;

static asn1_stack *asn1_stack_new()
{
	asn1_stack *stack = NULL;
	uint32_t size = ASN1_STACK_DEPTH;

	stack = malloc(sizeof(asn1_stack) + (sizeof(size_t) * size));

	if (stack == NULL)
	{
		return NULL;
	}

	memset(stack, 0, sizeof(asn1_stack) + (sizeof(size_t) * size));

	stack->size = size;
	stack->st = PTR_OFFSET(stack, sizeof(asn1_stack));

	return stack;
}

static void asn1_stack_delete(asn1_stack *stack)
{
	free(stack);
}

static size_t asn1_stack_top(asn1_stack *stack)
{
	return stack->st[stack->top];
}

static asn1_error_t asn1_stack_pop(asn1_stack *stack)
{
	if (stack->top == 0)
	{
		return ASN1_STACK_OVERFLOW;
	}

	stack->st[stack->top--] = 0;

	return ASN1_SUCCESS;
}

static asn1_error_t asn1_stack_push(asn1_stack *stack, size_t value)
{
	if (stack->top == ASN1_STACK_DEPTH)
	{
		return ASN1_STACK_OVERFLOW;
	}

	stack->st[stack->top++] = value;

	return ASN1_SUCCESS;
}

asn1_reader *asn1_reader_new(void *data, size_t size)
{
	asn1_reader *reader = NULL;
	asn1_stack *stack = NULL;

	reader = malloc(sizeof(asn1_reader));
	stack = asn1_stack_new();

	if (reader == NULL || stack == NULL)
	{
		free(reader);
		free(stack);

		return NULL;
	}

	reader->stack = stack;
	reader->start = data;
	reader->data = data;
	reader->pos = 0;
	reader->size = size;

	return reader;
}

void asn1_reader_delete(asn1_reader *reader)
{
	if (reader != NULL)
	{
		free(reader->stack);
		free(reader);
	}
}

asn1_error_t asn1_reader_push(asn1_reader *reader, byte_t type, byte_t context, byte_t flags)
{
	asn1_error_t error = 0;
	asn1_field field = {0};

	if (context == 0)
	{
		error = asn1_field_read(&field, 0, type, 0, PTR_OFFSET(reader->data, reader->pos), reader->size);
	}
	else
	{
		error = asn1_field_read(&field, context, 0, 0, PTR_OFFSET(reader->data, reader->pos), reader->size);

		if ((flags & ASN1_FLAG_IMPLICIT_TAG) == 0)
		{
		}
		else
		{
			error = asn1_field_read(&field, context, 0, 0, PTR_OFFSET(reader->data, reader->pos), reader->size);
		}
	}

	if (error != ASN1_SUCCESS)
	{
		return error;
	}

	error = asn1_stack_push(reader->stack, reader->size);

	if (error != ASN1_SUCCESS)
	{
		return error;
	}

	reader->data = PTR_OFFSET(reader->data, field.data_size);
	reader->pos = 0;
	reader->size = field.data_size;

	return ASN1_SUCCESS;
}

asn1_error_t asn1_reader_pop(asn1_reader *reader)
{
	if (reader->pos != reader->size)
	{
		return ASN1_LENGTH_MISMATCH;
	}

	reader->size = asn1_stack_top(reader->stack);
	reader->pos += reader->size;

	if (asn1_stack_pop(reader->stack) != ASN1_SUCCESS)
	{
		return ASN1_STACK_OVERFLOW;
	}

	return ASN1_SUCCESS;
}
