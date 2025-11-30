/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef X509_ASN1_H
#define X509_ASN1_H

#include <x509/error.h>

// Tag Classes
#define ASN1_UNIVERSAL_TAG(T)   (((T) >> 6) == 0x00)
#define ASN1_APPLICATION_TAG(T) (((T) >> 6) == 0x01)
#define ASN1_CONTEXT_TAG(T)     (((T) >> 6) == 0x02)
#define ASN1_PRIVATE_TAG(T)     (((T) >> 6) == 0x03)

// Tag Construction
#define ASN1_PRIMITIVE_TAG(T)   ((((T) >> 5) & 0x1) == 0x0)
#define ASN1_CONSTRUCTED_TAG(T) ((((T) >> 5) & 0x1) == 0x1)

// Tag Flags
#define ASN1_FLAG_IMPLICIT_TAG    0x01
#define ASN1_FLAG_CONSTRUCTED_TAG 0x20

#define ASN1_FLAG_APPLICATION_TAG 0x40
#define ASN1_FLAG_CONTEXT_TAG     0x80
#define ASN1_FLAG_PRIVATE_TAG     0xC0

typedef enum _asn1_type
{
	ASN1_INTEGER = 0x02,
	ASN1_BIT_STRING = 0x03,
	ASN1_OCTET_STRING = 0x04,
	ASN1_NULL = 0x05,
	ASN1_OBJECT_IDENTIFIER = 0x06,
	ASN1_UTF8_STRING = 0x0C,
	ASN1_PRINTABLE_STRING = 0x13,
	ASN1_TELETEX_STRING = 0x14,
	ASN1_IA5_STRING = 0x16,
	ASN1_UTC_TIME = 0x17,
	ASN1_GENERAL_TIME = 0x18,
	ASN1_UNIVERSAL_STRING = 0x1C,
	ASN1_BMP_STRING = 0x1E,
	ASN1_SEQUENCE = 0x30,
	ASN1_SET = 0x31

} asn1_type;

typedef struct _asn1_field
{
	byte_t tag;
	byte_t header_size;
	size_t data_size;
	void *data;

} asn1_field;

asn1_error_t asn1_header_read(asn1_field *field, void *data, size_t size);
size_t asn1_header_write(asn1_field *field, void *buffer, size_t size);

asn1_error_t asn1_field_read(asn1_field *field, byte_t type, byte_t context, byte_t flags, void *data, size_t size);
size_t asn1_field_write(asn1_field *field, void *buffer, size_t size);

typedef struct _asn1_reader
{
	void *stack;
	void *data;
	size_t size;

	void *current_start;
	size_t current_pos;
	size_t current_size;

} asn1_reader;

asn1_reader *asn1_reader_new(void *data, size_t size);
void asn1_reader_delete(asn1_reader *reader);

asn1_error_t asn1_reader_push(asn1_reader *reader, byte_t type, byte_t context, byte_t flags);
asn1_error_t asn1_reader_pop(asn1_reader *reader);

asn1_error_t asn1_reader_read(asn1_reader *reader, asn1_field *field, byte_t context, byte_t type, byte_t flags);

#endif
