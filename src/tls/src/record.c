/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/alert.h>
#include <tls/error.h>
#include <tls/record.h>
#include <tls/version.h>
#include <tls/cs.h>
#include <tls/handshake.h>
#include <tls/memory.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

tls_error_t tls_record_header_read(tls_record_header *header, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	if (size < 5)
	{
		return TLS_INSUFFICIENT_DATA;
	}

	memset(header, 0, sizeof(tls_record_header));

	// 1 octet content type
	LOAD_8(&header->type, in + pos);
	pos += 1;

	// 2 octet protocol version
	LOAD_8(&header->version.major, in + pos);
	pos += 1;

	LOAD_8(&header->version.minor, in + pos);
	pos += 1;

	// TLS version check
	if (header->version.major == 0x03)
	{
		if (header->version.minor > 0x04)
		{
			return TLS_UNKNOWN_PROTOCOL_VERSION;
		}
	}

	// 2-octet record size
	LOAD_16BE(&header->size, in + pos);
	pos += 2;

	return TLS_SUCCESS;
}

uint32_t tls_record_header_write(tls_record_header *header, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < 5)
	{
		return 0;
	}

	// 1-octet content type
	LOAD_8(out + pos, &header->type);
	pos += 1;

	// 2-octet protocol version
	LOAD_8(out + pos, &header->version.major);
	pos += 1;

	LOAD_8(out + pos, &header->version.minor);
	pos += 1;

	// 2-octet record size
	LOAD_16BE(out + pos, &header->size);
	pos += 2;

	return pos;
}

tls_error_t tls_record_read(void **record, void *data, uint32_t size)
{
	tls_error_t error = 0;
	tls_record_header header = {0};

	error = tls_record_header_read(&header, data, size);

	if (error != TLS_SUCCESS)
	{
		return error;
	}

	switch (header.type)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		error = tls_change_cipher_spec_read_body((tls_change_cipher_spec **)record, &header, PTR_OFFSET(data, TLS_RECORD_HEADER_OCTETS),
												 header.size);
		break;
	case TLS_ALERT:
		error = tls_alert_read_body((tls_alert **)record, &header, PTR_OFFSET(data, TLS_RECORD_HEADER_OCTETS), header.size);
		break;
	case TLS_HANDSHAKE:
		error = tls_handshake_read_body(record, &header, PTR_OFFSET(data, TLS_RECORD_HEADER_OCTETS), header.size);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	if (error != TLS_SUCCESS)
	{
		return error;
	}

	return TLS_SUCCESS;
}

uint32_t tls_record_write(void *record, void *buffer, uint32_t size)
{
	tls_record_header *header = record;
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < (5 + header->size))
	{
		return 0;
	}

	pos += tls_record_header_write(header, out + pos, size - pos);

	switch (header->type)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += tls_change_cipher_spec_write_body(record, out + pos, size - pos);
		break;
	case TLS_ALERT:
		pos += tls_alert_write_body(record, out + pos, size - pos);
		break;
	case TLS_HANDSHAKE:
		pos += tls_handshake_write_body(record, out + pos, size - pos);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	return pos;
}

static size_t print_format(uint32_t indent, void *str, size_t size, const char *format, ...)
{
	size_t pos = 0;

	va_list args;
	va_start(args, format);

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "%*s", indent * 4, "");
	pos += vsnprintf(PTR_OFFSET(str, pos), size - pos, format, args);

	va_end(args);

	return pos;
}

static uint32_t print_record_header(tls_record_header *header, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;
	char *version = NULL;

	switch (TLS_VERSION_RAW(header->version))
	{
	case TLS_VERSION_1_0:
		version = "TLS 1.0";
		break;
	case TLS_VERSION_1_1:
		version = "TLS 1.1";
		break;
	case TLS_VERSION_1_2:
		version = "TLS 1.2";
		break;
	case TLS_VERSION_1_3:
		version = "TLS 1.3";
		break;
	default:
		version = "Unknown";
		break;
	}

	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*s", indent * 4, "");

	switch (header->type)
	{
	case TLS_INVALID_CONTENT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Invalid Content Type (ID 0) (%hu bytes) ", header->size);
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Cipher Specification Change (ID 20) (%hu bytes) ", header->size);
		break;
	case TLS_ALERT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Alert (ID 21) (%hu bytes) ", header->size);
		break;
	case TLS_HANDSHAKE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Handshake (ID 22) (%hu bytes) ", header->size);
		break;
	case TLS_APPLICATION_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Application Data (ID 23) (%hu bytes) ", header->size);
		break;
	case TLS_HEARTBEAT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Heartbeat (ID 24) (%hu bytes) ", header->size);
		break;
	case TLS_CID:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Content Identifier (ID 25) (%hu bytes) ", header->size);
		break;
	case TLS_ACK:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Acknowledge (ID 26) (%hu bytes) ", header->size);
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu) (%hu bytes) ", header->type, header->size);
		break;
	}

	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "(%s)\n", version);

	return pos;
}

uint32_t tls_record_print(void *record, void *buffer, uint32_t size, uint32_t indent)
{
	tls_record_header *header = record;
	uint32_t pos = 0;

	pos += print_record_header(header, PTR_OFFSET(buffer, pos), size - pos, indent);

	switch (header->type)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += tls_change_cipher_spec_print(record, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_ALERT:
		pos += tls_alert_print(record, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_HANDSHAKE:
		pos += tls_handshake_print(record, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	return pos;
}
