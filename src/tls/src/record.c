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
#include <tls/print.h>

#include <load.h>
#include <ptr.h>

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

static uint32_t print_record_header(tls_record_header *header, buffer_t *buffer, uint32_t indent)
{
	const char *version = NULL;
	const char *type = NULL;

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

	switch (header->type)
	{
	case TLS_INVALID_CONTENT:
		type = "TLS Invalid Content Type";
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		type = "TLS Cipher Specification Change";
		break;
	case TLS_ALERT:
		type = "TLS Alert";
		break;
	case TLS_HANDSHAKE:
		type = "TLS Handshake";
		break;
	case TLS_APPLICATION_DATA:
		type = "TLS Application Data";
		break;
	case TLS_HEARTBEAT:
		type = "TLS Heartbeat";
		break;
	case TLS_CID:
		type = "TLS Content Identifier";
		break;
	case TLS_ACK:
		type = "TLS Acknowledge";
		break;
	default:
		type = "Unknown";
		break;
	}

	return print_format(buffer, indent, "%s (ID %hhu) (%hu bytes) (%s)\n", type, header->type, header->size, version);
}

uint32_t tls_record_print(void *record, buffer_t *buffer, uint32_t indent)
{
	tls_record_header *header = record;
	uint32_t pos = 0;

	pos += print_record_header(header, buffer, indent);
	indent += 1;

	switch (header->type)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += tls_change_cipher_spec_print_body(record, buffer, indent);
		break;
	case TLS_ALERT:
		pos += tls_alert_print_body(record, buffer, indent);
		break;
	case TLS_HANDSHAKE:
		pos += tls_handshake_print_body(record, buffer, indent);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	return pos;
}
