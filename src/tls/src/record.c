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

void tls_record_read(tls_record **record, void *data, uint32_t size)
{
	tls_record *result = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	result = zmalloc(sizeof(tls_record));

	if (result == NULL)
	{
		return;
	}

	// 1 octet content type
	LOAD_8(&result->content, in + pos);
	pos += 1;

	// 2 octet protocol version
	LOAD_8(&result->version.major, in + pos);
	pos += 1;

	LOAD_8(&result->version.minor, in + pos);
	pos += 1;

	// 2-octet record size
	LOAD_16BE(&result->size, in + pos);
	pos += 2;

	switch (result->content)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		tls_change_cipher_spec_read(&result->data, PTR_OFFSET(data, pos), result->size);
		break;
	case TLS_ALERT:
		tls_alert_read(&result->data, PTR_OFFSET(data, pos), result->size);
		break;
	case TLS_HANDSHAKE:
		tls_handshake_read(&result->data, PTR_OFFSET(data, pos), result->size);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	*record = result;
}

uint32_t tls_record_write(tls_record *record, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < (5 + record->size))
	{
		return 0;
	}

	// 1-octet content type
	LOAD_8(out + pos, &record->content);
	pos += 1;

	// 2-octet protocol version
	LOAD_8(out + pos, &record->version.major);
	pos += 1;

	LOAD_8(out + pos, &record->version.minor);
	pos += 1;

	// 2-octet record size
	LOAD_16BE(out + pos, &record->size);
	pos += 2;

	switch (record->content)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += tls_change_cipher_spec_write(record->data, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_ALERT:
		pos += tls_alert_write(record->data, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_HANDSHAKE:
		pos += tls_handshake_write(record->data, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	return pos;
}

uint32_t tls_record_print(tls_record *record, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	// Content Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sContent Type: ", indent * 4, "");

	switch (record->content)
	{
	case TLS_INVALID_CONTENT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Invalid Content Type (ID 0)\n");
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Cipher Specification Change (ID 20)\n");
		break;
	case TLS_ALERT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Alert (ID 21)\n");
		break;
	case TLS_HANDSHAKE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Handshake (ID 22)\n");
		break;
	case TLS_APPLICATION_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Application Data (ID 23)\n");
		break;
	case TLS_HEARTBEAT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Heartbeat (ID 24)\n");
		break;
	case TLS_CID:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Content Identifier (ID 25)\n");
		break;
	case TLS_ACK:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Acknowledge (ID 26)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", record->content);
		break;
	}

	// Protocol Version
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sProtocol Version: ", indent * 4, "");

	switch (TLS_VERSION_RAW(record->version))
	{
	case TLS_VERSION_1_0:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.0 (3, 1)\n");
		break;
	case TLS_VERSION_1_1:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.1 (3, 2)\n");
		break;
	case TLS_VERSION_1_2:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.2 (3, 3)\n");
		break;
	case TLS_VERSION_1_3:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.3 (3, 4)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unkown (%hhu, %hhu)\n", record->version.major, record->version.minor);
		break;
	}

	// Record Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sRecord Size: %hu\n", indent * 4, "", record->size);

	switch (record->content)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
		pos += tls_change_cipher_spec_print(record->data, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_ALERT:
		pos += tls_alert_print(record->data, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_HANDSHAKE:
		pos += tls_handshake_print(record->data, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	return pos;
}
