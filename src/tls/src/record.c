/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/record.h>
#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tls_record_read(tls_record **record, void *data, uint32_t size)
{
	tls_record *result = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	result = malloc(sizeof(tls_record));

	if (result == NULL)
	{
		return;
	}

	memset(result, 0, sizeof(tls_record));

	// 1-octet content type
	LOAD_8(&result->content, in + pos);
	pos += 1;

	// 2-octet protocol version
	LOAD_16(&result->version, in + pos);
	pos += 2;

	// 2-octet record size
	LOAD_16BE(&result->size, in + pos);
	pos += 2;

	switch (result->content)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
	case TLS_ALERT:
	case TLS_HANDSHAKE:
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}
}

uint32_t tls_record_write(tls_record *record, void *data, uint32_t size)
{
	uint8_t *out = data;
	uint32_t pos = 0;

	if (size < (5 + record->size))
	{
		return 0;
	}

	// 1-octet content type
	LOAD_8(out + pos, &record->content);
	pos += 1;

	// 2-octet protocol version
	LOAD_16(out + pos, &record->version);
	pos += 2;

	// 2-octet record size
	LOAD_16BE(out + pos, &record->size);
	pos += 2;

	switch (record->content)
	{
	case TLS_INVALID_CONTENT:
		break;
	case TLS_CHANGE_CIPHER_SPEC:
	case TLS_ALERT:
	case TLS_HANDSHAKE:
	case TLS_APPLICATION_DATA:
	case TLS_HEARTBEAT:
	case TLS_CID:
	case TLS_ACK:
		break;
	}

	return pos;
}

