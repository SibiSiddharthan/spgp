/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <tls/types.h>
#include <tls/version.h>

typedef enum _tls_content_type
{
	TLS_INVALID_CONTENT = 0,
	TLS_CHANGE_CIPHER_SPEC = 20,
	TLS_ALERT = 21,
	TLS_HANDSHAKE = 22,
	TLS_APPLICATION_DATA = 23,
	TLS_HEARTBEAT = 24,
	TLS_CID = 25,
	TLS_ACK = 26
} tls_content_type;

typedef struct _tls_record
{
	tls_content_type content;
	tls_protocol_version version;
	uint16_t size;
	void *data;
} tls_record;

void tls_record_read(tls_record **record, void *data, uint32_t size);
uint32_t tls_record_write(tls_record *record, void *buffer, uint32_t size);
uint32_t tls_record_print(tls_record *record, void *buffer, uint32_t size);

#endif
