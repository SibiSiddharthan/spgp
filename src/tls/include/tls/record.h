/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <tls/types.h>
#include <tls/version.h>
#include <tls/error.h>

#define TLS_RECORD_HEADER_OCTETS 5

#define TLS_RECORD_SIZE(R) ((((tls_record *)(R))->size) + 5)

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

typedef struct _tls_record_header
{
	tls_content_type type;
	tls_protocol_version version;
	uint16_t size;
} tls_record_header;

tls_error_t tls_record_header_read(tls_record_header *header, void *data, uint32_t size);
uint32_t tls_record_header_write(tls_record_header *header, void *buffer, uint32_t size);

tls_error_t tls_record_read(void **record, void *data, uint32_t size);
uint32_t tls_record_write(void *record, void *buffer, uint32_t size);
uint32_t tls_record_print(void *record, void *buffer, uint32_t size, uint32_t indent);

#endif
