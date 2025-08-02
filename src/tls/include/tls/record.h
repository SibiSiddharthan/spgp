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

typedef enum _tls_content_type
{
	// RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
	TLS_INVALID_CONTENT = 0,
	TLS_CHANGE_CIPHER_SPEC = 20,

	// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
	TLS_ALERT = 21,
	TLS_HANDSHAKE = 22,
	TLS_APPLICATION_DATA = 23,

	// RFC 6520: Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension
	TLS_HEARTBEAT = 24,

	// RFC 9146: Connection Identifier for DTLS 1.2
	TLS_CID = 25,

	// RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
	TLS_ACK = 26,

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
