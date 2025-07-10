/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <stdint.h>

typedef enum _tls_content_type
{
	TLS_INVALID_CONTENT = 0,
	TLS_CHANGE_CIPHER_SPEC = 20,
	TLS_ALERT = 21,
	TLS_HANDSHAKE = 22,
	TLS_APPLICATION_DATA = 23,
} tls_content_type;

typedef struct _tls_protocol_version
{
	uint8_t major;
	uint8_t minor;
} tls_protocol_version;

typedef struct _tls_record
{
	tls_content_type content;
	tls_protocol_version version;
	uint16_t size;
	void *data;
} tls_record;

#endif
