/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_ALERT_H
#define TLS_ALERT_H

#include <tls/record.h>

#define TLS_ALERT_OCTETS 2

typedef enum _tls_alert_level
{
	TLS_WARNING = 1,
	TLS_FATAL = 2
} tls_alert_level;

typedef enum _tls_alert_description
{
	TLS_CLOSE_NOTIFY = 0,
	TLS_UNEXPECTED_MESSAGE = 10,
	TLS_BAD_RECORD_MAC = 20,
	TLS_DECRYPTION_FAILURE = 21,
	TLS_RECORD_OVERFLOW = 22,
	TLS_DECOMPRESSION_FAILURE = 30,
	TLS_HANDSHAKE_FAILURE = 40,
	TLS_NO_CERTIFICATE_RESERVED = 41,
	TLS_BAD_CERTIFICATE = 42,
	TLS_UNSUPPORTED_CERTIFICATE = 43,
	TLS_CERTIFICATE_REVOKED = 44,
	TLS_CERTIFICATE_EXPIRED = 45,
	TLS_CERTIFICATE_UNKNOWN = 46,
	TLS_ILLEGAL_PARAMETER = 47,
	TLS_UNKNOWN_CA = 48,
	TLS_ACCESS_DENIED = 49,
	TLS_DECODE_ERROR = 50,
	TLS_DECRYPT_ERROR = 51,
	TLS_EXPORT_RESTRICTION = 60,
	TLS_PROTOCOL_VERSION = 70,
	TLS_INSUFFICIENT_SECURITY = 71,
	TLS_INTERNAL_ERROR = 80,
	TLS_INAPPROPRIATE_FALLBACK = 86,
	TLS_USER_CANCELLED = 90,
	TLS_NO_RENEGOTIATION = 100,
	TLS_MISSING_EXTENSION = 109,
	TLS_UNSUPPORTED_EXTENSION = 110,
	TLS_UNRECOGNIZED_NAME = 112,
	TLS_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
	TLS_UNKNOWN_PSK_IDENTITY = 115,
	TLS_CERTIFICATE_REQUIRED = 116,
	TLS_NO_APPLICATION_PROTOCOL = 120
} tls_alert_description;

typedef struct _tls_alert
{
	tls_record_header header;
	uint8_t level;
	uint8_t description;
} tls_alert;

tls_error_t tls_alert_read_body(tls_alert **alert, tls_record_header *header, void *data, uint32_t size);
uint32_t tls_alert_write_body(tls_alert *alert, void *buffer, uint32_t size);
uint32_t tls_alert_print_body(tls_alert *alert, buffer_t *buffer, uint32_t indent);

#endif
