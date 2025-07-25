/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include <tls/error.h>
#include <tls/record.h>
#include <tls/version.h>
#include <tls/extensions.h>

#define TLS_HANDSHAKE_HEADER_OCTETS 4

typedef enum _tls_handshake_type
{
	TLS_HELLO_REQUEST = 0,
	TLS_CLIENT_HELLO = 1,
	TLS_SERVER_HELLO = 2,
	TLS_HELLO_VERIFY_REQUEST = 3,
	TLS_NEW_SESSION_TICKET = 4,
	TLS_END_OF_EARLY_DATA = 5,
	TLS_HELLO_RETRY_REQUEST = 6,
	TLS_ENCRYPTED_EXTENSIONS = 8,
	TLS_CERTIFICATE = 11,
	TLS_SERVER_KEY_EXCHANGE = 12,
	TLS_CERTIFICATE_REQUEST = 13,
	TLS_SERVER_HELLO_DONE = 14,
	TLS_CERTIFICATE_VERIFY = 15,
	TLS_CLIENT_KEY_EXCHANGE = 16,
	TLS_FINISHED = 20,
	TLS_CERTIFICATE_URL = 21,
	TLS_CERTIFICATE_STATUS = 22,
	TLS_SUPPLEMENTAL_DATA = 23,
	TLS_KEY_UPDATE = 24,
	TLS_MESSAGE_HASH = 254,
} tls_handshake_type;

typedef struct _tls_handshake_header
{
	tls_record_header header;
	uint8_t type;
	uint32_t size : 24;
} tls_handshake_header;

typedef tls_handshake_header tls_hello_request, tls_end_of_early_data;

typedef struct _tls_client_hello
{
	tls_handshake_header header;

	tls_protocol_version version;
	uint16_t cipher_suites_size;
	uint8_t compression_methods_size;
	uint8_t session_id_size;
	uint16_t extensions_size;
	uint16_t extensions_count;
	uint8_t session_id[32];
	uint8_t random[32];
	void **extensions;

	uint8_t data[];

} tls_client_hello;

typedef struct _tls_server_hello
{
	tls_handshake_header header;

	tls_protocol_version version;
	uint16_t cipher_suite;
	uint8_t compression_method;
	uint8_t session_id_size;
	uint16_t extensions_size;
	uint16_t extensions_count;
	uint8_t session_id[32];
	uint8_t random[32];
	void **extensions;

} tls_server_hello;

typedef struct _tls_new_session_ticket
{
	tls_handshake_header header;

	uint32_t ticket_lifetime;
	uint32_t ticket_age_add;
	uint8_t ticket_nonce[256];
	uint16_t ticket_size;
	uint16_t extensions_size;
	uint8_t data[];
} tls_new_session_ticket;

typedef enum _tls_key_update_request
{
	TLS_KEY_UPDATE_NOT_REQUESTED = 0,
	TLS_KEY_UPDATE_REQUESTED = 1
} tls_key_update_request;

typedef struct _tls_key_update
{
	tls_handshake_header header;
	uint8_t request;
} tls_key_update;

tls_error_t tls_handshake_read_body(void **handshake, tls_record_header *header, void *data, uint32_t size);
uint32_t tls_handshake_write_body(void *handshake, void *buffer, uint32_t size);
uint32_t tls_handshake_print_body(void *handshake, void *buffer, uint32_t size, uint32_t indent);

#endif
