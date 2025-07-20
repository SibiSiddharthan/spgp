/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include <stdint.h>
#include <tls/version.h>

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

typedef enum _tls_extension
{
	TLS_SERVER_NAME = 0,
	TLS_MAX_FRAGMENT_LENGTH = 1,
	TLS_CLIENT_CERTIFICATE_URL = 2,
	TLS_TRUSTED_CA_KEYS = 3,
	TLS_TRUNCATED_HMAC = 4,
	TLS_STATUS_REQUEST = 5,
	TLS_USER_MAPPING = 6,
	TLS_CLIENT_AUTHORIZATION = 7,
	TLS_SERVER_AUTHORIZATION = 8,
	TLS_CERTIFICATE_TYPE = 9,
	TLS_SUPPORTED_GROUPS = 10,
	TLS_EC_POINT_FORMATS = 11,
	TLS_SRP = 12,
	TLS_SIGNATURE_ALGORITHMS = 13,
	TLS_USE_SRTP = 14,
	TLS_HEARTBEAT = 15,
	TLS_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
	TLS_STATUS_REQUEST_V2 = 17,
	TLS_SIGNED_CERTIFICATE_TIMESTAMP = 18,
	TLS_CLIENT_CERTIFICATE_TYPE = 19,
	TLS_SERVER_CERTIFICATE_TYPE = 20,
	TLS_PADDING = 21,
	TLS_ENCRYPT_THEN_MAC = 22,
	TLS_EXTENDED_MASTER_SECRET = 23,
	TLS_TOKEN_BINDING = 24,
	TLS_CACHED_INFO = 25,
	TLS_LTS = 26,
	TLS_COMPRESS_CERTIFICATE = 27,
	TLS_RECORD_SIZE_LIMIT = 28,
	TLS_PASSWORD_PROTECT = 29,
	TLS_PASSWORD_CLEAR = 30,
	TLS_PASSWORD_SALT = 31,
	TLS_TICKET_PINNING = 32,
	TLS_DELEGATED_CREDENTIAL = 34,
	TLS_SESSION_TICKET = 35,
	TLS_PSK = 41,
	TLS_EARLY_DATA = 42,
	TLS_SUPPORTED_VERSIONS = 43,
	TLS_COOKIE = 44,
	TLS_PSK_KEY_EXCHANGE_MODES = 45,
	TLS_CERTIFICATE_AUTHORITIES = 47,
	TLS_OID_FILTERS = 48,
	TLS_POST_HANDSHAKE_AUTH = 49,
	TLS_SIGNATURE_ALGORITHMS_CERTIFICATE = 50,
	TLS_KEY_SHARE = 51,
	TLS_TRANSPARENCY_INFO = 52,
	TLS_CONNECTION_INFO_LEGACY = 53,
	TLS_CONNECTION_INFO = 54,
	TLS_EXTERNAL_ID_HASH = 55,
	TLS_EXTERNAL_SESSION_ID = 56,
} tls_extension;

typedef struct _tls_handshake_header
{
	uint8_t handshake_type;
	uint32_t handshake_size : 24;
} tls_handshake_header;

typedef tls_handshake_header tls_hello_request, tls_end_of_early_data;

typedef struct _tls_session_id
{
	uint8_t size;
	uint8_t id[32];
} tls_session_id;

typedef struct _tls_client_hello
{
	tls_handshake_header header;

	tls_protocol_version version;
	uint8_t compression_methods_size;
	uint16_t cipher_suites_size;
	uint16_t extensions_size;
	tls_session_id session;
	uint8_t random[32];
	uint8_t data[];
} tls_client_hello;

typedef struct _tls_server_hello
{
	tls_handshake_header header;

	tls_protocol_version version;
	uint16_t cipher_suite;
	uint8_t compression_method;
	uint16_t extensions_size;
	tls_session_id session;
	uint8_t random[32];
	uint8_t data[];
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

void tls_handshake_read(void **handshake, void *data, uint32_t size);
uint32_t tls_handshake_write(tls_handshake_header *handshake, void *buffer, uint32_t size);
uint32_t tls_handshake_print(tls_handshake_header *handshake, void *buffer, uint32_t size);

#endif
