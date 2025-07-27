/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_EXTENSIONS_H
#define TLS_EXTENSIONS_H

#include <tls/types.h>
#include <tls/algorithms.h>
#include <tls/version.h>

#define TLS_EXTENSION_OCTETS(H) ((((tls_extension_header *)(H))->size) + 4)

typedef enum _tls_extension_type
{
	TLS_EXT_SERVER_NAME = 0,
	TLS_EXT_MAX_FRAGMENT_LENGTH = 1,
	TLS_EXT_CLIENT_CERTIFICATE_URL = 2,
	TLS_EXT_TRUSTED_CA_KEYS = 3,
	TLS_EXT_TRUNCATED_HMAC = 4,
	TLS_EXT_STATUS_REQUEST = 5,
	TLS_EXT_USER_MAPPING = 6,
	TLS_EXT_CLIENT_AUTHORIZATION = 7,
	TLS_EXT_SERVER_AUTHORIZATION = 8,
	TLS_EXT_CERTIFICATE_TYPE = 9,
	TLS_EXT_SUPPORTED_GROUPS = 10,
	TLS_EXT_EC_POINT_FORMATS = 11,
	TLS_EXT_SRP = 12,
	TLS_EXT_SIGNATURE_ALGORITHMS = 13,
	TLS_EXT_USE_SRTP = 14,
	TLS_EXT_HEARTBEAT = 15,
	TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
	TLS_EXT_STATUS_REQUEST_V2 = 17,
	TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP = 18,
	TLS_EXT_CLIENT_CERTIFICATE_TYPE = 19,
	TLS_EXT_SERVER_CERTIFICATE_TYPE = 20,
	TLS_EXT_PADDING = 21,
	TLS_EXT_ENCRYPT_THEN_MAC = 22,
	TLS_EXT_EXTENDED_MASTER_SECRET = 23,
	TLS_EXT_TOKEN_BINDING = 24,
	TLS_EXT_CACHED_INFO = 25,
	TLS_EXT_LTS = 26,
	TLS_EXT_COMPRESS_CERTIFICATE = 27,
	TLS_EXT_RECORD_SIZE_LIMIT = 28,
	TLS_EXT_PASSWORD_PROTECT = 29,
	TLS_EXT_PASSWORD_CLEAR = 30,
	TLS_EXT_PASSWORD_SALT = 31,
	TLS_EXT_TICKET_PINNING = 32,
	TLS_EXT_DELEGATED_CREDENTIAL = 34,
	TLS_EXT_SESSION_TICKET = 35,
	TLS_EXT_PSK = 41,
	TLS_EXT_EARLY_DATA = 42,
	TLS_EXT_SUPPORTED_VERSIONS = 43,
	TLS_EXT_COOKIE = 44,
	TLS_EXT_PSK_KEY_EXCHANGE_MODES = 45,
	TLS_EXT_CERTIFICATE_AUTHORITIES = 47,
	TLS_EXT_OID_FILTERS = 48,
	TLS_EXT_POST_HANDSHAKE_AUTH = 49,
	TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE = 50,
	TLS_EXT_KEY_SHARE = 51,
	TLS_EXT_TRANSPARENCY_INFO = 52,
	TLS_EXT_CONNECTION_INFO_LEGACY = 53,
	TLS_EXT_CONNECTION_INFO = 54,
	TLS_EXT_EXTERNAL_ID_HASH = 55,
	TLS_EXT_EXTERNAL_SESSION_ID = 56,
} tls_extension_type;

typedef struct _tls_extension_header
{
	tls_extension_type type;
	uint16_t size;
} tls_extension_header;

typedef enum _tls_name_type
{
	TLS_HOST_NAME = 0
} tls_name_type;

typedef struct _tls_server_name
{
	tls_name_type name_type;
	uint16_t name_size;
	uint8_t name[];
} tls_server_name;

typedef struct _tls_extension_server_name
{
	tls_extension_header header;
	uint16_t count;
	uint16_t size;
	void **list;
} tls_extension_server_name;

#define TLS_MAX_FRAGMENT_LENGTH      16384
#define TLS_MAX_FRAGMENT_LENGTH_512  1 // (1 << 9)
#define TLS_MAX_FRAGMENT_LENGTH_1024 2 // (1 << 10)
#define TLS_MAX_FRAGMENT_LENGTH_2048 3 // (1 << 11)
#define TLS_MAX_FRAGMENT_LENGTH_4096 4 // (1 << 12)

typedef struct _tls_extension_max_fragment_length
{
	tls_extension_header header;
	uint8_t max_fragment_length;
} tls_extension_max_fragment_length;

typedef struct _tls_extension_record_size_limit
{
	tls_extension_header header;
	uint16_t limit;
} tls_extension_record_size_limit;

typedef struct _tls_extension_ec_point_format
{
	tls_extension_header header;
	uint8_t size;
	uint8_t formats[];
} tls_extension_ec_point_format;

typedef struct _tls_extension_supported_group
{
	tls_extension_header header;
	uint16_t size;
	uint16_t groups[];
} tls_extension_supported_group;

typedef struct _tls_extension_signature_algorithm
{
	tls_extension_header header;
	uint16_t size;
	uint16_t algorithms[];
} tls_extension_signature_algorithm;

typedef struct _tls_extension_psk_exchange_mode
{
	tls_extension_header header;
	uint8_t size;
	uint8_t modes[];
} tls_extension_psk_exchange_mode;

typedef struct _tls_extension_supported_version
{
	tls_extension_header header;
	uint8_t size;
	tls_protocol_version version[];
} tls_extension_supported_version;

typedef struct _tls_opaque_data
{
	uint16_t offset;
	uint16_t size;
} tls_opaque_data;

typedef struct _tls_extensions_application_protocol_negotiation
{
	tls_extension_header header;
	uint16_t size;
	uint16_t count;
	tls_opaque_data protocols[];

} tls_extensions_application_protocol_negotiation;

typedef struct _tls_key_share
{
	uint16_t group;
	uint16_t offset;
	uint16_t size;
} tls_key_share;

typedef struct _tls_extension_key_share
{
	tls_extension_header header;
	uint16_t size;
	uint16_t count;
	tls_key_share shares[];
} tls_extension_key_share;

void tls_extension_read(void **extension, void *data, uint32_t size);
uint32_t tls_extension_write(void *extension, void *buffer, uint32_t size);
uint32_t tls_extension_print(void *extension, void *buffer, uint32_t size, uint32_t indent);

uint16_t tls_extension_count(void *data, uint32_t size);

#endif
