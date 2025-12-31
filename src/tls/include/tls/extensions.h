/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_EXTENSIONS_H
#define TLS_EXTENSIONS_H

#include <tls/types.h>
#include <tls/algorithms.h>
#include <tls/version.h>
#include <tls/error.h>
#include <tls/handshake.h>

#define TLS_EXTENSION_HEADER_OCTETS 4
#define TLS_EXTENSION_OCTETS(H)     ((((tls_extension_header *)(H))->size) + 4)

typedef enum _tls_extension_type
{
	// RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
	TLS_EXT_SERVER_NAME = 0,
	TLS_EXT_MAX_FRAGMENT_LENGTH = 1,
	TLS_EXT_CLIENT_CERTIFICATE_URL = 2,
	TLS_EXT_TRUSTED_CA_KEYS = 3,
	TLS_EXT_TRUNCATED_HMAC = 4,
	TLS_EXT_STATUS_REQUEST = 5,

	// RFC 4681: TLS User Mapping Extension
	TLS_EXT_USER_MAPPING = 6,

	// RFC 5878: Transport Layer Security (TLS) Authorization Extensions
	TLS_EXT_CLIENT_AUTHORIZATION = 7,
	TLS_EXT_SERVER_AUTHORIZATION = 8,

	// RFC 6091: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
	TLS_EXT_CERTIFICATE_TYPE = 9,

	// RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
	TLS_EXT_SUPPORTED_GROUPS = 10,
	TLS_EXT_EC_POINT_FORMATS = 11,

	// RFC 5054: Using the Secure Remote Password (SRP) Protocol for TLS Authentication
	TLS_EXT_SRP = 12,

	// RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
	TLS_EXT_SIGNATURE_ALGORITHMS = 13,

	// RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)
	TLS_EXT_USE_SRTP = 14,

	// RFC 6520: Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension
	TLS_EXT_HEARTBEAT = 15,

	// RFC 7301: Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
	TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,

	// RFC 6961: The Transport Layer Security (TLS) Multiple Certificate Status Request Extension
	TLS_EXT_STATUS_REQUEST_V2 = 17,

	// RFC 6962: Certificate Transparency
	TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP = 18,

	// RFC 7250: Using Raw Public Keys in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
	TLS_EXT_CLIENT_CERTIFICATE_TYPE = 19,
	TLS_EXT_SERVER_CERTIFICATE_TYPE = 20,

	// RFC 7685: A Transport Layer Security (TLS) ClientHello Padding Extension
	TLS_EXT_PADDING = 21,

	// RFC 7366: Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
	TLS_EXT_ENCRYPT_THEN_MAC = 22,

	// RFC 7627: Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
	TLS_EXT_EXTENDED_MASTER_SECRET = 23,

	// RFC 8472: Transport Layer Security (TLS) Extension for Token Binding Protocol Negotiation
	TLS_EXT_TOKEN_BINDING = 24,

	// RFC 7924: Transport Layer Security (TLS) Cached Information Extension
	TLS_EXT_CACHED_INFO = 25,

	// RFC Draft: draft-gutmann-tls-lts
	TLS_EXT_LTS = 26,

	// RFC 8879: TLS Certificate Compression
	TLS_EXT_COMPRESS_CERTIFICATE = 27,

	// RFC 8449: Record Size Limit Extension for TLS
	TLS_EXT_RECORD_SIZE_LIMIT = 28,

	// RFC 8492: Secure Password Ciphersuites for Transport Layer Security (TLS)
	TLS_EXT_PASSWORD_PROTECT = 29,
	TLS_EXT_PASSWORD_CLEAR = 30,
	TLS_EXT_PASSWORD_SALT = 31,

	// RFC 8672: TLS Server Identity Pinning with Tickets
	TLS_EXT_TICKET_PINNING = 32,

	// RFC 8773: TLS 1.3 Extension for Certificate-Based Authentication with an External Pre-Shared Key
	TLS_EXT_PSK_EXTERNAL_CERTIFICATE = 33,

	// RFC 9345: Delegated Credentials for TLS and DTLS
	TLS_EXT_DELEGATED_CREDENTIAL = 34,

	// RFC 5077: Transport Layer Security (TLS) Session Resumption without Server-Side State
	TLS_EXT_SESSION_TICKET = 35,

	// RFC 8870: Encrypted Key Transport for DTLS and Secure RTP
	TLS_SUPPORTED_EKT_CIPHERS = 39,

	// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
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

	// RFC 9162: Certificate Transparency Version 2.0
	TLS_EXT_TRANSPARENCY_INFO = 52,

	// RFC 9146: Connection Identifier for DTLS 1.2
	TLS_EXT_CONNECTION_INFO_LEGACY = 53,
	TLS_EXT_CONNECTION_INFO = 54,

	// RFC 8844: Unknown Key-Share Attacks on Uses of TLS with the Session Description Protocol (SDP)
	TLS_EXT_EXTERNAL_ID_HASH = 55,
	TLS_EXT_EXTERNAL_SESSION_ID = 56,

	// RFC 9149: TLS Ticket Requests
	TLS_EXT_TICKET_REQUEST = 58,

	// RFC 9102: TLS DNSSEC Chain Extension
	TLS_EXT_DNSSEC_CHAIN = 59,

	// Chrome (Private)
	TLS_EXT_APPLICATION_SETTINGS = 17613,

	// RFC Draft: draft-ietf-tls-esni
	TLS_EXT_ECH_OUTER_EXTENSIONS = 64768,
	TLS_EXT_ENCRYPTED_CLIENT_HELLO = 65037,

	// RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension
	TLS_EXT_RENEGOTIATION_INFO = 65281,
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

typedef enum _tls_identifier_type
{
	TLS_PRE_AGREED = 0,
	TLS_KEY_SHA1 = 1,
	TLS_X509_NAME = 2,
	TLS_CERT_SHA1 = 3
} tls_identifier_type;

typedef struct _tls_trusted_authority
{
	tls_identifier_type type;

	union
	{
		struct
		{
			uint16_t size;
			uint8_t name[];
		} distinguished_name;

		uint8_t sha1_hash[];
	};

} tls_trusted_authority;

typedef struct _tls_extension_trusted_authority
{
	tls_extension_header header;
	uint16_t size;
	uint16_t count;
	void **authorities;

} tls_extension_trusted_authority;

typedef enum _tls_certificate_status_type
{
	TLS_CERTIFICATE_STATUS_OCSP = 1
} tls_certificate_status_type;

typedef struct _tls_extension_status_request
{
	tls_extension_header header;
	tls_certificate_status_type type;

	uint16_t responder_size;
	uint16_t extension_size;
	uint8_t data[];

} tls_extension_status_request;

typedef struct _tls_extension_user_mapping
{
	tls_extension_header header;
	uint8_t size;
	uint8_t types[];
} tls_extension_user_mapping;

typedef enum _tls_authorization_format
{
	TLS_X509_ATTR_CERT = 0,
	TLS_SAML_ASSERTION = 1,
	TLS_X509_ATTR_CERT_URL = 2,
	TLS_SAML_ASSERTION_URL = 3
} tls_authorization_format;

typedef struct _tls_extension_authorization_formats
{
	tls_extension_header header;
	uint8_t size;
	uint8_t formats[];
} tls_extension_authorization_formats;

typedef enum _tls_certificate_type
{
	TLS_CERTIFICATE_X509 = 0,
	TLS_CERTIFICATE_PGP = 1,
	TLS_CERTIFICATE_RAW = 2,
} tls_certificate_type;

typedef struct _tls_extension_certificate_type
{
	tls_extension_header header;
	uint8_t size;
	uint8_t types[];
} tls_extension_certificate_type;

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

typedef struct _tls_extension_padding
{
	tls_extension_header header;
	uint8_t pad[];
} tls_extension_padding;

typedef struct _tls_extension_compressed_certificate
{
	tls_extension_header header;
	uint8_t size;
	uint8_t algorithms[];
} tls_extension_compressed_certificate;

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

tls_error_t tls_extension_header_read(tls_extension_header *header, void *data, uint32_t size);
uint32_t tls_extension_header_write(tls_extension_header *header, void *buffer, uint32_t size);

tls_error_t tls_extension_read(tls_handshake_type context, void **extension, void *data, uint32_t size);
uint32_t tls_extension_write(tls_handshake_type context, void *extension, void *buffer, uint32_t size);
uint32_t tls_extension_print(tls_handshake_type context, void *extension, buffer_t *buffer, uint32_t indent);

uint16_t tls_extension_count(void *data, uint32_t size);

#endif
