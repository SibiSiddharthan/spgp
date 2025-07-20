/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/extensions.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tls_extension_read(void **extension, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	tls_extension_type extension_type = 0;
	uint16_t extension_size = 0;

	// 2 octet extension type
	LOAD_16BE(&extension_type, in + pos);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(&extension_size, in + pos);
	pos += 2;

	switch (extension_type)
	{
	case TLS_EXT_SERVER_NAME:
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
	case TLS_EXT_TRUSTED_CA_KEYS:
	case TLS_EXT_TRUNCATED_HMAC:
	case TLS_EXT_STATUS_REQUEST:
	case TLS_EXT_USER_MAPPING:
	case TLS_EXT_CLIENT_AUTHORIZATION:
	case TLS_EXT_SERVER_AUTHORIZATION:
	case TLS_EXT_CERTIFICATE_TYPE:
	case TLS_EXT_SUPPORTED_GROUPS:
	case TLS_EXT_EC_POINT_FORMATS:
	case TLS_EXT_SRP:
	case TLS_EXT_SIGNATURE_ALGORITHMS:
	case TLS_EXT_USE_SRTP:
	case TLS_EXT_HEARTBEAT:
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
	case TLS_EXT_STATUS_REQUEST_V2:
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
	case TLS_EXT_PADDING:
	case TLS_EXT_ENCRYPT_THEN_MAC:
	case TLS_EXT_EXTENDED_MASTER_SECRET:
	case TLS_EXT_TOKEN_BINDING:
	case TLS_EXT_CACHED_INFO:
	case TLS_EXT_LTS:
	case TLS_EXT_COMPRESS_CERTIFICATE:
	case TLS_EXT_RECORD_SIZE_LIMIT:
	case TLS_EXT_PASSWORD_PROTECT:
	case TLS_EXT_PASSWORD_CLEAR:
	case TLS_EXT_PASSWORD_SALT:
	case TLS_EXT_TICKET_PINNING:
	case TLS_EXT_DELEGATED_CREDENTIAL:
	case TLS_EXT_SESSION_TICKET:
	case TLS_EXT_PSK:
	case TLS_EXT_EARLY_DATA:
	case TLS_EXT_SUPPORTED_VERSIONS:
	case TLS_EXT_COOKIE:
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
	case TLS_EXT_OID_FILTERS:
	case TLS_EXT_POST_HANDSHAKE_AUTH:
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
	case TLS_EXT_KEY_SHARE:
	case TLS_EXT_TRANSPARENCY_INFO:
	case TLS_EXT_CONNECTION_INFO_LEGACY:
	case TLS_EXT_CONNECTION_INFO:
	case TLS_EXT_EXTERNAL_ID_HASH:
	case TLS_EXT_EXTERNAL_SESSION_ID:
	default:
	{
		tls_extension_header *header = malloc(sizeof(tls_extension_header));

		if (header == NULL)
		{
			return;
		}

		header->extension = extension_type;
		header->size = extension_size;

		*extension = header;
	}
	break;
	}

	return;
}

uint32_t tls_extension_write(void *extension, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// 2 octet extension type
	LOAD_16BE(out + pos, &header->extension);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(out + pos, &header->size);
	pos += 2;

	return pos;
}

uint32_t tls_extension_print(void *extension, void *buffer, uint32_t size)
{
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// Extension Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Extension Type: ");

	// Extension Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Extension Size: %hu bytes", header->size);

	return pos;
}

uint32_t tls_extension_count(void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	uint16_t extension_size = 0;
	uint16_t extension_count = 0;

	while (pos < size)
	{
		LOAD_16BE(&extension_size, in + pos + 2);
		pos += 4;

		extension_count += 1;
		pos += extension_size;
	}

	return extension_count;
}
