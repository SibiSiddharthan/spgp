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

uint32_t tls_extension_print(void *extension, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// Extension Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sExtension Type: ", indent * 4, "");

	switch (header->extension)
	{
	case TLS_EXT_SERVER_NAME:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Name (ID 0)\n");
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Max Fragment Length (ID 1)\n");
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Certificate URL (ID 2)\n");
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Trusted CA Keys (ID 3)\n");
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Truncated HMAC (ID 4)\n");
		break;
	case TLS_EXT_STATUS_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Status Request (ID 5)\n");
		break;
	case TLS_EXT_USER_MAPPING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "User Mapping (ID 6)\n");
		break;
	case TLS_EXT_CLIENT_AUTHORIZATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Authorization (ID 7)\n");
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Authorization (ID 8)\n");
		break;
	case TLS_EXT_CERTIFICATE_TYPE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Type (ID 9)\n");
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Supported Groups (ID 10)\n");
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "EC Point Formats (ID 11)\n");
		break;
	case TLS_EXT_SRP:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Secure Remote Password (ID 12)\n");
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Signature Algorithms (ID 13)\n");
		break;
	case TLS_EXT_USE_SRTP:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Use SRTP (ID 14)\n");
		break;
	case TLS_EXT_HEARTBEAT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Heartbeat (ID 15)\n");
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Application Layer Protocol Negotiation (ID 16)\n");
		break;
	case TLS_EXT_STATUS_REQUEST_V2:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Status Request V2 (ID 17)\n");
		break;
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Signed Certificate Timestamp (ID 18)\n");
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Certificate Type (ID 19)\n");
		break;
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Certificate Type (ID 20)\n");
		break;
	case TLS_EXT_PADDING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Padding (ID 21)\n");
		break;
	case TLS_EXT_ENCRYPT_THEN_MAC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Encrypt Then MAC (ID 22)\n");
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Extended Master Secret (ID 23)\n");
		break;
	case TLS_EXT_TOKEN_BINDING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Token Binding (ID 24)\n");
		break;
	case TLS_EXT_CACHED_INFO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Cached Information (ID 25)\n");
		break;
	case TLS_EXT_LTS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Long Term Support (ID 26)\n");
		break;
	case TLS_EXT_COMPRESS_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Compressed Certificate (ID 27)\n");
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Max Record Size (ID 28)\n");
		break;
	case TLS_EXT_PASSWORD_PROTECT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Password Protect (ID 29)\n");
		break;
	case TLS_EXT_PASSWORD_CLEAR:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Password Clear (ID 30)\n");
		break;
	case TLS_EXT_PASSWORD_SALT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Password Salt (ID 31)\n");
		break;
	case TLS_EXT_TICKET_PINNING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Ticket Pinning (ID 32)\n");
		break;
	case TLS_EXT_DELEGATED_CREDENTIAL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Delegated Credential (ID 34)\n");
		break;
	case TLS_EXT_SESSION_TICKET:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Session Ticket (ID 35)\n");
		break;
	case TLS_EXT_PSK:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Pre-Shared Key (ID 41)\n");
		break;
	case TLS_EXT_EARLY_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Early Data (ID 42)\n");
		break;
	case TLS_EXT_SUPPORTED_VERSIONS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Supported Version (ID 43)\n");
		break;
	case TLS_EXT_COOKIE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Cookie (ID 44)\n");
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "PSK Exchange Modes (ID 45)\n");
		break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Authorities (ID 47)\n");
		break;
	case TLS_EXT_OID_FILTERS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "OID Filters (ID 48)\n");
		break;
	case TLS_EXT_POST_HANDSHAKE_AUTH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Post Handshake Authorization (ID 49)\n");
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Signature Algorithms Certificate (ID 50)\n");
		break;
	case TLS_EXT_KEY_SHARE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Key Share (ID 51)\n");
		break;
	case TLS_EXT_TRANSPARENCY_INFO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Transparency Information (ID 52)\n");
		break;
	case TLS_EXT_CONNECTION_INFO_LEGACY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Connection Information (Legacy) (ID 53)\n");
		break;
	case TLS_EXT_CONNECTION_INFO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Connection Information (ID 54)\n");
		break;
	case TLS_EXT_EXTERNAL_ID_HASH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "External ID Hash (ID 55)\n");
		break;
	case TLS_EXT_EXTERNAL_SESSION_ID:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "External Session ID (ID 56)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hu)\n", header->extension);
		break;
	}

	// Extension Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sExtension Size: %hu bytes\n", indent * 4, "", header->size);

	return pos;
}

uint16_t tls_extension_count(void *data, uint32_t size)
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
