/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/extensions.h>
#include <tls/memory.h>
#include <tls/grease.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tls_extension_read(void **extension, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	tls_extension_header header = {0};

	// 2 octet extension type
	LOAD_16BE(&header.extension, in + pos);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(&header.size, in + pos);
	pos += 2;

	switch (header.extension)
	{
	case TLS_EXT_SERVER_NAME:
	{
		tls_extension_server_name *server = zmalloc(sizeof(tls_extension_server_name));
		uint32_t new_pos = 0;
		uint16_t name_size = 0;
		uint16_t name_count = 0;

		if (server == NULL)
		{
			return;
		}

		// Copy the header
		server->header = header;

		// 2 octet list size
		LOAD_16BE(&server->size, in + pos);
		pos += 2;

		while (new_pos < server->size)
		{
			LOAD_16BE(&name_size, in + pos + new_pos + 1);
			new_pos += 3 + name_size;
			name_count += 1;
		}

		server->count = name_count;
		server->list = malloc(sizeof(void *) * server->count);

		if (server->list == NULL)
		{
			return;
		}

		memset(server->list, 0, sizeof(void *) * server->count);

		for (uint16_t i = 0; i < name_count; ++i)
		{
			tls_server_name *name = NULL;
			uint16_t name_size = 0;
			tls_name_type name_type = 0;

			// 1 octet name type
			LOAD_8(&name_type, in + pos);
			pos += 1;

			switch (name_type)
			{
			case TLS_HOST_NAME:
			{
				// 2 octet name size
				LOAD_16BE(&name_size, in + pos);
				pos += 2;

				name = zmalloc(sizeof(tls_server_name) + name_size);

				if (name == NULL)
				{
					return;
				}

				name->name_type = name_type;
				name->name_size = name_size;

				// N octets of name
				memcpy(name->name, in + pos, name->name_size);
				pos += name->name_size;
			}
			break;
			}

			server->list[i] = name;
		}

		*extension = server;
	}
	break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
	{
		tls_extension_max_fragment_length *fragment = zmalloc(sizeof(tls_extension_max_fragment_length));

		if (fragment == NULL)
		{
			return;
		}

		// Copy the header
		fragment->header = header;

		// 1 octet length identifier
		LOAD_8(&fragment->max_fragment_length, in + pos);
		pos += 1;

		*extension = fragment;
	}
	break;
		// case TLS_EXT_CLIENT_CERTIFICATE_URL:
		// case TLS_EXT_TRUSTED_CA_KEYS:
		// case TLS_EXT_TRUNCATED_HMAC:
		// case TLS_EXT_STATUS_REQUEST:
		// case TLS_EXT_USER_MAPPING:
		// case TLS_EXT_CLIENT_AUTHORIZATION:
		// case TLS_EXT_SERVER_AUTHORIZATION:
		// case TLS_EXT_CERTIFICATE_TYPE:
	case TLS_EXT_SUPPORTED_GROUPS:
	{
		tls_extension_ec_group *group = zmalloc(sizeof(tls_extension_ec_group) + (header.size - 2));
		uint16_t count = 0;

		if (group == NULL)
		{
			return;
		}

		// Copy the header
		group->header = header;

		// 2 octet size
		LOAD_16BE(&group->size, in + pos);
		pos += 2;

		if (group->size != (header.size - 2))
		{
			return;
		}

		// N octets of data
		count = group->size / 2;

		for (uint16_t i = 0; i < count; ++i)
		{
			LOAD_16BE(&group->groups[i], in + pos);
			pos += 2;
		}

		*extension = group;
	}
	break;
	case TLS_EXT_EC_POINT_FORMATS:
	{
		tls_extension_ec_point_format *format = zmalloc(sizeof(tls_extension_ec_point_format) + (header.size - 1));

		if (format == NULL)
		{
			return;
		}

		// Copy the header
		format->header = header;

		// 1 octet size
		LOAD_8(&format->size, in + pos);
		pos += 1;

		if (format->size != (header.size - 1))
		{
			return;
		}

		// N octets of data
		memcpy(format->formats, in + pos, format->size);
		pos += format->size;

		*extension = format;
	}
	break;
	// case TLS_EXT_SRP:
	case TLS_EXT_SIGNATURE_ALGORITHMS:
	{
		tls_extension_signature_algorithm *signatures = zmalloc(sizeof(tls_extension_signature_algorithm) + (header.size - 2));
		uint16_t count = 0;

		if (signatures == NULL)
		{
			return;
		}

		// Copy the header
		signatures->header = header;

		// 2 octet size
		LOAD_16BE(&signatures->size, in + pos);
		pos += 2;

		if (signatures->size != (header.size - 2))
		{
			return;
		}

		// N octets of data
		count = signatures->size / 2;

		for (uint16_t i = 0; i < count; ++i)
		{
			LOAD_16BE(&signatures->algorithms[i], in + pos);
			pos += 2;
		}

		*extension = signatures;
	}
	break;
	// case TLS_EXT_USE_SRTP:
	// case TLS_EXT_HEARTBEAT:
	// case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
	// case TLS_EXT_STATUS_REQUEST_V2:
	// case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
	// case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
	// case TLS_EXT_SERVER_CERTIFICATE_TYPE:
	// case TLS_EXT_PADDING:
	// case TLS_EXT_ENCRYPT_THEN_MAC:
	// case TLS_EXT_EXTENDED_MASTER_SECRET:
	// case TLS_EXT_TOKEN_BINDING:
	// case TLS_EXT_CACHED_INFO:
	// case TLS_EXT_LTS:
	// case TLS_EXT_COMPRESS_CERTIFICATE:
	// case TLS_EXT_RECORD_SIZE_LIMIT:
	// case TLS_EXT_PASSWORD_PROTECT:
	// case TLS_EXT_PASSWORD_CLEAR:
	// case TLS_EXT_PASSWORD_SALT:
	// case TLS_EXT_TICKET_PINNING:
	// case TLS_EXT_DELEGATED_CREDENTIAL:
	// case TLS_EXT_SESSION_TICKET:
	// case TLS_EXT_PSK:
	// case TLS_EXT_EARLY_DATA:
	// case TLS_EXT_SUPPORTED_VERSIONS:
	// case TLS_EXT_COOKIE:
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
	{
		tls_extension_psk_exchange_mode *modes = zmalloc(sizeof(tls_extension_psk_exchange_mode) + (header.size - 1));

		if (modes == NULL)
		{
			return;
		}

		// Copy the header
		modes->header = header;

		// 1 octet size
		LOAD_8(&modes->size, in + pos);
		pos += 1;

		if (modes->size != (header.size - 1))
		{
			return;
		}

		// N octets of data
		memcpy(modes->modes, in + pos, modes->size);
		pos += modes->size;

		*extension = modes;
	}
	break;
	// case TLS_EXT_CERTIFICATE_AUTHORITIES:
	// case TLS_EXT_OID_FILTERS:
	// case TLS_EXT_POST_HANDSHAKE_AUTH:
	// case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
	// case TLS_EXT_KEY_SHARE:
	// case TLS_EXT_TRANSPARENCY_INFO:
	// case TLS_EXT_CONNECTION_INFO_LEGACY:
	// case TLS_EXT_CONNECTION_INFO:
	// case TLS_EXT_EXTERNAL_ID_HASH:
	// case TLS_EXT_EXTERNAL_SESSION_ID:
	default:
	{
		tls_extension_header *unknown = zmalloc(sizeof(tls_extension_header));

		if (unknown == NULL)
		{
			return;
		}

		unknown->extension = header.extension;
		unknown->size = header.size;

		*extension = unknown;
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

	switch (header->extension)
	{
	case TLS_EXT_SERVER_NAME:
	{
		tls_extension_server_name *server = extension;

		// 2 octet list size
		LOAD_16BE(out + pos, &server->size);
		pos += 2;

		for (uint16_t i = 0; i < server->count; ++i)
		{
			tls_server_name *name = server->list[i];

			// 1 octet name type
			LOAD_8(out + pos, name->name_type);
			pos += 1;

			switch (name->name_type)
			{
			case TLS_HOST_NAME:
			{
				// 2 octet name size
				LOAD_16BE(out + pos, &name->name_size);
				pos += 2;

				// N octets of name
				memcpy(out + pos, name->name, name->name_size);
				pos += name->name_size;
			}
			break;
			}
		}
	}
	break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
	{
		tls_extension_max_fragment_length *fragment = extension;

		// 1 octet length identifier
		LOAD_8(out + pos, &fragment->max_fragment_length);
		pos += 1;
	}
	break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
	case TLS_EXT_TRUSTED_CA_KEYS:
	case TLS_EXT_TRUNCATED_HMAC:
	case TLS_EXT_STATUS_REQUEST:
	case TLS_EXT_USER_MAPPING:
	case TLS_EXT_CLIENT_AUTHORIZATION:
	case TLS_EXT_SERVER_AUTHORIZATION:
	case TLS_EXT_CERTIFICATE_TYPE:
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
	{
		tls_extension_ec_group *group = extension;
		uint16_t count = group->size / 2;

		// 2 octet size
		LOAD_16BE(out + pos, &group->size);
		pos += 2;

		// N octets of data
		for (uint16_t i = 0; i < count; ++i)
		{
			LOAD_16BE(out + pos, &group->groups[i]);
			pos += 2;
		}
	}
	break;
	case TLS_EXT_EC_POINT_FORMATS:
	{
		tls_extension_ec_point_format *format = extension;

		// 1 octet size
		LOAD_8(out + pos, &format->size);
		pos += 1;

		// N octets of data
		memcpy(out + pos, format->formats, format->size);
		pos += format->size;
	}
	break;
	case TLS_EXT_SRP:
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
	{
		tls_extension_signature_algorithm *signatures = extension;
		uint16_t count = signatures->size / 2;

		// 2 octet size
		LOAD_16BE(out + pos, &signatures->size);
		pos += 2;

		// N octets of data
		for (uint16_t i = 0; i < count; ++i)
		{
			LOAD_16BE(out + pos, &signatures->algorithms[i]);
			pos += 2;
		}
	}
	break;
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
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
	{
		tls_extension_psk_exchange_mode *modes = extension;

		// 1 octet size
		LOAD_8(out + pos, &modes->size);
		pos += 1;

		// N octets of data
		memcpy(out + pos, modes->modes, modes->size);
		pos += modes->size;
	}
	break;
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
		break;
	}

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
	{
		if (tls_check_grease_value(header->extension))
		{
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "GREASE (ID %04hX)\n", header->extension);
		}
		else
		{
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hu)\n", header->extension);
		}
	}
	break;
	}

	// Extension Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sExtension Size: %hu bytes\n", indent * 4, "", header->size);

	switch (header->extension)
	{
	case TLS_EXT_SERVER_NAME:
	{
		tls_extension_server_name *server = extension;

		for (uint16_t i = 0; i < server->count; ++i)
		{
			tls_server_name *name = server->list[i];

			switch (name->name_type)
			{
			case TLS_HOST_NAME:
			{
				// Name Type
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sName Type: Host Name (ID 0)\n", (indent + 1) * 4, "");

				// Name
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sName (%hu bytes): %.*s\n", (indent + 1) * 4, "", name->name_size,
								name->name_size, name->name);
			}
			break;
			}
		}
	}
	break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
	{
		tls_extension_max_fragment_length *fragment = extension;

		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sMaximum Fragment Length: ", (indent + 1) * 4, "");

		switch (fragment->max_fragment_length)
		{
		case TLS_MAX_FRAGMENT_LENGTH_512:
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "512 (ID 1)\n");
			break;
		case TLS_MAX_FRAGMENT_LENGTH_1024:
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "1024 (ID 2)\n");
			break;
		case TLS_MAX_FRAGMENT_LENGTH_2048:
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "2048 (ID 3)\n");
			break;
		case TLS_MAX_FRAGMENT_LENGTH_4096:
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "4096 (ID 4)\n");
			break;
		default:
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu) (Assuming 16384)\n", fragment->max_fragment_length);
			break;
		}
	}
	break;
	// case TLS_EXT_CLIENT_CERTIFICATE_URL:
	// case TLS_EXT_TRUSTED_CA_KEYS:
	// case TLS_EXT_TRUNCATED_HMAC:
	// case TLS_EXT_STATUS_REQUEST:
	// case TLS_EXT_USER_MAPPING:
	// case TLS_EXT_CLIENT_AUTHORIZATION:
	// case TLS_EXT_SERVER_AUTHORIZATION:
	// case TLS_EXT_CERTIFICATE_TYPE:
	case TLS_EXT_SUPPORTED_GROUPS:
	{
		tls_extension_ec_group *group = extension;
		uint16_t count = group->size / 2;

		for (uint16_t i = 0; i < count; ++i)
		{
			switch (group->groups[i])
			{
			case TLS_SECT_163K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect163k1 (ID 1)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_163R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect163r1 (ID 2)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_163R2:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect163r2 (ID 3)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_193R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect193r1 (ID 4)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_193R2:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect193r2 (ID 5)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_233K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect233k1 (ID 6)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_233R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect233r1 (ID 7)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_239K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect239k1 (ID 8)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_283K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect283k1 (ID 9)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_283R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect283r1 (ID 10)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_409K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect409k1 (ID 11)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_409R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect409r1 (ID 12)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_571K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect571k1 (ID 13)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECT_571R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssect571r1 (ID 14)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_160K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp160k1 (ID 15)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_160R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp160r1 (ID 16)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_160R2:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp160r2 (ID 17)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_192K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp192k1 (ID 18)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_192R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp192r1 (ID 19)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_224K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp224k1 (ID 20)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_224R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp224r1 (ID 21)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_256K1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp256k1 (ID 22)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_256R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp256r1 (ID 23)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_384R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp384r1 (ID 24)\n", (indent + 1) * 4, "");
				break;
			case TLS_SECP_521R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssecp521r1 (ID 25)\n", (indent + 1) * 4, "");
				break;
			case TLS_BRAINPOOL_256R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sbrainpoolP256r1 (ID 26)\n", (indent + 1) * 4, "");
				break;
			case TLS_BRAINPOOL_384R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sbrainpoolP384r1 (ID 27)\n", (indent + 1) * 4, "");
				break;
			case TLS_BRAINPOOL_512R1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sbrainpoolP512r1 (ID 28)\n", (indent + 1) * 4, "");
				break;
			case TLS_X25519:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sx25519 (ID 29)\n", (indent + 1) * 4, "");
				break;
			case TLS_X448:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sx448 (ID 30)\n", (indent + 1) * 4, "");
				break;
			case TLS_BRAINPOOL_256R1_TLS_13:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sbrainpoolP256r1tls13 (ID 31)\n", (indent + 1) * 4, "");
				break;
			case TLS_BRAINPOOL_384R1_TLS_13:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sbrainpoolP384r1tls13 (ID 32)\n", (indent + 1) * 4, "");
				break;
			case TLS_BRAINPOOL_512R1_TLS_13:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sbrainpoolP512r1tls13 (ID 33)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_256A:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC256A (ID 34)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_256B:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC256B (ID 35)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_256C:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC256C (ID 36)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_256D:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC256D (ID 37)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_512A:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC512A (ID 38)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_512B:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC512B (ID 39)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_512C:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGC512C (ID 40)\n", (indent + 1) * 4, "");
				break;
			case TLS_SM2:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sSM2 (ID 41)\n", (indent + 1) * 4, "");
				break;
			default:
			{
				if (tls_check_grease_value(group->groups[i]))
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGREASE (ID %04hX)\n", (indent + 1) * 4, "", group->groups[i]);
				}
				else
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sUnknown (ID %hu)\n", (indent + 1) * 4, "", group->groups[i]);
				}
			}
			break;
			}
		}
	}
	break;
	case TLS_EXT_EC_POINT_FORMATS:
	{
		tls_extension_ec_point_format *format = extension;

		for (uint8_t i = 0; i < format->size; ++i)
		{
			switch (format->formats[i])
			{
			case TLS_EC_POINT_UNCOMPRESSED:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sUncompressed (ID 0)\n", (indent + 1) * 4, "");
				break;
			case TLS_EC_POINT_ANSI_X962_COMPRESSED_PRIME:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sCompressed Prime (ID 1)\n", (indent + 1) * 4, "");
				break;
			case TLS_EC_POINT_ANSI_X962_COMPRESSED_CHAR2:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sCompressed Binary (ID 2)\n", (indent + 1) * 4, "");
				break;
			default:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sUnknown (ID %hhu)\n", (indent + 1) * 4, "", format->formats[i]);
				break;
			}
		}
	}
	break;
	case TLS_EXT_SRP:
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
	{
		tls_extension_signature_algorithm *signatures = extension;
		uint16_t count = signatures->size / 2;

		for (uint16_t i = 0; i < count; ++i)
		{
			switch (signatures->algorithms[i])
			{
			case TLS_RSA_PKCS_SHA1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pkcs1_sha1 (ID 0201)\n", (indent + 1) * 4, "");
				break;
			case TLS_DSA_SHA1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sdsa_sha1 (ID 0202)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_SHA1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_secp160r1_sha1 (ID 0203)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PKCS_SHA256:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pkcs1_sha256 (ID 0401)\n", (indent + 1) * 4, "");
				break;
			case TLS_DSA_SHA256:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sdsa_sha256 (ID 0402)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_SECP256R1_SHA256:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_secp256r1_sha1 (ID 0403)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PKCS_SHA384:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pkcs1_sha384 (ID 0501)\n", (indent + 1) * 4, "");
				break;
			case TLS_DSA_SHA384:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sdsa_sha384 (ID 0502)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_SECP384R1_SHA384:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_secp384r1_sha384 (ID 0503)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PKCS_SHA512:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pkcs1_sha512 (ID 0601)\n", (indent + 1) * 4, "");
				break;
			case TLS_DSA_SHA512:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sdsa_sha512 (ID 0602)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_SECP521R1_SHA512:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_secp521r1_sha512 (ID 0603)\n", (indent + 1) * 4, "");
				break;
			case TLS_SM2_SM3:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*ssm2sig_sm3 (ID 0708)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_256A:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_256a (ID 0709)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_256B:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_256b (ID 070A)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_256C:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_256c (ID 070B)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_256D:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_256d (ID 070C)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_512A:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_512a (ID 070D)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_512B:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_512b (ID 070E)\n", (indent + 1) * 4, "");
				break;
			case TLS_GOST_R34102012_512C:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sgostr34102012_512c (ID 070F)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PSS_RSAE_SHA256:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pss_rsae_sha256 (ID 0804)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PSS_RSAE_SHA384:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pss_rsae_sha384 (ID 0805)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PSS_RSAE_SHA512:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pss_rsae_sha512 (ID 0806)\n", (indent + 1) * 4, "");
				break;
			case TLS_ED25519:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sed25519 (ID 0807)\n", (indent + 1) * 4, "");
				break;
			case TLS_ED448:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sed448 (ID 0808)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PSS_PSS_SHA256:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pss_pss_sha256 (ID 0809)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PSS_PSS_SHA384:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pss_pss_sha384 (ID 080A)\n", (indent + 1) * 4, "");
				break;
			case TLS_RSA_PSS_PSS_SHA512:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*srsa_pss_pss_sha512 (ID 080B)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_BRAINPOOL_P256R1_TLS13_SHA256:
				pos +=
					snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_brainpoolP256r1tls13_sha256 (ID 081A)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_BRAINPOOL_P384R1_TLS13_SHA384:
				pos +=
					snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_brainpoolP384r1tls13_sha384 (ID 081B)\n", (indent + 1) * 4, "");
				break;
			case TLS_ECDSA_BRAINPOOL_P512R1_TLS13_SHA512:
				pos +=
					snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*secdsa_brainpoolP512r1tls13_sha512 (ID 081C)\n", (indent + 1) * 4, "");
				break;
			default:
			{
				if (tls_check_grease_value(signatures->algorithms[i]))
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGREASE (ID %04hX)\n", (indent + 1) * 4, "",
									signatures->algorithms[i]);
				}
				else
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sUnknown (ID %04hX)\n", (indent + 1) * 4, "",
									signatures->algorithms[i]);
				}
			}
			break;
			}
		}
	}
	break;
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
		break;
	}

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
