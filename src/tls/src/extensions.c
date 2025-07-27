/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/extensions.h>
#include <tls/grease.h>
#include <tls/memory.h>
#include <tls/print.h>

#include <load.h>
#include <ptr.h>

tls_error_t tls_extension_header_read(tls_extension_header *header, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	if (size < TLS_EXTENSION_HEADER_OCTETS)
	{
		return TLS_INSUFFICIENT_DATA;
	}

	memset(header, 0, sizeof(tls_extension_header));

	// 2 octet extension type
	LOAD_16BE(&header->type, in + pos);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(&header->size, in + pos);
	pos += 2;

	return TLS_SUCCESS;
}

uint32_t tls_extension_header_write(tls_extension_header *header, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < TLS_EXTENSION_HEADER_OCTETS)
	{
		return 0;
	}

	// 2 octet extension type
	LOAD_16BE(out + pos, &header->type);
	pos += 2;

	// 2 octet extension size
	LOAD_16BE(out + pos, &header->size);
	pos += 2;

	return pos;
}

tls_error_t tls_extension_read(void **extension, void *data, uint32_t size)
{
	tls_error_t error = 0;
	uint8_t *in = data;
	uint32_t pos = 0;

	tls_extension_header header = {0};

	error = tls_extension_header_read(&header, data, size);
	pos += TLS_EXTENSION_HEADER_OCTETS;

	if (error != TLS_SUCCESS)
	{
		return error;
	}

	switch (header.type)
	{
	case TLS_EXT_SERVER_NAME:
	{
		tls_extension_server_name *server = zmalloc(sizeof(tls_extension_server_name));
		uint32_t new_pos = 0;
		uint16_t name_size = 0;
		uint16_t name_count = 0;

		if (server == NULL)
		{
			return TLS_NO_MEMORY;
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
			free(server);
			return TLS_NO_MEMORY;
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
					return TLS_NO_MEMORY;
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
			return TLS_NO_MEMORY;
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
		tls_extension_supported_group *group = zmalloc(sizeof(tls_extension_supported_group) + (header.size - 2));
		uint16_t count = 0;

		if (group == NULL)
		{
			return TLS_NO_MEMORY;
		}

		// Copy the header
		group->header = header;

		// 2 octet size
		LOAD_16BE(&group->size, in + pos);
		pos += 2;

		if (group->size != (header.size - 2))
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
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
			return TLS_NO_MEMORY;
		}

		// Copy the header
		format->header = header;

		// 1 octet size
		LOAD_8(&format->size, in + pos);
		pos += 1;

		if (format->size != (header.size - 1))
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
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
			return TLS_NO_MEMORY;
		}

		// Copy the header
		signatures->header = header;

		// 2 octet size
		LOAD_16BE(&signatures->size, in + pos);
		pos += 2;

		if (signatures->size != (header.size - 2))
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
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
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
	{
		tls_extensions_application_protocol_negotiation *protocols = NULL;
		tls_opaque_data *name = NULL;
		uint16_t total_size = 0;
		uint16_t count = 0;
		uint16_t offset = 0;

		// 2 octet size
		LOAD_16BE(&total_size, in + pos);
		pos += 2;

		if ((total_size + 2) != header.size)
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
		}

		// Count the number of protocols
		while (offset < total_size)
		{
			offset += in[pos + offset] + 1;
			count += 1;
		}

		protocols =
			zmalloc(sizeof(tls_extensions_application_protocol_negotiation) + (sizeof(tls_opaque_data) * count) + (total_size - count));

		if (protocols == NULL)
		{
			return TLS_NO_MEMORY;
		}

		// Copy the header
		protocols->header = header;
		protocols->size = total_size;
		protocols->count = count;

		name = PTR_OFFSET(protocols, sizeof(tls_extensions_application_protocol_negotiation));
		offset = (sizeof(tls_opaque_data) * count);

		for (uint16_t i = 0; i < count; ++i)
		{
			// 1 octet size
			LOAD_8(&name[i].size, in + pos);
			pos += 1;

			// N octet data
			memcpy(PTR_OFFSET(name, offset), in + pos, name[i].size);
			pos += name[i].size;

			name[i].offset = offset;
			offset += name[i].size;
		}

		*extension = protocols;
	}
	break;
		// case TLS_EXT_STATUS_REQUEST_V2:
		// case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		// case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
		// case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		// case TLS_EXT_PADDING:
		// case TLS_EXT_ENCRYPT_THEN_MAC:
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		goto empty;
		break;
	// case TLS_EXT_TOKEN_BINDING:
	// case TLS_EXT_CACHED_INFO:
	// case TLS_EXT_LTS:
	// case TLS_EXT_COMPRESS_CERTIFICATE:
	case TLS_EXT_RECORD_SIZE_LIMIT:
	{
		tls_extension_record_size_limit *limit = zmalloc(sizeof(tls_extension_record_size_limit));

		if (limit == NULL)
		{
			return TLS_NO_MEMORY;
		}

		// Copy the header
		limit->header = header;

		// 2 octet length identifier
		LOAD_16BE(&limit->limit, in + pos);
		pos += 2;

		if (limit->limit < 64)
		{
			return TLS_INVALID_RECORD_LIMIT;
		}

		*extension = limit;
	}
	break;
	// case TLS_EXT_PASSWORD_PROTECT:
	// case TLS_EXT_PASSWORD_CLEAR:
	// case TLS_EXT_PASSWORD_SALT:
	// case TLS_EXT_TICKET_PINNING:
	// case TLS_EXT_DELEGATED_CREDENTIAL:
	case TLS_EXT_SESSION_TICKET:
		goto empty;
		break;
	// case TLS_EXT_PSK:
	// case TLS_EXT_EARLY_DATA:
	case TLS_EXT_SUPPORTED_VERSIONS:
	{
		tls_extension_supported_version *version = zmalloc(sizeof(tls_extension_psk_exchange_mode) + (header.size - 1));

		if (version == NULL)
		{
			return TLS_NO_MEMORY;
		}

		// Copy the header
		version->header = header;

		// 1 octet size
		LOAD_8(&version->size, in + pos);
		pos += 1;

		if (version->size != (header.size - 1))
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
		}

		// N octets of data
		memcpy(version->version, in + pos, version->size);
		pos += version->size;

		*extension = version;
	}
	break;
	// case TLS_EXT_COOKIE:
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
	{
		tls_extension_psk_exchange_mode *modes = zmalloc(sizeof(tls_extension_psk_exchange_mode) + (header.size - 1));

		if (modes == NULL)
		{
			return TLS_NO_MEMORY;
		}

		// Copy the header
		modes->header = header;

		// 1 octet size
		LOAD_8(&modes->size, in + pos);
		pos += 1;

		if (modes->size != (header.size - 1))
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
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
	case TLS_EXT_KEY_SHARE:
	{
		tls_extension_key_share *shares = NULL;
		tls_key_share *key = NULL;
		uint16_t total_size = 0;
		uint16_t count = 0;
		uint16_t offset = 0;

		// 2 octet size
		LOAD_16BE(&total_size, in + pos);
		pos += 2;

		if ((total_size + 2) != header.size)
		{
			return TLS_MALFORMED_EXTENSION_SIZE;
		}

		// Count the number of protocols
		while (offset < total_size)
		{
			offset += (in[pos + offset + 2] << 8) + in[pos + offset + 3] + 4;
			count += 1;
		}

		shares = zmalloc(sizeof(tls_extension_key_share) + (sizeof(tls_key_share) * count) + (total_size - (count * 4)));

		if (shares == NULL)
		{
			return TLS_NO_MEMORY;
		}

		// Copy the header
		shares->header = header;
		shares->size = total_size;
		shares->count = count;

		key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));
		offset = (sizeof(tls_key_share) * count);

		for (uint16_t i = 0; i < count; ++i)
		{
			// 2 octet group
			LOAD_16BE(&key[i].group, in + pos);
			pos += 2;

			// 2 octet size
			LOAD_16BE(&key[i].size, in + pos);
			pos += 2;

			// N octet data
			memcpy(PTR_OFFSET(key, offset), in + pos, key[i].size);
			pos += key[i].size;

			key[i].offset = offset;
			offset += key[i].size;
		}

		*extension = shares;
	}
	break;
	// case TLS_EXT_TRANSPARENCY_INFO:
	// case TLS_EXT_CONNECTION_INFO_LEGACY:
	// case TLS_EXT_CONNECTION_INFO:
	// case TLS_EXT_EXTERNAL_ID_HASH:
	// case TLS_EXT_EXTERNAL_SESSION_ID:
	default:
	{
	empty:
		tls_extension_header *unknown = zmalloc(sizeof(tls_extension_header));

		if (unknown == NULL)
		{
			return TLS_NO_MEMORY;
		}

		unknown->type = header.type;
		unknown->size = header.size;

		*extension = unknown;
	}
	break;
	}

	return TLS_SUCCESS;
}

uint32_t tls_extension_write(void *extension, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	pos += tls_extension_header_write(header, buffer, size);

	switch (header->type)
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
		tls_extension_supported_group *group = extension;
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
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
	{
		tls_extensions_application_protocol_negotiation *protocols = extension;
		tls_opaque_data *name = PTR_OFFSET(protocols, sizeof(tls_extensions_application_protocol_negotiation));

		// 2 octet size
		LOAD_16BE(out + pos, &protocols->size);
		pos += 2;

		for (uint16_t i = 0; i < protocols->count; ++i)
		{
			// 1 octet size
			LOAD_8(out + pos, &name[i].size);
			pos += 1;

			// N octet data
			memcpy(out + pos, PTR_OFFSET(name, name[i].offset), name[i].size);
			pos += name[i].size;
		}
	}
	break;
	case TLS_EXT_STATUS_REQUEST_V2:
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
	case TLS_EXT_PADDING:
	case TLS_EXT_ENCRYPT_THEN_MAC:
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		// empty body
		break;
	case TLS_EXT_TOKEN_BINDING:
	case TLS_EXT_CACHED_INFO:
	case TLS_EXT_LTS:
	case TLS_EXT_COMPRESS_CERTIFICATE:
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
	{
		tls_extension_record_size_limit *limit = extension;

		// 2 octet length identifier
		LOAD_16BE(out + pos, &limit->limit);
		pos += 2;
	}
	break;
	case TLS_EXT_PASSWORD_PROTECT:
	case TLS_EXT_PASSWORD_CLEAR:
	case TLS_EXT_PASSWORD_SALT:
	case TLS_EXT_TICKET_PINNING:
	case TLS_EXT_DELEGATED_CREDENTIAL:
		break;
	case TLS_EXT_SESSION_TICKET:
		// empty body
		break;
	case TLS_EXT_PSK:
	case TLS_EXT_EARLY_DATA:
		break;
	case TLS_EXT_SUPPORTED_VERSIONS:
	{
		tls_extension_supported_version *version = extension;

		// 1 octet size
		LOAD_8(out + pos, &version->size);
		pos += 1;

		// N octets of data
		memcpy(out + pos, version->version, version->size);
		pos += version->size;
	}
	break;
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
		break;
	case TLS_EXT_KEY_SHARE:
	{
		tls_extension_key_share *shares = extension;
		tls_key_share *key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));

		// 2 octet size
		LOAD_16BE(out + pos, &shares->size);
		pos += 2;

		for (uint16_t i = 0; i < shares->count; ++i)
		{
			// 2 octet group
			LOAD_16BE(out + pos, &key[i].group);
			pos += 2;

			// 2 octet size
			LOAD_16BE(out + pos, &key[i].size);
			pos += 2;

			// N octet data
			memcpy(out + pos, PTR_OFFSET(key, key[i].offset), key[i].size);
			pos += key[i].size;
		}
	}
	break;
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

static uint32_t print_extension_header(tls_extension_header *header, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*s", indent * 4, "");

	switch (header->type)
	{
	case TLS_EXT_SERVER_NAME:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Name (ID 0) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Max Fragment Length (ID 1) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Certificate URL (ID 2) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Trusted CA Keys (ID 3) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Truncated HMAC (ID 4) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_STATUS_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Status Request (ID 5) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_USER_MAPPING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "User Mapping (ID 6) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CLIENT_AUTHORIZATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Authorization (ID 7) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Authorization (ID 8) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CERTIFICATE_TYPE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Type (ID 9) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Supported Groups (ID 10) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "EC Point Formats (ID 11) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SRP:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Secure Remote Password (ID 12) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Signature Algorithms (ID 13) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_USE_SRTP:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Use SRTP (ID 14) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_HEARTBEAT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Heartbeat (ID 15) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Application Layer Protocol Negotiation (ID 16) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_STATUS_REQUEST_V2:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Status Request V2 (ID 17) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Signed Certificate Timestamp (ID 18) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Certificate Type (ID 19) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Certificate Type (ID 20) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_PADDING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Padding (ID 21) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_ENCRYPT_THEN_MAC:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Encrypt Then MAC (ID 22) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Extended Master Secret (ID 23) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_TOKEN_BINDING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Token Binding (ID 24) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CACHED_INFO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Cached Information (ID 25) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_LTS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Long Term Support (ID 26) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_COMPRESS_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Compressed Certificate (ID 27) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Max Record Size (ID 28) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_PASSWORD_PROTECT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Password Protect (ID 29) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_PASSWORD_CLEAR:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Password Clear (ID 30) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_PASSWORD_SALT:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Password Salt (ID 31) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_TICKET_PINNING:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Ticket Pinning (ID 32) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_DELEGATED_CREDENTIAL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Delegated Credential (ID 34) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SESSION_TICKET:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Session Ticket (ID 35) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_PSK:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Pre-Shared Key (ID 41) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_EARLY_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Early Data (ID 42) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SUPPORTED_VERSIONS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Supported Version (ID 43) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_COOKIE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Cookie (ID 44) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "PSK Exchange Modes (ID 45) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Authorities (ID 47) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_OID_FILTERS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "OID Filters (ID 48) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_POST_HANDSHAKE_AUTH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Post Handshake Authorization (ID 49) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Signature Algorithms Certificate (ID 50) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_KEY_SHARE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Key Share (ID 51) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_TRANSPARENCY_INFO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Transparency Information (ID 52) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CONNECTION_INFO_LEGACY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Connection Information (Legacy) (ID 53) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_CONNECTION_INFO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Connection Information (ID 54) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_EXTERNAL_ID_HASH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "External ID Hash (ID 55) (%hu bytes)\n", header->size);
		break;
	case TLS_EXT_EXTERNAL_SESSION_ID:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "External Session ID (ID 56) (%hu bytes)\n", header->size);
		break;
	default:
	{
		if (tls_check_grease_value(header->type))
		{
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "GREASE Extension (ID %04hX) (%hu bytes)\n", header->type, header->size);
		}
		else
		{
			pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hu) (%hu bytes)\n", header->type, header->size);
		}
	}
	break;
	}

	return pos;
}

uint32_t tls_extension_print(void *extension, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// Extension Type
	pos += print_extension_header(header, PTR_OFFSET(buffer, pos), size - pos, indent);

	switch (header->type)
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
		tls_extension_supported_group *group = extension;
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
			case TLS_FFDHE_2048:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sffdhe2048 (ID 256)\n", (indent + 1) * 4, "");
				break;
			case TLS_FFDHE_3072:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sffdhe3072 (ID 257)\n", (indent + 1) * 4, "");
				break;
			case TLS_FFDHE_4096:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sffdhe4096 (ID 258)\n", (indent + 1) * 4, "");
				break;
			case TLS_FFDHE_6144:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sffdhe6144 (ID 259)\n", (indent + 1) * 4, "");
				break;
			case TLS_FFDHE_8192:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sffdhe8192 (ID 260)\n", (indent + 1) * 4, "");
				break;
			default:
			{
				if (tls_check_grease_value(group->groups[i]))
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGREASE Group (ID %04hX)\n", (indent + 1) * 4, "",
									group->groups[i]);
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
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGREASE Signature (ID %04hX)\n", (indent + 1) * 4, "",
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
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
	{
		tls_extensions_application_protocol_negotiation *protocols = extension;
		tls_opaque_data *name = PTR_OFFSET(protocols, sizeof(tls_extensions_application_protocol_negotiation));

		for (uint16_t i = 0; i < protocols->count; ++i)
		{
			pos += print_format(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "%.*s\n", name[i].size, PTR_OFFSET(name, name[i].offset));
		}
	}
	break;
	case TLS_EXT_STATUS_REQUEST_V2:
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
	case TLS_EXT_PADDING:
	case TLS_EXT_ENCRYPT_THEN_MAC:
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		// empty body
		break;
	case TLS_EXT_TOKEN_BINDING:
	case TLS_EXT_CACHED_INFO:
	case TLS_EXT_LTS:
	case TLS_EXT_COMPRESS_CERTIFICATE:
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
	{
		tls_extension_record_size_limit *limit = extension;

		// Record Size Limit
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sRecord Size Limit: %hu bytes\n", (indent + 1) * 4, "", limit->limit);
	}
	break;
	case TLS_EXT_PASSWORD_PROTECT:
	case TLS_EXT_PASSWORD_CLEAR:
	case TLS_EXT_PASSWORD_SALT:
	case TLS_EXT_TICKET_PINNING:
	case TLS_EXT_DELEGATED_CREDENTIAL:
		break;
	case TLS_EXT_SESSION_TICKET:
		// empty body
		break;
	case TLS_EXT_PSK:
	case TLS_EXT_EARLY_DATA:
		break;
	case TLS_EXT_SUPPORTED_VERSIONS:
	{
		tls_extension_supported_version *version = extension;
		uint8_t count = version->size / 2;

		for (uint8_t i = 0; i < count; ++i)
		{
			switch (TLS_VERSION_RAW(version->version[i]))
			{
			case TLS_VERSION_1_0:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sTLS 1.0 (3, 1)\n", (indent + 1) * 4, "");
				break;
			case TLS_VERSION_1_1:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sTLS 1.1 (3, 2)\n", (indent + 1) * 4, "");
				break;
			case TLS_VERSION_1_2:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sTLS 1.2 (3, 3)\n", (indent + 1) * 4, "");
				break;
			case TLS_VERSION_1_3:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sTLS 1.3 (3, 4)\n", (indent + 1) * 4, "");
				break;
			default:
			{
				if (tls_check_grease_value(TLS_VERSION_RAW(version->version[i])))
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGREASE Version (%02hhX, %02hhX)\n", (indent + 1) * 4, "",
									version->version[i].major, version->version[i].minor);
				}
				else
				{
					pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sUnknown (%hhu, %hhu)\n", (indent + 1) * 4, "",
									version->version[i].major, version->version[i].minor);
				}
			}
			break;
			}
		}
	}
	break;
	case TLS_EXT_COOKIE:
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
	{
		tls_extension_psk_exchange_mode *modes = extension;

		for (uint8_t i = 0; i < modes->size; ++i)
		{
			switch (modes->modes[i])
			{
			case TLS_PSK_KEY_EXCHANGE:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sPSK-only key establishment (ID 0)\n", (indent + 1) * 4, "");
				break;
			case TLS_PSK_DHE_KEY_EXCHANGE:
				pos +=
					snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sPSK with (EC)DHE key establishment (ID 1)\n", (indent + 1) * 4, "");
				break;
				// GREASE
			case 0x0B:
			case 0x2A:
			case 0x49:
			case 0x68:
			case 0x87:
			case 0xA6:
			case 0xC5:
			case 0xE4:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sGREASE PSK (ID %02hhX)\n", (indent + 1) * 4, "", modes->modes[i]);
				break;
			default:
				pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sUnknown (ID %hhu)\n", (indent + 1) * 4, "", modes->modes[i]);
				break;
			}
		}
	}
	break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
	case TLS_EXT_OID_FILTERS:
	case TLS_EXT_POST_HANDSHAKE_AUTH:
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		break;
	case TLS_EXT_KEY_SHARE:
	{
		tls_extension_key_share *shares = extension;
		tls_key_share *key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));

		for (uint16_t i = 0; i < shares->count; ++i)
		{
			switch (key[i].group)
			{
			case TLS_SECT_163K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect163k1 (ID 1)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_163R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect163r1 (ID 2)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_163R2:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect163r2 (ID 3)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_193R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect193r1 (ID 4)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_193R2:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect193r2 (ID 5)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_233K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect233k1 (ID 6)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_233R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect233r1 (ID 7)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_239K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect239k1 (ID 8)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_283K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect283k1 (ID 9)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_283R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect283r1 (ID 10)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_409K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect409k1 (ID 11)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_409R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect409r1 (ID 12)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_571K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect571k1 (ID 13)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECT_571R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "sect571r1 (ID 14)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_160K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp160k1 (ID 15)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_160R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp160r1 (ID 16)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_160R2:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp160r2 (ID 17)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_192K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp192k1 (ID 18)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_192R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp192r1 (ID 19)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_224K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp224k1 (ID 20)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_224R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp224r1 (ID 21)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_256K1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp256k1 (ID 22)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_256R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp256r1 (ID 23)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_384R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp384r1 (ID 24)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SECP_521R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "secp521r1 (ID 25)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_BRAINPOOL_256R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP256r1 (ID 26)",
								   PTR_OFFSET(key, key[i].offset), key[i].size);
				break;
			case TLS_BRAINPOOL_384R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP384r1 (ID 27)",
								   PTR_OFFSET(key, key[i].offset), key[i].size);
				break;
			case TLS_BRAINPOOL_512R1:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP512r1 (ID 28)",
								   PTR_OFFSET(key, key[i].offset), key[i].size);
				break;
			case TLS_X25519:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "x25519 (ID 29)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_X448:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "x448 (ID 30)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_BRAINPOOL_256R1_TLS_13:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP256r1tls13 (ID 31)",
								   PTR_OFFSET(key, key[i].offset), key[i].size);
				break;
			case TLS_BRAINPOOL_384R1_TLS_13:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP384r1tls13 (ID 32)",
								   PTR_OFFSET(key, key[i].offset), key[i].size);
				break;
			case TLS_BRAINPOOL_512R1_TLS_13:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP512r1tls13 (ID 33)",
								   PTR_OFFSET(key, key[i].offset), key[i].size);
				break;
			case TLS_GOST_256A:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC256A (ID 34)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_GOST_256B:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC256B (ID 35)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_GOST_256C:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC256C (ID 36)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_GOST_256D:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC256D (ID 37)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_GOST_512A:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC512A (ID 38)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_GOST_512B:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC512B (ID 39)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_GOST_512C:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "GC512C (ID 40)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_SM2:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "SM2 (ID 41)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_FFDHE_2048:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "ffdhe2048 (ID 256)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_FFDHE_3072:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "ffdhe3072 (ID 257)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_FFDHE_4096:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "ffdhe4096 (ID 258)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_FFDHE_6144:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "ffdhe6144 (ID 259)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			case TLS_FFDHE_8192:
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "ffdhe8192 (ID 260)", PTR_OFFSET(key, key[i].offset),
								   key[i].size);
				break;
			default:
			{
				pos += print_bytes(indent + 1, PTR_OFFSET(buffer, pos), size - pos, "Unknown", PTR_OFFSET(key, key[i].offset), key[i].size);
			}
			break;
			}
		}
	}
	break;
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
