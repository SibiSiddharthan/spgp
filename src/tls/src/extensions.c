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

// RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
// Server Name
static tls_error_t tls_extension_server_name_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_server_name *server = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	uint32_t new_pos = 0;
	uint16_t name_size = 0;
	uint16_t name_count = 0;

	server = zmalloc(sizeof(tls_extension_server_name));

	if (server == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	server->header = *header;

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

	return TLS_SUCCESS;
}

static uint32_t tls_extension_server_name_write_body(tls_extension_server_name *server, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

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

	return pos;
}

static uint32_t tls_extension_server_name_print_body(tls_extension_server_name *server, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	for (uint16_t i = 0; i < server->count; ++i)
	{
		tls_server_name *name = server->list[i];

		switch (name->name_type)
		{
		case TLS_HOST_NAME:
		{
			// Name Type
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Name Type: Host Name (ID 0)\n");

			// Name
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Name (%hu bytes): %.*s\n", name->name_size, name->name_size,
								name->name);
		}
		break;
		}
	}

	return pos;
}

// RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
// Max Fragment Length
static tls_error_t tls_extension_max_fragment_length_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_max_fragment_length *fragment = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	fragment = zmalloc(sizeof(tls_extension_max_fragment_length));

	if (fragment == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	fragment->header = *header;

	// 1 octet length identifier
	LOAD_8(&fragment->max_fragment_length, in + pos);
	pos += 1;

	*extension = fragment;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_max_fragment_length_write_body(tls_extension_max_fragment_length *fragment, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet length identifier
	LOAD_8(out + pos, &fragment->max_fragment_length);
	pos += 1;

	return pos;
}

static uint32_t tls_extension_max_fragment_length_print_body(tls_extension_max_fragment_length *fragment, void *buffer, uint32_t size,
															 uint32_t indent)
{
	uint32_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Maximum Fragment Length: ");

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

	return pos;
}

// RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
// Trusted CA Keys
static tls_error_t tls_extension_trusted_ca_keys_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_trusted_authority *authorities = NULL;
	tls_trusted_authority *authority = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	uint8_t type = 0;
	uint16_t size = 0;

	authorities = zmalloc(sizeof(tls_extension_trusted_authority) + (4 * sizeof(void *)));

	if (authorities == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	authorities->header = *header;
	authorities->authorities = PTR_OFFSET(authorities, sizeof(tls_extension_trusted_authority));

	// 2 octet size
	LOAD_16BE(&authorities->size, in + pos);
	pos += 2;

	if ((authorities->size + 2) != header->size)
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	while (pos < header->size)
	{
		// 1 octet identifier type
		LOAD_8(&type, in + pos);
		pos += 1;

		switch (type)
		{
		case TLS_PRE_AGREED:
		{
			authority = zmalloc(sizeof(tls_trusted_authority));

			if (authority == NULL)
			{
				return TLS_NO_MEMORY;
			}

			authority->type = type;
		}
		break;
		case TLS_X509_NAME:
		{
			// 2 octet size
			LOAD_16BE(&size, in + pos);
			pos += 2;

			authority = zmalloc(sizeof(tls_trusted_authority) + 2 + size);

			if (authority == NULL)
			{
				return TLS_NO_MEMORY;
			}

			authority->type = type;
			authority->distinguished_name.size = size;

			// N octets of distinguished name
			memcpy(authority->distinguished_name.name, in + pos, authority->distinguished_name.size);
			pos += authority->distinguished_name.size;
		}
		break;
		case TLS_KEY_SHA1:
		case TLS_CERT_SHA1:
		{
			authority = zmalloc(sizeof(tls_trusted_authority) + 20);

			if (authority == NULL)
			{
				return TLS_NO_MEMORY;
			}

			authority->type = type;

			// 20 octets of sha1 hash
			memcpy(authority->sha1_hash, in + pos, 20);
			pos += 20;
		}
		break;
		default:
			break;
		}

		authorities->authorities[authorities->count] = authority;
		authorities->count += 1;
	}

	*extension = authorities;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_trusted_ca_keys_write_body(tls_extension_trusted_authority *authorities, void *buffer)
{
	tls_trusted_authority *authority = NULL;

	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 2 octet size
	LOAD_16BE(out + pos, &authorities->size);
	pos += 2;

	for (uint32_t i = 0; i < authorities->count; ++i)
	{
		authority = authorities->authorities[i];

		// 1 octet identifier type
		LOAD_8(out + pos, &authority->type);
		pos += 1;

		switch (authority->type)
		{
		case TLS_PRE_AGREED:
			// empty
			break;
		case TLS_X509_NAME:
		{
			// 2 octet size
			LOAD_16BE(out + pos, &authority->distinguished_name.name);
			pos += 2;

			// N octets of distinguished name
			memcpy(out + pos, authority->distinguished_name.name, authority->distinguished_name.size);
			pos += authority->distinguished_name.size;
		}
		break;
		case TLS_KEY_SHA1:
		case TLS_CERT_SHA1:
		{
			// 20 octets of sha1 hash
			memcpy(out + pos, authority->sha1_hash, 20);
			pos += 20;
		}
		break;
		default:
			break;
		}
	}

	return pos;
}

static uint32_t tls_extension_trusted_ca_keys_print_body(tls_extension_trusted_authority *authorities, void *buffer, uint32_t size,
														 uint32_t indent)
{
	tls_trusted_authority *authority = NULL;
	uint32_t pos = 0;

	for (uint32_t i = 0; i < authorities->count; ++i)
	{
		authority = authorities->authorities[i];

		switch (authority->type)
		{
		case TLS_PRE_AGREED:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Pre Agreed (ID 0)\n");
			break;
		case TLS_KEY_SHA1:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "Key SHA1-Hash (ID 1)", authority->sha1_hash, 20);
			break;
		case TLS_X509_NAME:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "X509 Name (ID 2): %.*s\n", authority->distinguished_name.size,
								authority->distinguished_name.name);
			break;
		case TLS_CERT_SHA1:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "Certificate SHA1-Hash (ID 3)", authority->sha1_hash, 20);
			break;
		default:
			break;
		}
	}

	return pos;
}

// RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
// Status Request
static tls_error_t tls_extension_status_request_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_status_request *status = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;
	uint16_t offset = 0;

	status = zmalloc(sizeof(tls_extension_status_request) + (header->size - 5));

	if (status == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	status->header = *header;

	// 1 octet request type
	LOAD_8(&status->type, in + pos);
	pos += 1;

	if (status->type == TLS_CERTIFICATE_STATUS_OCSP)
	{
		offset = sizeof(tls_extension_status_request);

		// 2 octet responder size
		LOAD_16BE(&status->responder_size, in + pos);
		pos += 2;

		if (status->responder_size > 0)
		{
			memcpy(PTR_OFFSET(status, offset), in + pos, status->responder_size);
			pos += status->responder_size;
			offset += status->responder_size;
		}

		// 2 octet extension size
		LOAD_16BE(&status->extension_size, in + pos);
		pos += 2;

		if (status->extension_size > 0)
		{
			memcpy(PTR_OFFSET(status, offset), in + pos, status->extension_size);
			pos += status->extension_size;
			offset += status->extension_size;
		}
	}

	*extension = status;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_status_request_write_body(tls_extension_status_request *status, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;
	uint16_t offset = 0;

	// 1 octet request type
	LOAD_8(out + pos, &status->type);
	pos += 1;

	if (status->type == TLS_CERTIFICATE_STATUS_OCSP)
	{
		offset = sizeof(tls_extension_status_request);

		// 2 octet responder size
		LOAD_16BE(out + pos, &status->responder_size);
		pos += 2;

		if (status->responder_size > 0)
		{
			memcpy(out + pos, PTR_OFFSET(status, offset), status->responder_size);
			pos += status->responder_size;
			offset += status->responder_size;
		}

		// 2 octet extension size
		LOAD_16BE(out + pos, &status->extension_size);
		pos += 2;

		if (status->extension_size > 0)
		{
			memcpy(out + pos, PTR_OFFSET(status, offset), status->extension_size);
			pos += status->extension_size;
			offset += status->extension_size;
		}
	}

	return pos;
}

static uint32_t tls_extension_status_request_print_body(tls_extension_status_request *status, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	if (status->type == TLS_CERTIFICATE_STATUS_OCSP)
	{
		pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "OCSP (ID 1)\n");
	}
	else
	{
		pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown Certificate Request (ID %hhu)\n", status->type);
	}

	return pos;
}

// RFC 4681: TLS User Mapping Extension
// User Mapping
static tls_error_t tls_extension_user_mapping_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_user_mapping *user = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	user = zmalloc(sizeof(tls_extension_user_mapping) + (header->size - 1));

	if (user == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	user->header = *header;

	// 1 octet size
	LOAD_8(&user->size, in + pos);
	pos += 1;

	if (user->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(user->types, in + pos, user->size);
	pos += user->size;

	*extension = user;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_user_mapping_write_body(tls_extension_user_mapping *user, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &user->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, user->types, user->size);
	pos += user->size;

	return pos;
}

static uint32_t tls_extension_user_mapping_print_body(tls_extension_user_mapping *user, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < user->size; ++i)
	{
		switch (user->types[i])
		{
		default:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", user->types[i]);
			break;
		}
	}

	return pos;
}

// RFC 6091: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
// User Mapping
static tls_error_t tls_extension_certificate_types_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_certificate_type *types = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	types = zmalloc(sizeof(tls_extension_certificate_type) + (header->size - 1));

	if (types == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	types->header = *header;

	// 1 octet size
	LOAD_8(&types->size, in + pos);
	pos += 1;

	if (types->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(types->types, in + pos, types->size);
	pos += types->size;

	*extension = types;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_certificate_types_write_body(tls_extension_certificate_type *types, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &types->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, types->types, types->size);
	pos += types->size;

	return pos;
}

static uint32_t tls_extension_certificate_types_print_body(tls_extension_certificate_type *types, void *buffer, uint32_t size,
														   uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < types->size; ++i)
	{
		switch (types->types[i])
		{
		case TLS_CERTIFICATE_X509:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "X.509 (ID 0)\n");
			break;
		case TLS_CERTIFICATE_PGP:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "PGP (ID 1)\n");
			break;
		default:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", types->types[i]);
			break;
		}
	}

	return pos;
}

// RFC 8442: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
// Supported Groups
static tls_error_t tls_extension_supported_groups_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_supported_group *group = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;
	uint16_t count = 0;

	group = zmalloc(sizeof(tls_extension_supported_group) + (header->size - 2));

	if (group == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	group->header = *header;

	// 2 octet size
	LOAD_16BE(&group->size, in + pos);
	pos += 2;

	if (group->size != (header->size - 2))
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

	return TLS_SUCCESS;
}

static uint32_t tls_extension_supported_groups_write_body(tls_extension_supported_group *group, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;
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

	return pos;
}

static uint32_t tls_extension_supported_groups_print_body(tls_extension_supported_group *group, void *buffer, uint32_t size,
														  uint32_t indent)
{
	uint32_t pos = 0;
	uint16_t count = group->size / 2;

	for (uint16_t i = 0; i < count; ++i)
	{
		switch (group->groups[i])
		{
		case TLS_SECT_163K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect163k1 (ID 1)\n");
			break;
		case TLS_SECT_163R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect163r1 (ID 2)\n");
			break;
		case TLS_SECT_163R2:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect163r2 (ID 3)\n");
			break;
		case TLS_SECT_193R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect193r1 (ID 4)\n");
			break;
		case TLS_SECT_193R2:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect193r2 (ID 5)\n");
			break;
		case TLS_SECT_233K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect233k1 (ID 6)\n");
			break;
		case TLS_SECT_233R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect233r1 (ID 7)\n");
			break;
		case TLS_SECT_239K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect239k1 (ID 8)\n");
			break;
		case TLS_SECT_283K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect283k1 (ID 9)\n");
			break;
		case TLS_SECT_283R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect283r1 (ID 10)\n");
			break;
		case TLS_SECT_409K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect409k1 (ID 11)\n");
			break;
		case TLS_SECT_409R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect409r1 (ID 12)\n");
			break;
		case TLS_SECT_571K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect571k1 (ID 13)\n");
			break;
		case TLS_SECT_571R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sect571r1 (ID 14)\n");
			break;
		case TLS_SECP_160K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp160k1 (ID 15)\n");
			break;
		case TLS_SECP_160R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp160r1 (ID 16)\n");
			break;
		case TLS_SECP_160R2:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp160r2 (ID 17)\n");
			break;
		case TLS_SECP_192K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp192k1 (ID 18)\n");
			break;
		case TLS_SECP_192R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp192r1 (ID 19)\n");
			break;
		case TLS_SECP_224K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp224k1 (ID 20)\n");
			break;
		case TLS_SECP_224R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp224r1 (ID 21)\n");
			break;
		case TLS_SECP_256K1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp256k1 (ID 22)\n");
			break;
		case TLS_SECP_256R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp256r1 (ID 23)\n");
			break;
		case TLS_SECP_384R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp384r1 (ID 24)\n");
			break;
		case TLS_SECP_521R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "secp521r1 (ID 25)\n");
			break;
		case TLS_BRAINPOOL_256R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP256r1 (ID 26)\n");
			break;
		case TLS_BRAINPOOL_384R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP384r1 (ID 27)\n");
			break;
		case TLS_BRAINPOOL_512R1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP512r1 (ID 28)\n");
			break;
		case TLS_X25519:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "x25519 (ID 29)\n");
			break;
		case TLS_X448:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "x448 (ID 30)\n");
			break;
		case TLS_BRAINPOOL_256R1_TLS_13:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP256r1tls13 (ID 31)\n");
			break;
		case TLS_BRAINPOOL_384R1_TLS_13:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP384r1tls13 (ID 32)\n");
			break;
		case TLS_BRAINPOOL_512R1_TLS_13:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP512r1tls13 (ID 33)\n");
			break;
		case TLS_GOST_256A:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256A (ID 34)\n");
			break;
		case TLS_GOST_256B:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256B (ID 35)\n");
			break;
		case TLS_GOST_256C:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256C (ID 36)\n");
			break;
		case TLS_GOST_256D:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256D (ID 37)\n");
			break;
		case TLS_GOST_512A:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC512A (ID 38)\n");
			break;
		case TLS_GOST_512B:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC512B (ID 39)\n");
			break;
		case TLS_GOST_512C:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GC512C (ID 40)\n");
			break;
		case TLS_SM2:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "SM2 (ID 41)\n");
			break;
		case TLS_FFDHE_2048:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe2048 (ID 256)\n");
			break;
		case TLS_FFDHE_3072:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe3072 (ID 257)\n");
			break;
		case TLS_FFDHE_4096:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe4096 (ID 258)\n");
			break;
		case TLS_FFDHE_6144:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe6144 (ID 259)\n");
			break;
		case TLS_FFDHE_8192:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe8192 (ID 260)\n");
			break;
		default:
		{
			if (tls_check_grease_value(group->groups[i]))
			{
				pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GREASE Group (ID %04hX)\n", group->groups[i]);
			}
			else
			{
				pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hu)\n", group->groups[i]);
			}
		}
		break;
		}
	}

	return pos;
}

// RFC 8442: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
// EC Point Formats
static tls_error_t tls_extension_ec_point_format_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_ec_point_format *format = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	format = zmalloc(sizeof(tls_extension_ec_point_format) + (header->size - 1));

	if (format == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	format->header = *header;

	// 1 octet size
	LOAD_8(&format->size, in + pos);
	pos += 1;

	if (format->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(format->formats, in + pos, format->size);
	pos += format->size;

	*extension = format;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_ec_point_format_write_body(tls_extension_ec_point_format *format, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &format->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, format->formats, format->size);
	pos += format->size;

	return pos;
}

static uint32_t tls_extension_ec_point_format_print_body(tls_extension_ec_point_format *format, void *buffer, uint32_t size,
														 uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < format->size; ++i)
	{
		switch (format->formats[i])
		{
		case TLS_EC_POINT_UNCOMPRESSED:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Uncompressed (ID 0)\n");
			break;
		case TLS_EC_POINT_ANSI_X962_COMPRESSED_PRIME:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Compressed Prime (ID 1)\n");
			break;
		case TLS_EC_POINT_ANSI_X962_COMPRESSED_CHAR2:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Compressed Binary (ID 2)\n");
			break;
		default:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", format->formats[i]);
			break;
		}
	}

	return pos;
}

// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
// Signature Algorithms
static tls_error_t tls_extension_signature_algorithms_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_signature_algorithm *signatures = NULL;
	uint16_t count = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	signatures = zmalloc(sizeof(tls_extension_signature_algorithm) + (header->size - 2));

	if (signatures == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	signatures->header = *header;

	// 2 octet size
	LOAD_16BE(&signatures->size, in + pos);
	pos += 2;

	if (signatures->size != (header->size - 2))
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

	return TLS_SUCCESS;
}

static uint32_t tls_extension_signature_algorithms_write_body(tls_extension_signature_algorithm *signatures, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

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

	return pos;
}

static uint32_t tls_extension_signature_algorithms_print_body(tls_extension_signature_algorithm *signatures, void *buffer, uint32_t size,
															  uint32_t indent)
{
	uint32_t pos = 0;
	uint16_t count = signatures->size / 2;

	for (uint16_t i = 0; i < count; ++i)
	{
		switch (signatures->algorithms[i])
		{
		case TLS_RSA_PKCS_SHA1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pkcs1_sha1 (ID 0201)\n");
			break;
		case TLS_DSA_SHA1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "dsa_sha1 (ID 0202)\n");
			break;
		case TLS_ECDSA_SHA1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_secp160r1_sha1 (ID 0203)\n");
			break;
		case TLS_RSA_PKCS_SHA256:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pkcs1_sha256 (ID 0401)\n");
			break;
		case TLS_DSA_SHA256:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "dsa_sha256 (ID 0402)\n");
			break;
		case TLS_ECDSA_SECP256R1_SHA256:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_secp256r1_sha1 (ID 0403)\n");
			break;
		case TLS_RSA_PKCS_SHA384:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pkcs1_sha384 (ID 0501)\n");
			break;
		case TLS_DSA_SHA384:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "dsa_sha384 (ID 0502)\n");
			break;
		case TLS_ECDSA_SECP384R1_SHA384:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_secp384r1_sha384 (ID 0503)\n");
			break;
		case TLS_RSA_PKCS_SHA512:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pkcs1_sha512 (ID 0601)\n");
			break;
		case TLS_DSA_SHA512:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "dsa_sha512 (ID 0602)\n");
			break;
		case TLS_ECDSA_SECP521R1_SHA512:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_secp521r1_sha512 (ID 0603)\n");
			break;
		case TLS_SM2_SM3:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "sm2sig_sm3 (ID 0708)\n");
			break;
		case TLS_GOST_R34102012_256A:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_256a (ID 0709)\n");
			break;
		case TLS_GOST_R34102012_256B:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_256b (ID 070A)\n");
			break;
		case TLS_GOST_R34102012_256C:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_256c (ID 070B)\n");
			break;
		case TLS_GOST_R34102012_256D:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_256d (ID 070C)\n");
			break;
		case TLS_GOST_R34102012_512A:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_512a (ID 070D)\n");
			break;
		case TLS_GOST_R34102012_512B:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_512b (ID 070E)\n");
			break;
		case TLS_GOST_R34102012_512C:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "gostr34102012_512c (ID 070F)\n");
			break;
		case TLS_RSA_PSS_RSAE_SHA256:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pss_rsae_sha256 (ID 0804)\n");
			break;
		case TLS_RSA_PSS_RSAE_SHA384:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pss_rsae_sha384 (ID 0805)\n");
			break;
		case TLS_RSA_PSS_RSAE_SHA512:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pss_rsae_sha512 (ID 0806)\n");
			break;
		case TLS_ED25519:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ed25519 (ID 0807)\n");
			break;
		case TLS_ED448:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ed448 (ID 0808)\n");
			break;
		case TLS_RSA_PSS_PSS_SHA256:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pss_pss_sha256 (ID 0809)\n");
			break;
		case TLS_RSA_PSS_PSS_SHA384:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pss_pss_sha384 (ID 080A)\n");
			break;
		case TLS_RSA_PSS_PSS_SHA512:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "rsa_pss_pss_sha512 (ID 080B)\n");
			break;
		case TLS_ECDSA_BRAINPOOL_P256R1_TLS13_SHA256:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_brainpoolP256r1tls13_sha256 (ID 081A)\n");
			break;
		case TLS_ECDSA_BRAINPOOL_P384R1_TLS13_SHA384:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_brainpoolP384r1tls13_sha384 (ID 081B)\n");
			break;
		case TLS_ECDSA_BRAINPOOL_P512R1_TLS13_SHA512:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "ecdsa_brainpoolP512r1tls13_sha512 (ID 081C)\n");
			break;
		default:
		{
			if (tls_check_grease_value(signatures->algorithms[i]))
			{
				pos +=
					print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GREASE Signature (ID %04hX)\n", signatures->algorithms[i]);
			}
			else
			{
				pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %04hX)\n", signatures->algorithms[i]);
			}
		}
		break;
		}
	}

	return pos;
}

// RFC 7301:  Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
// Application Layer Protocol Negotiation
static tls_error_t tls_extension_application_protocol_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extensions_application_protocol_negotiation *protocols = NULL;
	tls_opaque_data *name = NULL;
	uint16_t total_size = 0;
	uint16_t count = 0;
	uint16_t offset = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	// 2 octet size
	LOAD_16BE(&total_size, in + pos);
	pos += 2;

	if ((total_size + 2) != header->size)
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// Count the number of protocols
	while (offset < total_size)
	{
		offset += in[pos + offset] + 1;
		count += 1;
	}

	protocols = zmalloc(sizeof(tls_extensions_application_protocol_negotiation) + (sizeof(tls_opaque_data) * count) + (total_size - count));

	if (protocols == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	protocols->header = *header;
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

	return TLS_SUCCESS;
}

static uint32_t tls_extension_application_protocol_write_body(tls_extensions_application_protocol_negotiation *protocols, void *buffer)
{
	tls_opaque_data *name = PTR_OFFSET(protocols, sizeof(tls_extensions_application_protocol_negotiation));

	uint8_t *out = buffer;
	uint32_t pos = 0;

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

	return pos;
}

static uint32_t tls_extension_application_protocol_print_body(tls_extensions_application_protocol_negotiation *protocols, void *buffer,
															  uint32_t size, uint32_t indent)
{
	tls_opaque_data *name = PTR_OFFSET(protocols, sizeof(tls_extensions_application_protocol_negotiation));
	uint32_t pos = 0;

	for (uint16_t i = 0; i < protocols->count; ++i)
	{
		pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "%.*s\n", name[i].size, PTR_OFFSET(name, name[i].offset));
	}

	return pos;
}

// RFC 6962: Certificate Transparency
// Signed Certificate Timestamp
static tls_error_t tls_extension_signed_certificate_timestamp_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_header *sct = NULL;

	sct = zmalloc(sizeof(tls_extension_header));

	if (sct == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	*sct = *header;

	*extension = sct;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_signed_certificate_timestamp_write_body(void *sct, void *buffer)
{
	return 0;
}

static uint32_t tls_extension_signed_certificate_timestamp_print_body(void *sct, void *buffer, uint32_t size, uint32_t indent)
{
	return 0;
}

// RFC 8449: Record Size Limit Extension for TLS
// Record Size Limit
static tls_error_t tls_extension_record_size_limit_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_record_size_limit *limit = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	limit = zmalloc(sizeof(tls_extension_record_size_limit));

	if (limit == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	limit->header = *header;

	// 2 octet length identifier
	LOAD_16BE(&limit->limit, in + pos);
	pos += 2;

	if (limit->limit < 64)
	{
		return TLS_INVALID_RECORD_LIMIT;
	}

	*extension = limit;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_record_size_limit_write_body(tls_extension_record_size_limit *limit, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 2 octet length identifier
	LOAD_16BE(out + pos, &limit->limit);
	pos += 2;

	return pos;
}

static uint32_t tls_extension_record_size_limit_print_body(tls_extension_record_size_limit *limit, void *buffer, uint32_t size,
														   uint32_t indent)
{
	return print_format(indent, buffer, size, "Record Size Limit: %hu bytes\n", limit->limit);
}

// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
// Supported Versions
static tls_error_t tls_extension_supported_versions_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_supported_version *version = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	version = zmalloc(sizeof(tls_extension_psk_exchange_mode) + (header->size - 1));

	if (version == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	version->header = *header;

	// 1 octet size
	LOAD_8(&version->size, in + pos);
	pos += 1;

	if (version->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(version->version, in + pos, version->size);
	pos += version->size;

	*extension = version;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_supported_versions_write_body(tls_extension_supported_version *version, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &version->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, version->version, version->size);
	pos += version->size;

	return pos;
}

static uint32_t tls_extension_supported_versions_print_body(tls_extension_supported_version *version, void *buffer, uint32_t size,
															uint32_t indent)
{
	uint32_t pos = 0;
	uint8_t count = version->size / 2;

	for (uint8_t i = 0; i < count; ++i)
	{
		switch (TLS_VERSION_RAW(version->version[i]))
		{
		case TLS_VERSION_1_0:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "TLS 1.0 (3, 1)\n");
			break;
		case TLS_VERSION_1_1:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "TLS 1.1 (3, 2)\n");
			break;
		case TLS_VERSION_1_2:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "TLS 1.2 (3, 3)\n");
			break;
		case TLS_VERSION_1_3:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "TLS 1.3 (3, 4)\n");
			break;
		default:
		{
			if (tls_check_grease_value(TLS_VERSION_RAW(version->version[i])))
			{
				pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GREASE Version (%02hhX, %02hhX)\n",
									version->version[i].major, version->version[i].minor);
			}
			else
			{
				pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (%hhu, %hhu)\n", version->version[i].major,
									version->version[i].minor);
			}
		}
		break;
		}
	}

	return pos;
}

// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
// PSK Key Exchange Modes
static tls_error_t tls_extension_psk_exchange_modes_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_psk_exchange_mode *modes = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	modes = zmalloc(sizeof(tls_extension_psk_exchange_mode) + (header->size - 1));

	if (modes == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	modes->header = *header;

	// 1 octet size
	LOAD_8(&modes->size, in + pos);
	pos += 1;

	if (modes->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(modes->modes, in + pos, modes->size);
	pos += modes->size;

	*extension = modes;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_psk_exchange_modes_write_body(tls_extension_psk_exchange_mode *modes, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &modes->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, modes->modes, modes->size);
	pos += modes->size;

	return pos;
}

static uint32_t tls_extension_psk_exchange_modes_print_body(tls_extension_psk_exchange_mode *modes, void *buffer, uint32_t size,
															uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < modes->size; ++i)
	{
		switch (modes->modes[i])
		{
		case TLS_PSK_KEY_EXCHANGE:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "PSK-only key establishment (ID 0)\n");
			break;
		case TLS_PSK_DHE_KEY_EXCHANGE:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "PSK with (EC)DHE key establishment (ID 1)\n");
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
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "GREASE PSK (ID %02hhX)\n", modes->modes[i]);
			break;
		default:
			pos += print_format(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", modes->modes[i]);
			break;
		}
	}

	return pos;
}

// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
// Key Share
static tls_error_t tls_extension_key_share_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_key_share *shares = NULL;
	tls_key_share *key = NULL;
	uint16_t total_size = 0;
	uint16_t count = 0;
	uint16_t offset = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	// 2 octet size
	LOAD_16BE(&total_size, in + pos);
	pos += 2;

	if ((total_size + 2) != header->size)
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
	shares->header = *header;
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

	return TLS_SUCCESS;
}

static uint32_t tls_extension_key_share_write_body(tls_extension_key_share *shares, void *buffer)
{
	tls_key_share *key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));

	uint8_t *out = buffer;
	uint32_t pos = 0;

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

	return pos;
}

static uint32_t tls_extension_key_share_print_body(tls_extension_key_share *shares, void *buffer, uint32_t size, uint32_t indent)
{
	tls_key_share *key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));
	uint32_t pos = 0;

	for (uint16_t i = 0; i < shares->count; ++i)
	{
		switch (key[i].group)
		{
		case TLS_SECT_163K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect163k1 (ID 1)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_163R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect163r1 (ID 2)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_163R2:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect163r2 (ID 3)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_193R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect193r1 (ID 4)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_193R2:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect193r2 (ID 5)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_233K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect233k1 (ID 6)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_233R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect233r1 (ID 7)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_239K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect239k1 (ID 8)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_283K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect283k1 (ID 9)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_283R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect283r1 (ID 10)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_409K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect409k1 (ID 11)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_409R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect409r1 (ID 12)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_571K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect571k1 (ID 13)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECT_571R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "sect571r1 (ID 14)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_160K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp160k1 (ID 15)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_160R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp160r1 (ID 16)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_160R2:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp160r2 (ID 17)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_192K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp192k1 (ID 18)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_192R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp192r1 (ID 19)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_224K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp224k1 (ID 20)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_224R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp224r1 (ID 21)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_256K1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp256k1 (ID 22)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_256R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp256r1 (ID 23)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_384R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp384r1 (ID 24)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SECP_521R1:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "secp521r1 (ID 25)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_BRAINPOOL_256R1:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP256r1 (ID 26)", PTR_OFFSET(key, key[i].offset),
							   key[i].size);
			break;
		case TLS_BRAINPOOL_384R1:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP384r1 (ID 27)", PTR_OFFSET(key, key[i].offset),
							   key[i].size);
			break;
		case TLS_BRAINPOOL_512R1:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP512r1 (ID 28)", PTR_OFFSET(key, key[i].offset),
							   key[i].size);
			break;
		case TLS_X25519:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "x25519 (ID 29)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_X448:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "x448 (ID 30)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_BRAINPOOL_256R1_TLS_13:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP256r1tls13 (ID 31)", PTR_OFFSET(key, key[i].offset),
							   key[i].size);
			break;
		case TLS_BRAINPOOL_384R1_TLS_13:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP384r1tls13 (ID 32)", PTR_OFFSET(key, key[i].offset),
							   key[i].size);
			break;
		case TLS_BRAINPOOL_512R1_TLS_13:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "brainpoolP512r1tls13 (ID 33)", PTR_OFFSET(key, key[i].offset),
							   key[i].size);
			break;
		case TLS_GOST_256A:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256A (ID 34)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_GOST_256B:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256B (ID 35)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_GOST_256C:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256C (ID 36)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_GOST_256D:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC256D (ID 37)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_GOST_512A:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC512A (ID 38)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_GOST_512B:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC512B (ID 39)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_GOST_512C:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "GC512C (ID 40)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_SM2:
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "SM2 (ID 41)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_FFDHE_2048:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe2048 (ID 256)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_FFDHE_3072:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe3072 (ID 257)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_FFDHE_4096:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe4096 (ID 258)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_FFDHE_6144:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe6144 (ID 259)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		case TLS_FFDHE_8192:
			pos +=
				print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "ffdhe8192 (ID 260)", PTR_OFFSET(key, key[i].offset), key[i].size);
			break;
		default:
		{
			pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "Unknown", PTR_OFFSET(key, key[i].offset), key[i].size);
		}
		break;
		}
	}

	return pos;
}

tls_error_t tls_extension_read(void **extension, void *data, uint32_t size)
{
	tls_error_t error = 0;
	tls_extension_header header = {0};

	error = tls_extension_header_read(&header, data, size);

	if (error != TLS_SUCCESS)
	{
		return error;
	}

	if (size < TLS_EXTENSION_OCTETS(&header))
	{
		return TLS_INSUFFICIENT_DATA;
	}

	switch (header.type)
	{
	case TLS_EXT_SERVER_NAME:
		error = tls_extension_server_name_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		error = tls_extension_max_fragment_length_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		goto empty;
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		error = tls_extension_trusted_ca_keys_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		goto empty;
		break;
	case TLS_EXT_STATUS_REQUEST:
		error = tls_extension_status_request_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_USER_MAPPING:
		error = tls_extension_user_mapping_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
		// case TLS_EXT_CLIENT_AUTHORIZATION:
		// case TLS_EXT_SERVER_AUTHORIZATION:
	case TLS_EXT_CERTIFICATE_TYPE:
		error = tls_extension_certificate_types_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		error = tls_extension_supported_groups_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		error = tls_extension_ec_point_format_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	// case TLS_EXT_SRP:
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		error = tls_extension_signature_algorithms_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
		// case TLS_EXT_USE_SRTP:
		// case TLS_EXT_HEARTBEAT:
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		error = tls_extension_application_protocol_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
		// case TLS_EXT_STATUS_REQUEST_V2:
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		error = tls_extension_signed_certificate_timestamp_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
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
		error = tls_extension_record_size_limit_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
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
		error = tls_extension_supported_versions_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	// case TLS_EXT_COOKIE:
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		error = tls_extension_psk_exchange_modes_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	// case TLS_EXT_CERTIFICATE_AUTHORITIES:
	// case TLS_EXT_OID_FILTERS:
	// case TLS_EXT_POST_HANDSHAKE_AUTH:
	// case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
	case TLS_EXT_KEY_SHARE:
		error = tls_extension_key_share_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
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

	return error;
}

uint32_t tls_extension_write(void *extension, void *buffer, uint32_t size)
{
	tls_extension_header *header = extension;
	uint32_t pos = 0;

	if (size < TLS_EXTENSION_OCTETS(header))
	{
		return 0;
	}

	pos += tls_extension_header_write(header, buffer, size);

	switch (header->type)
	{
	case TLS_EXT_SERVER_NAME:
		pos += tls_extension_server_name_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		pos += tls_extension_max_fragment_length_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		// empty body
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		pos += tls_extension_trusted_ca_keys_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		// empty body
		break;
	case TLS_EXT_STATUS_REQUEST:
		pos += tls_extension_status_request_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_USER_MAPPING:
		pos += tls_extension_user_mapping_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_CLIENT_AUTHORIZATION:
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		break;
	case TLS_EXT_CERTIFICATE_TYPE:
		pos += tls_extension_certificate_types_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		pos += tls_extension_supported_groups_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		pos += tls_extension_ec_point_format_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SRP:
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		pos += tls_extension_signature_algorithms_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_USE_SRTP:
	case TLS_EXT_HEARTBEAT:
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		pos += tls_extension_application_protocol_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_STATUS_REQUEST_V2:
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		pos += tls_extension_signed_certificate_timestamp_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
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
		pos += tls_extension_record_size_limit_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
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
		pos += tls_extension_supported_versions_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_COOKIE:
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		pos += tls_extension_psk_exchange_modes_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
	case TLS_EXT_OID_FILTERS:
	case TLS_EXT_POST_HANDSHAKE_AUTH:
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		break;
	case TLS_EXT_KEY_SHARE:
		pos += tls_extension_key_share_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
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
		pos += tls_extension_server_name_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		pos += tls_extension_max_fragment_length_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		// empty body
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		pos += tls_extension_trusted_ca_keys_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		// empty body
		break;
	case TLS_EXT_STATUS_REQUEST:
		pos += tls_extension_status_request_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_USER_MAPPING:
		pos += tls_extension_user_mapping_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
		// case TLS_EXT_CLIENT_AUTHORIZATION:
		// case TLS_EXT_SERVER_AUTHORIZATION:
	case TLS_EXT_CERTIFICATE_TYPE:
		pos += tls_extension_certificate_types_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		pos += tls_extension_supported_groups_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		pos += tls_extension_ec_point_format_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_SRP:
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		pos += tls_extension_signature_algorithms_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_USE_SRTP:
	case TLS_EXT_HEARTBEAT:
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		pos += tls_extension_application_protocol_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_STATUS_REQUEST_V2:
		break;
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		pos += tls_extension_signed_certificate_timestamp_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
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
		pos += tls_extension_record_size_limit_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
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
		pos += tls_extension_supported_versions_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_COOKIE:
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		pos += tls_extension_psk_exchange_modes_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
	case TLS_EXT_OID_FILTERS:
	case TLS_EXT_POST_HANDSHAKE_AUTH:
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		break;
	case TLS_EXT_KEY_SHARE:
		pos += tls_extension_key_share_print_body(extension, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
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
