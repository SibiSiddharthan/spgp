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
#include <unused.h>

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

static uint32_t tls_extension_server_name_print_body(tls_extension_server_name *server, buffer_t *buffer, uint32_t indent)
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
			pos += print_format(buffer, indent, "Name Type: Host Name (ID 0)\n");

			// Name
			pos += print_format(buffer, indent, "Name (%hu bytes): %.*s\n", name->name_size, name->name_size, name->name);
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

static uint32_t tls_extension_max_fragment_length_print_body(tls_extension_max_fragment_length *fragment, buffer_t *buffer, uint32_t indent)
{
	switch (fragment->max_fragment_length)
	{
	case TLS_MAX_FRAGMENT_LENGTH_512:
		return print_format(buffer, indent, "Maximum Fragment Length: 512 (ID %hhu)\n", fragment->max_fragment_length);
	case TLS_MAX_FRAGMENT_LENGTH_1024:
		return print_format(buffer, indent, "Maximum Fragment Length: 1024 (ID %hhu)\n", fragment->max_fragment_length);
	case TLS_MAX_FRAGMENT_LENGTH_2048:
		return print_format(buffer, indent, "Maximum Fragment Length: 2048 (ID %hhu)\n", fragment->max_fragment_length);
	case TLS_MAX_FRAGMENT_LENGTH_4096:
		return print_format(buffer, indent, "Maximum Fragment Length: 4096 (ID %hhu)\n", fragment->max_fragment_length);
	default:
		return print_format(buffer, indent, "Maximum Fragment Length: Unknown (ID %hhu) (Assuming 16384)\n", fragment->max_fragment_length);
	}
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

static uint32_t tls_extension_trusted_ca_keys_print_body(tls_extension_trusted_authority *authorities, buffer_t *buffer, uint32_t indent)
{
	tls_trusted_authority *authority = NULL;
	uint32_t pos = 0;

	for (uint32_t i = 0; i < authorities->count; ++i)
	{
		authority = authorities->authorities[i];

		switch (authority->type)
		{
		case TLS_PRE_AGREED:
			pos += print_format(buffer, indent, "Pre Agreed (ID 0)\n");
			break;
		case TLS_KEY_SHA1:
			pos += print_bytes(buffer, indent, "Key SHA1-Hash (ID 1)", authority->sha1_hash, 20);
			break;
		case TLS_X509_NAME:
			pos += print_format(buffer, indent, "X509 Name (ID 2): %.*s\n", authority->distinguished_name.size,
								authority->distinguished_name.name);
			break;
		case TLS_CERT_SHA1:
			pos += print_bytes(buffer, indent, "Certificate SHA1-Hash (ID 3)", authority->sha1_hash, 20);
			break;
		default:
			pos += print_format(buffer, indent, "Unknown (ID %hu)\n", authority->type);
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

static uint32_t tls_extension_status_request_print_body(tls_extension_status_request *status, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	if (status->type == TLS_CERTIFICATE_STATUS_OCSP)
	{
		pos += print_format(buffer, indent, "OCSP (ID %hhu)\n", status->type);
	}
	else
	{
		pos += print_format(buffer, indent, "Unknown Certificate Request (ID %hhu)\n", status->type);
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

static uint32_t tls_extension_user_mapping_print_body(tls_extension_user_mapping *user, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < user->size; ++i)
	{
		switch (user->types[i])
		{
		default:
			pos += print_format(buffer, indent, "Unknown (ID %hhu)\n", user->types[i]);
			break;
		}
	}

	return pos;
}

// RFC 5878: Transport Layer Security (TLS) Authorization Extensions
// Client Authorization Extensions
// Server Authorization Extensions
static tls_error_t tls_extension_authorization_formats_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_authorization_formats *formats = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	formats = zmalloc(sizeof(tls_extension_authorization_formats) + (header->size - 1));

	if (formats == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	formats->header = *header;

	// 1 octet size
	LOAD_8(&formats->size, in + pos);
	pos += 1;

	if (formats->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(formats->formats, in + pos, formats->size);
	pos += formats->size;

	*extension = formats;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_authorization_formats_write_body(tls_extension_authorization_formats *formats, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &formats->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, formats->formats, formats->size);
	pos += formats->size;

	return pos;
}

static uint32_t tls_extension_authorization_formats_print_body(tls_extension_authorization_formats *formats, buffer_t *buffer,
															   uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < formats->size; ++i)
	{
		switch (formats->formats[i])
		{
		case TLS_X509_ATTR_CERT:
			pos += print_format(buffer, indent, "X.509 Attibute Certificate (ID %hhu)\n", formats->formats[i]);
			break;
		case TLS_SAML_ASSERTION:
			pos += print_format(buffer, indent, "SAML (ID %hhu)\n", formats->formats[i]);
			break;
		case TLS_X509_ATTR_CERT_URL:
			pos += print_format(buffer, indent, "X.509 Attibute Certificate URL (ID %hhu)\n", formats->formats[i]);
			break;
		case TLS_SAML_ASSERTION_URL:
			pos += print_format(buffer, indent, "SAML URL (ID %hhu)\n", formats->formats[i]);
			break;
		default:
			pos += print_format(buffer, indent, "Unknown Format (ID %hhu)\n", formats->formats[i]);
			break;
		}
	}

	return pos;
}

// RFC 6091: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
// RFC 7250: Using Raw Public Keys in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
// Certificate Type
// Client Certificate Type
// Server Certificate Type
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

static uint32_t tls_extension_certificate_types_print_body(tls_extension_certificate_type *types, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < types->size; ++i)
	{
		switch (types->types[i])
		{
		case TLS_CERTIFICATE_X509:
			pos += print_format(buffer, indent, "X.509 (ID %hhu)\n", types->types[i]);
			break;
		case TLS_CERTIFICATE_PGP:
			pos += print_format(buffer, indent, "PGP (ID %hhu)\n", types->types[i]);
			break;
		case TLS_CERTIFICATE_RAW:
			pos += print_format(buffer, indent, "RAW (ID %hhu)\n", types->types[i]);
			break;
		default:
			pos += print_format(buffer, indent, "Unknown (ID %hhu)\n", types->types[i]);
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

static const char *group_name(uint16_t group)
{
	switch (group)
	{
	case TLS_SECT_163K1:
		return "sect163k1";
		break;
	case TLS_SECT_163R1:
		return "sect163r1";
		break;
	case TLS_SECT_163R2:
		return "sect163r2";
		break;
	case TLS_SECT_193R1:
		return "sect193r1";
		break;
	case TLS_SECT_193R2:
		return "sect193r2";
		break;
	case TLS_SECT_233K1:
		return "sect233k1";
		break;
	case TLS_SECT_233R1:
		return "sect233r1";
		break;
	case TLS_SECT_239K1:
		return "sect239k1";
		break;
	case TLS_SECT_283K1:
		return "sect283k1";
		break;
	case TLS_SECT_283R1:
		return "sect283r1";
		break;
	case TLS_SECT_409K1:
		return "sect409k1";
		break;
	case TLS_SECT_409R1:
		return "sect409r1";
		break;
	case TLS_SECT_571K1:
		return "sect571k1";
		break;
	case TLS_SECT_571R1:
		return "sect571r1";
		break;
	case TLS_SECP_160K1:
		return "secp160k1";
		break;
	case TLS_SECP_160R1:
		return "secp160r1";
		break;
	case TLS_SECP_160R2:
		return "secp160r2";
		break;
	case TLS_SECP_192K1:
		return "secp192k1";
		break;
	case TLS_SECP_192R1:
		return "secp192r1";
		break;
	case TLS_SECP_224K1:
		return "secp224k1";
		break;
	case TLS_SECP_224R1:
		return "secp224r1";
		break;
	case TLS_SECP_256K1:
		return "secp256k1";
		break;
	case TLS_SECP_256R1:
		return "secp256r1";
		break;
	case TLS_SECP_384R1:
		return "secp384r1";
		break;
	case TLS_SECP_521R1:
		return "secp521r1";
		break;
	case TLS_BRAINPOOL_256R1_TLS_12:
		return "brainpoolP256r1 (TLS 1.2)";
		break;
	case TLS_BRAINPOOL_384R1_TLS_12:
		return "brainpoolP384r1 (TLS 1.2)";
		break;
	case TLS_BRAINPOOL_512R1_TLS_12:
		return "brainpoolP512r1 (TLS 1.2)";
		break;
	case TLS_X25519:
		return "x25519";
		break;
	case TLS_X448:
		return "x448";
		break;
	case TLS_BRAINPOOL_256R1_TLS_13:
		return "brainpoolP256r1 (TLS 1.3)";
		break;
	case TLS_BRAINPOOL_384R1_TLS_13:
		return "brainpoolP384r1 (TLS 1.3)";
		break;
	case TLS_BRAINPOOL_512R1_TLS_13:
		return "brainpoolP512r1 (TLS 1.3)";
		break;
	case TLS_GOST_256A:
		return "GC256A";
		break;
	case TLS_GOST_256B:
		return "GC256B";
		break;
	case TLS_GOST_256C:
		return "GC256C";
		break;
	case TLS_GOST_256D:
		return "GC256D";
		break;
	case TLS_GOST_512A:
		return "GC512A";
		break;
	case TLS_GOST_512B:
		return "GC512B";
		break;
	case TLS_GOST_512C:
		return "GC512C";
		break;
	case TLS_SM2:
		return "SM2";
		break;
	case TLS_FFDHE_2048:
		return "ffdhe2048";
		break;
	case TLS_FFDHE_3072:
		return "ffdhe3072";
		break;
	case TLS_FFDHE_4096:
		return "ffdhe4096";
		break;
	case TLS_FFDHE_6144:
		return "ffdhe6144";
		break;
	case TLS_FFDHE_8192:
		return "ffdhe8192";
		break;
	case TLS_MLKEM_512:
		return "MLKEM512";
		break;
	case TLS_MLKEM_768:
		return "MLKEM768";
		break;
	case TLS_MLKEM_1024:
		return "MLKEM1024";
		break;
	case TLS_SECP_256R1_MLKEM_768:
		return "secP256r1MLKEM768";
		break;
	case TLS_X25519_MLKEM_768:
		return "x25519MLKEM768";
		break;
	case TLS_SECP_384R1_MLKEM_1024:
		return "secP384r1MLKEM1024";
		break;
	default:
	{
		if (tls_check_grease_value(group))
		{
			return "GREASE Group";
		}
		else
		{
			return "Unknown Group";
		}
	}
	break;
	}
}

static uint32_t tls_extension_supported_groups_print_body(tls_extension_supported_group *group, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;
	uint16_t count = group->size / 2;

	for (uint16_t i = 0; i < count; ++i)
	{
		pos += print_format(buffer, indent, "%s (ID %hu)\n", group_name(group->groups[i]), group->groups[i]);
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

static uint32_t tls_extension_ec_point_format_print_body(tls_extension_ec_point_format *format, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < format->size; ++i)
	{
		switch (format->formats[i])
		{
		case TLS_EC_POINT_UNCOMPRESSED:
			pos += print_format(buffer, indent, "Uncompressed (ID %hhu)\n", format->formats[i]);
			break;
		case TLS_EC_POINT_ANSI_X962_COMPRESSED_PRIME:
			pos += print_format(buffer, indent, "Compressed Prime (ID %hhu)\n", format->formats[i]);
			break;
		case TLS_EC_POINT_ANSI_X962_COMPRESSED_CHAR2:
			pos += print_format(buffer, indent, "Compressed Binary (ID %hhu)\n", format->formats[i]);
			break;
		default:
			pos += print_format(buffer, indent, "Unknown (ID %hhu)\n", format->formats[i]);
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

// From hanshake.c
uint32_t print_signature_algorithm(buffer_t *buffer, uint32_t indent, uint16_t algorithm);

static uint32_t tls_extension_signature_algorithms_print_body(tls_extension_signature_algorithm *signatures, buffer_t *buffer,
															  uint32_t indent)
{
	uint32_t pos = 0;
	uint16_t count = signatures->size / 2;

	for (uint16_t i = 0; i < count; ++i)
	{
		pos += print_signature_algorithm(buffer, indent, signatures->algorithms[i]);
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

static uint32_t tls_extension_application_protocol_print_body(tls_extensions_application_protocol_negotiation *protocols, buffer_t *buffer,
															  uint32_t indent)
{
	tls_opaque_data *name = PTR_OFFSET(protocols, sizeof(tls_extensions_application_protocol_negotiation));
	uint32_t pos = 0;

	for (uint16_t i = 0; i < protocols->count; ++i)
	{
		pos += print_format(buffer, indent, "%.*s\n", name[i].size, PTR_OFFSET(name, name[i].offset));
	}

	return pos;
}

// RFC 6962: Certificate Transparency
// Signed Certificate Timestamp
static tls_error_t tls_extension_signed_certificate_timestamp_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_header *sct = NULL;

	UNUSED(data);

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
	UNUSED(sct);
	UNUSED(buffer);

	return 0;
}

static uint32_t tls_extension_signed_certificate_timestamp_print_body(void *sct, buffer_t *buffer, uint32_t indent)
{
	UNUSED(sct);
	UNUSED(buffer);
	UNUSED(indent);

	return 0;
}

// RFC 7685: A Transport Layer Security (TLS) ClientHello Padding Extension
// Padding
static tls_error_t tls_extension_padding_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_padding *padding = NULL;

	padding = zmalloc(sizeof(tls_extension_padding) + header->size);

	if (padding == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	padding->header = *header;

	if (header->size > 0)
	{
		// Copy the padding data
		memcpy(padding->pad, data, header->size);
	}

	*extension = padding;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_padding_write_body(tls_extension_padding *padding, void *buffer)
{
	// Copy the padding data
	memcpy(buffer, padding->pad, padding->header.size);
	return padding->header.size;
}

static uint32_t tls_extension_padding_print_body(tls_extension_padding *padding, buffer_t *buffer, uint32_t indent)
{
	return print_bytes(buffer, indent, "Padding", padding->pad, padding->header.size);
}

// RFC 8879: TLS Certificate Compression
// Certificate Compression
static tls_error_t tls_extension_compressed_certificate_read_body(void **extension, tls_extension_header *header, void *data)
{
	tls_extension_compressed_certificate *compressed = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	compressed = zmalloc(sizeof(tls_extension_compressed_certificate) + (header->size - 1));

	if (compressed == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	compressed->header = *header;

	// 1 octet size
	LOAD_8(&compressed->size, in + pos);
	pos += 1;

	if (compressed->size != (header->size - 1))
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// N octets of data
	memcpy(compressed->algorithms, in + pos, compressed->size);
	pos += compressed->size;

	*extension = compressed;

	return TLS_SUCCESS;
}

static uint32_t tls_extension_compressed_certificate_write_body(tls_extension_compressed_certificate *compressed, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet size
	LOAD_8(out + pos, &compressed->size);
	pos += 1;

	// N octets of data
	memcpy(out + pos, compressed->algorithms, compressed->size);
	pos += compressed->size;

	return pos;
}

static uint32_t tls_extension_compressed_certificate_print_body(tls_extension_compressed_certificate *compressed, buffer_t *buffer,
																uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < compressed->size; ++i)
	{
		switch (compressed->algorithms[i])
		{
		case TLS_UNCOMPRESSED:
			pos += print_format(buffer, indent, "Uncompressed (ID %hhu)\n", compressed->algorithms[i]);
			break;
		case TLS_ZLIB:
			pos += print_format(buffer, indent, "zlib (ID %hhu)\n", compressed->algorithms[i]);
			break;
		case TLS_BROTLI:
			pos += print_format(buffer, indent, "brotli (ID %hhu)\n", compressed->algorithms[i]);
			break;
		case TLS_ZSTD:
			pos += print_format(buffer, indent, "zstd (ID %hhu)\n", compressed->algorithms[i]);
			break;
		default:
			pos += print_format(buffer, indent, "Unknown Compression(ID %hhu)\n", compressed->algorithms[i]);
			break;
		}
	}

	return pos;
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

static uint32_t tls_extension_record_size_limit_print_body(tls_extension_record_size_limit *limit, buffer_t *buffer, uint32_t indent)
{
	return print_format(buffer, indent, "Record Size Limit: %hu bytes\n", limit->limit);
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

static uint32_t tls_extension_supported_versions_print_body(tls_extension_supported_version *version, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;
	uint8_t count = version->size / 2;

	for (uint8_t i = 0; i < count; ++i)
	{
		switch (TLS_VERSION_RAW(version->version[i]))
		{
		case TLS_VERSION_1_0:
			pos += print_format(buffer, indent, "TLS 1.0 (%hhu, %hhu)\n", version->version[i].major, version->version[i].minor);
			break;
		case TLS_VERSION_1_1:
			pos += print_format(buffer, indent, "TLS 1.1 (%hhu, %hhu)\n", version->version[i].major, version->version[i].minor);
			break;
		case TLS_VERSION_1_2:
			pos += print_format(buffer, indent, "TLS 1.2 (%hhu, %hhu)\n", version->version[i].major, version->version[i].minor);
			break;
		case TLS_VERSION_1_3:
			pos += print_format(buffer, indent, "TLS 1.3 (%hhu, %hhu)\n", version->version[i].major, version->version[i].minor);
			break;
		default:
		{
			if (tls_check_grease_value(TLS_VERSION_RAW(version->version[i])))
			{
				pos += print_format(buffer, indent, "GREASE Version (%^.2hhx, %^.2hhx)\n", version->version[i].major,
									version->version[i].minor);
			}
			else
			{
				pos += print_format(buffer, indent, "Unknown Version (%hhu, %hhu)\n", version->version[i].major, version->version[i].minor);
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

static uint32_t tls_extension_psk_exchange_modes_print_body(tls_extension_psk_exchange_mode *modes, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	for (uint8_t i = 0; i < modes->size; ++i)
	{
		switch (modes->modes[i])
		{
		case TLS_PSK_KEY_EXCHANGE:
			pos += print_format(buffer, indent, "PSK-only key establishment (ID%hhu)\n", modes->modes[i]);
			break;
		case TLS_PSK_DHE_KEY_EXCHANGE:
			pos += print_format(buffer, indent, "PSK with (EC)DHE key establishment (ID %hhu)\n", modes->modes[i]);
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
			pos += print_format(buffer, indent, "GREASE PSK (ID %^.2hhx)\n", modes->modes[i]);
			break;
		default:
			pos += print_format(buffer, indent, "Unknown (ID %hhu)\n", modes->modes[i]);
			break;
		}
	}

	return pos;
}

// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
// Key Share
static tls_error_t tls_extension_key_share_read_body(tls_handshake_type context, void **extension, tls_extension_header *header, void *data)
{
	tls_extension_key_share *shares = NULL;
	tls_key_share *key = NULL;
	uint16_t total_size = 0;
	uint16_t count = 0;
	uint16_t offset = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	if (context != TLS_CLIENT_HELLO && context != TLS_SERVER_HELLO && context != TLS_HELLO_RETRY_REQUEST)
	{
		return TLS_INVALID_PARAMETER;
	}

	// 2 octet size
	LOAD_16BE(&total_size, in + pos);
	pos += 2;

	if ((total_size + 2) != header->size)
	{
		return TLS_MALFORMED_EXTENSION_SIZE;
	}

	// Count the number of entries
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

static uint32_t tls_extension_key_share_write_body(tls_handshake_type context, tls_extension_key_share *shares, void *buffer)
{
	tls_key_share *key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));

	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (context != TLS_CLIENT_HELLO && context != TLS_SERVER_HELLO && context != TLS_HELLO_RETRY_REQUEST)
	{
		return 0;
	}

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

static uint32_t tls_extension_key_share_print_body(tls_handshake_type context, tls_extension_key_share *shares, buffer_t *buffer,
												   uint32_t indent)
{
	tls_key_share *key = PTR_OFFSET(shares, sizeof(tls_extension_key_share));
	uint32_t pos = 0;

	if (context != TLS_CLIENT_HELLO && context != TLS_SERVER_HELLO && context != TLS_HELLO_RETRY_REQUEST)
	{
		return 0;
	}

	for (uint16_t i = 0; i < shares->count; ++i)
	{
		pos += print_bytes(buffer, indent, group_name(key[i].group), PTR_OFFSET(key, key[i].offset), key[i].size);
	}

	return pos;
}

tls_error_t tls_extension_read(tls_handshake_type context, void **extension, void *data, uint32_t size)
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
	case TLS_EXT_CLIENT_AUTHORIZATION:
		error = tls_extension_authorization_formats_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		error = tls_extension_authorization_formats_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
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
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
		error = tls_extension_certificate_types_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		error = tls_extension_certificate_types_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_PADDING:
		error = tls_extension_padding_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_ENCRYPT_THEN_MAC:
		goto empty;
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		goto empty;
		break;
		// case TLS_EXT_TOKEN_BINDING:
		// case TLS_EXT_CACHED_INFO:
		// case TLS_EXT_LTS:
	case TLS_EXT_COMPRESS_CERTIFICATE:
		error = tls_extension_compressed_certificate_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
		error = tls_extension_record_size_limit_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	// case TLS_EXT_PASSWORD_PROTECT:
	// case TLS_EXT_PASSWORD_CLEAR:
	// case TLS_EXT_PASSWORD_SALT:
	// case TLS_EXT_TICKET_PINNING:
	case TLS_EXT_DELEGATED_CREDENTIAL:
		error = tls_extension_signature_algorithms_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
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
		error = tls_extension_key_share_read_body(context, extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
	// case TLS_EXT_TRANSPARENCY_INFO:
	// case TLS_EXT_CONNECTION_INFO_LEGACY:
	// case TLS_EXT_CONNECTION_INFO:
	// case TLS_EXT_EXTERNAL_ID_HASH:
	// case TLS_EXT_EXTERNAL_SESSION_ID:
	case TLS_EXT_APPLICATION_SETTINGS:
		error = tls_extension_application_protocol_read_body(extension, &header, PTR_OFFSET(data, TLS_EXTENSION_HEADER_OCTETS));
		break;
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

uint32_t tls_extension_write(tls_handshake_type context, void *extension, void *buffer, uint32_t size)
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
		pos += tls_extension_authorization_formats_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		pos += tls_extension_authorization_formats_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
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
		pos += tls_extension_certificate_types_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		pos += tls_extension_certificate_types_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_PADDING:
		pos += tls_extension_padding_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_ENCRYPT_THEN_MAC:
		// empty body
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		// empty body
		break;
	case TLS_EXT_TOKEN_BINDING:
	case TLS_EXT_CACHED_INFO:
	case TLS_EXT_LTS:
		break;
	case TLS_EXT_COMPRESS_CERTIFICATE:
		pos += tls_extension_compressed_certificate_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
		pos += tls_extension_record_size_limit_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_PASSWORD_PROTECT:
	case TLS_EXT_PASSWORD_CLEAR:
	case TLS_EXT_PASSWORD_SALT:
	case TLS_EXT_TICKET_PINNING:
		break;
	case TLS_EXT_DELEGATED_CREDENTIAL:
		pos += tls_extension_signature_algorithms_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
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
		pos += tls_extension_key_share_write_body(context, extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	case TLS_EXT_TRANSPARENCY_INFO:
	case TLS_EXT_CONNECTION_INFO_LEGACY:
	case TLS_EXT_CONNECTION_INFO:
	case TLS_EXT_EXTERNAL_ID_HASH:
	case TLS_EXT_EXTERNAL_SESSION_ID:
		break;
	case TLS_EXT_APPLICATION_SETTINGS:
		pos += tls_extension_application_protocol_write_body(extension, PTR_OFFSET(buffer, TLS_EXTENSION_HEADER_OCTETS));
		break;
	default:
		break;
	}

	return pos;
}

static uint32_t print_extension_header(tls_extension_header *header, buffer_t *buffer, uint32_t indent)
{
	const char *name = NULL;

	switch (header->type)
	{
	case TLS_EXT_SERVER_NAME:
		name = "Server Name";
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		name = "Max Fragment Length";
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		name = "Client Certificate URL";
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		name = "Trusted CA Keys";
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		name = "Truncated HMAC";
		break;
	case TLS_EXT_STATUS_REQUEST:
		name = "Status Request";
		break;
	case TLS_EXT_USER_MAPPING:
		name = "User Mapping";
		break;
	case TLS_EXT_CLIENT_AUTHORIZATION:
		name = "Client Authorization";
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		name = "Server Authorization";
		break;
	case TLS_EXT_CERTIFICATE_TYPE:
		name = "Certificate Type";
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		name = "Supported Groups";
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		name = "EC Point Formats";
		break;
	case TLS_EXT_SRP:
		name = "Secure Remote Password";
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		name = "Signature Algorithms";
		break;
	case TLS_EXT_USE_SRTP:
		name = "Use SRTP";
		break;
	case TLS_EXT_HEARTBEAT:
		name = "Heartbeat";
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		name = "Application Layer Protocol Negotiation";
		break;
	case TLS_EXT_STATUS_REQUEST_V2:
		name = "Status Request V2";
		break;
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		name = "Signed Certificate Timestamp";
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
		name = "Client Certificate Type";
		break;
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		name = "Server Certificate Type";
		break;
	case TLS_EXT_PADDING:
		name = "Padding";
		break;
	case TLS_EXT_ENCRYPT_THEN_MAC:
		name = "Encrypt Then MAC";
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		name = "Extended Master Secret";
		break;
	case TLS_EXT_TOKEN_BINDING:
		name = "Token Binding";
		break;
	case TLS_EXT_CACHED_INFO:
		name = "Cached Information";
		break;
	case TLS_EXT_LTS:
		name = "Long Term Support";
		break;
	case TLS_EXT_COMPRESS_CERTIFICATE:
		name = "Compressed Certificate";
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
		name = "Max Record Size";
		break;
	case TLS_EXT_PASSWORD_PROTECT:
		name = "Password Protect";
		break;
	case TLS_EXT_PASSWORD_CLEAR:
		name = "Password Clear";
		break;
	case TLS_EXT_PASSWORD_SALT:
		name = "Password Salt";
		break;
	case TLS_EXT_TICKET_PINNING:
		name = "Ticket Pinning";
		break;
	case TLS_EXT_PSK_EXTERNAL_CERTIFICATE:
		name = "Certificate With External Pre-Shared Key";
		break;
	case TLS_EXT_DELEGATED_CREDENTIAL:
		name = "Delegated Credential";
		break;
	case TLS_EXT_SESSION_TICKET:
		name = "Session Ticket";
		break;
	case TLS_SUPPORTED_EKT_CIPHERS:
		name = "Supported Encrypted Key Transport Ciphers";
		break;
	case TLS_EXT_PSK:
		name = "Pre-Shared Key";
		break;
	case TLS_EXT_EARLY_DATA:
		name = "Early Data";
		break;
	case TLS_EXT_SUPPORTED_VERSIONS:
		name = "Supported Version";
		break;
	case TLS_EXT_COOKIE:
		name = "Cookie";
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		name = "PSK Exchange Modes";
		break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
		name = "Certificate Authorities";
		break;
	case TLS_EXT_OID_FILTERS:
		name = "OID Filters";
		break;
	case TLS_EXT_POST_HANDSHAKE_AUTH:
		name = "Post Handshake Authorization";
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		name = "Signature Algorithms Certificate";
		break;
	case TLS_EXT_KEY_SHARE:
		name = "Key Share";
		break;
	case TLS_EXT_TRANSPARENCY_INFO:
		name = "Transparency Information";
		break;
	case TLS_EXT_CONNECTION_INFO_LEGACY:
		name = "Connection Information (Legacy)";
		break;
	case TLS_EXT_CONNECTION_INFO:
		name = "Connection Information";
		break;
	case TLS_EXT_EXTERNAL_ID_HASH:
		name = "External ID Hash";
		break;
	case TLS_EXT_EXTERNAL_SESSION_ID:
		name = "External Session ID";
		break;
	case TLS_EXT_TICKET_REQUEST:
		name = "Ticket Request";
		break;
	case TLS_EXT_DNSSEC_CHAIN:
		name = "DNSSEC Chain";
		break;
	case TLS_EXT_APPLICATION_SETTINGS:
		name = "Application Layer Protocol Settings";
		break;
	case TLS_EXT_ECH_OUTER_EXTENSIONS:
		name = "Encrypted Outer Extensions";
		break;
	case TLS_EXT_ENCRYPTED_CLIENT_HELLO:
		name = "Encrypted Client Hello";
		break;
	case TLS_EXT_RENEGOTIATION_INFO:
		name = "Renegotiation Info";
		break;
	default:
	{
		if (tls_check_grease_value(header->type))
		{
			name = "GREASE Extension";
		}
		else
		{
			name = "Unknown Extension";
		}
	}
	break;
	}

	return print_format(buffer, indent, "%s (ID %hu) (%hu bytes)\n", name, header->type, header->size);
}

uint32_t tls_extension_print(tls_handshake_type context, void *extension, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	tls_extension_header *header = extension;

	// Extension Type
	pos += print_extension_header(header, buffer, indent);
	indent += 1;

	switch (header->type)
	{
	case TLS_EXT_SERVER_NAME:
		pos += tls_extension_server_name_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_MAX_FRAGMENT_LENGTH:
		pos += tls_extension_max_fragment_length_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_URL:
		// empty body
		break;
	case TLS_EXT_TRUSTED_CA_KEYS:
		pos += tls_extension_trusted_ca_keys_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_TRUNCATED_HMAC:
		// empty body
		break;
	case TLS_EXT_STATUS_REQUEST:
		pos += tls_extension_status_request_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_USER_MAPPING:
		pos += tls_extension_user_mapping_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_CLIENT_AUTHORIZATION:
		pos += tls_extension_authorization_formats_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_SERVER_AUTHORIZATION:
		pos += tls_extension_authorization_formats_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_CERTIFICATE_TYPE:
		pos += tls_extension_certificate_types_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_SUPPORTED_GROUPS:
		pos += tls_extension_supported_groups_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_EC_POINT_FORMATS:
		pos += tls_extension_ec_point_format_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_SRP:
		break;
	case TLS_EXT_SIGNATURE_ALGORITHMS:
		pos += tls_extension_signature_algorithms_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_USE_SRTP:
	case TLS_EXT_HEARTBEAT:
		break;
	case TLS_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		pos += tls_extension_application_protocol_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_STATUS_REQUEST_V2:
		break;
	case TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
		pos += tls_extension_signed_certificate_timestamp_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_CLIENT_CERTIFICATE_TYPE:
		pos += tls_extension_certificate_types_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_SERVER_CERTIFICATE_TYPE:
		pos += tls_extension_certificate_types_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_PADDING:
		pos += tls_extension_padding_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_ENCRYPT_THEN_MAC:
		// empty body
		break;
	case TLS_EXT_EXTENDED_MASTER_SECRET:
		// empty body
		break;
	case TLS_EXT_TOKEN_BINDING:
	case TLS_EXT_CACHED_INFO:
	case TLS_EXT_LTS:
		break;
	case TLS_EXT_COMPRESS_CERTIFICATE:
		pos += tls_extension_compressed_certificate_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_RECORD_SIZE_LIMIT:
		pos += tls_extension_record_size_limit_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_PASSWORD_PROTECT:
	case TLS_EXT_PASSWORD_CLEAR:
	case TLS_EXT_PASSWORD_SALT:
	case TLS_EXT_TICKET_PINNING:
		break;
	case TLS_EXT_DELEGATED_CREDENTIAL:
		pos += tls_extension_signature_algorithms_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_SESSION_TICKET:
		// empty body
		break;
	case TLS_EXT_PSK:
	case TLS_EXT_EARLY_DATA:
		break;
	case TLS_EXT_SUPPORTED_VERSIONS:
		pos += tls_extension_supported_versions_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_COOKIE:
		break;
	case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
		pos += tls_extension_psk_exchange_modes_print_body(extension, buffer, indent);
		break;
	case TLS_EXT_CERTIFICATE_AUTHORITIES:
	case TLS_EXT_OID_FILTERS:
	case TLS_EXT_POST_HANDSHAKE_AUTH:
	case TLS_EXT_SIGNATURE_ALGORITHMS_CERTIFICATE:
		break;
	case TLS_EXT_KEY_SHARE:
		pos += tls_extension_key_share_print_body(context, extension, buffer, indent);
		break;
	case TLS_EXT_TRANSPARENCY_INFO:
	case TLS_EXT_CONNECTION_INFO_LEGACY:
	case TLS_EXT_CONNECTION_INFO:
	case TLS_EXT_EXTERNAL_ID_HASH:
	case TLS_EXT_EXTERNAL_SESSION_ID:
		break;
	case TLS_EXT_APPLICATION_SETTINGS:
		pos += tls_extension_application_protocol_print_body(extension, buffer, indent);
		break;
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
