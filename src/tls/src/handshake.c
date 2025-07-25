/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/algorithms.h>
#include <tls/handshake.h>
#include <tls/version.h>
#include <tls/extensions.h>
#include <tls/memory.h>
#include <tls/grease.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static tls_error_t tls_client_hello_read(tls_client_hello **handshake, tls_handshake_header *header, void *data, uint32_t size)
{
	tls_client_hello *hello = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;
	uint32_t offset = 0;
	uint32_t extra = 64;

	hello = zmalloc(sizeof(tls_client_hello) + extra);

	if (hello == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	hello->header = *header;

	// 2 octet protocol version
	LOAD_8(&hello->version.major, in + pos);
	pos += 1;

	LOAD_8(&hello->version.minor, in + pos);
	pos += 1;

	// 32 octets of random data
	memcpy(&hello->random, in + pos, 32);
	pos += 32;

	// 1 octet session id size
	LOAD_8(&hello->session_id_size, in + pos);
	pos += 1;

	// N octets of session id
	if (hello->session_id_size > 0)
	{
		memcpy(&hello->session_id, in + pos, hello->session_id_size);
		pos += hello->session_id_size;
	}

	// 2 octet cipher suites size
	LOAD_16BE(&hello->cipher_suites_size, in + pos);
	pos += 2;

	// N octets of cipher suites
	if (hello->cipher_suites_size > 0)
	{
		if (hello->cipher_suites_size + offset > extra)
		{
			extra *= 2;
			hello = zrealloc(hello, sizeof(tls_client_hello) + extra);

			if (hello == NULL)
			{
				return TLS_NO_MEMORY;
			}
		}

		memcpy(hello->data + offset, in + pos, hello->cipher_suites_size);
		pos += hello->cipher_suites_size;
		offset += hello->cipher_suites_size;
	}

	// 1 octet compression method size
	LOAD_8(&hello->compression_methods_size, in + pos);
	pos += 1;

	if (hello->compression_methods_size > 0)
	{
		if (hello->compression_methods_size + offset > extra)
		{
			extra *= 2;
			hello = zrealloc(hello, sizeof(tls_client_hello) + extra);

			if (hello == NULL)
			{
				return TLS_NO_MEMORY;
			}
		}

		memcpy(hello->data + offset, in + pos, hello->compression_methods_size);
		pos += hello->compression_methods_size;
		offset += hello->compression_methods_size;
	}

	// 2 octet extensions size
	LOAD_16BE(&hello->extensions_size, in + pos);
	pos += 2;

	if (hello->extensions_size > 0)
	{
		hello->extensions_count = tls_extension_count(in + pos, size - pos);
		hello->extensions = zmalloc(hello->extensions_count * sizeof(void *));

		if (hello->extensions == NULL)
		{
			return TLS_NO_MEMORY;
		}

		for (uint16_t i = 0; i < hello->extensions_count; ++i)
		{
			tls_extension_read(&hello->extensions[i], in + pos, size - pos);
			pos += TLS_EXTENSION_SIZE(hello->extensions[i]);
		}
	}

	*handshake = hello;

	return TLS_SUCCESS;
}

static tls_error_t tls_handshake_header_read(tls_handshake_header *handshake_header, tls_record_header *record_header, void *data,
											 uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;

	if (size < 4)
	{
		return TLS_INSUFFICIENT_DATA;
	}

	// Copy the record header
	handshake_header->header = *record_header;

	// 1 octet handshake type
	handshake_header->type = in[pos];
	pos += 1;

	// 3 octet handshake size
	handshake_header->size = (in[pos] << 16) + (in[pos + 1] << 8) + in[pos + 2];
	pos += 3;

	return TLS_SUCCESS;
}

static uint32_t tls_handshake_header_write(tls_handshake_header *header, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < 4)
	{
		return 0;
	}

	// 1 octet handshake type
	out[pos++] = header->type;

	// 3 octet handshake size
	out[pos++] = (header->size >> 16) & 0xFF;
	out[pos++] = (header->size >> 8) & 0xFF;
	out[pos++] = (header->size >> 0) & 0xFF;

	return pos;
}

tls_error_t tls_handshake_read_body(void **handshake, tls_record_header *record_header, void *data, uint32_t size)
{
	tls_error_t error = 0;
	tls_handshake_header handshake_header = {0};

	error = tls_handshake_header_read(&handshake_header, record_header, data, size);

	if (error != TLS_SUCCESS)
	{
		return error;
	}

	switch (handshake_header.type)
	{
	case TLS_HELLO_REQUEST:
		break;
	case TLS_CLIENT_HELLO:
		error = tls_client_hello_read((tls_client_hello **)handshake, &handshake_header, PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS),
									  handshake_header.size);
		break;
	case TLS_SERVER_HELLO:
		break;
	case TLS_HELLO_VERIFY_REQUEST:
	case TLS_NEW_SESSION_TICKET:
	case TLS_END_OF_EARLY_DATA:
	case TLS_HELLO_RETRY_REQUEST:
	case TLS_ENCRYPTED_EXTENSIONS:
	case TLS_CERTIFICATE:
	case TLS_SERVER_KEY_EXCHANGE:
	case TLS_CERTIFICATE_REQUEST:
	case TLS_SERVER_HELLO_DONE:
	case TLS_CERTIFICATE_VERIFY:
	case TLS_CLIENT_KEY_EXCHANGE:
	case TLS_FINISHED:
	case TLS_CERTIFICATE_URL:
	case TLS_CERTIFICATE_STATUS:
	case TLS_SUPPLEMENTAL_DATA:
	case TLS_KEY_UPDATE:
	case TLS_MESSAGE_HASH:
		break;
	}

	if (error != TLS_SUCCESS)
	{
		return TLS_SUCCESS;
	}

	return TLS_SUCCESS;
}

uint32_t tls_handshake_write_body(void *handshake, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	tls_handshake_header *header = handshake;

	if (size < (TLS_HANDSHAKE_HEADER_OCTETS + header->size))
	{
		return 0;
	}

	pos += tls_handshake_header_write(header, out + pos, size - pos);

	switch (header->type)
	{
	case TLS_HELLO_REQUEST:
	case TLS_CLIENT_HELLO:
	case TLS_SERVER_HELLO:
	case TLS_HELLO_VERIFY_REQUEST:
	case TLS_NEW_SESSION_TICKET:
	case TLS_END_OF_EARLY_DATA:
	case TLS_HELLO_RETRY_REQUEST:
	case TLS_ENCRYPTED_EXTENSIONS:
	case TLS_CERTIFICATE:
	case TLS_SERVER_KEY_EXCHANGE:
	case TLS_CERTIFICATE_REQUEST:
	case TLS_SERVER_HELLO_DONE:
	case TLS_CERTIFICATE_VERIFY:
	case TLS_CLIENT_KEY_EXCHANGE:
	case TLS_FINISHED:
	case TLS_CERTIFICATE_URL:
	case TLS_CERTIFICATE_STATUS:
	case TLS_SUPPLEMENTAL_DATA:
	case TLS_KEY_UPDATE:
	case TLS_MESSAGE_HASH:
		break;
	}

	return pos;
}

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static uint32_t print_hex(void *buffer, void *data, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	for (uint32_t i = 0; i < size; ++i)
	{
		uint8_t a, b;

		a = ((uint8_t *)data)[i] / 16;
		b = ((uint8_t *)data)[i] % 16;

		out[pos++] = hex_lower_table[a];
		out[pos++] = hex_lower_table[b];
	}

	out[pos++] = '\n';

	return pos;
}

static uint32_t print_bytes(uint32_t indent, void *buffer, uint32_t buffer_size, char *prefix, void *data, uint32_t data_size)
{
	uint32_t pos = 0;

	pos += snprintf(PTR_OFFSET(buffer, pos), buffer_size, "%*s%s (%u bytes): ", indent * 4, "", prefix, data_size);
	pos += print_hex(PTR_OFFSET(buffer, pos), data, data_size);

	return pos;
}

static uint32_t print_compression_method(uint32_t indent, void *buffer, uint32_t size, uint8_t method)
{
	if (method == 0)
	{
		return snprintf(buffer, size, "%*sNULL (ID 0)\n", indent * 4, "");
	}
	else
	{
		return snprintf(buffer, size, "%*sUnknown (ID %hhu)\n", indent * 4, "", method);
	}
}

static uint32_t print_cipher_suite(uint32_t indent, void *buffer, uint32_t size, uint8_t o1, uint8_t o2)
{
	uint16_t id = TLS_MAKE_CIPHER_SUITE(o1, o2);

	switch (id)
	{
	case TLS_NULL_WITH_NULL_NULL:
		return snprintf(buffer, size, "%*sTLS_NULL_WITH_NULL_NULL (ID {0x00, 0x00})\n", indent * 4, "");

	case TLS_RSA_WITH_NULL_MD5:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_NULL_MD5 (ID {0x00, 0x01})\n", indent * 4, "");
	case TLS_RSA_WITH_NULL_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_NULL_SHA1 (ID {0x00, 0x02})\n", indent * 4, "");
	case TLS_RSA_WITH_NULL_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_NULL_SHA256 (ID {0x00, 0x3B})\n", indent * 4, "");
	case TLS_RSA_WITH_RC4_128_MD5:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_RC4_128_MD5 (ID {0x00, 0x04})\n", indent * 4, "");
	case TLS_RSA_WITH_RC4_128_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_RC4_128_SHA1 (ID {0x00, 0x05})\n", indent * 4, "");
	case TLS_RSA_WITH_IDEA_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_IDEA_CBC_SHA1 (ID {0x00, 0x07})\n", indent * 4, "");
	case TLS_RSA_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_DES_CBC_SHA1 (ID {0x00, 0x09})\n", indent * 4, "");
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x0A})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x2F})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x35})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x3C})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x3D})\n", indent * 4, "");

	case TLS_DH_DSS_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_DES_CBC_SHA1 (ID {0x00, 0x0C})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x0D})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_DES_CBC_SHA1 (ID {0x00, 0x0F})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x10})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_DES_CBC_SHA1 (ID {0x00, 0x12})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x13})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_DES_CBC_SHA1 (ID {0x00, 0x15})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x16})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x30})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x31})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x32})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x33})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x36})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x37})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x38})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x39})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x3E})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x3F})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x40})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x67})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x68})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x69})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x6A})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x6B})\n", indent * 4, "");

	case TLS_DH_ANON_WITH_RC4_128_MD5:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_RC4_128_MD5 (ID {0x00, 0x18})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_DES_CBC_SHA1 (ID {0x00, 0x1A})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x1B})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x34})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x3A})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x6C})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x6D})\n", indent * 4, "");

	// RFC 5288: AES Galois Counter Mode (GCM) Cipher Suites for TLS
	case TLS_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_128_GCM_SHA256 (ID {0x00, 0x9C})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_256_GCM_SHA384 (ID {0x00, 0x9D})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (ID {0x00, 0x9E})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (ID {0x00, 0x9F})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xA0})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xA1})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xA2})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xA3})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xA4})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xA5})\n", indent * 4, "");
	case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_anon_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xA6})\n", indent * 4, "");
	case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_anon_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xA7})\n", indent * 4, "");

	// RFC 5487: Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xA8})\n", indent * 4, "");
	case TLS_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xA9})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xAA})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xAB})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xAC})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xAD})\n", indent * 4, "");

	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_128_CBC_SHA256 (ID {0x00, 0xAE})\n", indent * 4, "");
	case TLS_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_256_CBC_SHA384 (ID {0x00, 0xAF})\n", indent * 4, "");
	case TLS_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_NULL_SHA256 (ID {0x00, 0xB0})\n", indent * 4, "");
	case TLS_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_NULL_SHA384 (ID {0x00, 0xB1})\n", indent * 4, "");

	case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (ID {0x00, 0xB2})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (ID {0x00, 0xB3})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_NULL_SHA256 (ID {0x00, 0xB4})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_NULL_SHA384 (ID {0x00, 0xB5})\n", indent * 4, "");

	case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (ID {0x00, 0xB6})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (ID {0x00, 0xB7})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_NULL_SHA256 (ID {0x00, 0xB8})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_NULL_SHA384 (ID {0x00, 0xB9})\n", indent * 4, "");

	// RFC 5932:  Camellia Cipher Suites for TLS
	case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x41})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x42})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x43})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x44})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x45})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x46})\n", indent * 4, "");

	case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x84})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x85})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x86})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x87})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x88})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x89})\n", indent * 4, "");

	case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBA})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBB})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBC})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBD})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBE})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBF})\n", indent * 4, "");

	case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC0})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC1})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC2})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC3})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC4})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC5})\n", indent * 4, "");

	// RFC 8998: ShangMi (SM) Cipher Suites for TLS 1.3
	case TLS_SM4_GCM_SM3:
		return snprintf(buffer, size, "%*sTLS_SM4_GCM_SM3 (ID {0x00, 0xC6})\n", indent * 4, "");
	case TLS_SM4_CCM_SM3:
		return snprintf(buffer, size, "%*sTLS_SM4_CCM_SM3 (ID {0x00, 0xC7})\n", indent * 4, "");

	// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
	case TLS_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_AES_128_GCM_SHA256 (ID {0x13, 0x01})\n", indent * 4, "");
	case TLS_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_AES_256_GCM_SHA384 (ID {0x13, 0x02})\n", indent * 4, "");
	case TLS_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_CHACHA20_POLY1305_SHA256 (ID {0x13, 0x03})\n", indent * 4, "");
	case TLS_AES_128_CCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_AES_128_CCM_SHA256 (ID {0x13, 0x04})\n", indent * 4, "");
	case TLS_AES_128_CCM_8_SHA256:
		return snprintf(buffer, size, "%*sTLS_AES_128_CCM_8_SHA256 (ID {0x13, 0x05})\n", indent * 4, "");

	// RFC 8422:  Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
	case TLS_ECDHE_ECDSA_WITH_NULL_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_NULL_SHA1 (ID {0xC0, 0x06})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x08})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x09})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x0A})\n", indent * 4, "");

	case TLS_ECDHE_RSA_WITH_NULL_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_NULL_SHA1 (ID {0xC0, 0x10})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x12})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x13})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x14})\n", indent * 4, "");

	case TLS_ECDH_ANON_WITH_NULL_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDH_ANON_WITH_NULL_SHA1 (ID {0xC0, 0x15})\n", indent * 4, "");
	case TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x17})\n", indent * 4, "");
	case TLS_ECDH_ANON_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDH_ANON_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x18})\n", indent * 4, "");
	case TLS_ECDH_ANON_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDH_ANON_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x19})\n", indent * 4, "");

	// RFC 5054: Using the Secure Remote Password (SRP) Protocol for TLS Authentication
	case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x1A})\n", indent * 4, "");
	case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x1B})\n", indent * 4, "");
	case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x1C})\n", indent * 4, "");
	case TLS_SRP_SHA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x1D})\n", indent * 4, "");
	case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x1E})\n", indent * 4, "");
	case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x1F})\n", indent * 4, "");
	case TLS_SRP_SHA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x20})\n", indent * 4, "");
	case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x21})\n", indent * 4, "");
	case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x22})\n", indent * 4, "");

	// RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x23})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x24})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x25})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x26})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x27})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x28})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x29})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x2A})\n", indent * 4, "");

	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x2B})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x2C})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x2D})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x2E})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x2F})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x30})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x31})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x32})\n", indent * 4, "");

	// RFC 5489: ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)
	case TLS_ECDHE_PSK_WITH_RC4_128_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_RC4_128_SHA1 (ID {0xC0, 0x33})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x34})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x35})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x36})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x37})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x38})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_NULL_SHA1:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_NULL_SHA1 (ID {0xC0, 0x39})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_NULL_SHA256 (ID {0xC0, 0x3A})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_NULL_SHA384 (ID {0xC0, 0x3B})\n", indent * 4, "");

	// RFC 6209: Addition of the ARIA Cipher Suites to Transport Layer Security (TLS)
	case TLS_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x3C})\n", indent * 4, "");
	case TLS_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x3D})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x3E})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x3F})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x40})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x41})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x42})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x43})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x44})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x45})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x46})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x47})\n", indent * 4, "");

	case TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x48})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x49})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x4A})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x4B})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x4C})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x4D})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x4E})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x4F})\n", indent * 4, "");

	case TLS_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x50})\n", indent * 4, "");
	case TLS_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x51})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x52})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x53})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x54})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x55})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x56})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x57})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x58})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x59})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x5A})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x5B})\n", indent * 4, "");

	case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x5C})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x5D})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x5E})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x5F})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x60})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x61})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x62})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x63})\n", indent * 4, "");

	case TLS_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x64})\n", indent * 4, "");
	case TLS_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x65})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x66})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x67})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x68})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x69})\n", indent * 4, "");
	case TLS_PSK_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x6A})\n", indent * 4, "");
	case TLS_PSK_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x6B})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x6C})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x6D})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x6E})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x6F})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x70})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x71})\n", indent * 4, "");

	// RFC 6367: Addition of the Camellia Cipher Suites to Transport Layer Security (TLS)
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x72})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x73})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x74})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x75})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x76})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x77})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x78})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x79})\n", indent * 4, "");

	case TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x7A})\n", indent * 4, "");
	case TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x7B})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x7C})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x7D})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x7E})\n", indent * 4, "");
	case TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x7F})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x80})\n", indent * 4, "");
	case TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x81})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x82})\n", indent * 4, "");
	case TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x83})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x84})\n", indent * 4, "");
	case TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x85})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x86})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x87})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x88})\n", indent * 4, "");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x89})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x8A})\n", indent * 4, "");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x8B})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x8C})\n", indent * 4, "");
	case TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x8D})\n", indent * 4, "");

	case TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x8D})\n", indent * 4, "");
	case TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x8F})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x90})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x91})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x92})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x93})\n", indent * 4, "");
	case TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x94})\n", indent * 4, "");
	case TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x95})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x96})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x97})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x98})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x99})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x9A})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x9B})\n", indent * 4, "");

	// RFC 6655: AES-CCM Cipher Suites for Transport Layer Security (TLS)
	case TLS_RSA_WITH_AES_128_CCM:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_128_CCM (ID {0xC0, 0x9C})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_256_CCM:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_256_CCM (ID {0xC0, 0x9D})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_128_CCM:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_128_CCM (ID {0xC0, 0x9E})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_256_CCM:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_256_CCM (ID {0xC0, 0x9F})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_128_CCM_8 (ID {0xC0, 0xA0})\n", indent * 4, "");
	case TLS_RSA_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "%*sTLS_RSA_WITH_AES_256_CCM_8 (ID {0xC0, 0xA1})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_128_CCM_8 (ID {0xC0, 0xA2})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_AES_256_CCM_8 (ID {0xC0, 0xA3})\n", indent * 4, "");

	case TLS_PSK_WITH_AES_128_CCM:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_128_CCM (ID {0xC0, 0xA4})\n", indent * 4, "");
	case TLS_PSK_WITH_AES_256_CCM:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_256_CCM (ID {0xC0, 0xA5})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_AES_128_CCM:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_AES_128_CCM (ID {0xC0, 0xA6})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_AES_256_CCM:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_AES_256_CCM (ID {0xC0, 0xA7})\n", indent * 4, "");
	case TLS_PSK_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_128_CCM_8 (ID {0xC0, 0xA8})\n", indent * 4, "");
	case TLS_PSK_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_AES_256_CCM_8 (ID {0xC0, 0xA9})\n", indent * 4, "");
	case TLS_PSK_DHE_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "%*sTLS_PSK_DHE_WITH_AES_128_CCM_8 (ID {0xC0, 0xAA})\n", indent * 4, "");
	case TLS_PSK_DHE_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "%*sTLS_PSK_DHE_WITH_AES_256_CCM_8 (ID {0xC0, 0xAB})\n", indent * 4, "");

	// RFC 9150: TLS 1.3 Authentication and Integrity-Only Cipher Suites
	case TLS_SHA256_SHA256:
		return snprintf(buffer, size, "%*sTLS_SHA256_SHA256 (ID {0xC0, 0xB4})\n", indent * 4, "");
	case TLS_SHA384_SHA384:
		return snprintf(buffer, size, "%*sTLS_SHA384_SHA384 (ID {0xC0, 0xB5})\n", indent * 4, "");

	// RFC 9189: GOST Cipher Suites for Transport Layer Security (TLS) Protocol Version 1.2
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_CTR_OMAC:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_KUZNYECHIK_CTR_OMAC (ID {0xC1, 0x00})\n", indent * 4, "");
	case TLS_GOST_R341112_256_WITH_MAGMA_CTR_OMAC:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_MAGMA_CTR_OMAC (ID {0xC1, 0x01})\n", indent * 4, "");
	case TLS_GOST_R341112_256_WITH_28147_CNT_IMIT:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_28147_CNT_IMIT (ID {0xC1, 0x02})\n", indent * 4, "");
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_LIGHT:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_LIGHT (ID {0xC1, 0x03})\n", indent * 4, "");
	case TLS_GOST_R341112_256_WITH_MAGMA_MGM_LIGHT:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_MAGMA_MGM_LIGHT (ID {0xC1, 0x04})\n", indent * 4, "");
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_STRONG:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_STRONG (ID {0xC1, 0x05})\n", indent * 4, "");
	case TLS_GOST_R341112_256_WITH_MAGMA_MGM_STRONG:
		return snprintf(buffer, size, "%*sTLS_GOST_R341112_256_WITH_MAGMA_MGM_STRONG (ID {0xC1, 0x06})\n", indent * 4, "");

	// RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xA8})\n", indent * 4, "");
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xA9})\n", indent * 4, "");
	case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAA})\n", indent * 4, "");

	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAB})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAC})\n", indent * 4, "");
	case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAD})\n", indent * 4, "");
	case TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "%*sTLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAE})\n", indent * 4, "");

	// RFC 8442: ECDHE_PSK with AES-GCM and AES-CCM Cipher Suites for TLS 1.2 and DTLS 1.2
	case TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 (ID {0xD0, 0x01})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 (ID {0xD0, 0x02})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 (ID {0xD0, 0x03})\n", indent * 4, "");
	case TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
		return snprintf(buffer, size, "%*sTLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 (ID {0xD0, 0x05})\n", indent * 4, "");

	default:
	{
		if (tls_check_grease_value(id))
		{
			return snprintf(buffer, size, "%*sGREASE (ID {0x%02hhX, 0x%02hhX})\n", indent * 4, "", o1, o2);
		}
		else
		{
			return snprintf(buffer, size, "%*sUnknown (ID {0x%02hhX, 0x%02hhX})\n", indent * 4, "", o1, o2);
		}
	}
	}
}

static uint32_t tls_client_hello_print(tls_client_hello *hello, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	// Protocol Version
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sProtocol Version: ", indent * 4, "");

	switch (TLS_VERSION_RAW(hello->version))
	{
	case TLS_VERSION_1_0:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.0 (3, 1)\n");
		break;
	case TLS_VERSION_1_1:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.1 (3, 2)\n");
		break;
	case TLS_VERSION_1_2:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.2 (3, 3)\n");
		break;
	case TLS_VERSION_1_3:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS 1.3 (3, 4)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (%hhu, %hhu)\n", hello->version.major, hello->version.minor);
		break;
	}

	// Random
	pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "Random", hello->random, 32);

	// Session ID
	if (hello->session_id_size > 0)
	{
		pos += print_bytes(indent, PTR_OFFSET(buffer, pos), size - pos, "Session ID", hello->session_id, hello->session_id_size);
	}

	// Compression Methods
	if (hello->compression_methods_size > 0)
	{
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sCompression Methods:\n", indent * 4, "");

		for (uint32_t i = 0; i < hello->compression_methods_size; ++i)
		{
			pos += print_compression_method(indent + 1, PTR_OFFSET(buffer, pos), size - pos, hello->data[hello->cipher_suites_size + i]);
		}
	}

	// Cipher Suites
	if (hello->cipher_suites_size > 0)
	{
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sPreferred Cipher Suites:\n", indent * 4, "");

		for (uint32_t i = 0; i < hello->cipher_suites_size; i += 2)
		{
			pos += print_cipher_suite(indent + 1, PTR_OFFSET(buffer, pos), size - pos, hello->data[i], hello->data[i + 1]);
		}
	}

	if (hello->extensions_count > 0)
	{
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sExtensions (%hu bytes):\n", indent * 4, "", hello->extensions_size);

		for (uint16_t i = 0; i < hello->extensions_count; ++i)
		{
			pos += tls_extension_print(hello->extensions[i], PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		}
	}

	return pos;
}

uint32_t tls_handshake_print(tls_handshake_header *handshake, void *buffer, uint32_t size, uint32_t indent)
{
	uint32_t pos = 0;

	// Handshake Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sHandshake Type: ", indent * 4, "");

	switch (handshake->type)
	{
	case TLS_HELLO_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Hello Request (ID 0)\n");
		break;
	case TLS_CLIENT_HELLO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Hello (ID 1)\n");
		break;
	case TLS_SERVER_HELLO:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Hello (ID 2)\n");
		break;
	case TLS_HELLO_VERIFY_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Hello Verify Request (ID 3)\n");
		break;
	case TLS_NEW_SESSION_TICKET:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "New Session Ticket (ID 4)\n");
		break;
	case TLS_END_OF_EARLY_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "End Of Early Data (ID 5)\n");
		break;
	case TLS_HELLO_RETRY_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Hello Retry Request (ID 6)\n");
		break;
	case TLS_ENCRYPTED_EXTENSIONS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Encrypted Extensions (ID 8)\n");
		break;
	case TLS_CERTIFICATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "TLS Certificate (ID 11)\n");
		break;
	case TLS_SERVER_KEY_EXCHANGE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Key Exchange (ID 12)\n");
		break;
	case TLS_CERTIFICATE_REQUEST:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Request (ID 13)\n");
		break;
	case TLS_SERVER_HELLO_DONE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Server Hello Done (ID 14)\n");
		break;
	case TLS_CERTIFICATE_VERIFY:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Verify (ID 15)\n");
		break;
	case TLS_CLIENT_KEY_EXCHANGE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Client Key Exchange (ID 16)\n");
		break;
	case TLS_FINISHED:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Finished (ID 20)\n");
		break;
	case TLS_CERTIFICATE_URL:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate URL (ID 21)\n");
		break;
	case TLS_CERTIFICATE_STATUS:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Certificate Status (ID 22)\n");
		break;
	case TLS_SUPPLEMENTAL_DATA:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Supplemental Data (ID 23)\n");
		break;
	case TLS_KEY_UPDATE:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Key Update (ID 24)\n");
		break;
	case TLS_MESSAGE_HASH:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Message Hash (ID 254)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", handshake->type);
		break;
	}

	// Handshake Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "%*sHandshake Size: %u\n", indent * 4, "", handshake->size);

	switch (handshake->type)
	{
	case TLS_HELLO_REQUEST:
		break;
	case TLS_CLIENT_HELLO:
		pos += tls_client_hello_print(handshake, PTR_OFFSET(buffer, pos), size - pos, indent + 1);
		break;
	case TLS_SERVER_HELLO:
		break;
	case TLS_HELLO_VERIFY_REQUEST:
	case TLS_NEW_SESSION_TICKET:
	case TLS_END_OF_EARLY_DATA:
	case TLS_HELLO_RETRY_REQUEST:
	case TLS_ENCRYPTED_EXTENSIONS:
	case TLS_CERTIFICATE:
	case TLS_SERVER_KEY_EXCHANGE:
	case TLS_CERTIFICATE_REQUEST:
	case TLS_SERVER_HELLO_DONE:
	case TLS_CERTIFICATE_VERIFY:
	case TLS_CLIENT_KEY_EXCHANGE:
	case TLS_FINISHED:
	case TLS_CERTIFICATE_URL:
	case TLS_CERTIFICATE_STATUS:
	case TLS_SUPPLEMENTAL_DATA:
	case TLS_KEY_UPDATE:
	case TLS_MESSAGE_HASH:
		break;
	}

	return pos;
}
