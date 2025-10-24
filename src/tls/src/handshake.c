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
#include <tls/print.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static tls_error_t tls_client_hello_read_body(tls_client_hello **handshake, tls_handshake_header *header, void *data, uint32_t size)
{
	tls_client_hello *hello = NULL;
	tls_error_t error = 0;

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

	// Check for extensions
	if (pos == size)
	{
		goto end;
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
			error = tls_extension_read(hello->header.type, &hello->extensions[i], in + pos, size - pos);

			if (error != TLS_SUCCESS)
			{
				return error;
			}

			pos += TLS_EXTENSION_OCTETS(hello->extensions[i]);
		}
	}

end:
	*handshake = hello;

	return TLS_SUCCESS;
}

static uint32_t tls_client_hello_write_body(tls_client_hello *hello, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;
	uint32_t offset = 0;

	// 2 octet protocol version
	LOAD_8(out + pos, &hello->version.major);
	pos += 1;

	LOAD_8(out + pos, &hello->version.minor);
	pos += 1;

	// 32 octets of random data
	memcpy(out + pos, &hello->random, 32);
	pos += 32;

	// 1 octet session id size
	LOAD_8(out + pos, &hello->session_id_size);
	pos += 1;

	// N octets of session id
	if (hello->session_id_size > 0)
	{
		memcpy(out + pos, &hello->session_id, hello->session_id_size);
		pos += hello->session_id_size;
	}

	// 2 octet cipher suites size
	LOAD_16BE(out + pos, &hello->cipher_suites_size);
	pos += 2;

	// N octets of cipher suites
	if (hello->cipher_suites_size > 0)
	{
		memcpy(out + pos, hello->data + offset, hello->cipher_suites_size);
		pos += hello->cipher_suites_size;
		offset += hello->cipher_suites_size;
	}

	// 1 octet compression method size
	LOAD_8(out + pos, &hello->compression_methods_size);
	pos += 1;

	if (hello->compression_methods_size > 0)
	{
		memcpy(out + pos, hello->data + offset, hello->compression_methods_size);
		pos += hello->compression_methods_size;
		offset += hello->compression_methods_size;
	}

	// Check for extensions
	if (hello->extensions_size == 0)
	{
		return pos;
	}

	// 2 octet extensions size
	LOAD_16BE(out + pos, &hello->extensions_size);
	pos += 2;

	if (hello->extensions_size > 0)
	{
		for (uint16_t i = 0; i < hello->extensions_count; ++i)
		{
			pos += tls_extension_write(hello->header.type, &hello->extensions[i], out + pos, size - pos);
		}
	}

	return pos;
}

static uint32_t print_handshake_version(buffer_t *buffer, uint32_t indent, tls_protocol_version version)
{
	const char *name = NULL;

	switch (TLS_VERSION_RAW(version))
	{
	case TLS_VERSION_1_0:
		name = "TLS 1.0";
		break;
	case TLS_VERSION_1_1:
		name = "TLS 1.1";
		break;
	case TLS_VERSION_1_2:
		name = "TLS 1.2";
		break;
	case TLS_VERSION_1_3:
		name = "TLS 1.3";
		break;
	default:
		name = "Unknown";
		break;
	}

	return print_format(buffer, indent, "Protocol Version: %s (%hhu, %hhu)", name, version.major, version.minor);
}

static uint32_t print_compression_method(buffer_t *buffer, uint32_t indent, uint8_t method)
{
	switch (method)
	{
	case TLS_UNCOMPRESSED:
		return print_format(buffer, indent, "NULL (ID %hhu)\n", method);
	case TLS_ZLIB:
		return print_format(buffer, indent, "DEFLATE (ID %hhu)\n", method);
	default:
		return print_format(buffer, indent, "Unknown (ID %hhu)\n", method);
	}
}

static uint32_t print_cipher_suite(buffer_t *buffer, uint32_t indent, uint8_t o1, uint8_t o2)
{
	const char *name = NULL;
	uint16_t id = TLS_MAKE_CIPHER_SUITE(o1, o2);

	switch (id)
	{
	case TLS_NULL_WITH_NULL_NULL:
		name = "TLS_NULL_WITH_NULL_NULL";
		break;

	case TLS_RSA_WITH_NULL_MD5:
		name = "TLS_RSA_WITH_NULL_MD5";
		break;
	case TLS_RSA_WITH_NULL_SHA1:
		name = "TLS_RSA_WITH_NULL_SHA1";
		break;
	case TLS_RSA_WITH_NULL_SHA256:
		name = "TLS_RSA_WITH_NULL_SHA256";
		break;
	case TLS_RSA_WITH_RC4_128_MD5:
		name = "TLS_RSA_WITH_RC4_128_MD5";
		break;
	case TLS_RSA_WITH_RC4_128_SHA1:
		name = "TLS_RSA_WITH_RC4_128_SHA1";
		break;
	case TLS_RSA_WITH_IDEA_CBC_SHA1:
		name = "TLS_RSA_WITH_IDEA_CBC_SHA1";
		break;
	case TLS_RSA_WITH_DES_CBC_SHA1:
		name = "TLS_RSA_WITH_DES_CBC_SHA1";
		break;
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_RSA_WITH_AES_128_CBC_SHA1:
		name = "TLS_RSA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_RSA_WITH_AES_256_CBC_SHA1:
		name = "TLS_RSA_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_RSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		name = "TLS_RSA_WITH_AES_256_CBC_SHA256";
		break;

	case TLS_DH_DSS_WITH_DES_CBC_SHA1:
		name = "TLS_DH_DSS_WITH_DES_CBC_SHA1";
		break;
	case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_DH_RSA_WITH_DES_CBC_SHA1:
		name = "TLS_DH_RSA_WITH_DES_CBC_SHA1";
		break;
	case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_DHE_DSS_WITH_DES_CBC_SHA1:
		name = "TLS_DHE_DSS_WITH_DES_CBC_SHA1";
		break;
	case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_DHE_RSA_WITH_DES_CBC_SHA1:
		name = "TLS_DHE_RSA_WITH_DES_CBC_SHA1";
		break;
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_DH_DSS_WITH_AES_128_CBC_SHA1:
		name = "TLS_DH_DSS_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_DH_RSA_WITH_AES_128_CBC_SHA1:
		name = "TLS_DH_RSA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_DHE_DSS_WITH_AES_128_CBC_SHA1:
		name = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA1:
		name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_DH_DSS_WITH_AES_256_CBC_SHA1:
		name = "TLS_DH_DSS_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_DH_RSA_WITH_AES_256_CBC_SHA1:
		name = "TLS_DH_RSA_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_DHE_DSS_WITH_AES_256_CBC_SHA1:
		name = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA1:
		name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
		name = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
		name = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
		name = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
		break;
	case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
		name = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
		break;
	case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
		name = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
		break;
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
		name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
		break;

	case TLS_DH_ANON_WITH_RC4_128_MD5:
		name = "TLS_DH_ANON_WITH_RC4_128_MD5";
		break;
	case TLS_DH_ANON_WITH_DES_CBC_SHA1:
		name = "TLS_DH_ANON_WITH_DES_CBC_SHA1";
		break;
	case TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_DH_ANON_WITH_AES_128_CBC_SHA1:
		name = "TLS_DH_ANON_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_DH_ANON_WITH_AES_256_CBC_SHA1:
		name = "TLS_DH_ANON_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_DH_ANON_WITH_AES_128_CBC_SHA256:
		name = "TLS_DH_ANON_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_DH_ANON_WITH_AES_256_CBC_SHA256:
		name = "TLS_DH_ANON_WITH_AES_256_CBC_SHA256";
		break;

	// RFC 5288: AES Galois Counter Mode (GCM) Cipher Suites for TLS
	case TLS_RSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_RSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_RSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_RSA_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
		name = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
		name = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
		name = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
		name = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
		name = "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
		name = "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
		break;

	// RFC 5487: Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		name = "TLS_PSK_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_PSK_WITH_AES_256_GCM_SHA384:
		name = "TLS_PSK_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
		name = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
		name = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
		name = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
		name = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
		break;

	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		name = "TLS_PSK_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_PSK_WITH_AES_256_CBC_SHA384:
		name = "TLS_PSK_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_PSK_WITH_NULL_SHA256:
		name = "TLS_PSK_WITH_NULL_SHA256";
		break;
	case TLS_PSK_WITH_NULL_SHA384:
		name = "TLS_PSK_WITH_NULL_SHA384";
		break;

	case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
		name = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
		name = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_DHE_PSK_WITH_NULL_SHA256:
		name = "TLS_DHE_PSK_WITH_NULL_SHA256";
		break;
	case TLS_DHE_PSK_WITH_NULL_SHA384:
		name = "TLS_DHE_PSK_WITH_NULL_SHA384";
		break;

	case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
		name = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
		name = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_RSA_PSK_WITH_NULL_SHA256:
		name = "TLS_RSA_PSK_WITH_NULL_SHA256";
		break;
	case TLS_RSA_PSK_WITH_NULL_SHA384:
		name = "TLS_RSA_PSK_WITH_NULL_SHA384";
		break;

	// RFC 5932:  Camellia Cipher Suites for TLS
	case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		name = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA1";
		break;
	case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA1:
		name = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA1";
		break;
	case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		name = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA1";
		break;
	case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA1:
		name = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA1";
		break;
	case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		name = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA1";
		break;
	case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA1:
		name = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA1";
		break;

	case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		name = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA1";
		break;
	case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA1:
		name = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA1";
		break;
	case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		name = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA1";
		break;
	case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA1:
		name = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA1";
		break;
	case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		name = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA1";
		break;
	case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA1:
		name = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA1";
		break;

	case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256";
		break;

	case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		name = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
		break;
	case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
		name = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256";
		break;
	case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		name = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256";
		break;
	case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
		name = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256";
		break;
	case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		name = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
		break;
	case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256:
		name = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256";
		break;

	// RFC 8998: ShangMi (SM) Cipher Suites for TLS 1.3
	case TLS_SM4_GCM_SM3:
		name = "TLS_SM4_GCM_SM3";
		break;
	case TLS_SM4_CCM_SM3:
		name = "TLS_SM4_CCM_SM3";
		break;

	// RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension
	case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
		name = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
		break;

	// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
	case TLS_AES_128_GCM_SHA256:
		name = "TLS_AES_128_GCM_SHA256";
		break;
	case TLS_AES_256_GCM_SHA384:
		name = "TLS_AES_256_GCM_SHA384";
		break;
	case TLS_CHACHA20_POLY1305_SHA256:
		name = "TLS_CHACHA20_POLY1305_SHA256";
		break;
	case TLS_AES_128_CCM_SHA256:
		name = "TLS_AES_128_CCM_SHA256";
		break;
	case TLS_AES_128_CCM_8_SHA256:
		name = "TLS_AES_128_CCM_8_SHA256";
		break;

	// RFC 8422:  Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
	case TLS_ECDHE_ECDSA_WITH_NULL_SHA1:
		name = "TLS_ECDHE_ECDSA_WITH_NULL_SHA1";
		break;
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA1:
		name = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA1:
		name = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA1";
		break;

	case TLS_ECDHE_RSA_WITH_NULL_SHA1:
		name = "TLS_ECDHE_RSA_WITH_NULL_SHA1";
		break;
	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA1:
		name = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA1:
		name = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA1";
		break;

	case TLS_ECDH_ANON_WITH_NULL_SHA1:
		name = "TLS_ECDH_ANON_WITH_NULL_SHA1";
		break;
	case TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_ECDH_ANON_WITH_AES_128_CBC_SHA1:
		name = "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_ECDH_ANON_WITH_AES_256_CBC_SHA1:
		name = "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA1";
		break;

	// RFC 5054: Using the Secure Remote Password (SRP) Protocol for TLS Authentication
	case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_SRP_SHA_WITH_AES_128_CBC_SHA1:
		name = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA1:
		name = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA1:
		name = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_SRP_SHA_WITH_AES_256_CBC_SHA1:
		name = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA1:
		name = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA1:
		name = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA1";
		break;

	// RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		name = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		name = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		name = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
		name = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
		name = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
		break;

	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
		name = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
		name = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
		break;

	// RFC 5489: ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)
	case TLS_ECDHE_PSK_WITH_RC4_128_SHA1:
		name = "TLS_ECDHE_PSK_WITH_RC4_128_SHA1";
		break;
	case TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA1:
		name = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA1";
		break;
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA1:
		name = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA1";
		break;
	case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA1:
		name = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA1";
		break;
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		name = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
		name = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
		break;
	case TLS_ECDHE_PSK_WITH_NULL_SHA1:
		name = "TLS_ECDHE_PSK_WITH_NULL_SHA1";
		break;
	case TLS_ECDHE_PSK_WITH_NULL_SHA256:
		name = "TLS_ECDHE_PSK_WITH_NULL_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_NULL_SHA384:
		name = "TLS_ECDHE_PSK_WITH_NULL_SHA384";
		break;

	// RFC 6209: Addition of the ARIA Cipher Suites to Transport Layer Security (TLS)
	case TLS_RSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_RSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_RSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_RSA_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384";
		break;

	case TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384";
		break;

	case TLS_RSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_RSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_RSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_RSA_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384";
		break;

	case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
		break;

	case TLS_PSK_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_PSK_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_PSK_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_PSK_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384";
		break;
	case TLS_PSK_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_PSK_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_PSK_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_PSK_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
		name = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256";
		break;
	case TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
		name = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384";
		break;
	case TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
		name = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
		name = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384";
		break;

	// RFC 6367: Addition of the Camellia Cipher Suites to Transport Layer Security (TLS)
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
		break;
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
		break;
	case TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
		break;
	case TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
		break;

	case TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
		break;

	case TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		name = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256";
		break;
	case TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		name = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384";
		break;
	case TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
		break;
	case TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
		break;
	case TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
		break;
	case TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		name = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		name = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
		break;

	// RFC 6655: AES-CCM Cipher Suites for Transport Layer Security (TLS)
	case TLS_RSA_WITH_AES_128_CCM:
		name = "TLS_RSA_WITH_AES_128_CCM";
		break;
	case TLS_RSA_WITH_AES_256_CCM:
		name = "TLS_RSA_WITH_AES_256_CCM";
		break;
	case TLS_DHE_RSA_WITH_AES_128_CCM:
		name = "TLS_DHE_RSA_WITH_AES_128_CCM";
		break;
	case TLS_DHE_RSA_WITH_AES_256_CCM:
		name = "TLS_DHE_RSA_WITH_AES_256_CCM";
		break;
	case TLS_RSA_WITH_AES_128_CCM_8:
		name = "TLS_RSA_WITH_AES_128_CCM_8";
		break;
	case TLS_RSA_WITH_AES_256_CCM_8:
		name = "TLS_RSA_WITH_AES_256_CCM_8";
		break;
	case TLS_DHE_RSA_WITH_AES_128_CCM_8:
		name = "TLS_DHE_RSA_WITH_AES_128_CCM_8";
		break;
	case TLS_DHE_RSA_WITH_AES_256_CCM_8:
		name = "TLS_DHE_RSA_WITH_AES_256_CCM_8";
		break;

	case TLS_PSK_WITH_AES_128_CCM:
		name = "TLS_PSK_WITH_AES_128_CCM";
		break;
	case TLS_PSK_WITH_AES_256_CCM:
		name = "TLS_PSK_WITH_AES_256_CCM";
		break;
	case TLS_DHE_PSK_WITH_AES_128_CCM:
		name = "TLS_DHE_PSK_WITH_AES_128_CCM";
		break;
	case TLS_DHE_PSK_WITH_AES_256_CCM:
		name = "TLS_DHE_PSK_WITH_AES_256_CCM";
		break;
	case TLS_PSK_WITH_AES_128_CCM_8:
		name = "TLS_PSK_WITH_AES_128_CCM_8";
		break;
	case TLS_PSK_WITH_AES_256_CCM_8:
		name = "TLS_PSK_WITH_AES_256_CCM_8";
		break;
	case TLS_PSK_DHE_WITH_AES_128_CCM_8:
		name = "TLS_PSK_DHE_WITH_AES_128_CCM_8";
		break;
	case TLS_PSK_DHE_WITH_AES_256_CCM_8:
		name = "TLS_PSK_DHE_WITH_AES_256_CCM_8";
		break;

	// RFC 9150: TLS 1.3 Authentication and Integrity-Only Cipher Suites
	case TLS_SHA256_SHA256:
		name = "TLS_SHA256_SHA256";
		break;
	case TLS_SHA384_SHA384:
		name = "TLS_SHA384_SHA384";
		break;

	// RFC 9189: GOST Cipher Suites for Transport Layer Security (TLS) Protocol Version 1.2
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_CTR_OMAC:
		name = "TLS_GOST_R341112_256_WITH_KUZNYECHIK_CTR_OMAC";
		break;
	case TLS_GOST_R341112_256_WITH_MAGMA_CTR_OMAC:
		name = "TLS_GOST_R341112_256_WITH_MAGMA_CTR_OMAC";
		break;
	case TLS_GOST_R341112_256_WITH_28147_CNT_IMIT:
		name = "TLS_GOST_R341112_256_WITH_28147_CNT_IMIT";
		break;
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_LIGHT:
		name = "TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_LIGHT";
		break;
	case TLS_GOST_R341112_256_WITH_MAGMA_MGM_LIGHT:
		name = "TLS_GOST_R341112_256_WITH_MAGMA_MGM_LIGHT";
		break;
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_STRONG:
		name = "TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_STRONG";
		break;
	case TLS_GOST_R341112_256_WITH_MAGMA_MGM_STRONG:
		name = "TLS_GOST_R341112_256_WITH_MAGMA_MGM_STRONG";
		break;

	// RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
		break;
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
		break;
	case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
		break;

	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
		break;
	case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
		break;
	case TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
		name = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256";
		break;

	// RFC 8442: ECDHE_PSK with AES-GCM and AES-CCM Cipher Suites for TLS 1.2 and DTLS 1.2
	case TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
		name = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
		name = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384";
		break;
	case TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
		name = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256";
		break;
	case TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
		name = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256";
		break;

	default:
	{
		if (tls_check_grease_value(id))
		{
			name = "GREASE Cipher";
		}
		else
		{
			name = "Unknown";
		}
	}
	break;
	}

	return print_format(buffer, indent, "%s (ID {%#^.2hhx, %#^.2hhx})\n", name, o1, o2);
}

uint32_t print_signature_algorithm(buffer_t *buffer, uint32_t indent, uint16_t algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case TLS_RSA_PKCS_MD5:
		name = "rsa_pkcs1_md5";
		break;
	case TLS_DSA_MD5:
		name = "dsa_md5";
		break;
	case TLS_ECDSA_MD5:
		name = "ecdsa_md5";
		break;
	case TLS_RSA_PKCS_SHA1:
		name = "rsa_pkcs1_sha1";
		break;
	case TLS_DSA_SHA1:
		name = "dsa_sha1";
		break;
	case TLS_ECDSA_SHA1:
		name = "ecdsa_sha1";
		break;
	case TLS_RSA_PKCS_SHA224:
		name = "rsa_pkcs1_sha224";
		break;
	case TLS_DSA_SHA224:
		name = "dsa_sha224";
		break;
	case TLS_ECDSA_SHA224:
		name = "ecdsa_sha224";
		break;
	case TLS_RSA_PKCS_SHA256:
		name = "rsa_pkcs1_sha256";
		break;
	case TLS_DSA_SHA256:
		name = "dsa_sha256";
		break;
	case TLS_ECDSA_SECP256R1_SHA256:
		name = "ecdsa_secp256r1_sha1";
		break;
	case TLS_RSA_PKCS_SHA384:
		name = "rsa_pkcs1_sha384";
		break;
	case TLS_DSA_SHA384:
		name = "dsa_sha384";
		break;
	case TLS_ECDSA_SECP384R1_SHA384:
		name = "ecdsa_secp384r1_sha384";
		break;
	case TLS_RSA_PKCS_SHA512:
		name = "rsa_pkcs1_sha512";
		break;
	case TLS_DSA_SHA512:
		name = "dsa_sha512";
		break;
	case TLS_ECDSA_SECP521R1_SHA512:
		name = "ecdsa_secp521r1_sha512";
		break;
	case TLS_SM2_SM3:
		name = "sm2sig_sm3";
		break;
	case TLS_GOST_R34102012_256A:
		name = "gostr34102012_256a";
		break;
	case TLS_GOST_R34102012_256B:
		name = "gostr34102012_256b";
		break;
	case TLS_GOST_R34102012_256C:
		name = "gostr34102012_256c";
		break;
	case TLS_GOST_R34102012_256D:
		name = "gostr34102012_256d";
		break;
	case TLS_GOST_R34102012_512A:
		name = "gostr34102012_512a";
		break;
	case TLS_GOST_R34102012_512B:
		name = "gostr34102012_512b";
		break;
	case TLS_GOST_R34102012_512C:
		name = "gostr34102012_512c";
		break;
	case TLS_RSA_PSS_RSAE_SHA256:
		name = "rsa_pss_rsae_sha256";
		break;
	case TLS_RSA_PSS_RSAE_SHA384:
		name = "rsa_pss_rsae_sha384";
		break;
	case TLS_RSA_PSS_RSAE_SHA512:
		name = "rsa_pss_rsae_sha512";
		break;
	case TLS_ED25519:
		name = "ed25519";
		break;
	case TLS_ED448:
		name = "ed448";
		break;
	case TLS_RSA_PSS_PSS_SHA256:
		name = "rsa_pss_pss_sha256";
		break;
	case TLS_RSA_PSS_PSS_SHA384:
		name = "rsa_pss_pss_sha384";
		break;
	case TLS_RSA_PSS_PSS_SHA512:
		name = "rsa_pss_pss_sha512";
		break;
	case TLS_ECDSA_BRAINPOOL_P256R1_TLS13_SHA256:
		name = "ecdsa_brainpoolP256r1tls13_sha256";
		break;
	case TLS_ECDSA_BRAINPOOL_P384R1_TLS13_SHA384:
		name = "ecdsa_brainpoolP384r1tls13_sha384";
		break;
	case TLS_ECDSA_BRAINPOOL_P512R1_TLS13_SHA512:
		name = "ecdsa_brainpoolP512r1tls13_sha512";
		break;
	case TLS_MLDSA44:
		name = "mldsa44";
		break;
	case TLS_MLDSA65:
		name = "mldsa65";
		break;
	case TLS_MLDSA87:
		name = "mldsa87";
		break;
	default:
	{
		if (tls_check_grease_value(algorithm))
		{
			name = "GREASE Signature";
		}
		else
		{
			name = "Unknown";
		}
	}
	break;
	}

	return print_format(buffer, indent, "%s (ID %^.4hx)\n", name, algorithm);
}

static uint32_t tls_client_hello_print_body(tls_client_hello *hello, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	// Protocol Version
	pos += print_handshake_version(buffer, indent, hello->version);

	// Random
	pos += print_bytes(buffer, indent, "Random", hello->random, 32);

	// Session ID
	if (hello->session_id_size > 0)
	{
		pos += print_bytes(buffer, indent, "Session ID", hello->session_id, hello->session_id_size);
	}

	// Compression Methods
	if (hello->compression_methods_size > 0)
	{
		pos += print_format(buffer, indent, "Compression Methods:\n");
		indent += 1;

		for (uint32_t i = 0; i < hello->compression_methods_size; ++i)
		{
			pos += print_compression_method(buffer, indent, hello->data[hello->cipher_suites_size + i]);
		}

		indent -= 1;
	}

	// Cipher Suites
	if (hello->cipher_suites_size > 0)
	{
		pos += print_format(buffer, indent, "Preferred Cipher Suites:\n");
		indent += 1;

		for (uint32_t i = 0; i < hello->cipher_suites_size; i += 2)
		{
			pos += print_cipher_suite(buffer, indent, hello->data[i], hello->data[i + 1]);
		}

		indent -= 1;
	}

	if (hello->extensions_count > 0)
	{
		pos += print_format(buffer, indent, "Extensions (%hu bytes):\n", hello->extensions_size);
		indent += 1;

		for (uint16_t i = 0; i < hello->extensions_count; ++i)
		{
			pos += tls_extension_print(hello->header.type, hello->extensions[i], buffer, indent);
		}

		indent -= 1;
	}

	return pos;
}

static tls_error_t tls_server_hello_read_body(tls_server_hello **handshake, tls_handshake_header *header, void *data, uint32_t size)
{
	tls_server_hello *hello = NULL;
	tls_error_t error = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	hello = zmalloc(sizeof(tls_server_hello));

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

	// 2 octet selected cipher suite
	LOAD_16BE(&hello->cipher_suite, in + pos);
	pos += 2;

	// 1 octet selected compression method
	LOAD_8(&hello->compression_method, in + pos);
	pos += 1;

	// Check for extensions
	if (pos == size)
	{
		goto end;
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
			error = tls_extension_read(hello->header.type, &hello->extensions[i], in + pos, size - pos);

			if (error != TLS_SUCCESS)
			{
				return error;
			}

			pos += TLS_EXTENSION_OCTETS(hello->extensions[i]);
		}
	}

end:
	*handshake = hello;

	return TLS_SUCCESS;
}

static uint32_t tls_server_hello_write_body(tls_server_hello *hello, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 2 octet protocol version
	LOAD_8(out + pos, &hello->version.major);
	pos += 1;

	LOAD_8(out + pos, &hello->version.minor);
	pos += 1;

	// 32 octets of random data
	memcpy(out + pos, &hello->random, 32);
	pos += 32;

	// 1 octet session id size
	LOAD_8(out + pos, &hello->session_id_size);
	pos += 1;

	// N octets of session id
	if (hello->session_id_size > 0)
	{
		memcpy(out + pos, &hello->session_id, hello->session_id_size);
		pos += hello->session_id_size;
	}

	// 2 octet selected cipher suite
	LOAD_16BE(out + pos, &hello->cipher_suite);
	pos += 2;

	// 1 octet selected compression method
	LOAD_8(out + pos, &hello->compression_method);
	pos += 1;

	// Check for extensions
	if (hello->extensions_size == 0)
	{
		return pos;
	}

	// 2 octet extensions size
	LOAD_16BE(out + pos, &hello->extensions_size);
	pos += 2;

	if (hello->extensions_size > 0)
	{
		for (uint16_t i = 0; i < hello->extensions_count; ++i)
		{
			pos += tls_extension_write(hello->header.type, &hello->extensions[i], out + pos, size - pos);
		}
	}

	return pos;
}

static uint32_t tls_server_hello_print_body(tls_server_hello *hello, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	// Protocol Version
	pos += print_handshake_version(buffer, indent, hello->version);

	// Random
	pos += print_bytes(buffer, indent, "Random", hello->random, 32);

	// Session ID
	if (hello->session_id_size > 0)
	{
		pos += print_bytes(buffer, indent, "Session ID", hello->session_id, hello->session_id_size);
	}

	// Selected Compression Method
	pos += print_compression_method(buffer, indent, hello->compression_method);

	// Selected Cipher Suite
	pos += print_cipher_suite(buffer, indent, (hello->cipher_suite >> 8) & 0xFF, hello->cipher_suite & 0xFF);

	if (hello->extensions_count > 0)
	{
		pos += print_format(buffer, indent, "Extensions (%hu bytes):\n", hello->extensions_size);
		indent += 1;

		for (uint16_t i = 0; i < hello->extensions_count; ++i)
		{
			pos += tls_extension_print(hello->header.type, hello->extensions[i], buffer, indent);
		}
	}

	return pos;
}

static tls_error_t tls_new_session_ticket_read_body(tls_new_session_ticket **handshake, tls_handshake_header *header, void *data,
													uint32_t size)
{
	tls_new_session_ticket *session = NULL;
	tls_error_t error = 0;

	uint8_t *in = data;
	uint32_t pos = 0;
	uint32_t offset = 0;

	session = zmalloc(sizeof(tls_new_session_ticket) + 512);

	if (session == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	session->header = *header;

	// 4 octet ticket lifetime
	LOAD_32BE(&session->ticket_lifetime, in + pos);
	pos += 4;

	// 4 octet ticket age add
	LOAD_32BE(&session->ticket_age_add, in + pos);
	pos += 4;

	// 1 octet ticket nonce size
	LOAD_8(&session->ticket_nonce_size, in + pos);
	pos += 1;

	if (session->ticket_nonce_size > 0)
	{
		memcpy(PTR_OFFSET(session->data, offset), in + pos, session->ticket_nonce_size);
		pos += session->ticket_nonce_size;
		offset += session->ticket_nonce_size;
	}

	// 2 octet ticket size
	LOAD_16BE(&session->ticket_size, in + pos);
	pos += 2;

	if (session->ticket_size > 0)
	{
		if (session->ticket_size + session->ticket_nonce_size > 512)
		{
			session = zrealloc(session, sizeof(tls_new_session_ticket) + session->ticket_size + session->ticket_nonce_size);

			if (session == NULL)
			{
				return TLS_NO_MEMORY;
			}
		}

		memcpy(PTR_OFFSET(session->data, offset), in + pos, session->ticket_size);
		pos += session->ticket_size;
		offset += session->ticket_size;
	}

	// 2 octet extensions size
	LOAD_16BE(&session->extensions_size, in + pos);
	pos += 2;

	if (session->extensions_size > 0)
	{
		session->extensions_count = tls_extension_count(in + pos, size - pos);
		session->extensions = zmalloc(session->extensions_count * sizeof(void *));

		if (session->extensions == NULL)
		{
			return TLS_NO_MEMORY;
		}

		for (uint16_t i = 0; i < session->extensions_count; ++i)
		{
			error = tls_extension_read(session->header.type, &session->extensions[i], in + pos, size - pos);

			if (error != TLS_SUCCESS)
			{
				return error;
			}

			pos += TLS_EXTENSION_OCTETS(session->extensions[i]);
		}
	}

	*handshake = session;

	return TLS_SUCCESS;
}

static uint32_t tls_new_session_ticket_write_body(tls_new_session_ticket *session, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;
	uint32_t offset = 0;

	// 4 octet ticket lifetime
	LOAD_32BE(out + pos, &session->ticket_lifetime);
	pos += 4;

	// 4 octet ticket age add
	LOAD_32BE(out + pos, &session->ticket_age_add);
	pos += 4;

	// 1 octet ticket nonce size
	LOAD_8(out + pos, &session->ticket_nonce_size);
	pos += 1;

	if (session->ticket_nonce_size > 0)
	{
		memcpy(out + pos, PTR_OFFSET(session->data, offset), session->ticket_nonce_size);
		pos += session->ticket_nonce_size;
		offset += session->ticket_nonce_size;
	}

	// 2 octet ticket size
	LOAD_16BE(out + pos, &session->ticket_size);
	pos += 2;

	if (session->ticket_size > 0)
	{

		memcpy(out + pos, PTR_OFFSET(session->data, offset), session->ticket_size);
		pos += session->ticket_size;
		offset += session->ticket_size;
	}

	// 2 octet extensions size
	LOAD_16BE(out + pos, &session->extensions_size);
	pos += 2;

	if (session->extensions_size > 0)
	{
		for (uint16_t i = 0; i < session->extensions_count; ++i)
		{
			pos += tls_extension_write(session->header.type, &session->extensions[i], out + pos, size - pos);
		}
	}

	return pos;
}

static uint32_t tls_new_session_ticket_print_body(tls_new_session_ticket *session, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	// Ticket Lifetime
	pos += print_format(buffer, indent, "Ticket Lifetime: %u seconds\n", session->ticket_lifetime);

	// Ticket Age Add
	pos += print_format(buffer, indent, "Ticket Age Add: %u seconds\n", session->ticket_age_add);

	// Ticket Nonce
	if (session->ticket_nonce_size > 0)
	{
		pos += print_bytes(buffer, indent, "Ticket Nonce", session->data, session->ticket_nonce_size);
	}

	// Ticket
	if (session->ticket_size > 0)
	{
		pos += print_bytes(buffer, indent, "Ticket", PTR_OFFSET(session->data, session->ticket_nonce_size), session->ticket_size);
	}

	if (session->extensions_count > 0)
	{
		pos += print_format(buffer, indent, "Extensions (%hu bytes):\n", session->extensions_size);
		indent += 1;

		for (uint16_t i = 0; i < session->extensions_count; ++i)
		{
			pos += tls_extension_print(session->header.type, session->extensions[i], buffer, indent);
		}
	}

	return pos;
}

static tls_error_t tls_encrypted_extensions_read_body(tls_encrypted_extensions **handshake, tls_handshake_header *header, void *data,
													  uint32_t size)
{
	tls_encrypted_extensions *extensions = NULL;
	tls_error_t error = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	extensions = zmalloc(sizeof(tls_encrypted_extensions));

	if (extensions == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	extensions->header = *header;

	// 2 octet extensions size
	LOAD_16BE(&extensions->extensions_size, in + pos);
	pos += 2;

	if (extensions->extensions_size > 0)
	{
		extensions->extensions_count = tls_extension_count(in + pos, size - pos);
		extensions->extensions = zmalloc(extensions->extensions_count * sizeof(void *));

		if (extensions->extensions == NULL)
		{
			return TLS_NO_MEMORY;
		}

		for (uint16_t i = 0; i < extensions->extensions_count; ++i)
		{
			error = tls_extension_read(extensions->header.type, &extensions->extensions[i], in + pos, size - pos);

			if (error != TLS_SUCCESS)
			{
				return error;
			}

			pos += TLS_EXTENSION_OCTETS(extensions->extensions[i]);
		}
	}

	*handshake = extensions;

	return TLS_SUCCESS;
}

static uint32_t tls_encrypted_extensions_write_body(tls_encrypted_extensions *extensions, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 2 octet extensions size
	LOAD_16BE(out + pos, &extensions->extensions_size);
	pos += 2;

	if (extensions->extensions_size > 0)
	{
		for (uint16_t i = 0; i < extensions->extensions_count; ++i)
		{
			pos += tls_extension_write(extensions->header.type, &extensions->extensions[i], out + pos, size - pos);
		}
	}

	return pos;
}

static uint32_t tls_encrypted_extensions_print_body(tls_encrypted_extensions *extensions, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	if (extensions->extensions_count > 0)
	{
		pos += print_format(buffer, indent, "Extensions (%hu bytes):\n", extensions->extensions_size);
		indent += 1;

		for (uint16_t i = 0; i < extensions->extensions_count; ++i)
		{
			pos += tls_extension_print(extensions->header.type, extensions->extensions[i], buffer, indent);
		}
	}

	return pos;
}

static tls_error_t tls_certificate_request_read_body(tls_certificate_request **handshake, tls_handshake_header *header, void *data,
													 uint32_t size)
{
	tls_certificate_request *request = NULL;
	tls_error_t error = 0;

	uint8_t *in = data;
	uint32_t pos = 0;

	request = zmalloc(sizeof(tls_certificate_request));

	if (request == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	request->header = *header;

	// 1 octet context size
	LOAD_8(&request->context_size, in + pos);
	pos += 1;

	// N octets of context
	if (request->context_size > 0)
	{
		memcpy(request->context, in + pos, request->context_size);
		pos += request->context_size;
	}

	// 2 octet extensions size
	LOAD_16BE(&request->extensions_size, in + pos);
	pos += 2;

	if (request->extensions_size > 0)
	{
		request->extensions_count = tls_extension_count(in + pos, size - pos);
		request->extensions = zmalloc(request->extensions_count * sizeof(void *));

		if (request->extensions == NULL)
		{
			return TLS_NO_MEMORY;
		}

		for (uint16_t i = 0; i < request->extensions_count; ++i)
		{
			error = tls_extension_read(request->header.type, &request->extensions[i], in + pos, size - pos);

			if (error != TLS_SUCCESS)
			{
				return error;
			}

			pos += TLS_EXTENSION_OCTETS(request->extensions[i]);
		}
	}

	*handshake = request;

	return TLS_SUCCESS;
}

static uint32_t tls_certificate_request_write_body(tls_certificate_request *request, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet context size
	LOAD_8(out + pos, &request->context_size);
	pos += 1;

	// N octets of context
	if (request->context_size > 0)
	{
		memcpy(out + pos, request->context, request->context_size);
		pos += request->context_size;
	}

	// 2 octet extensions size
	LOAD_16BE(out + pos, &request->extensions_size);
	pos += 2;

	if (request->extensions_size > 0)
	{
		for (uint16_t i = 0; i < request->extensions_count; ++i)
		{
			pos += tls_extension_write(request->header.type, &request->extensions[i], out + pos, size - pos);
		}
	}

	return pos;
}

static uint32_t tls_certificate_request_print_body(tls_certificate_request *request, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	// Request Context
	if (request->context_size > 0)
	{
		pos += print_bytes(buffer, indent, "Context", request->context, request->context_size);
	}

	// Request Extensions
	if (request->extensions_count > 0)
	{
		pos += print_format(buffer, indent, "Extensions (%hu bytes):\n", request->extensions_size);
		indent += 1;

		for (uint16_t i = 0; i < request->extensions_count; ++i)
		{
			pos += tls_extension_print(request->header.type, request->extensions[i], buffer, indent);
		}
	}

	return pos;
}

static tls_error_t tls_certificate_verify_read_body(tls_certificate_verify **handshake, tls_handshake_header *header, void *data)
{
	tls_certificate_verify *verify = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	verify = zmalloc(sizeof(tls_certificate_verify) + (header->size - 2));

	if (verify == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	verify->header = *header;

	// 2 octet signature algorithm
	LOAD_16BE(&verify->algorithm, in + pos);
	pos += 2;

	// N octets of signature
	memcpy(verify->signature, in + pos, verify->header.size - 2);
	pos += verify->header.size - 2;

	*handshake = verify;

	return TLS_SUCCESS;
}

static uint32_t tls_certificate_verify_write_body(tls_certificate_verify *verify, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 2 octet signature algorithm
	LOAD_16BE(out + pos, &verify->algorithm);
	pos += 2;

	// N octets of signature
	memcpy(out + pos, verify->signature, verify->header.size - 2);
	pos += verify->header.size - 2;

	return pos;
}

static uint32_t tls_certificate_verify_print_body(tls_certificate_verify *verify, buffer_t *buffer, uint32_t indent)
{
	uint32_t pos = 0;

	// Algorithm
	pos += print_signature_algorithm(buffer, indent, verify->algorithm);

	// Signature
	pos += print_bytes(buffer, indent, "Signature", verify->signature, verify->header.size - 2);

	return pos;
}

static tls_error_t tls_key_update_read_body(tls_key_update **handshake, tls_handshake_header *header, void *data)
{
	tls_key_update *update = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	if (header->size != 1)
	{
		return TLS_INVALID_PARAMETER;
	}

	update = zmalloc(sizeof(tls_key_update));

	if (update == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	update->header = *header;

	// 1 octet request
	LOAD_8(&update->request, in + pos);
	pos += 1;

	*handshake = update;

	return TLS_SUCCESS;
}

static uint32_t tls_key_update_write_body(tls_key_update *update, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// 1 octet request
	LOAD_8(out + pos, &update->request);
	pos += 1;

	return pos;
}

static uint32_t tls_key_update_print_body(tls_key_update *update, buffer_t *buffer, uint32_t indent)
{
	// Update Request
	switch (update->request)
	{
	case TLS_KEY_UPDATE_NOT_REQUESTED:
		return print_format(buffer, indent, "Key Update Not Requested (ID %hhu)\n", update->header);
	case TLS_KEY_UPDATE_REQUESTED:
		return print_format(buffer, indent, "Key Update Requested (ID %hhu)\n", update->header);
	default:
		return print_format(buffer, indent, "Unkown Key Update Request (ID %hhu)\n", update->request);
	}
}

static tls_error_t tls_handshake_finished_read_body(tls_handshake_finished **handshake, tls_handshake_header *header, void *data)
{
	tls_handshake_finished *finish = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	if (header->size > 255)
	{
		return TLS_INVALID_PARAMETER;
	}

	finish = zmalloc(sizeof(tls_handshake_finished) + header->size);

	if (finish == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	finish->header = *header;

	// N octets of verify MAC
	memcpy(finish->verify, in + pos, finish->header.size);
	pos += finish->header.size;

	*handshake = finish;

	return TLS_SUCCESS;
}

static uint32_t tls_handshake_finished_write_body(tls_handshake_finished *finish, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// N octets of verify MAC
	memcpy(out + pos, finish->verify, finish->header.size);
	pos += 1;

	return pos;
}

static uint32_t tls_handshake_finished_print_body(tls_handshake_finished *finish, buffer_t *buffer, uint32_t indent)
{
	// Verify MAC
	return print_bytes(buffer, indent, "Verification MAC", finish->verify, finish->header.size);
}

static tls_error_t tls_handshake_message_hash_read_body(tls_handshake_message_hash **handshake, tls_handshake_header *header, void *data)
{
	tls_handshake_message_hash *hash = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	if (header->size > 255)
	{
		return TLS_INVALID_PARAMETER;
	}

	hash = zmalloc(sizeof(tls_handshake_message_hash) + header->size);

	if (hash == NULL)
	{
		return TLS_NO_MEMORY;
	}

	// Copy the header
	hash->header = *header;

	// N octets of message hash
	memcpy(hash->hash, in + pos, hash->header.size);
	pos += hash->header.size;

	*handshake = hash;

	return TLS_SUCCESS;
}

static uint32_t tls_handshake_message_hash_write_body(tls_handshake_message_hash *hash, void *buffer)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	// N octets of message hash
	memcpy(out + pos, hash->hash, hash->header.size);
	pos += 1;

	return pos;
}

static uint32_t tls_handshake_message_hash_print_body(tls_handshake_message_hash *hash, buffer_t *buffer, uint32_t indent)
{
	// Message Hash
	return print_bytes(buffer, indent, "Message Hash", hash->hash, hash->header.size);
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
		goto empty;
		break;
	case TLS_CLIENT_HELLO:
		error = tls_client_hello_read_body((tls_client_hello **)handshake, &handshake_header, PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS),
										   handshake_header.size);
		break;
	case TLS_SERVER_HELLO:
		error = tls_server_hello_read_body((tls_server_hello **)handshake, &handshake_header, PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS),
										   handshake_header.size);
		break;
	case TLS_HELLO_VERIFY_REQUEST:
		break;
	case TLS_NEW_SESSION_TICKET:
		error = tls_new_session_ticket_read_body((tls_new_session_ticket **)handshake, &handshake_header,
												 PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS), handshake_header.size);
		break;
	case TLS_END_OF_EARLY_DATA:
		goto empty;
		break;
	case TLS_HELLO_RETRY_REQUEST:
		error = tls_server_hello_read_body((tls_server_hello **)handshake, &handshake_header, PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS),
										   handshake_header.size);
		break;
	case TLS_ENCRYPTED_EXTENSIONS:
		error = tls_encrypted_extensions_read_body((tls_encrypted_extensions **)handshake, &handshake_header,
												   PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS), handshake_header.size);
		break;
	case TLS_CERTIFICATE:
		break;
	case TLS_SERVER_KEY_EXCHANGE:
		break;
	case TLS_CERTIFICATE_REQUEST:
		error = tls_certificate_request_read_body((tls_certificate_request **)handshake, &handshake_header,
												  PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS), handshake_header.size);
		break;
	case TLS_SERVER_HELLO_DONE:
		goto empty;
		break;
	case TLS_CERTIFICATE_VERIFY:
		error = tls_certificate_verify_read_body((tls_certificate_verify **)handshake, &handshake_header,
												 PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS));
		break;
	case TLS_CLIENT_KEY_EXCHANGE:
		break;
	case TLS_FINISHED:
		error = tls_handshake_finished_read_body((tls_handshake_finished **)handshake, &handshake_header,
												 PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS));
		break;
	case TLS_CERTIFICATE_URL:
		break;
	case TLS_CERTIFICATE_STATUS:
		break;
	case TLS_SUPPLEMENTAL_DATA:
		break;
	case TLS_KEY_UPDATE:
		error = tls_key_update_read_body((tls_key_update **)handshake, &handshake_header, PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS));
		break;
	case TLS_MESSAGE_HASH:
		error = tls_handshake_message_hash_read_body((tls_handshake_message_hash **)handshake, &handshake_header,
													 PTR_OFFSET(data, TLS_HANDSHAKE_HEADER_OCTETS));
		break;
	default:
	{
	empty:
		tls_handshake_header *unknown = zmalloc(sizeof(tls_handshake_header));

		if (unknown == NULL)
		{
			return TLS_NO_MEMORY;
		}

		unknown->type = handshake_header.type;
		unknown->size = handshake_header.size;

		*handshake = unknown;
	}
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
	uint32_t pos = 0;

	tls_handshake_header *header = handshake;

	if (size < (TLS_HANDSHAKE_HEADER_OCTETS + header->size))
	{
		return 0;
	}

	pos += tls_handshake_header_write(header, buffer, size);

	switch (header->type)
	{
	case TLS_HELLO_REQUEST:
		// empty body
		break;
	case TLS_CLIENT_HELLO:
		pos += tls_client_hello_write_body(handshake, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_SERVER_HELLO:
		pos += tls_server_hello_write_body(handshake, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_HELLO_VERIFY_REQUEST:
		break;
	case TLS_NEW_SESSION_TICKET:
		pos += tls_new_session_ticket_write_body(handshake, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_END_OF_EARLY_DATA:
		// empty body
		break;
	case TLS_HELLO_RETRY_REQUEST:
		pos += tls_server_hello_write_body(handshake, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_ENCRYPTED_EXTENSIONS:
		pos += tls_encrypted_extensions_write_body(handshake, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_CERTIFICATE:
		break;
	case TLS_SERVER_KEY_EXCHANGE:
		break;
	case TLS_CERTIFICATE_REQUEST:
		pos += tls_certificate_request_write_body(handshake, PTR_OFFSET(buffer, pos), size - pos);
		break;
	case TLS_SERVER_HELLO_DONE:
		// empty body
		break;
	case TLS_CERTIFICATE_VERIFY:
		pos += tls_certificate_verify_write_body(handshake, PTR_OFFSET(buffer, pos));
		break;
	case TLS_CLIENT_KEY_EXCHANGE:
		break;
	case TLS_FINISHED:
		pos += tls_handshake_finished_write_body(handshake, PTR_OFFSET(buffer, pos));
		break;
	case TLS_CERTIFICATE_URL:
		break;
	case TLS_CERTIFICATE_STATUS:
		break;
	case TLS_SUPPLEMENTAL_DATA:
		break;
	case TLS_KEY_UPDATE:
		pos += tls_key_update_write_body(handshake, PTR_OFFSET(buffer, pos));
		break;
	case TLS_MESSAGE_HASH:
		pos += tls_handshake_message_hash_write_body(handshake, PTR_OFFSET(buffer, pos));
		break;
	default:
		break;
	}

	return pos;
}

static uint32_t print_handshake_header(tls_handshake_header *header, buffer_t *buffer, uint32_t indent)
{
	const char *name = NULL;

	switch (header->type)
	{
	case TLS_HELLO_REQUEST:
		name = "Hello Request";
		break;
	case TLS_CLIENT_HELLO:
		name = "Client Hello";
		break;
	case TLS_SERVER_HELLO:
		name = "Server Hello";
		break;
	case TLS_HELLO_VERIFY_REQUEST:
		name = "Hello Verify Request";
		break;
	case TLS_NEW_SESSION_TICKET:
		name = "New Session Ticket";
		break;
	case TLS_END_OF_EARLY_DATA:
		name = "End Of Early Data";
		break;
	case TLS_HELLO_RETRY_REQUEST:
		name = "Hello Retry Request";
		break;
	case TLS_ENCRYPTED_EXTENSIONS:
		name = "Encrypted Extensions";
		break;
	case TLS_REQUEST_CONNECTION_ID:
		name = "Request Connection ID";
		break;
	case TLS_NEW_CONNECTION_ID:
		name = "New Connection ID";
		break;
	case TLS_CERTIFICATE:
		name = "TLS Certificate";
		break;
	case TLS_SERVER_KEY_EXCHANGE:
		name = "Server Key Exchange";
		break;
	case TLS_CERTIFICATE_REQUEST:
		name = "Certificate Request";
		break;
	case TLS_SERVER_HELLO_DONE:
		name = "Server Hello Done";
		break;
	case TLS_CERTIFICATE_VERIFY:
		name = "Certificate Verify";
		break;
	case TLS_CLIENT_KEY_EXCHANGE:
		name = "Client Key Exchange";
		break;
	case TLS_CLIENT_CERTIFICATE_REQUEST:
		name = "Client Certificate Request";
		break;
	case TLS_FINISHED:
		name = "Finished";
		break;
	case TLS_CERTIFICATE_URL:
		name = "Certificate URL";
		break;
	case TLS_CERTIFICATE_STATUS:
		name = "Certificate Status";
		break;
	case TLS_SUPPLEMENTAL_DATA:
		name = "Supplemental Data";
		break;
	case TLS_KEY_UPDATE:
		name = "Key Update";
		break;
	case TLS_COMPRESSED_CERTIFICATE:
		name = "Compressed Certificate";
		break;
	case TLS_EKT_KEY:
		name = "EKT Key";
		break;
	case TLS_MESSAGE_HASH:
		name = "Message Hash";
		break;
	default:
		name = "Unknown";
		break;
	}

	return print_format(buffer, indent, "%s (ID %hhu) (%u bytes)\n", name, header->type, header->size);
}

uint32_t tls_handshake_print_body(void *handshake, buffer_t *buffer, uint32_t indent)
{
	tls_handshake_header *header = handshake;
	uint32_t pos = 0;

	// Handshake Type
	pos += print_handshake_header(header, buffer, indent);
	indent += 1;

	switch (header->type)
	{
	case TLS_HELLO_REQUEST:
		// empty body
		break;
	case TLS_CLIENT_HELLO:
		pos += tls_client_hello_print_body(handshake, buffer, indent);
		break;
	case TLS_SERVER_HELLO:
		pos += tls_server_hello_print_body(handshake, buffer, indent);
		break;
	case TLS_HELLO_VERIFY_REQUEST:
		break;
	case TLS_NEW_SESSION_TICKET:
		pos += tls_new_session_ticket_print_body(handshake, buffer, indent);
		break;
	case TLS_END_OF_EARLY_DATA:
		// empty body
		break;
	case TLS_HELLO_RETRY_REQUEST:
		pos += tls_server_hello_print_body(handshake, buffer, indent);
		break;
	case TLS_ENCRYPTED_EXTENSIONS:
		pos += tls_encrypted_extensions_print_body(handshake, buffer, indent);
		break;
	case TLS_CERTIFICATE:
		break;
	case TLS_SERVER_KEY_EXCHANGE:
		break;
	case TLS_CERTIFICATE_REQUEST:
		pos += tls_certificate_request_print_body(handshake, buffer, indent);
		break;
	case TLS_SERVER_HELLO_DONE:
		// empty body
		break;
	case TLS_CERTIFICATE_VERIFY:
		pos += tls_certificate_verify_print_body(handshake, buffer, indent);
		break;
	case TLS_CLIENT_KEY_EXCHANGE:
		break;
	case TLS_FINISHED:
		pos += tls_handshake_finished_print_body(handshake, buffer, indent);
		break;
	case TLS_CERTIFICATE_URL:
		break;
	case TLS_CERTIFICATE_STATUS:
		break;
	case TLS_SUPPLEMENTAL_DATA:
		break;
	case TLS_KEY_UPDATE:
		pos += tls_key_update_print_body(handshake, buffer, indent);
		break;
	case TLS_MESSAGE_HASH:
		pos += tls_handshake_message_hash_print_body(handshake, buffer, indent);
		break;
	default:
		break;
	}

	return pos;
}
