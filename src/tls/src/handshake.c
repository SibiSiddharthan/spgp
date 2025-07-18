/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <tls/algorithms.h>
#include <tls/handshake.h>
#include <tls/version.h>

#include <load.h>
#include <ptr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void tls_client_hello_read(tls_client_hello *hello, void *data, uint32_t size)
{
	uint8_t *in = data;
	uint32_t pos = 0;
	uint32_t offset = 0;

	// 2 octet protocol version
	LOAD_8(&hello->version.major, in + pos);
	pos += 1;

	LOAD_8(&hello->version.minor, in + pos);
	pos += 1;

	// 32 octets of random data
	memcpy(&hello->random, in + pos, 32);
	pos += 32;

	// 1 octet session id size
	LOAD_8(&hello->session.size, in + pos);
	pos += 1;

	// N octets of session id
	if (hello->session.size > 0)
	{
		memcpy(&hello->session.id, in + pos, hello->session.size);
		pos += hello->session.size;
	}

	// 2 octet cipher suites size
	LOAD_16BE(&hello->cipher_suites_size, in + pos);
	pos += 2;

	// N octets of cipher suites
	if (hello->cipher_suites_size > 0)
	{
		memcpy(hello->data + offset, in + pos, hello->cipher_suites_size);
		pos += hello->cipher_suites_size;
		offset += hello->cipher_suites_size;
	}

	// 1 octet compression method size
	LOAD_8(&hello->compression_methods_size, in + pos);
	pos += 1;

	if (hello->compression_methods_size > 0)
	{
		memcpy(hello->data + offset, in + pos, hello->compression_methods_size);
		pos += hello->compression_methods_size;
		offset += hello->compression_methods_size;
	}

	// 2 octet extensions size
	LOAD_16BE(&hello->extensions_size, in + pos);
	pos += 2;
}

void tls_handshake_read(void **handshake, void *data, uint32_t size)
{
	void *result = NULL;

	uint8_t *in = data;
	uint32_t pos = 0;

	tls_handshake_header header = {0};

	// 1 octet handshake type
	header.handshake_type = in[pos];
	pos += 1;

	// 3 octet handshake size
	header.handshake_size = (in[pos] << 16) + (in[pos + 1] << 8) + in[pos + 2];
	pos += 3;

	result = malloc(sizeof(tls_client_hello) + 2048);

	if (result == NULL)
	{
		return;
	}

	memset(result, 0, sizeof(tls_client_hello) + 2048);
	memcpy(result, &header, sizeof(tls_handshake_header));

	switch (header.handshake_type)
	{
	case TLS_HELLO_REQUEST:
		break;
	case TLS_CLIENT_HELLO:
		tls_client_hello_read(result, PTR_OFFSET(data, pos), size - pos);
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

	*handshake = result;
}

uint32_t tls_handshake_write(tls_handshake_header *handshake, void *buffer, uint32_t size)
{
	uint8_t *out = buffer;
	uint32_t pos = 0;

	if (size < (4 + handshake->handshake_size))
	{
		return 0;
	}

	// 1 octet handshake type
	out[pos++] = handshake->handshake_type;

	// 3 octet handshake size
	out[pos++] = (handshake->handshake_size >> 16) & 0xFF;
	out[pos++] = (handshake->handshake_size >> 8) & 0xFF;
	out[pos++] = (handshake->handshake_size >> 0) & 0xFF;

	switch (handshake->handshake_type)
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

static uint32_t print_bytes(void *buffer, uint32_t buffer_size, char *prefix, void *data, uint32_t data_size)
{
	uint32_t pos = 0;

	pos += snprintf(PTR_OFFSET(buffer, pos), buffer_size, "%s (%u bytes): ", prefix, data_size);
	pos += print_hex(PTR_OFFSET(buffer, pos), data, data_size);

	return pos;
}

static uint32_t print_compression_method(void *buffer, uint32_t size, uint8_t method)
{
	if (method == 0)
	{
		return snprintf(buffer, size, "    NULL (ID 0)\n");
	}
	else
	{
		return snprintf(buffer, size, "    Unknown (ID %hhu)\n", method);
	}
}

static uint32_t print_cipher_suite(void *buffer, uint32_t size, uint8_t o1, uint8_t o2)
{
	uint16_t id = TLS_MAKE_CIPHER_SUITE(o1, o2);

	switch (id)
	{
	case TLS_NULL_WITH_NULL_NULL:
		return snprintf(buffer, size, "    TLS_NULL_WITH_NULL_NULL (ID {0x00, 0x00})\n");

	case TLS_RSA_WITH_NULL_MD5:
		return snprintf(buffer, size, "    TLS_RSA_WITH_NULL_MD5 (ID {0x00, 0x01})\n");
	case TLS_RSA_WITH_NULL_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_NULL_SHA1 (ID {0x00, 0x02})\n");
	case TLS_RSA_WITH_NULL_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_NULL_SHA256 (ID {0x00, 0x3B})\n");
	case TLS_RSA_WITH_RC4_128_MD5:
		return snprintf(buffer, size, "    TLS_RSA_WITH_RC4_128_MD5 (ID {0x00, 0x04})\n");
	case TLS_RSA_WITH_RC4_128_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_RC4_128_SHA1 (ID {0x00, 0x05})\n");
	case TLS_RSA_WITH_IDEA_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_IDEA_CBC_SHA1 (ID {0x00, 0x07})\n");
	case TLS_RSA_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_DES_CBC_SHA1 (ID {0x00, 0x09})\n");
	case TLS_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x0A})\n");
	case TLS_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x2F})\n");
	case TLS_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x35})\n");
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x3C})\n");
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x3D})\n");

	case TLS_DH_DSS_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_DES_CBC_SHA1 (ID {0x00, 0x0C})\n");
	case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x0D})\n");
	case TLS_DH_RSA_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_DES_CBC_SHA1 (ID {0x00, 0x0F})\n");
	case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x10})\n");
	case TLS_DHE_DSS_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_DES_CBC_SHA1 (ID {0x00, 0x12})\n");
	case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x13})\n");
	case TLS_DHE_RSA_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_DES_CBC_SHA1 (ID {0x00, 0x15})\n");
	case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x16})\n");
	case TLS_DH_DSS_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x30})\n");
	case TLS_DH_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x31})\n");
	case TLS_DHE_DSS_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x32})\n");
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x33})\n");
	case TLS_DH_DSS_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x36})\n");
	case TLS_DH_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x37})\n");
	case TLS_DHE_DSS_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x38})\n");
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x39})\n");
	case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x3E})\n");
	case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x3F})\n");
	case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x40})\n");
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x67})\n");
	case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x68})\n");
	case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x69})\n");
	case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x6A})\n");
	case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x6B})\n");

	case TLS_DH_ANON_WITH_RC4_128_MD5:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_RC4_128_MD5 (ID {0x00, 0x18})\n");
	case TLS_DH_ANON_WITH_DES_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_DES_CBC_SHA1 (ID {0x00, 0x1A})\n");
	case TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA1 (ID {0x00, 0x1B})\n");
	case TLS_DH_ANON_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_AES_128_CBC_SHA1 (ID {0x00, 0x34})\n");
	case TLS_DH_ANON_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_AES_256_CBC_SHA1 (ID {0x00, 0x3A})\n");
	case TLS_DH_ANON_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_AES_128_CBC_SHA256 (ID {0x00, 0x6C})\n");
	case TLS_DH_ANON_WITH_AES_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_AES_256_CBC_SHA256 (ID {0x00, 0x6D})\n");

	// RFC 5487: Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xA8})\n");
	case TLS_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xA9})\n");
	case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xAA})\n");
	case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xAB})\n");
	case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (ID {0x00, 0xAC})\n");
	case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (ID {0x00, 0xAD})\n");

	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_128_CBC_SHA256 (ID {0x00, 0xAE})\n");
	case TLS_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_256_CBC_SHA384 (ID {0x00, 0xAF})\n");
	case TLS_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_NULL_SHA256 (ID {0x00, 0xB0})\n");
	case TLS_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_NULL_SHA384 (ID {0x00, 0xB1})\n");

	case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (ID {0x00, 0xB2})\n");
	case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (ID {0x00, 0xB3})\n");
	case TLS_DHE_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_NULL_SHA256 (ID {0x00, 0xB4})\n");
	case TLS_DHE_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_NULL_SHA384 (ID {0x00, 0xB5})\n");

	case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (ID {0x00, 0xB6})\n");
	case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (ID {0x00, 0xB7})\n");
	case TLS_RSA_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_NULL_SHA256 (ID {0x00, 0xB8})\n");
	case TLS_RSA_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_NULL_SHA384 (ID {0x00, 0xB9})\n");

	// RFC 5932:  Camellia Cipher Suites for TLS
	case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x41})\n");
	case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x42})\n");
	case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x43})\n");
	case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x44})\n");
	case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x45})\n");
	case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA1 (ID {0x00, 0x46})\n");

	case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x84})\n");
	case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x85})\n");
	case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x86})\n");
	case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x87})\n");
	case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x88})\n");
	case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA1 (ID {0x00, 0x89})\n");

	case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBA})\n");
	case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBB})\n");
	case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBC})\n");
	case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBD})\n");
	case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBE})\n");
	case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256 (ID {0x00, 0xBF})\n");

	case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC0})\n");
	case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC1})\n");
	case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC2})\n");
	case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC3})\n");
	case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC4})\n");
	case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256 (ID {0x00, 0xC5})\n");

	// RFC 8998: ShangMi (SM) Cipher Suites for TLS 1.3
	case TLS_SM4_GCM_SM3:
		return snprintf(buffer, size, "    TLS_SM4_GCM_SM3 (ID {0x00, 0xC6})\n");
	case TLS_SM4_CCM_SM3:
		return snprintf(buffer, size, "    TLS_SM4_CCM_SM3 (ID {0x00, 0xC7})\n");

	// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
	case TLS_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_AES_128_GCM_SHA256 (ID {0x13, 0x01})\n");
	case TLS_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_AES_256_GCM_SHA384 (ID {0x13, 0x02})\n");
	case TLS_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_CHACHA20_POLY1305_SHA256 (ID {0x13, 0x03})\n");
	case TLS_AES_128_CCM_SHA256:
		return snprintf(buffer, size, "    TLS_AES_128_CCM_SHA256 (ID {0x13, 0x04})\n");
	case TLS_AES_128_CCM_8_SHA256:
		return snprintf(buffer, size, "    TLS_AES_128_CCM_8_SHA256 (ID {0x13, 0x05})\n");

		// RFC 8422:  Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
	case TLS_ECDHE_ECDSA_WITH_NULL_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_NULL_SHA1 (ID {0xC0, 0x06})\n");
	case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x08})\n");
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x09})\n");
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x0A})\n");

	case TLS_ECDHE_RSA_WITH_NULL_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_NULL_SHA1 (ID {0xC0, 0x10})\n");
	case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x12})\n");
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x13})\n");
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x14})\n");

	case TLS_ECDH_ANON_WITH_NULL_SHA1:
		return snprintf(buffer, size, "    TLS_ECDH_ANON_WITH_NULL_SHA1 (ID {0xC0, 0x15})\n");
	case TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x17})\n");
	case TLS_ECDH_ANON_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDH_ANON_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x18})\n");
	case TLS_ECDH_ANON_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDH_ANON_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x19})\n");

	// RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x23})\n");
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x24})\n");
	case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x25})\n");
	case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x26})\n");
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x27})\n");
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x28})\n");
	case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x29})\n");
	case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x2A})\n");

	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x2B})\n");
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x2C})\n");
	case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x2D})\n");
	case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x2E})\n");
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x2F})\n");
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x30})\n");
	case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (ID {0xC0, 0x31})\n");
	case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (ID {0xC0, 0x32})\n");

	// RFC 5489: ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)
	case TLS_ECDHE_PSK_WITH_RC4_128_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_RC4_128_SHA1 (ID {0xC0, 0x33})\n");
	case TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA1 (ID {0xC0, 0x34})\n");
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA1 (ID {0xC0, 0x35})\n");
	case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA1 (ID {0xC0, 0x36})\n");
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (ID {0xC0, 0x37})\n");
	case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (ID {0xC0, 0x38})\n");
	case TLS_ECDHE_PSK_WITH_NULL_SHA1:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_NULL_SHA1 (ID {0xC0, 0x39})\n");
	case TLS_ECDHE_PSK_WITH_NULL_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_NULL_SHA256 (ID {0xC0, 0x3A})\n");
	case TLS_ECDHE_PSK_WITH_NULL_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_NULL_SHA384 (ID {0xC0, 0x3B})\n");

	// RFC 6209: Addition of the ARIA Cipher Suites to Transport Layer Security (TLS)
	case TLS_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x3C})\n");
	case TLS_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x3D})\n");
	case TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x3E})\n");
	case TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x3F})\n");
	case TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x40})\n");
	case TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x41})\n");
	case TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x42})\n");
	case TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x43})\n");
	case TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x44})\n");
	case TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x45})\n");
	case TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x46})\n");
	case TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x47})\n");

	case TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x48})\n");
	case TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x49})\n");
	case TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x4A})\n");
	case TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x4B})\n");
	case TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x4C})\n");
	case TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x4D})\n");
	case TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x4E})\n");
	case TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x4F})\n");

	case TLS_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x50})\n");
	case TLS_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x51})\n");
	case TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x52})\n");
	case TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x53})\n");
	case TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x54})\n");
	case TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x55})\n");
	case TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x56})\n");
	case TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x57})\n");
	case TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x58})\n");
	case TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x59})\n");
	case TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x5A})\n");
	case TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x5B})\n");

	case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x5C})\n");
	case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x5D})\n");
	case TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x5E})\n");
	case TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x5F})\n");
	case TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x60})\n");
	case TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x61})\n");
	case TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x62})\n");
	case TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x63})\n");

	case TLS_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x64})\n");
	case TLS_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x65})\n");
	case TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x66})\n");
	case TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x67})\n");
	case TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x68})\n");
	case TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x69})\n");
	case TLS_PSK_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x6A})\n");
	case TLS_PSK_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x6B})\n");
	case TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x6C})\n");
	case TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x6D})\n");
	case TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 (ID {0xC0, 0x6E})\n");
	case TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 (ID {0xC0, 0x6F})\n");
	case TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 (ID {0xC0, 0x70})\n");
	case TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 (ID {0xC0, 0x71})\n");

	// RFC 6367: Addition of the Camellia Cipher Suites to Transport Layer Security (TLS)
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x72})\n");
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x73})\n");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x74})\n");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x75})\n");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x76})\n");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x77})\n");
	case TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x78})\n");
	case TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x79})\n");

	case TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x7A})\n");
	case TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x7B})\n");
	case TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x7C})\n");
	case TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x7D})\n");
	case TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x7E})\n");
	case TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x7F})\n");
	case TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x80})\n");
	case TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x81})\n");
	case TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x82})\n");
	case TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x83})\n");
	case TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x84})\n");
	case TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x85})\n");
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x86})\n");
	case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x87})\n");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x88})\n");
	case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x89})\n");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x8A})\n");
	case TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x8B})\n");
	case TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x8C})\n");
	case TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x8D})\n");

	case TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x8D})\n");
	case TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x8F})\n");
	case TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x90})\n");
	case TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x91})\n");
	case TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 (ID {0xC0, 0x92})\n");
	case TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 (ID {0xC0, 0x93})\n");
	case TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x94})\n");
	case TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x95})\n");
	case TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x96})\n");
	case TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x97})\n");
	case TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x98})\n");
	case TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x99})\n");
	case TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (ID {0xC0, 0x9A})\n");
	case TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (ID {0xC0, 0x9B})\n");

	// RFC 6655: AES-CCM Cipher Suites for Transport Layer Security (TLS)
	case TLS_RSA_WITH_AES_128_CCM:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_128_CCM (ID {0xC0, 0x9C})\n");
	case TLS_RSA_WITH_AES_256_CCM:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_256_CCM (ID {0xC0, 0x9D})\n");
	case TLS_DHE_RSA_WITH_AES_128_CCM:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_128_CCM (ID {0xC0, 0x9E})\n");
	case TLS_DHE_RSA_WITH_AES_256_CCM:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_256_CCM (ID {0xC0, 0x9F})\n");
	case TLS_RSA_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_128_CCM_8 (ID {0xC0, 0xA0})\n");
	case TLS_RSA_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "    TLS_RSA_WITH_AES_256_CCM_8 (ID {0xC0, 0xA1})\n");
	case TLS_DHE_RSA_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_128_CCM_8 (ID {0xC0, 0xA2})\n");
	case TLS_DHE_RSA_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_AES_256_CCM_8 (ID {0xC0, 0xA3})\n");

	case TLS_PSK_WITH_AES_128_CCM:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_128_CCM (ID {0xC0, 0xA4})\n");
	case TLS_PSK_WITH_AES_256_CCM:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_256_CCM (ID {0xC0, 0xA5})\n");
	case TLS_DHE_PSK_WITH_AES_128_CCM:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_AES_128_CCM (ID {0xC0, 0xA6})\n");
	case TLS_DHE_PSK_WITH_AES_256_CCM:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_AES_256_CCM (ID {0xC0, 0xA7})\n");
	case TLS_PSK_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_128_CCM_8 (ID {0xC0, 0xA8})\n");
	case TLS_PSK_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "    TLS_PSK_WITH_AES_256_CCM_8 (ID {0xC0, 0xA9})\n");
	case TLS_PSK_DHE_WITH_AES_128_CCM_8:
		return snprintf(buffer, size, "    TLS_PSK_DHE_WITH_AES_128_CCM_8 (ID {0xC0, 0xAA})\n");
	case TLS_PSK_DHE_WITH_AES_256_CCM_8:
		return snprintf(buffer, size, "    TLS_PSK_DHE_WITH_AES_256_CCM_8 (ID {0xC0, 0xAB})\n");

	// RFC 9150: TLS 1.3 Authentication and Integrity-Only Cipher Suites
	case TLS_SHA256_SHA256:
		return snprintf(buffer, size, "    TLS_SHA256_SHA256 (ID {0xC0, 0xB4})\n");
	case TLS_SHA384_SHA384:
		return snprintf(buffer, size, "    TLS_SHA384_SHA384 (ID {0xC0, 0xB5})\n");

	// RFC 9189: GOST Cipher Suites for Transport Layer Security (TLS) Protocol Version 1.2
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_CTR_OMAC:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_KUZNYECHIK_CTR_OMAC (ID {0xC1, 0x00})\n");
	case TLS_GOST_R341112_256_WITH_MAGMA_CTR_OMAC:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_MAGMA_CTR_OMAC (ID {0xC1, 0x01})\n");
	case TLS_GOST_R341112_256_WITH_28147_CNT_IMIT:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_28147_CNT_IMIT (ID {0xC1, 0x02})\n");
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_LIGHT:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_LIGHT (ID {0xC1, 0x03})\n");
	case TLS_GOST_R341112_256_WITH_MAGMA_MGM_LIGHT:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_MAGMA_MGM_LIGHT (ID {0xC1, 0x04})\n");
	case TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_STRONG:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_KUZNYECHIK_MGM_STRONG (ID {0xC1, 0x05})\n");
	case TLS_GOST_R341112_256_WITH_MAGMA_MGM_STRONG:
		return snprintf(buffer, size, "    TLS_GOST_R341112_256_WITH_MAGMA_MGM_STRONG (ID {0xC1, 0x06})\n");

	// RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xA8})\n");
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xA9})\n");
	case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAA})\n");

	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAB})\n");
	case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAC})\n");
	case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAD})\n");
	case TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return snprintf(buffer, size, "    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 (ID {0xCC, 0xAE})\n");

	// RFC 8442: ECDHE_PSK with AES-GCM and AES-CCM Cipher Suites for TLS 1.2 and DTLS 1.2
	case TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 (ID {0xD0, 0x01})\n");
	case TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 (ID {0xD0, 0x02})\n");
	case TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 (ID {0xD0, 0x03})\n");
	case TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:
		return snprintf(buffer, size, "    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 (ID {0xD0, 0x05})\n");

	default:
		// Check GREASE values
		if (o1 == o2)
		{
			if ((o1 & 0x0F) == 0x0A)
			{
				return snprintf(buffer, size, "    GREASE (ID {%02hhx, %02hhx})\n", o1, o2);
			}
		}

		return snprintf(buffer, size, "    Unknown (ID {%02hhx, %02hhx})\n", o1, o2);
	}
}

static uint32_t tls_client_hello_print(tls_client_hello *hello, void *buffer, uint32_t size)
{
	uint32_t pos = 0;

	// Protocol Version
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Protocol Version: ");

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
	pos += print_bytes(PTR_OFFSET(buffer, pos), size - pos, "Random", hello->random, 32);

	// Session ID
	pos += print_bytes(PTR_OFFSET(buffer, pos), size - pos, "Session ID", hello->session.id, hello->session.size);

	// Compression Methods
	if (hello->compression_methods_size > 0)
	{
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Compression Methods:\n");

		for (uint32_t i = 0; i < hello->compression_methods_size; ++i)
		{
			pos += print_compression_method(PTR_OFFSET(buffer, pos), size - pos, hello->data[hello->cipher_suites_size + i]);
		}
	}

	// Cipher Suites
	if (hello->cipher_suites_size > 0)
	{
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Preferred Cipher Suites:\n");

		for (uint32_t i = 0; i < hello->cipher_suites_size; i += 2)
		{
			pos += print_cipher_suite(PTR_OFFSET(buffer, pos), size - pos, hello->data[i], hello->data[i + 1]);
		}
	}

	return pos;
}

uint32_t tls_handshake_print(tls_handshake_header *handshake, void *buffer, uint32_t size)
{
	uint32_t pos = 0;

	// Handshake Type
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Handshake Type: ");

	switch (handshake->handshake_type)
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
		pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Unknown (ID %hhu)\n", handshake->handshake_type);
		break;
	}

	// Handshake Size
	pos += snprintf(PTR_OFFSET(buffer, pos), size - pos, "Handshake Size: %u\n", handshake->handshake_size);

	switch (handshake->handshake_type)
	{
	case TLS_HELLO_REQUEST:
		break;
	case TLS_CLIENT_HELLO:
		pos += tls_client_hello_print(handshake, PTR_OFFSET(buffer, pos), size - pos);
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
