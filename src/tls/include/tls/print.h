/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_PRINT_H
#define TLS_PRINT_H

#include <stdarg.h>
#include <stdint.h>

#include <print.h>
#include <ptr.h>

#include <tls/algorithms.h>
#include <tls/grease.h>

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static size_t print_indent(buffer_t *buffer, uint32_t indent)
{
	return xprint(buffer, "%*s", indent * 4, "");
}

static size_t print_format(buffer_t *buffer, uint32_t indent, const char *format, ...)
{
	size_t pos = 0;

	va_list args;
	va_start(args, format);

	pos += print_indent(buffer, indent);
	pos += vxprint(buffer, format, args);

	va_end(args);

	return pos;
}
static inline uint32_t print_hex(void *buffer, void *data, uint32_t size)
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

static inline uint32_t print_bytes(void *buffer, uint32_t indent, char *prefix, void *data, uint32_t size)
{
	return print_format(buffer, indent, "%1$s (%3$u bytes): %2$.*3$R\n", prefix, data, size);
}

static inline uint32_t print_signature_algorithm(uint32_t indent, void *buffer, uint32_t size, uint16_t algorithm)
{
	switch (algorithm)
	{
	case TLS_RSA_PKCS_MD5:
		return print_format(indent, buffer, size, "rsa_pkcs1_md5 (ID 0101)\n");
	case TLS_DSA_MD5:
		return print_format(indent, buffer, size, "dsa_md5 (ID 0102)\n");
	case TLS_ECDSA_MD5:
		return print_format(indent, buffer, size, "ecdsa_md5 (ID 0103)\n");
	case TLS_RSA_PKCS_SHA1:
		return print_format(indent, buffer, size, "rsa_pkcs1_sha1 (ID 0201)\n");
	case TLS_DSA_SHA1:
		return print_format(indent, buffer, size, "dsa_sha1 (ID 0202)\n");
	case TLS_ECDSA_SHA1:
		return print_format(indent, buffer, size, "ecdsa_sha1 (ID 0203)\n");
	case TLS_RSA_PKCS_SHA224:
		return print_format(indent, buffer, size, "rsa_pkcs1_sha224 (ID 0301)\n");
	case TLS_DSA_SHA224:
		return print_format(indent, buffer, size, "dsa_sha224 (ID 0302)\n");
	case TLS_ECDSA_SHA224:
		return print_format(indent, buffer, size, "ecdsa_sha224 (ID 0303)\n");
	case TLS_RSA_PKCS_SHA256:
		return print_format(indent, buffer, size, "rsa_pkcs1_sha256 (ID 0401)\n");
	case TLS_DSA_SHA256:
		return print_format(indent, buffer, size, "dsa_sha256 (ID 0402)\n");
	case TLS_ECDSA_SECP256R1_SHA256:
		return print_format(indent, buffer, size, "ecdsa_secp256r1_sha1 (ID 0403)\n");
	case TLS_RSA_PKCS_SHA384:
		return print_format(indent, buffer, size, "rsa_pkcs1_sha384 (ID 0501)\n");
	case TLS_DSA_SHA384:
		return print_format(indent, buffer, size, "dsa_sha384 (ID 0502)\n");
	case TLS_ECDSA_SECP384R1_SHA384:
		return print_format(indent, buffer, size, "ecdsa_secp384r1_sha384 (ID 0503)\n");
	case TLS_RSA_PKCS_SHA512:
		return print_format(indent, buffer, size, "rsa_pkcs1_sha512 (ID 0601)\n");
	case TLS_DSA_SHA512:
		return print_format(indent, buffer, size, "dsa_sha512 (ID 0602)\n");
	case TLS_ECDSA_SECP521R1_SHA512:
		return print_format(indent, buffer, size, "ecdsa_secp521r1_sha512 (ID 0603)\n");
	case TLS_SM2_SM3:
		return print_format(indent, buffer, size, "sm2sig_sm3 (ID 0708)\n");
	case TLS_GOST_R34102012_256A:
		return print_format(indent, buffer, size, "gostr34102012_256a (ID 0709)\n");
	case TLS_GOST_R34102012_256B:
		return print_format(indent, buffer, size, "gostr34102012_256b (ID 070A)\n");
	case TLS_GOST_R34102012_256C:
		return print_format(indent, buffer, size, "gostr34102012_256c (ID 070B)\n");
	case TLS_GOST_R34102012_256D:
		return print_format(indent, buffer, size, "gostr34102012_256d (ID 070C)\n");
	case TLS_GOST_R34102012_512A:
		return print_format(indent, buffer, size, "gostr34102012_512a (ID 070D)\n");
	case TLS_GOST_R34102012_512B:
		return print_format(indent, buffer, size, "gostr34102012_512b (ID 070E)\n");
	case TLS_GOST_R34102012_512C:
		return print_format(indent, buffer, size, "gostr34102012_512c (ID 070F)\n");
	case TLS_RSA_PSS_RSAE_SHA256:
		return print_format(indent, buffer, size, "rsa_pss_rsae_sha256 (ID 0804)\n");
	case TLS_RSA_PSS_RSAE_SHA384:
		return print_format(indent, buffer, size, "rsa_pss_rsae_sha384 (ID 0805)\n");
	case TLS_RSA_PSS_RSAE_SHA512:
		return print_format(indent, buffer, size, "rsa_pss_rsae_sha512 (ID 0806)\n");
	case TLS_ED25519:
		return print_format(indent, buffer, size, "ed25519 (ID 0807)\n");
	case TLS_ED448:
		return print_format(indent, buffer, size, "ed448 (ID 0808)\n");
	case TLS_RSA_PSS_PSS_SHA256:
		return print_format(indent, buffer, size, "rsa_pss_pss_sha256 (ID 0809)\n");
	case TLS_RSA_PSS_PSS_SHA384:
		return print_format(indent, buffer, size, "rsa_pss_pss_sha384 (ID 080A)\n");
	case TLS_RSA_PSS_PSS_SHA512:
		return print_format(indent, buffer, size, "rsa_pss_pss_sha512 (ID 080B)\n");
	case TLS_ECDSA_BRAINPOOL_P256R1_TLS13_SHA256:
		return print_format(indent, buffer, size, "ecdsa_brainpoolP256r1tls13_sha256 (ID 081A)\n");
	case TLS_ECDSA_BRAINPOOL_P384R1_TLS13_SHA384:
		return print_format(indent, buffer, size, "ecdsa_brainpoolP384r1tls13_sha384 (ID 081B)\n");
	case TLS_ECDSA_BRAINPOOL_P512R1_TLS13_SHA512:
		return print_format(indent, buffer, size, "ecdsa_brainpoolP512r1tls13_sha512 (ID 081C)\n");
	case TLS_MLDSA44:
		return print_format(indent, buffer, size, "mldsa44 (ID 0904)\n");
	case TLS_MLDSA65:
		return print_format(indent, buffer, size, "mldsa65 (ID 0905)\n");
	case TLS_MLDSA87:
		return print_format(indent, buffer, size, "mldsa87 (ID 0906)\n");
	default:
	{
		if (tls_check_grease_value(algorithm))
		{
			return print_format(indent, buffer, size, "GREASE Signature (ID %04hX)\n", algorithm);
		}
		else
		{
			return print_format(indent, buffer, size, "Unknown (ID %04hX)\n", algorithm);
		}
	}
	break;
	}

	return 0;
}

#endif
