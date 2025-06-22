/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <pgp.h>
#include <algorithms.h>
#include <packet.h>
#include <seipd.h>
#include <session.h>
#include <signature.h>
#include <crypto.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char hex_lower_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static const char hex_upper_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static size_t pgp_signature_packet_body_print(uint32_t indent, pgp_signature_packet *packet, void *ptr, size_t size, uint32_t options);

static size_t print_indent(uint32_t indent, void *str, size_t size)
{
	size_t pos = 0;

	for (uint32_t i = 0; i < indent; ++i)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "    "); // 4 spaces
	}

	return pos;
}

static size_t print_format(uint32_t indent, void *str, size_t size, const char *format, ...)
{
	size_t pos = 0;

	va_list args;
	va_start(args, format);

	pos += print_indent(indent, PTR_OFFSET(str, pos), size - pos);
	pos += vsnprintf(PTR_OFFSET(str, pos), size - pos, format, args);

	va_end(args);

	return pos;
}

static size_t print_hex(const char *table, void *str, void *data, size_t data_size)
{
	byte_t *out = str;
	size_t pos = 0;

	for (uint32_t i = 0; i < data_size; ++i)
	{
		byte_t a, b;

		a = ((byte_t *)data)[i] / 16;
		b = ((byte_t *)data)[i] % 16;

		out[pos++] = table[a];
		out[pos++] = table[b];
	}

	out[pos++] = '\n';

	return pos;
}

static size_t print_bytes(uint32_t indent, char *prefix, void *str, size_t str_size, void *data, size_t data_size)
{
	size_t pos = 0;

	// Print prefix
	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "%s", prefix);
	pos += print_hex(hex_lower_table, PTR_OFFSET(str, pos), data, data_size);

	return pos;
}

static size_t print_key(uint32_t indent, void *str, size_t str_size, void *data, size_t data_size)
{
	size_t pos = 0;

	switch (data_size)
	{
	case PGP_KEY_ID_SIZE:
		pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Key ID: ");
		break;
	case PGP_KEY_V3_FINGERPRINT_SIZE:
		pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Key Fingerprint: ");
		break;
	case PGP_KEY_V4_FINGERPRINT_SIZE:
		pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Key Fingerprint: ");
		break;
	case PGP_KEY_V6_FINGERPRINT_SIZE:
		pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Key Fingerprint: ");
		break;
	default:
		pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Key Fingerprint: ");
		break;
	}

	pos += print_hex(hex_upper_table, PTR_OFFSET(str, pos), data, data_size);

	return pos;
}

static size_t print_mpi(uint32_t indent, char *prefix, mpi_t *mpi, void *str, size_t str_size, uint32_t options)
{
	size_t pos = 0;

	if (options & PGP_PRINT_MPI_MINIMAL)
	{
		return print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "%s (%hu bits): ...\n", prefix, mpi->bits);
	}

	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "%s (%hu bits): ", prefix, mpi->bits);
	pos += print_hex(hex_lower_table, PTR_OFFSET(str, pos), mpi->bytes, CEIL_DIV(mpi->bits, 8));

	return pos;
}

static size_t print_timestamp(uint32_t indent, char *prefix, time_t timestamp, void *str, size_t str_size)
{
	size_t pos = 0;
	char date_buffer[64] = {0};

	strftime(date_buffer, 64, "%B %d, %Y, %I:%M:%S %p (%z)", localtime(&timestamp));
	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "%s: %s\n", prefix, date_buffer);

	return pos;
}

size_t pgp_packet_header_print(pgp_packet_header *header, void *str, size_t size)
{
	pgp_packet_header_format format = PGP_PACKET_HEADER_FORMAT(header->tag);
	pgp_packet_type type = pgp_packet_type_from_tag(header->tag);

	size_t pos = 0;

	if (header->partial_continue || header->partial_end)
	{
		return pgp_partial_packet_print((pgp_partial_packet *)header, str, size);
	}

	switch (type)
	{
	case PGP_PKESK:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Public Key Encrypted Session Key Packet (Tag 1)");
		break;
	case PGP_SIG:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Signature Packet (Tag 2)");
		break;
	case PGP_SKESK:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Symmetric Key Encrypted Session Key Packet (Tag 3)");
		break;
	case PGP_OPS:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "One-Pass Signature Packet (Tag 4)");
		break;
	case PGP_SECKEY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Secret Key Packet (Tag 5)");
		break;
	case PGP_PUBKEY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Public Key Packet (Tag 6)");
		break;
	case PGP_SECSUBKEY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Secret Subkey Packet (Tag 7)");
		break;
	case PGP_COMP:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Compressed Data Packet (Tag 8)");
		break;
	case PGP_SED:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Symmetrically Encrypted Data Packet (Obsolete) (Tag 9)");
		break;
	case PGP_MARKER:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Marker Packet (Tag 10)");
		break;
	case PGP_LIT:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Literal Data Packet (Tag 11)");
		break;
	case PGP_TRUST:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Trust Packet (Tag 12)");
		break;
	case PGP_UID:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "User ID Packet (Tag 13)");
		break;
	case PGP_PUBSUBKEY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Public Subkey Packet (Tag 14)");
		break;
	case PGP_UAT:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "User Attribute Packet (Tag 17)");
		break;
	case PGP_SEIPD:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Symmetrically Encrypted and Integrity Protected Data Packet (Tag 18)");
		break;
	case PGP_MDC:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Modification Detection Code Packet (Deprecated) (Tag 19)");
		break;
	case PGP_AEAD:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Authenticated Encryption Data Packet Packet (Tag 20)");
		break;
	case PGP_PADDING:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Padding Packet (Tag 21)");
		break;
	case PGP_KEYDEF:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key definition Packet (Private)");
		break;
	case PGP_KEYRING:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Keyring Packet (Private)");
		break;
	case PGP_ARMOR:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Armor Packet (Private)");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Packet (Tag %hhu)", header->tag);
	}

	// Add packet size
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, " (%zu bytes)", header->body_size);

	// Mention if packet is having legacy header format
	if (format == PGP_LEGACY_HEADER)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "%s", " (Old)");
	}

	// Mention if packet is having partial data
	if (header->partial)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "%s", " (Partial)");
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "\n");

	return pos;
}

static size_t pgp_public_key_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Public-Key Algorithm: ");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA Encrypt or Sign (Tag 1)\n");
		break;
	case PGP_RSA_ENCRYPT_ONLY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA (Encrypt Only) (Tag 2)\n");
		break;
	case PGP_RSA_SIGN_ONLY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA (Sign Only) (Tag 2)\n");
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Elgamal (Encrypt Only) (Tag 16)\n");
		break;
	case PGP_DSA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "DSA (Tag 17)\n");
		break;
	case PGP_ECDH:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "ECDH (Tag 18)\n");
		break;
	case PGP_ECDSA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "ECDSA (Tag 19)\n");
		break;
	case PGP_EDDSA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "EdDSA (Tag 22)\n");
		break;
	case PGP_X25519:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "X25519 (Tag 22)\n");
		break;
	case PGP_X448:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "X448 (Tag 23)\n");
		break;
	case PGP_ED25519:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Ed25519 (Tag 27)\n");
		break;
	case PGP_ED448:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Ed448 (Tag 28)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Public Key Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_kex_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Key Exchange Algorithm: ");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA Encrypt or Sign (Tag 1)\n");
		break;
	case PGP_RSA_ENCRYPT_ONLY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA (Encrypt Only) (Tag 2)\n");
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Elgamal (Encrypt Only) (Tag 16)\n");
		break;
	case PGP_ECDH:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "ECDH (Tag 18)\n");
		break;
	case PGP_X25519:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "X25519 (Tag 22)\n");
		break;
	case PGP_X448:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "X448 (Tag 23)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Key Exchange Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_signature_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Signature Algorithm: ");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA Encrypt or Sign (Tag 1)\n");
		break;
	case PGP_RSA_SIGN_ONLY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA (Sign Only) (Tag 2)\n");
		break;
	case PGP_DSA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "DSA (Tag 17)\n");
		break;
	case PGP_ECDSA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "ECDSA (Tag 19)\n");
		break;
	case PGP_EDDSA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "EdDSA (Tag 22)\n");
		break;
	case PGP_ED25519:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Ed25519 (Tag 27)\n");
		break;
	case PGP_ED448:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Ed448 (Tag 28)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Signature algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_symmetric_key_algorithm_print(pgp_symmetric_key_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Cipher Algorithm: ");

	switch (algorithm)
	{
	case PGP_PLAINTEXT:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Plaintext (Tag 0)\n");
		break;
	case PGP_IDEA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "IDEA (Tag 1)\n");
		break;
	case PGP_TDES:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "TDES (Tag 2)\n");
		break;
	case PGP_CAST5_128:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "CAST5 (Tag 3)\n");
		break;
	case PGP_BLOWFISH:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Blowfish (Tag 4)\n");
		break;
	case PGP_AES_128:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AES-128 (Tag 7)\n");
		break;
	case PGP_AES_192:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AES-192 (Tag 8)\n");
		break;
	case PGP_AES_256:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AES-256 (Tag 9)\n");
		break;
	case PGP_TWOFISH:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Twofish-256 (Tag 10)\n");
		break;
	case PGP_CAMELLIA_128:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Camellia-128 (Tag 11)\n");
		break;
	case PGP_CAMELLIA_192:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Camellia-192 (Tag 12)\n");
		break;
	case PGP_CAMELLIA_256:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Camellia-256 (Tag 13)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Symmetric Key Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_aead_algorithm_print(pgp_aead_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "AEAD Algorithm: ");

	switch (algorithm)
	{
	case PGP_AEAD_EAX:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "EAX (Tag 1)\n");
		break;
	case PGP_AEAD_OCB:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "OCB (Tag 2)\n");
		break;
	case PGP_AEAD_GCM:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "GCM (Tag 3)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown AEAD Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_cipher_aead_algorithm_pair_print(pgp_symmetric_key_algorithms symmetric_algorithm, pgp_aead_algorithms aead_algorithm,
												   void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "AEAD Ciphersuite: ");

	switch (symmetric_algorithm)
	{
	case PGP_PLAINTEXT:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Plaintext ");
		break;
	case PGP_IDEA:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "IDEA ");
		break;
	case PGP_TDES:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "TDES ");
		break;
	case PGP_CAST5_128:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "CAST5 ");
		break;
	case PGP_BLOWFISH:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Blowfish ");
		break;
	case PGP_AES_128:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AES-128 ");
		break;
	case PGP_AES_192:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AES-192 ");
		break;
	case PGP_AES_256:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AES-256 ");
		break;
	case PGP_TWOFISH:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Twofish-256 ");
		break;
	case PGP_CAMELLIA_128:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Camellia-128 ");
		break;
	case PGP_CAMELLIA_192:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Camellia-192 ");
		break;
	case PGP_CAMELLIA_256:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Camellia-256 ");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown ");
		break;
	}

	switch (aead_algorithm)
	{
	case PGP_AEAD_EAX:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "EAX ");
		break;
	case PGP_AEAD_OCB:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "OCB ");
		break;
	case PGP_AEAD_GCM:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "GCM ");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown ");
		break;
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "(%02hhx %02hhx)\n", symmetric_algorithm, aead_algorithm);

	return pos;
}

static size_t pgp_hash_algorithm_print(pgp_hash_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Hash Algorithm: ");

	switch (algorithm)
	{
	case PGP_MD5:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "MD5 (Tag 1)\n");
		break;
	case PGP_SHA1:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA-1 (Tag 2)\n");
		break;
	case PGP_RIPEMD_160:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RIPEMD-160 (Tag 3)\n");
		break;
	case PGP_SHA2_256:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA-256 (Tag 8)\n");
		break;
	case PGP_SHA2_384:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA-384 (Tag 9)\n");
		break;
	case PGP_SHA2_512:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA-512 (Tag 10)\n");
		break;
	case PGP_SHA2_224:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA-224 (Tag 11)\n");
		break;
	case PGP_SHA3_256:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA3-256 (Tag 12)\n");
		break;
	case PGP_SHA3_512:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA3-512 (Tag 14)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Hash Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_compression_algorithm_print(pgp_compression_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Compression Algorithm: ");

	switch (algorithm)
	{
	case PGP_UNCOMPRESSED:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Uncompressed (Tag 0)\n");
		break;
	case PGP_DEFALTE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Deflate (Tag 1)\n");
		break;
	case PGP_ZLIB:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "ZLIB (Tag 2)\n");
		break;
	case PGP_BZIP2:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "BZIP2 (Tag 3)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", algorithm);
	}

	return pos;
}

static size_t pgp_curve_print(pgp_elliptic_curve_id curve, byte_t *oid, byte_t oid_size, void *str, size_t str_size, uint32_t indent)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Elliptic Curve: ");

	switch (curve)
	{
	case PGP_EC_NIST_P256:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "NIST-P256 (2A 86 48 CE 3D 03 01 07)\n");
		break;
	case PGP_EC_NIST_P384:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "NIST-P384 (2B 81 04 00 22)\n");
		break;
	case PGP_EC_NIST_P521:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "NIST-P521 (2B 81 04 00 23)\n");
		break;
	case PGP_EC_BRAINPOOL_256R1:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "BRAINPOOL-P256R1 (2B 24 03 03 02 08 01 01 07)\n");
		break;
	case PGP_EC_BRAINPOOL_384R1:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "BRAINPOOL-P384R1 (2B 24 03 03 02 08 01 01 0B)\n");
		break;
	case PGP_EC_BRAINPOOL_512R1:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "BRAINPOOL-P512R1 (2B 24 03 03 02 08 01 01 0D)\n");
		break;
	case PGP_EC_CURVE25519:
	{
		if (oid_size == 10)
		{
			pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Curve25519 (2B 06 01 04 01 97 55 01 05 01) (Legacy OID)\n");
		}
		else
		{
			pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Curve25519 (2B 65 6E)\n");
		}
	}
	break;
	case PGP_EC_CURVE448:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Curve448 (2B 65 6F)\n");
		break;
	case PGP_EC_ED25519:
	{
		if (oid_size == 9)
		{
			pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Ed25519 (2B 06 01 04 01 DA 47 0F 01) (Legacy OID)\n");
		}
		else
		{
			pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Ed25519 (2B 65 70)\n");
		}
	}
	break;
	case PGP_EC_ED448:
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Ed448 (2B 65 71)\n");
		break;
	default:
	{
		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, "Unknown (");

		for (byte_t i = 0; i < oid_size; ++i)
		{
			byte_t a, b;

			a = oid[i] / 16;
			b = oid[i] % 16;

			out[pos++] = hex_upper_table[a];
			out[pos++] = hex_upper_table[b];

			if (i != oid_size - 1)
			{
				out[pos++] = ' ';
			}
		}

		pos += snprintf(PTR_OFFSET(str, pos), str_size - pos, ")\n");
	}
	break;
	}

	return pos;
}

static size_t pgp_s2k_print(pgp_s2k *s2k, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "S2K Specifier: ");

	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Simple S2K (Tag 0)\n");
		pos += pgp_hash_algorithm_print(s2k->simple.hash_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		break;
	case PGP_S2K_SALTED:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Salted S2K (Tag 1)\n");
		pos += pgp_hash_algorithm_print(s2k->simple.hash_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += print_bytes(indent + 1, "Salt: ", PTR_OFFSET(str, pos), size - pos, s2k->salted.salt, 8);
		break;
	case PGP_S2K_ITERATED:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Iterated and Salted S2K (Tag 3)\n");
		pos += pgp_hash_algorithm_print(s2k->simple.hash_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += print_bytes(indent + 1, "Salt: ", PTR_OFFSET(str, pos), size - pos, s2k->iterated.salt, 8);
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Count: %u (Code %hhu)\n", IT_COUNT(s2k->iterated.count),
							s2k->iterated.count);
		break;
	case PGP_S2K_ARGON2:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Argon2 S2K (Tag 4)\n");
		pos += print_bytes(indent + 1, "Salt: ", PTR_OFFSET(str, pos), size - pos, s2k->argon2.salt, 16);
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Iterations: %hhu\n", s2k->argon2.t);
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Parallelism: %hhu\n", s2k->argon2.p);
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Memory: %hhu\n", s2k->argon2.m);
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown S2K Specifier (Tag %hhu)\n", s2k->id);
		break;
	}

	return pos;
}

static size_t pgp_trust_print(pgp_trust_level trust, void *str, size_t size, uint32_t indent)
{
	switch (trust)
	{
	case PGP_TRUST_NEVER:
		return print_format(indent, str, size, "Trust Level: Never\n");
	case PGP_TRUST_REVOKED:
		return print_format(indent, str, size, "Trust Level: Revoked\n");
	case PGP_TRUST_MARGINAL:
		return print_format(indent, str, size, "Trust Level: Marginal\n");
	case PGP_TRUST_FULL:
		return print_format(indent, str, size, "Trust Level: Full\n");
	case PGP_TRUST_ULTIMATE:
		return print_format(indent, str, size, "Trust Level: Ultimate\n");
	default:
		return print_format(indent, str, size, "Trust Level: Unknown\n");
	}
}

static size_t pgp_kdf_print(void *kdf, void *str, size_t size, uint32_t indent)
{
	byte_t *in = kdf;
	size_t pos = 0;

	byte_t hash_algorithm_id = in[2];
	byte_t symmetric_key_algorithm_id = in[3];

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "ECDH KDF Parameters\n");
	pos += pgp_hash_algorithm_print(hash_algorithm_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
	pos += pgp_symmetric_key_algorithm_print(symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, indent + 1);

	return pos;
}

static size_t pgp_kex_print(pgp_public_key_algorithms algorithm, void *kex, uint16_t kex_size, void *str, size_t str_size, uint32_t indent,
							uint32_t options)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Exchange Material\n");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	{
		pgp_rsa_kex *sk = kex;
		pos += print_mpi(indent + 1, "RSA m^e mod n", sk->c, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_kex *sk = kex;
		pos += print_mpi(indent + 1, "Elgamal g^k mod p", sk->r, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "Elgamal m*(y^k) mod p", sk->r, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_kex *sk = kex;
		pos += print_mpi(indent + 1, "ECDH Ephemeral Point", sk->ephemeral_point, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_bytes(indent + 1, "ECDH Encrypted Session Key: ", PTR_OFFSET(str, pos), str_size - pos, sk->encoded_session_key,
						   sk->encoded_session_key_size);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_kex *sk = kex;
		byte_t octet_count = sk->octet_count;

		if (sk->symmetric_key_algorithm_id != 0)
		{
			pos += pgp_symmetric_key_algorithm_print(sk->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), str_size - pos, indent);
			octet_count -= 1;
		}

		pos += print_bytes(indent + 1, "X25519 Ephemeral Key: ", PTR_OFFSET(str, pos), str_size - pos, sk->ephemeral_key, 32);
		pos += print_bytes(indent + 1, "X25519 Encrypted Session Key: ", PTR_OFFSET(str, pos), str_size - pos, sk->encrypted_session_key,
						   octet_count);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_kex *sk = kex;
		byte_t octet_count = sk->octet_count;

		if (sk->symmetric_key_algorithm_id != 0)
		{
			pos += pgp_symmetric_key_algorithm_print(sk->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), str_size - pos, indent);
			octet_count -= 1;
		}

		pos += print_bytes(indent + 1, "X448 Ephemeral Key: ", PTR_OFFSET(str, pos), str_size - pos, sk->ephemeral_key, 56);
		pos += print_bytes(indent + 1, "X448 Encrypted Session Key: ", PTR_OFFSET(str, pos), str_size - pos, sk->encrypted_session_key,
						   octet_count);
	}
	break;
	default:
	{
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Unknown Session Key Material (%hu bytes)\n", kex_size);
	}
	break;
	}

	return pos;
}

static size_t pgp_signature_print(pgp_public_key_algorithms algorithm, void *sign, uint16_t sign_size, void *str, size_t str_size,
								  uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Signature Material\n");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_signature *sg = sign;
		pos += print_mpi(indent + 1, "RSA m^d mod n", sg->e, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_signature *sg = sign;
		pos += print_mpi(indent + 1, "DSA r", sg->r, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "DSA s", sg->s, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_signature *sg = sign;
		pos += print_mpi(indent + 1, "ECDSA r", sg->r, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "ECDSA s", sg->s, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_signature *sg = sign;
		pos += print_mpi(indent + 1, "EdDSA r", sg->r, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "EdDSA s", sg->s, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_signature *sg = sign;
		pos += print_bytes(indent + 1, "Ed25519 Signature: ", PTR_OFFSET(str, pos), str_size - pos, sg->sig, 64);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_signature *sg = sign;
		pos += print_bytes(indent + 1, "Ed448 Signature: ", PTR_OFFSET(str, pos), str_size - pos, sg->sig, 114);
	}
	break;
	default:
	{
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Unknown Signature Material (%hu bytes)\n", sign_size);
	}
	break;
	}
	return pos;
}

static size_t pgp_public_key_print(pgp_public_key_algorithms public_key_algorithm, void *public_key, uint16_t public_key_size, void *str,
								   size_t str_size, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), str_size - pos, "Key Material:\n");

	switch (public_key_algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = public_key;
		pos += print_mpi(indent + 1, "RSA modulus n", key->n, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "RSA public exponent e", key->e, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = public_key;
		pos += print_mpi(indent + 1, "Elgamal prime p", key->p, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "Elgamal group generator g", key->g, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "Elgamal public key y", key->y, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = public_key;
		pos += print_mpi(indent + 1, "DSA prime p", key->p, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "DSA group order q", key->q, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "DSA group generator g", key->g, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += print_mpi(indent + 1, "DSA public key y", key->y, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = public_key;
		pos += pgp_curve_print(key->curve, key->oid, key->oid_size, PTR_OFFSET(str, pos), str_size - pos, indent + 1);
		pos += print_mpi(indent + 1, "MPI of public point", key->point, PTR_OFFSET(str, pos), str_size - pos, options);
		pos += pgp_kdf_print(&key->kdf, PTR_OFFSET(str, pos), str_size - pos, indent);
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = public_key;
		pos += pgp_curve_print(key->curve, key->oid, key->oid_size, PTR_OFFSET(str, pos), str_size - pos, indent + 1);
		pos += print_mpi(indent + 1, "MPI of public point", key->point, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_key *key = public_key;
		pos += pgp_curve_print(key->curve, key->oid, key->oid_size, PTR_OFFSET(str, pos), str_size - pos, indent + 1);
		pos += print_mpi(indent + 1, "MPI of public point", key->point, PTR_OFFSET(str, pos), str_size - pos, options);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *key = public_key;
		pos += print_bytes(indent + 1, "X25519 Public Key: ", PTR_OFFSET(str, pos), str_size - pos, key->public_key, 32);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *key = public_key;
		pos += print_bytes(indent + 1, "X448 Public Key: ", PTR_OFFSET(str, pos), str_size - pos, key->public_key, 56);
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = public_key;
		pos += print_bytes(indent + 1, "Ed25519 Public Key: ", PTR_OFFSET(str, pos), str_size - pos, key->public_key, 32);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *key = public_key;
		pos += print_bytes(indent + 1, "Ed448 Public Key: ", PTR_OFFSET(str, pos), str_size - pos, key->public_key, 57);
	}
	break;
	default:
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Unknown Public Key Material (%hu bytes)\n", public_key_size);
		break;
	}

	return pos;
}

static size_t pgp_private_key_print(pgp_public_key_algorithms public_key_algorithm, void *private_key, uint16_t private_key_size, void *str,
									size_t str_size, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_public_key_print(public_key_algorithm, private_key, private_key_size, PTR_OFFSET(str, pos), str_size - pos, indent, options);

	switch (public_key_algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = private_key;

		if (key->d == NULL || key->p == NULL || key->q == NULL || key->u == NULL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "RSA secret exponent d (Encrypted)\n");
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "RSA secret prime p (Encrypted)\n");
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "RSA secret prime q (Encrypted)\n");
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "RSA (1/p mod q) u (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(indent + 1, "RSA secret exponent d", key->d, PTR_OFFSET(str, pos), str_size - pos, options);
			pos += print_mpi(indent + 1, "RSA secret prime p", key->p, PTR_OFFSET(str, pos), str_size - pos, options);
			pos += print_mpi(indent + 1, "RSA secret prime q", key->q, PTR_OFFSET(str, pos), str_size - pos, options);
			pos += print_mpi(indent + 1, "RSA (1/p mod q) u", key->u, PTR_OFFSET(str, pos), str_size - pos, options);
		}
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Elgamal secret exponent x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(indent + 1, "Elgamal secret exponent x", key->x, PTR_OFFSET(str, pos), str_size - pos, options);
		}
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "DSA secret exponent x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(indent + 1, "DSA secret exponent x", key->x, PTR_OFFSET(str, pos), str_size - pos, options);
		}
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "ECDH secret scalar x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(indent + 1, "ECDH secret scalar x", key->x, PTR_OFFSET(str, pos), str_size - pos, options);
		}
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "ECDSA secret scalar x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(indent + 1, "ECDSA secret scalar x", key->x, PTR_OFFSET(str, pos), str_size - pos, options);
		}
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "EdDSA secret scalar x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(indent + 1, "EdDSA secret scalar x", key->x, PTR_OFFSET(str, pos), str_size - pos, options);
		}
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *key = private_key;
		byte_t zero[32] = {0};

		if (memcmp(zero, key->private_key, 32) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "X25519 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_bytes(indent + 1, "X25519 Secret Key: ", PTR_OFFSET(str, pos), str_size - pos, key->private_key, 32);
		}
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *key = private_key;
		byte_t zero[56] = {0};

		if (memcmp(zero, key->private_key, 56) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "X448 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_bytes(indent + 1, "X448 Secret Key: ", PTR_OFFSET(str, pos), str_size - pos, key->private_key, 56);
		}
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = private_key;
		byte_t zero[32] = {0};

		if (memcmp(zero, key->private_key, 32) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Ed25519 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_bytes(indent + 1, "Ed25519 Secret Key: ", PTR_OFFSET(str, pos), str_size - pos, key->private_key, 32);
		}
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *key = private_key;
		byte_t zero[57] = {0};

		if (memcmp(zero, key->private_key, 57) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Ed448 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_bytes(indent + 1, "Ed448 Secret Key: ", PTR_OFFSET(str, pos), str_size - pos, key->private_key, 57);
		}
	}
	break;
	default:
		pos +=
			print_format(indent + 1, PTR_OFFSET(str, pos), str_size - pos, "Unknown Secret Key Material (%hu bytes)\n", private_key_size);
		break;
	}
	return pos;
}

static size_t pgp_signature_type_print(pgp_signature_type type, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Signature Type: ");

	switch (type)
	{
	case PGP_BINARY_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Binary Signature (Tag 0x00)\n");
		break;
	case PGP_TEXT_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Text Signature (Tag 0x01)\n");
		break;
	case PGP_STANDALONE_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Standalone Signature (Tag 0x02)\n");
		break;
	case PGP_GENERIC_CERTIFICATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Generic Certification Signature (Tag 0x10)\n");
		break;
	case PGP_PERSONA_CERTIFICATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Persona Certification Signature (Tag 0x11)\n");
		break;
	case PGP_CASUAL_CERTIFICATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Casual Certification Signature (Tag 0x12)\n");
		break;
	case PGP_POSITIVE_CERTIFICATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Positive Certification Signature (Tag 0x13)\n");
		break;
	case PGP_ATTESTED_KEY_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Attested Key Signature (Tag 0x16)\n");
		break;
	case PGP_SUBKEY_BINDING_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Subkey Binding Signature (Tag 0x18)\n");
		break;
	case PGP_PRIMARY_KEY_BINDING_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Primary Key Binding Signature (Tag 0x19)\n");
		break;
	case PGP_DIRECT_KEY_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Direct Key Signature (Tag 0x1F)\n");
		break;
	case PGP_KEY_REVOCATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Revocation Signature (Tag 0x20)\n");
		break;
	case PGP_SUBKEY_REVOCATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Subkey Revocation Signature (Tag 0x28)\n");
		break;
	case PGP_CERTIFICATION_REVOCATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Certificate Revocation Signature (Tag 0x30)\n");
		break;
	case PGP_TIMESTAMP_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Timestamp Signature (Tag 0x40)\n");
		break;
	case PGP_THIRD_PARTY_CONFIRMATION_SIGNATURE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Third Party Confirmation Signature (Tag 0x50)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Signature Type (Tag 0x%02X)\n", type);
		break;
	}

	return pos;
}

static size_t pgp_signature_subpacket_header_print(pgp_subpacket_header header, void *str, size_t size, uint32_t indent)
{
	pgp_signature_subpacket_type type = header.tag & PGP_SUBPACKET_TAG_MASK;
	size_t pos = 0;

	switch (type)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Signature Creation Time (Tag 2)");
		break;
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Signature Expiration Time (Tag 3)");
		break;
	case PGP_EXPORTABLE_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Exportable Certification (Tag 4)");
		break;
	case PGP_TRUST_SIGNATURE_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Trust Signature (Tag 5)");
		break;
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Regular Expression (Tag 6)");
		break;
	case PGP_REVOCABLE_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Revocable (Tag 7)");
		break;
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Key Expiration Time (Tag 9)");
		break;
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred Symmetric Ciphers (Tag 11)");
		break;
	case PGP_REVOCATION_KEY_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Revocation Key (Tag 12)");
		break;
	case PGP_ISSUER_KEY_ID_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Issuer Key ID (Tag 16)");
		break;
	case PGP_NOTATION_DATA_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Notation Data (Tag 20)");
		break;
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred Hash Algorithms (Tag 21)");
		break;
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred Compression Algorithms (Tag 22)");
		break;
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Key Server Preferences (Tag 23)");
		break;
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred Key Server (Tag 24)");
		break;
	case PGP_PRIMARY_USER_ID_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Primary User ID (Tag 25)");
		break;
	case PGP_POLICY_URI_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Policy URI (Tag 26)");
		break;
	case PGP_KEY_FLAGS_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Key Flags (Tag 27)");
		break;
	case PGP_SIGNER_USER_ID_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Signer's User ID (Tag 28)");
		break;
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Reason for Revocation (Tag 29)");
		break;
	case PGP_FEATURES_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Features (Tag 30)");
		break;
	case PGP_SIGNATURE_TARGET_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Signature Target (Tag 31)");
		break;
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Embedded Signature (Tag 32)");
		break;
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Issuer Fingerprint (Tag 33)");
		break;
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred Encryption Modes (Tag 33) (Deprecated)");
		break;
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Intended Recipient Fingerprint (Tag 35)");
		break;
	case PGP_ATTESTED_CERTIFICATIONS_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Attested Certifications (Tag 37) (Deprecated)");
		break;
	case PGP_KEY_BLOCK_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Key Block (Tag 38)");
		break;
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred AEAD Ciphersuites (Tag 39)");
		break;
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Literal Data Mesh (Tag 40)");
		break;
	case PGP_TRUST_ALIAS_SUBPACKET:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Trust Alias (Tag 41)");
		break;
	default:
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Unkown Signature Subpacket (Tag %hhu)", type);
		break;
	}

	// Add critical bit
	if (header.tag & 0x80)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, " (Critical)");
	}

	// Add packet size
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, " (%zu bytes)\n", header.body_size);

	return pos;
}

static size_t pgp_signature_subpacket_print(void *subpacket, void *str, size_t size, uint32_t indent, uint32_t options)
{
	pgp_subpacket_header *header = subpacket;
	pgp_signature_subpacket_type type = header->tag & PGP_SUBPACKET_TAG_MASK;

	size_t pos = 0;

	// Print the header
	pos += pgp_signature_subpacket_header_print(*header, PTR_OFFSET(str, pos), size - pos, indent);

	switch (type)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
	{
		pgp_signature_creation_time_subpacket *timestamp_subpacket = subpacket;
		pos += print_timestamp(indent + 1, "Creation Time", timestamp_subpacket->timestamp, PTR_OFFSET(str, pos), size - pos);
	}
	break;
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
	{
		pgp_signature_expiry_time_subpacket *timestamp_subpacket = subpacket;
		uint32_t expiry_seconds = timestamp_subpacket->duration;

		if (expiry_seconds == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: Never\n");
		}
		else if ((expiry_seconds % 31536000) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: %u years\n", expiry_seconds / 31536000);
		}
		else if ((expiry_seconds % 86400) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: %u days\n", expiry_seconds / 86400);
		}
		else
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: %u seconds\n", expiry_seconds);
		}
	}
	break;
	case PGP_EXPORTABLE_SUBPACKET:
	{
		pgp_exportable_subpacket *exportable_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Exportable: %s\n", exportable_subpacket->state ? "Yes" : "No");
	}
	break;
	case PGP_TRUST_SIGNATURE_SUBPACKET:
	{
		pgp_trust_signature_subpacket *trust_subpacket = subpacket;
		char *level = NULL;
		char *amount = NULL;

		switch (trust_subpacket->trust_level)
		{
		case PGP_TRUST_LEVEL_ORDINARY:
			level = "Ordinary";
			break;
		case PGP_TRUST_LEVEL_TRUSTED:
			level = "Trusted";
			break;
		case PGP_TRUST_LEVEL_ISSUER:
			level = "Issuer";
			break;
		default:
			level = "Issuer";
			break;
		}

		if (trust_subpacket->trust_amount < PGP_TRUST_AMOUNT_PARTIAL)
		{
			amount = "Untrusted";
		}
		else if (trust_subpacket->trust_amount < PGP_TRUST_AMOUNT_COMPLETE)
		{
			amount = "Partial";
		}
		else
		{
			amount = "Complete";
		}

		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Trust Level: %hhu (%s)\n", trust_subpacket->trust_level, level);
		pos +=
			print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Trust Amount: %hhu (%s)\n", trust_subpacket->trust_amount, amount);
	}
	break;
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	{
		pgp_regular_expression_subpacket *re_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Regular Expression: %.*s\n", re_subpacket->header.body_size,
							re_subpacket->regex);
	}
	break;
	case PGP_REVOCABLE_SUBPACKET:
	{
		pgp_revocable_subpacket *revocable_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revocable: %s\n", revocable_subpacket->state ? "Yes" : "No");
	}
	break;
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
	{
		pgp_key_expiration_time_subpacket *timestamp_subpacket = subpacket;
		uint32_t expiry_seconds = timestamp_subpacket->duration;

		if (expiry_seconds == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: Never\n");
		}
		else if ((expiry_seconds % 31536000) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: %u years\n", expiry_seconds / 31536000);
		}
		else if ((expiry_seconds % 86400) == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: %u days\n", expiry_seconds / 86400);
		}
		else
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Expiry Time: %u seconds\n", expiry_seconds);
		}
	}
	break;
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	{
		pgp_preferred_symmetric_ciphers_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_symmetric_key_algorithm_print(preferred_subpacket->preferred_algorithms[i], PTR_OFFSET(str, pos), size - pos,
													 indent + 1);
		}
	}
	break;
	case PGP_REVOCATION_KEY_SUBPACKET:
	{
		pgp_revocation_key_subpacket *revocation_subpacket = subpacket;

		if (revocation_subpacket->revocation_class & PGP_REVOCATION_CLASS_NORMAL)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revocation Class: Normal (0x80)\n");
		}
		if (revocation_subpacket->revocation_class & PGP_REVOCATION_CLASS_SENSITIVE)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revocation Class: Sensitive (0x40)\n");
		}

		pos += pgp_public_key_algorithm_print(revocation_subpacket->algorithm_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += print_key(indent + 1, PTR_OFFSET(str, pos), size - pos, revocation_subpacket->fingerprint,
						 revocation_subpacket->header.body_size - 2);
	}
	break;
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	{
		pgp_issuer_key_id_subpacket *key_id_subpacket = subpacket;
		pos += print_key(indent + 1, PTR_OFFSET(str, pos), size - pos, key_id_subpacket->key_id, 8);
	}
	break;
	case PGP_NOTATION_DATA_SUBPACKET:
	{
		pgp_notation_data_subpacket *notation_subpacket = subpacket;

		if (notation_subpacket->flags == 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: None\n");
		}

		if (notation_subpacket->flags & PGP_NOTATION_DATA_UTF8)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: UTF-8 text (0x80000000)\n");
		}

		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Name (%hu bytes): %.*s\n", notation_subpacket->name_size,
							notation_subpacket->name_size, notation_subpacket->data);

		if (notation_subpacket->flags & PGP_NOTATION_DATA_UTF8)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Value (%hu bytes): %.*s\n", notation_subpacket->value_size,
								notation_subpacket->value_size, PTR_OFFSET(notation_subpacket->data, notation_subpacket->name_size));
		}
		else
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Value (%hu bytes): ", notation_subpacket->value_size);
			pos += print_hex(hex_lower_table, PTR_OFFSET(str, pos), PTR_OFFSET(notation_subpacket->data, notation_subpacket->name_size),
							 notation_subpacket->value_size);
		}
	}
	break;
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	{
		pgp_preferred_hash_algorithms_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_hash_algorithm_print(preferred_subpacket->preferred_algorithms[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}
	break;
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	{
		pgp_preferred_compression_algorithms_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos +=
				pgp_compression_algorithm_print(preferred_subpacket->preferred_algorithms[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}
	break;
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
	{
		pgp_key_server_preferences_subpacket *ksp_subpacket = subpacket;

		for (uint32_t i = 0; i < ksp_subpacket->header.body_size; ++i)
		{
			switch (ksp_subpacket->flags[i])
			{
			case PGP_KEY_SERVER_NO_MODIFY:
				pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: No Modify (0x80)\n");
				break;
			default:
				pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Unknown (0x%hhx)\n", ksp_subpacket->flags[i]);
				break;
			}
		}
	}
	break;
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	{
		pgp_preferred_key_server_subpacket *pks_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Preferred Key Server: %.*s\n", pks_subpacket->header.body_size,
							pks_subpacket->server);
	}
	break;
	case PGP_PRIMARY_USER_ID_SUBPACKET:
	{
		pgp_primary_user_id_subpacket *primary_uid_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Primary User Id: %s\n",
							primary_uid_subpacket->state ? "Yes" : "No");
	}
	break;
	case PGP_POLICY_URI_SUBPACKET:
	{
		pgp_policy_uri_subpacket *policy_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Policy URI: %.*s\n", policy_subpacket->header.body_size,
							policy_subpacket->policy);
	}
	break;
	case PGP_KEY_FLAGS_SUBPACKET:
	{
		pgp_key_flags_subpacket *key_flags_subpacket = subpacket;

		for (uint32_t i = 0; i < key_flags_subpacket->header.body_size; ++i)
		{
			// First Octet
			if (i == 0)
			{
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_CERTIFY)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Certification Key (0x01)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_SIGN)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Signing Key (0x02)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_ENCRYPT_COM)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Communication Encryption Key (0x04)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_ENCRYPT_STORAGE)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Storage Encryption Key (0x08)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_PRIVATE_SPLIT)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Key Secret Split (0x10)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_AUTHENTICATION)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Authentication Key (0x20)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_PRIVATE_SHARED)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Key Secret Shared (0x80)\n");
				}
			}

			// Second Octet
			if (i == 1)
			{
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_RESTRICTED_ENCRYPT)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Restricted Encryption Key (0x04)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_TIMESTAMP)
				{
					pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Flag: Timestamping Key (0x08)\n");
				}
			}
		}
	}
	break;
	case PGP_SIGNER_USER_ID_SUBPACKET:
	{
		pgp_signer_user_id_subpacket *signer_uid_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Signer User ID: %.*s\n", signer_uid_subpacket->header.body_size,
							signer_uid_subpacket->uid);
	}
	break;
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	{
		pgp_reason_for_revocation_subpacket *revocation_subpacket = subpacket;

		switch (revocation_subpacket->code)
		{
		case PGP_REVOCATION_NO_REASON:
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Code: None (Tag 0)\n");
			break;
		case PGP_REVOCATION_KEY_SUPERSEDED:
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Code: Key Superseded (Tag 1)\n");
			break;
		case PGP_REVOCATION_KEY_COMPROMISED:
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Code: Key Compromised (Tag 2)\n");
			break;
		case PGP_REVOCATION_KEY_RETIRED:
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Code: Key Retired (Tag 3)\n");
			break;
		case PGP_REVOCATION_USER_ID_INVALID:
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Code: User ID Invalid (Tag 32)\n");
			break;
		default:
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Code: Unknown (Tag %hhu)\n",
								revocation_subpacket->code);
			break;
		}

		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Revoction Reason: %.*s\n",
							revocation_subpacket->header.body_size - 1, revocation_subpacket->reason);
	}
	break;
	case PGP_FEATURES_SUBPACKET:
	{
		pgp_features_subpacket *features_subpacket = subpacket;

		for (uint32_t i = 0; i < features_subpacket->header.body_size; ++i)
		{
			switch (features_subpacket->flags[i])
			{
			case PGP_FEATURE_SEIPD_V1:
				pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: SEIPD-V1 (MDC) Supported (0x01)\n");
				break;
			case PGP_FEATURE_AEAD:
				pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: AEAD Supported (0x02)\n");
				break;
			case PGP_FEATURE_KEY_V5:
				pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: V5 Keys Supported (0x04)\n");
				break;
			case PGP_FEATURE_SEIPD_V2:
				pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: SEIPD-V2 Supported (0x08)\n");
				break;
			default:
				pos +=
					print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: Unknown (0x%hhx)\n", features_subpacket->flags[i]);
				break;
			}
		}
	}
	break;
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	{
		pgp_signature_target_subpacket *target_subpacket = subpacket;

		pos += pgp_signature_algorithm_print(target_subpacket->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += pgp_hash_algorithm_print(target_subpacket->hash_algorithm_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += print_bytes(indent + 1, "Hash: ", PTR_OFFSET(str, pos), size - pos, target_subpacket->hash,
						   target_subpacket->header.body_size - 2);
	}
	break;
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
	{
		pgp_embedded_signature_subpacket *embedded_subpacket = subpacket;
		pos += pgp_signature_packet_body_print(indent + 1, embedded_subpacket, PTR_OFFSET(str, pos), size - pos, options);
	}
	break;
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	{
		pgp_issuer_fingerprint_subpacket *fingerprint_subpacket = subpacket;

		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", fingerprint_subpacket->version);
		pos += print_key(indent + 1, PTR_OFFSET(str, pos), size - pos, fingerprint_subpacket->fingerprint,
						 fingerprint_subpacket->header.body_size - 1);
	}
	break;
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
	{
		pgp_preferred_encryption_modes_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_aead_algorithm_print(preferred_subpacket->preferred_algorithms[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}
	break;
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
	{
		pgp_recipient_fingerprint_subpacket *fingerprint_subpacket = subpacket;

		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", fingerprint_subpacket->version);
		pos += print_key(indent + 1, PTR_OFFSET(str, pos), size - pos, fingerprint_subpacket->fingerprint,
						 fingerprint_subpacket->header.body_size - 1);
	}
	break;
	case PGP_ATTESTED_CERTIFICATIONS_SUBPACKET:
	{
		pgp_attested_certifications_subpacket *attestation_subpacket = subpacket;
		uint32_t hash_size = 0;
		uint32_t hash_count = 0;

		// Try 32 (SHA-256), 20 (SHA-1)
		if (header->body_size % 32 == 0)
		{
			hash_size = 32;
			hash_count = header->body_size / 32;
		}
		else if (header->body_size % 20 == 0)
		{
			hash_size = 20;
			hash_count = header->body_size / 20;
		}

		if (hash_count != 0)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Attestations:\n");

			for (uint16_t i = 0; i < hash_count; ++i)
			{
				pos += print_bytes(indent + 2, "", PTR_OFFSET(str, pos), size - pos, PTR_OFFSET(attestation_subpacket->hash, hash_size * i),
								   hash_size);
			}
		}
		else
		{
			pos +=
				print_bytes(indent + 1, "Attestations: ", PTR_OFFSET(str, pos), size - pos, attestation_subpacket->hash, header->body_size);
		}
	}
	break;
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	{
		pgp_preferred_aead_ciphersuites_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < (preferred_subpacket->header.body_size / 2); i += 2)
		{
			pgp_symmetric_key_algorithms symmetric_algorithm = preferred_subpacket->preferred_algorithms[i];
			pgp_aead_algorithms aead_algorithm = preferred_subpacket->preferred_algorithms[i + 1];

			pos += pgp_cipher_aead_algorithm_pair_print(symmetric_algorithm, aead_algorithm, PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}
	break;
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
	{
		pgp_literal_data_meta_hash_subpacket *meta_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Octet: %hhu\n", meta_subpacket->octet);
		pos += print_bytes(indent + 1, "SHA256 Hash: ", PTR_OFFSET(str, pos), size - pos, meta_subpacket->hash, 32);
	}
	break;
	case PGP_TRUST_ALIAS_SUBPACKET:
	{
		pgp_trust_alias_subpacket *trust_alias_subpacket = subpacket;
		pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Trust Alias: %.*s\n", trust_alias_subpacket->header.body_size,
							trust_alias_subpacket->alias);
	}
	break;
	default:
		break;
	}

	return pos;
}

size_t pgp_pkesk_packet_print(pgp_pkesk_packet *packet, void *str, size_t size, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	if (packet->version == PGP_PKESK_V6)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: 6\n");

		switch (packet->key_version)
		{
		case PGP_KEY_V2:
		case PGP_KEY_V3:
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu (Deprecated)\n", packet->key_version);
			pos += print_key(1, PTR_OFFSET(str, pos), size - pos, packet->key_fingerprint, PGP_KEY_V3_FINGERPRINT_SIZE);
			break;
		case PGP_KEY_V4:
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", packet->key_version);
			pos += print_key(1, PTR_OFFSET(str, pos), size - pos, packet->key_fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE);
			break;
		case PGP_KEY_V5:
		case PGP_KEY_V6:
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", packet->key_version);
			pos += print_key(1, PTR_OFFSET(str, pos), size - pos, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);
			break;
		default:
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu (Unknown)\n", packet->key_version);
			break;
		}

		pos += pgp_kex_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_kex_print(packet->public_key_algorithm_id, packet->encrypted_session_key, packet->encrypted_session_key_octets,
							 PTR_OFFSET(str, pos), size - pos, 1, options);
	}
	else if (packet->version == PGP_PKESK_V3)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: 3\n");
		pos += print_key(1, PTR_OFFSET(str, pos), size - pos, packet->key_id, 8);
		pos += pgp_kex_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_kex_print(packet->public_key_algorithm_id, packet->encrypted_session_key, packet->encrypted_session_key_octets,
							 PTR_OFFSET(str, pos), size - pos, 1, options);
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_skesk_packet_print(pgp_skesk_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	if (packet->version == PGP_SKESK_V6 || packet->version == PGP_SKESK_V5)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu\n", packet->version);
		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 1);

		pos += print_bytes(1, "IV: ", PTR_OFFSET(str, pos), size - pos, packet->iv, packet->iv_size);
		pos += print_bytes(1, "Tag: ", PTR_OFFSET(str, pos), size - pos, packet->tag, packet->tag_size);
		pos += print_bytes(1, "Encrypted Session Key: ", PTR_OFFSET(str, pos), size - pos, packet->session_key, packet->session_key_size);
	}
	else if (packet->version == PGP_SKESK_V4)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: 4\n");
		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 1);

		if (packet->session_key_size > 0)
		{
			pos +=
				print_bytes(1, "Encrypted Session Key: ", PTR_OFFSET(str, pos), size - pos, packet->session_key, packet->session_key_size);
		}
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

static size_t pgp_signature_packet_body_print(uint32_t indent, pgp_signature_packet *packet, void *ptr, size_t size, uint32_t options)
{
	size_t pos = 0;

	if (packet->version == PGP_SIGNATURE_V6 || packet->version == PGP_SIGNATURE_V5 || packet->version == PGP_SIGNATURE_V4)
	{
		pos += print_format(indent, PTR_OFFSET(ptr, pos), size - pos, "Version: %hhu\n", packet->version);
		pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos, indent);
		pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, indent);
		pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, indent);

		if (packet->hashed_subpackets != NULL)
		{
			if (packet->hashed_subpackets->count > 0)
			{
				pos += print_format(indent, PTR_OFFSET(ptr, pos), size - pos, "Hashed Subpackets:\n");
			}

			for (uint32_t i = 0; i < packet->hashed_subpackets->count; ++i)
			{
				pos += pgp_signature_subpacket_print(packet->hashed_subpackets->packets[i], PTR_OFFSET(ptr, pos), size - pos, indent + 1,
													 options);
			}
		}

		if (packet->unhashed_subpackets != NULL)
		{
			if (packet->unhashed_subpackets->count > 0)
			{
				pos += print_format(indent, PTR_OFFSET(ptr, pos), size - pos, "Unhashed Subpackets:\n");
			}

			for (uint32_t i = 0; i < packet->unhashed_subpackets->count; ++i)
			{
				pos += pgp_signature_subpacket_print(packet->unhashed_subpackets->packets[i], PTR_OFFSET(ptr, pos), size - pos, indent + 1,
													 options);
			}
		}

		pos += print_bytes(indent, "Hash Check: ", PTR_OFFSET(ptr, pos), size - pos, packet->quick_hash, 2);

		if (packet->version == PGP_SIGNATURE_V6)
		{
			pos += print_bytes(indent, "Salt: ", PTR_OFFSET(ptr, pos), size - pos, packet->salt, packet->salt_size);
		}

		pos += pgp_signature_print(packet->public_key_algorithm_id, packet->signature, packet->signature_octets, PTR_OFFSET(ptr, pos),
								   size - pos, indent, options);
	}
	else if (packet->version == PGP_SIGNATURE_V3)
	{
		pos += print_format(indent, PTR_OFFSET(ptr, pos), size - pos, "Version: 3 (Deprecated)\n");
		pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos, indent);
		pos += print_timestamp(indent, "Signature Creation Time", packet->timestamp, PTR_OFFSET(ptr, pos), size - pos);
		pos += print_key(indent, PTR_OFFSET(ptr, pos), size - pos, packet->key_id, 8);
		pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, indent);
		pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, indent);
		pos += print_bytes(indent, "Hash Check: ", PTR_OFFSET(ptr, pos), size - pos, packet->quick_hash, 2);
		pos += pgp_signature_print(packet->public_key_algorithm_id, packet->signature, packet->signature_octets, PTR_OFFSET(ptr, pos),
								   size - pos, indent, options);
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(ptr, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_signature_packet_print(pgp_signature_packet *packet, void *ptr, size_t size, uint32_t options)
{
	size_t pos = 0;

	// Header
	pos += pgp_packet_header_print(&packet->header, ptr, size);

	// Body
	pos += pgp_signature_packet_body_print(1, packet, PTR_OFFSET(ptr, pos), size - pos, options);

	return pos;
}

size_t pgp_one_pass_signature_packet_print(pgp_one_pass_signature_packet *packet, void *ptr, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, ptr, size);

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		pos += print_format(1, PTR_OFFSET(ptr, pos), size - pos, "Version: 6\n");
		pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);

		pos += print_bytes(1, "Salt: ", PTR_OFFSET(ptr, pos), size - pos, packet->salt, packet->salt_size);
		pos += print_key(1, PTR_OFFSET(ptr, pos), size - pos, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);

		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Nested: %s\n", packet->nested ? "Yes" : "No");
	}
	else if (packet->version == PGP_ONE_PASS_SIGNATURE_V3)
	{
		pos += print_format(1, PTR_OFFSET(ptr, pos), size - pos, "Version: 3 (Deprecated)\n");
		pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += print_key(1, PTR_OFFSET(ptr, pos), size - pos, packet->key_id, 8);

		pos += print_format(1, PTR_OFFSET(ptr, pos), size - pos, "Nested: %s\n", packet->nested ? "Yes" : "No");
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(ptr, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_public_key_packet_print(pgp_key_packet *packet, void *str, size_t size, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5 || packet->version == PGP_KEY_V4)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu\n", packet->version);
		pos += print_timestamp(1, "Key Creation Time", packet->key_creation_time, PTR_OFFSET(str, pos), size - pos);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->key, packet->public_key_data_octets, PTR_OFFSET(str, pos),
									size - pos, 1, options);
	}
	else if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Deprecated)\n", packet->version);
		pos += print_timestamp(1, "Key Creation Time", packet->key_creation_time, PTR_OFFSET(str, pos), size - pos);
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Expiry: %hu days\n", packet->key_expiry_days);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->key, packet->public_key_data_octets, PTR_OFFSET(str, pos),
									size - pos, 1, options);
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_secret_key_packet_print(pgp_key_packet *packet, void *str, size_t size, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5 || packet->version == PGP_KEY_V4)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu\n", packet->version);
		pos += print_timestamp(1, "Key Creation Time", packet->key_creation_time, PTR_OFFSET(str, pos), size - pos);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);

		if (packet->s2k_usage != 0)
		{
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "S2K Usage: ");
			switch (packet->s2k_usage)
			{
			case 253:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AEAD (Tag 253)\n");
				break;
			case 254:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "CFB (Tag 254)\n");
				break;
			case 255:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Malleable CFB (Tag 255) (Deprecated)\n");
				break;
			default:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Legacy CFB (Tag 255) (Deprecated)\n");
				break;
			}

			pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 2);

			if (packet->s2k_usage == 253)
			{
				pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 2);
			}

			if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
			{
				pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 2);
			}

			pos += print_bytes(2, "IV: ", PTR_OFFSET(str, pos), size - pos, packet->iv, packet->iv_size);
		}

		pos += pgp_private_key_print(packet->public_key_algorithm_id, packet->key, packet->private_key_data_octets, PTR_OFFSET(str, pos),
									 size - pos, 1, options);

		if (packet->s2k_usage == 0)
		{
			pos += print_bytes(1, "Checksum: ", PTR_OFFSET(str, pos), size - pos, &packet->key_checksum, 2);
		}
	}
	else if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Deprecated)\n", packet->version);
		pos += print_timestamp(1, "Key Creation Time", packet->key_creation_time, PTR_OFFSET(str, pos), size - pos);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Expiry: %hu days\n", packet->key_expiry_days);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);

		if (packet->s2k_usage != 0)
		{
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "S2K Usage: ");
			switch (packet->s2k_usage)
			{
			case 253:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AEAD (Tag 253)\n");
				break;
			case 254:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "CFB (Tag 254)\n");
				break;
			case 255:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Malleable CFB (Tag 255) (Deprecated)\n");
				break;
			default:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Legacy CFB (Tag 255) (Deprecated)\n");
				break;
			}

			pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 2);

			if (packet->s2k_usage == 253)
			{
				pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 2);
			}

			if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
			{
				pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 2);
			}

			pos += print_bytes(2, "IV: ", PTR_OFFSET(str, pos), size - pos, packet->iv, packet->iv_size);
		}

		pos += pgp_private_key_print(packet->public_key_algorithm_id, packet->key, packet->private_key_data_octets, PTR_OFFSET(str, pos),
									 size - pos, 1, options);

		if (packet->s2k_usage == 0)
		{
			pos += print_bytes(1, "Checksum: ", PTR_OFFSET(str, pos), size - pos, &packet->key_checksum, 2);
		}
	}
	else
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_compressed_packet_print(pgp_compresed_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += pgp_compression_algorithm_print(packet->compression_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->header.body_size - 1);

	return pos;
}

size_t pgp_sed_packet_print(pgp_sed_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

size_t pgp_marker_packet_print(pgp_marker_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Marker: %c%c%c\n", packet->marker[0], packet->marker[1], packet->marker[2]);

	return pos;
}

size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Format: ");

	switch (packet->format)
	{
	case PGP_LITERAL_DATA_BINARY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Binary (Tag 'b')\n");
		break;
	case PGP_LITERAL_DATA_MIME:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Mime (Tag 'm')\n");
		break;
	case PGP_LITERAL_DATA_LOCAL:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Local (Tag 'l') (Deprecated)\n");
		break;
	case PGP_LITERAL_DATA_TEXT:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Text (Tag 't')\n");
		break;
	case PGP_LITERAL_DATA_UTF8:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "UTF-8 (Tag 'u')\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", packet->format);
	}

	pos += print_timestamp(1, "Date", packet->date, PTR_OFFSET(str, pos), size - pos);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Filename (%u bytes): ", packet->filename_size);

	if (packet->filename_size > 0)
	{
		memcpy(PTR_OFFSET(str, pos), packet->filename, packet->filename_size);
		pos += packet->filename_size;
	}

	out[pos++] = '\n';

	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->data_size);

	return pos;
}

size_t pgp_trust_packet_print(pgp_trust_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += pgp_trust_print(packet->level, PTR_OFFSET(str, pos), size - pos, 1);

	return pos;
}

size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "User ID: %.*s\n", packet->header.body_size, packet->user_data);

	return pos;
}

size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	for (uint32_t i = 0; i < packet->subpackets->count; ++i)
	{
		pgp_subpacket_header *subpacket_header = packet->subpackets->packets[i];

		switch (subpacket_header->tag)
		{
		case PGP_USER_ATTRIBUTE_IMAGE:
		{
			pgp_user_attribute_image_subpacket *image_subpacket = packet->subpackets->packets[i];
			uint32_t image_size = image_subpacket->header.body_size - 16;

			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "User Attribute Image Subpacket (Tag 1)\n");
			pos += print_format(2, PTR_OFFSET(str, pos), size - pos, "Image Header Version: %hhu\n", image_subpacket->image_header_version);

			switch (image_subpacket->image_encoding)
			{
			case PGP_USER_ATTRIBUTE_IMAGE_JPEG:
			{
				pos += print_format(2, PTR_OFFSET(str, pos), size - pos, "Image Encoding: JPEG (Tag 1)\n");
			}
			break;
			default:
				pos += print_format(2, PTR_OFFSET(str, pos), size - pos, "Unknown Image Encoding (Tag %hhu)\n",
									image_subpacket->image_encoding);
			}

			pos += print_format(2, PTR_OFFSET(str, pos), size - pos, "Image Size: %u bytes\n", image_size);
		}
		break;
		case PGP_USER_ATTRIBUTE_UID:
		{
			pgp_user_attribute_uid_subpacket *uid_subpacket = packet->subpackets->packets[i];
			uint32_t uid_size = uid_subpacket->header.body_size;

			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "User Attribute Image User ID Subpacket (Tag 2)\n");
			pos += print_format(2, PTR_OFFSET(str, pos), size - pos, "User ID: %.*s\n", uid_size, uid_subpacket->user_data);
		}
		break;
		default:
			pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Unknown Subpacket (Tag %hhu) (%u bytes)\n", subpacket_header->tag,
								subpacket_header->body_size);
		}
	}

	return pos;
}

size_t pgp_seipd_packet_print(pgp_seipd_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	if (packet->version == PGP_SEIPD_V2)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: 2\n");

		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Chunk Size: %u Code (%hhu)\n", PGP_CHUNK_SIZE(packet->chunk_size),
							packet->chunk_size);

		pos += print_bytes(1, "Salt: ", PTR_OFFSET(str, pos), size - pos, packet->salt, 32);
		pos += print_bytes(1, "Tag: ", PTR_OFFSET(str, pos), size - pos, packet->tag, packet->tag_size);

		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->data_size);
	}
	else if (packet->version == PGP_SEIPD_V1)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: 1\n");
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->header.body_size - 1);
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "%hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_bytes(1, "SHA-1 MDC: ", PTR_OFFSET(str, pos), size - pos, packet->sha1_hash, 20);

	return pos;
}

size_t pgp_aead_packet_print(pgp_aead_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	if (packet->version == PGP_AEAD_V1)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: 1\n");

		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Chunk Size: %u Code (%hhu)\n", PGP_CHUNK_SIZE(packet->chunk_size),
							packet->chunk_size);

		pos += print_bytes(1, "IV: ", PTR_OFFSET(str, pos), size - pos, packet->iv, pgp_aead_iv_size(packet->aead_algorithm_id));
		pos += print_bytes(1, "Tag: ", PTR_OFFSET(str, pos), size - pos, packet->tag, packet->tag_size);

		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->data_size);
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "%hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_padding_packet_print(pgp_padding_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Padding Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

static size_t print_capabilities(byte_t capabilities, void *str, size_t size, uint32_t indent)
{
	byte_t comma_insert = 0;
	char buffer[128] = {0};

	if (capabilities & PGP_KEY_FLAG_CERTIFY)
	{
		strncat(buffer, "Certify", 7);
		comma_insert = 1;
	}
	if (capabilities & PGP_KEY_FLAG_SIGN)
	{
		if (comma_insert)
		{
			strncat(buffer, ", ", 2);
		}

		strncat(buffer, "Sign", 4);
		comma_insert = 1;
	}
	if (capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
	{
		if (comma_insert)
		{
			strncat(buffer, ", ", 2);
		}

		strncat(buffer, "Encrypt", 7);
		comma_insert = 1;
	}
	if (capabilities & PGP_KEY_FLAG_AUTHENTICATION)
	{
		if (comma_insert)
		{
			strncat(buffer, ", ", 2);
		}

		strncat(buffer, "Authenticate", 12);
	}

	return print_format(indent, str, size, "Capabilities: %s\n", buffer);
}

static size_t print_flags(byte_t flags, void *str, size_t size, uint32_t indent)
{
	byte_t comma_insert = 0;
	char buffer[128] = {0};

	if (flags & PGP_KEY_FLAG_PRIVATE_SPLIT)
	{
		strncat(buffer, "Split", 5);
		comma_insert = 1;
	}
	if (flags & PGP_KEY_FLAG_PRIVATE_SHARED)
	{
		if (comma_insert)
		{
			strncat(buffer, ", ", 2);
		}

		strncat(buffer, "Shared", 7);
		comma_insert = 1;
	}
	if (flags & PGP_KEY_FLAG_TIMESTAMP)
	{
		if (comma_insert)
		{
			strncat(buffer, ", ", 2);
		}

		strncat(buffer, "Timestamp", 9);
		comma_insert = 1;
	}
	if (flags & PGP_KEY_FLAG_RESTRICTED_ENCRYPT)
	{
		if (comma_insert)
		{
			strncat(buffer, ", ", 2);
		}

		strncat(buffer, "Restricted", 10);
	}

	return print_format(indent, str, size, "Flags: %s\n", buffer);
}

size_t pgp_key_packet_print(pgp_key_packet *packet, void *str, size_t size, uint32_t options)
{
	size_t pos = 0;
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	pos += pgp_packet_header_print(&packet->header, str, size);

	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Version: %hhu\n", packet->version);
	pos +=
		print_format(1, PTR_OFFSET(str, pos), size - pos, "Type: %s\n", packet->type == PGP_KEY_TYPE_PUBLIC ? "Public Key" : "Secret Key");
	pos += print_capabilities(packet->capabilities, PTR_OFFSET(str, pos), size - pos, 1);
	pos += print_flags(packet->flags, PTR_OFFSET(str, pos), size - pos, 1);

	if (pgp_key_fingerprint(packet, fingerprint, &fingerprint_size) == PGP_SUCCESS)
	{
		pos += print_key(1, PTR_OFFSET(str, pos), size - pos, fingerprint, fingerprint_size);
	}

	pos += print_timestamp(1, "Key Creation Time", packet->key_creation_time, PTR_OFFSET(str, pos), size - pos);

	if (packet->key_revocation_time != 0)
	{
		pos += print_timestamp(1, "Key Revocation Time", packet->key_revocation_time, PTR_OFFSET(str, pos), size - pos);
	}

	if (packet->key_expiry_seconds != 0)
	{
		pos +=
			print_timestamp(1, "Key Expiry Time", packet->key_creation_time + packet->key_expiry_seconds, PTR_OFFSET(str, pos), size - pos);
	}
	else
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Expiry Time: None\n");
	}

	pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);

	if (packet->type == PGP_KEY_TYPE_PUBLIC)
	{
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->key, packet->public_key_data_octets, PTR_OFFSET(str, pos),
									size - pos, 1, options);

		return pos;
	}

	if (packet->s2k_usage != 0)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "S2K Usage: ");
		switch (packet->s2k_usage)
		{
		case 253:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AEAD (Tag 253)\n");
			break;
		case 254:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "CFB (Tag 254)\n");
			break;
		case 255:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Malleable CFB (Tag 255) (Deprecated)\n");
			break;
		default:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Legacy CFB (Tag 255) (Deprecated)\n");
			break;
		}

		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 2);

		if (packet->s2k_usage == 253)
		{
			pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 2);
		}

		if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
		{
			pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 2);
		}

		pos += print_bytes(2, "IV: ", PTR_OFFSET(str, pos), size - pos, packet->iv, packet->iv_size);
	}

	pos += pgp_private_key_print(packet->public_key_algorithm_id, packet->key, packet->private_key_data_octets, PTR_OFFSET(str, pos),
								 size - pos, 1, options);

	return pos;
}

static size_t pgp_user_info_print(pgp_user_info *user, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "User ID: %.*s\n", user->uid_octets, user->uid);
	pos += pgp_trust_print(user->trust, PTR_OFFSET(str, pos), size - pos, indent);

	if (user->features != 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Supported Features:\n");

		if (user->features & PGP_FEATURE_MDC)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: SEIPD-V1 (MDC) Supported (0x01)\n");
		}
		if (user->features & PGP_FEATURE_AEAD)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: AEAD Supported (0x02)\n");
		}
		if (user->features & PGP_FEATURE_KEY_V5)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: V5 Keys Supported (0x04)\n");
		}
		if (user->features & PGP_FEATURE_SEIPD_V2)
		{
			pos += print_format(indent + 1, PTR_OFFSET(str, pos), size - pos, "Feature: SEIPD-V2 Supported (0x08)\n");
		}
	}

	if (user->flags & PGP_KEY_SERVER_NO_MODIFY)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Key Server Preferences: No Modify (0x80)\n");
	}

	if (user->server_octets > 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Preferred Key Server: %.*s\n", user->server_octets, user->server);
	}

	if (user->hash_algorithm_preferences_octets > 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Hash Alogrithm Preferences:\n");

		for (byte_t i = 0; i < user->hash_algorithm_preferences_octets; ++i)
		{
			pos += pgp_hash_algorithm_print(user->hash_algorithm_preferences[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}

	if (user->cipher_algorithm_preferences_octets > 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Cipher Alogrithm Preferences:\n");

		for (byte_t i = 0; i < user->cipher_algorithm_preferences_octets; ++i)
		{
			pos += pgp_symmetric_key_algorithm_print(user->cipher_algorithm_preferences[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}

	if (user->compression_algorithm_preferences_octets > 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Compression Alogrithm Preferences:\n");

		for (byte_t i = 0; i < user->compression_algorithm_preferences_octets; ++i)
		{
			pos +=
				pgp_compression_algorithm_print(user->compression_algorithm_preferences[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}

	if (user->cipher_modes_preferences_octets > 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "Encryption Mode Preferences:\n");

		for (byte_t i = 0; i < user->cipher_modes_preferences_octets; ++i)
		{
			pos += pgp_aead_algorithm_print(user->cipher_modes_preferences[i], PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}

	if (user->aead_algorithm_preferences_octets > 0)
	{
		pos += print_format(indent, PTR_OFFSET(str, pos), size - pos, "AEAD Preferences:\n");

		for (byte_t i = 0; i < user->aead_algorithm_preferences_octets; i += 2)
		{
			pos +=
				pgp_cipher_aead_algorithm_pair_print(user->aead_algorithm_preferences[i / 2][0], user->aead_algorithm_preferences[i / 2][1],
													 PTR_OFFSET(str, pos), size - pos, indent + 1);
		}
	}

	return pos;
}

size_t pgp_keyring_packet_print(pgp_keyring_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", packet->key_version);

	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Primary Key: ");
	pos += print_hex(hex_upper_table, PTR_OFFSET(str, pos), packet->primary_fingerprint, packet->fingerprint_size);

	if (packet->subkey_count > 0)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Subkeys:\n");

		for (byte_t i = 0; i < packet->subkey_count; ++i)
		{
			pos += print_indent(2, PTR_OFFSET(str, pos), size - pos);
			pos += print_hex(hex_upper_table, PTR_OFFSET(str, pos), PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size),
							 packet->fingerprint_size);
		}
	}

	if (packet->users->count > 0)
	{
		pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "User Information:\n");

		for (uint32_t i = 0; i < packet->users->count; ++i)
		{
			pos += pgp_user_info_print(packet->users->packets[i], PTR_OFFSET(str, pos), size - pos, 2);
		}
	}

	return pos;
}

static inline byte_t memchr_count(void *data, byte_t size)
{
	void *result = 0;

	result = memchr(data, 0, size);

	if (result == NULL)
	{
		return size;
	}

	return (byte_t)((uintptr_t)result - (uintptr_t)data);
}

static size_t pgp_armor_header_print(const char *header, void *data, byte_t data_size, void *str, size_t str_size, uint32_t indent)
{
	size_t offset = 0;
	byte_t pos = 0;
	byte_t count = 0;

	if (data_size == 0)
	{
		return 0;
	}

	while (pos < data_size)
	{
		count = memchr_count(PTR_OFFSET(data, pos), data_size - pos);
		offset += print_format(indent, PTR_OFFSET(str, offset), str_size - offset, "%s: %.*s\n", header, PTR_OFFSET(data, pos), count);
		pos += count + 1;
	}

	return offset;
}

size_t pgp_armor_packet_print(pgp_armor_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);

	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Marker: %.*s\n", packet->marker_size, packet->marker);

	if ((packet->comment_size + packet->version_size + packet->charset_size + packet->message_id_size) == 0)
	{
		// No headers present
		return pos;
	}

	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Headers:\n");

	pos += pgp_armor_header_print("Version", packet->version, packet->version_size, PTR_OFFSET(str, pos), size - pos, 2);
	pos += pgp_armor_header_print("Comment", packet->comment, packet->comment_size, PTR_OFFSET(str, pos), size - pos, 2);
	pos += pgp_armor_header_print("Charset", packet->charset, packet->charset_size, PTR_OFFSET(str, pos), size - pos, 2);
	pos += pgp_armor_header_print("MessageID", packet->message_id, packet->message_id_size, PTR_OFFSET(str, pos), size - pos, 2);

	return pos;
}

size_t pgp_partial_packet_print(pgp_partial_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	if (packet->header.partial_continue)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Partial Packet (continue) (%zu bytes)\n", packet->header.body_size);
	}

	if (packet->header.partial_end)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Partial Packet (end) (%zu bytes)\n", packet->header.body_size);
	}

	return pos;
}

size_t pgp_unknown_packet_print(pgp_unknown_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, str, size);
	pos += print_format(1, PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->header.body_size);

	return pos;
}
