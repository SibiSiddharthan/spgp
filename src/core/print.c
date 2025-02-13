/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <seipd.h>
#include <session.h>
#include <signature.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static size_t print_bytes(void *str, size_t str_size, void *data, size_t data_size, uint16_t offset, uint16_t columns)
{
	byte_t *out = str;

	uint16_t row = 0;
	size_t pos = 0;

	if (str_size < (data_size * 3) + ((offset + 1) * (data_size / columns)))
	{
		return 0;
	}

	for (uint32_t i = 0; i < data_size; ++i)
	{
		byte_t a, b;

		a = ((byte_t *)data)[i] / 16;
		b = ((byte_t *)data)[i] % 16;

		if (row != 0)
		{
			memset(PTR_OFFSET(str, pos), ' ', offset);
			pos += offset;
		}

		out[pos++] = hex_table[a];
		out[pos++] = hex_table[b];

		if ((i + 1) % columns != 0)
		{
			out[pos++] = ' ';
		}
		else
		{
			out[pos++] = '\n';
			row += 1;
		}
	}

	// Only add a newline if the last character is not one.
	if (out[pos - 1] != '\n')
	{
		out[pos++] = '\n';
	}

	return pos;
}

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

static size_t pgp_packet_header_print(pgp_packet_header header, void *str, size_t size, uint32_t indent)
{
	pgp_packet_header_format format = PGP_PACKET_HEADER_FORMAT(header.tag);
	pgp_packet_type type = pgp_packet_get_type(header.tag);

	char *footer = NULL;
	size_t pos = 0;

	pos += print_indent(indent, str, size);

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
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Symmetrically Encrypted Data Packet (Tag 9)");
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
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Modification Detection Code Packet (Tag 19)");
		break;
	case PGP_PADDING:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Padding Packet (Tag 21)");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Packet (Tag %hhu)", header.tag);
	}

	// Add packet size
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, " (%u bytes)", header.body_size);

	// Mention if packet is having legacy header format
	if (format == PGP_LEGACY_HEADER)
	{
		footer = " (Old)";
	}
	else
	{
		footer = "";
	}

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "%s\n", footer);

	return pos;
}

static size_t pgp_public_key_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Public-Key Algorithm: ");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA Encrypt (Tag 1)\n");
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
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Public Key Algorithm (Tag %hhu)\n", algorithm);
		break;
	}

	return pos;
}

static size_t pgp_signature_algorithm_print(pgp_public_key_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Signature Algorithm: ");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "RSA Encrypt (Tag 1)\n");
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
	case PGP_EDDSA_LEGACY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "EdDSA (Legacy) (Tag 22)\n");
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

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Cipher Algorithm: ");

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
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Twofish (Tag 10)\n");
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

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "AEAD Algorithm: ");

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

static size_t pgp_hash_algorithm_print(pgp_hash_algorithms algorithm, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Hash Algorithm: ");

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

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Compression Algorithm: ");

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

static size_t pgp_s2k_print(pgp_s2k *s2k, void *str, size_t size, uint32_t indent)
{
	size_t pos = 0;

	pos += print_indent(indent, str, size);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "S2K Specifier: ");

	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Simple S2K (Tag 0)\n");
		pos += pgp_hash_algorithm_print(s2k->simple.hash_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		break;
	case PGP_S2K_SALTED:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Salted S2K (Tag 1)\n");
		pos += pgp_hash_algorithm_print(s2k->simple.hash_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Salt: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, s2k->salted.salt, 8, 0, 8);
		break;
	case PGP_S2K_ITERATED:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Iterated and Salted S2K (Tag 3)\n");
		pos += pgp_hash_algorithm_print(s2k->simple.hash_id, PTR_OFFSET(str, pos), size - pos, indent + 1);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Salt: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, s2k->iterated.salt, 8, 0, 8);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Count: %hhu\n", s2k->iterated.count);
		break;
	case PGP_S2K_ARGON2:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Argon2 S2K (Tag 4)\n");
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Salt: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, s2k->argon2.salt, 16, 0, 16);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Iterations: %hhu\n", s2k->argon2.t);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Parallelism: %hhu\n", s2k->argon2.p);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Memory: %hhu\n", s2k->argon2.m);
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown S2K Specifier (Tag %hhu)\n", s2k->id);
		break;
	}

	return pos;
}

static size_t pgp_public_key_print(pgp_public_key_algorithms public_key_algorithm, void *public_key, void *str, size_t size)
{
	size_t pos = 0;

	switch (public_key_algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		break;
	case PGP_DSA:
		break;
	case PGP_ECDH:
		break;
	case PGP_ECDSA:
		break;
	case PGP_X25519:
		break;
	case PGP_X448:
		break;
	case PGP_ED25519:
		break;
	case PGP_ED448:
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Public Key Algorithm (Tag %hhu)\n", public_key_algorithm);
		break;
	}
	return pos;
}

static size_t pgp_private_key_print(pgp_public_key_algorithms public_key_algorithm, void *private_key, void *str, size_t size)
{
	size_t pos = 0;

	switch (public_key_algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		break;
	case PGP_DSA:
		break;
	case PGP_ECDH:
		break;
	case PGP_ECDSA:
		break;
	case PGP_X25519:
		break;
	case PGP_X448:
		break;
	case PGP_ED25519:
		break;
	case PGP_ED448:
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Public Key Algorithm (Tag %hhu)\n", public_key_algorithm);
		break;
	}
	return pos;
}

static size_t pgp_signature_type_print(pgp_signature_type type, void *str, size_t size)
{
	size_t pos = 0;

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

size_t pgp_pkesk_packet_print(pgp_pkesk_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	if (packet->version == PGP_PKESK_V6)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: 6\n");

		switch (packet->key_version)
		{
		case PGP_KEY_V2:
		case PGP_KEY_V3:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu (Deprecated)\n", packet->key_version);
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Fingerprint: ");
			pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->key_fingerprint, PGP_KEY_V3_FINGERPRINT_SIZE, 0,
							   PGP_KEY_V3_FINGERPRINT_SIZE);
			break;
		case PGP_KEY_V4:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", packet->key_version);
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Fingerprint: ");
			pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->key_fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE, 0,
							   PGP_KEY_V4_FINGERPRINT_SIZE);
			break;
		case PGP_KEY_V6:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu\n", packet->key_version);
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Fingerprint: ");
			pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE, 0,
							   PGP_KEY_V6_FINGERPRINT_SIZE);
			break;
		default:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Version: %hhu (Unknown)\n", packet->key_version);
			break;
		}

		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
	}
	else if (packet->version == PGP_PKESK_V3)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: 3 (Deprecated)\n");
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);

		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key ID: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->key_id, 8, 0, 8);
	}
	else
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_skesk_packet_print(pgp_skesk_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	if (packet->version == PGP_SKESK_V6)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: 6\n");
		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 1);

		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "IV: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->iv, packet->iv_size, 0, packet->iv_size);

		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Tag: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->tag, packet->tag_size, 0, packet->tag_size);

		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Encrypted Session Key: ");
		pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->session_key, packet->session_key_size, 0, packet->session_key_size);
	}
	else if (packet->version == PGP_SKESK_V4)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: 4 (Deprecated)\n");
		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_s2k_print(&packet->s2k, PTR_OFFSET(str, pos), size - pos, 1);

		if (packet->session_key_size > 0)
		{
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Encrypted Session Key: ");
			pos +=
				print_bytes(PTR_OFFSET(str, pos), size - pos, packet->session_key, packet->session_key_size, 0, packet->session_key_size);
		}
	}
	else
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_signature_packet_print(pgp_signature_packet *packet, void *ptr, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, ptr, size, 0);

	return pos;
}

size_t pgp_one_pass_signature_packet_print(pgp_one_pass_signature_packet *packet, void *ptr, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, ptr, size, 0);

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Version: 6\n");
		pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos);
		pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);

		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Salt: ");
		pos += print_bytes(PTR_OFFSET(ptr, pos), size - pos, packet->salt, packet->salt_size, 0, packet->salt_size);

		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Key Fingerprint: ");
		pos += print_bytes(PTR_OFFSET(ptr, pos), size - pos, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE, 0,
						   PGP_KEY_V6_FINGERPRINT_SIZE);

		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Nested: %s\n", packet->nested ? "Yes" : "No");
	}
	else if (packet->version == PGP_ONE_PASS_SIGNATURE_V3)
	{
		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Version: 3 (Deprecated)\n");
		pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos);
		pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
		pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);

		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Key ID: ");
		pos += print_bytes(PTR_OFFSET(ptr, pos), size - pos, packet->key_id, 8, 0, 8);

		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Nested: %s\n", packet->nested ? "Yes" : "No");
	}
	else
	{
		pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Version: %hhu\n", packet->version);
	pos += pgp_signature_type_print(packet->type, PTR_OFFSET(ptr, pos), size - pos);
	pos += pgp_hash_algorithm_print(packet->hash_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
	pos += pgp_signature_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(ptr, pos), size - pos, 1);
	pos += snprintf(PTR_OFFSET(ptr, pos), size - pos, "Key ID: ");
	pos += print_bytes(PTR_OFFSET(ptr, pos), size - pos, packet->key_id, 8, 0, 8);

	return pos;
}

size_t pgp_public_key_packet_print(pgp_public_key_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V4)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu\n", packet->version);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Creation Time : %u\n", packet->key_creation_time);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->key_data, PTR_OFFSET(str, pos), size - pos);
	}
	else if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Deprecated)\n", packet->version);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Creation Time : %u\n", packet->key_creation_time);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Expiry : %hu days\n", packet->key_expiry_days);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->key_data, PTR_OFFSET(str, pos), size - pos);
	}
	else
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_secret_key_packet_print(pgp_secret_key_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V4)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu\n", packet->version);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Creation Time : %u\n", packet->key_creation_time);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->public_key_data, PTR_OFFSET(str, pos), size - pos);
		pos += pgp_private_key_print(packet->public_key_algorithm_id, packet->private_key_data, PTR_OFFSET(str, pos), size - pos);
	}
	else if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Version: %hhu (Deprecated)\n", packet->version);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Creation Time : %u\n", packet->key_creation_time);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Key Expiry : %hu days\n", packet->key_expiry_days);
		pos += pgp_public_key_algorithm_print(packet->public_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_public_key_print(packet->public_key_algorithm_id, packet->public_key_data, PTR_OFFSET(str, pos), size - pos);
		pos += pgp_private_key_print(packet->public_key_algorithm_id, packet->private_key_data, PTR_OFFSET(str, pos), size - pos);
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

	pos += pgp_packet_header_print(packet->header, str, size, 0);
	pos += pgp_compression_algorithm_print(packet->compression_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->header.body_size - 1);

	return pos;
}

size_t pgp_sed_packet_print(pgp_sed_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

size_t pgp_marker_packet_print(pgp_marker_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Marker: %c%c%c\n", packet->marker[0], packet->marker[1], packet->marker[2]);

	return pos;
}

size_t pgp_literal_packet_print(pgp_literal_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Format: ");

	switch (packet->format)
	{
	case PGP_LITERAL_DATA_BINARY:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Binary (Tag 0)\n");
		break;
	case PGP_LITERAL_DATA_TEXT:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Text (Tag 1)\n");
		break;
	case PGP_LITERAL_DATA_UTF8:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "UTF-8 (Tag 2)\n");
		break;
	default:
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown (Tag %hhu)\n", packet->format);
	}

	// TODO format date
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "\nDate: %u\n", packet->date);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Filename (%u bytes): ", packet->filename_size);

	if (packet->filename_size > 0)
	{
		memcpy(PTR_OFFSET(str, pos), packet->filename, packet->filename_size);
		pos += packet->filename_size;
	}

	out[pos++] = '\n';

	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Data (%u bytes)\n", packet->data_size);

	return pos;
}

size_t pgp_trust_packet_print(pgp_trust_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Trust Level: %hhu\n", packet->level);

	return pos;
}

size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	memcpy(PTR_OFFSET(str, pos), "User ID: ", 9);
	pos += 9;

	memcpy(PTR_OFFSET(str, pos), packet->user_data, packet->header.body_size);
	pos += packet->header.body_size;

	out[pos++] = '\n';

	return pos;
}

size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	for (uint16_t i = 0; i < packet->subpacket_count; ++i)
	{
		pgp_subpacket_header *subpacket_header = packet->subpackets[i];

		switch (subpacket_header->tag)
		{
		case PGP_USER_ATTRIBUTE_IMAGE:
		{
			pgp_user_attribute_image_subpacket *image_subpacket = (pgp_user_attribute_image_subpacket *)subpacket_header;
			uint32_t image_size = image_subpacket->header.body_size - 16;

			memcpy(PTR_OFFSET(str, pos), "User Attribute Image Subpacket (Tag 1)\n", 39);
			pos += 39;

			switch (image_subpacket->image_encoding)
			{
			case PGP_USER_ATTRIBUTE_IMAGE_JPEG:
			{
				memcpy(PTR_OFFSET(str, pos), "Image Encoding: JPEG (Tag 1)\n", 30);
				pos += 30;
			}
			break;
			default:
				pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Image Encoding (Tag %hhu)\n", image_subpacket->image_encoding);
			}

			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Image Size: %u bytes\n", image_size);
		}
		break;
		default:
			pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Unknown Subpacket (Tag %hhu) (%u bytes)\n", subpacket_header->tag,
							subpacket_header->body_size);
		}
	}

	return pos;
}

size_t pgp_seipd_packet_print(pgp_seipd_packet *packet, void *str, size_t size)
{
	byte_t *out = str;
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);

	memcpy(PTR_OFFSET(str, pos), "Version: ", 9);
	pos += 9;

	if (packet->version == PGP_SEIPD_V2)
	{
		memcpy(PTR_OFFSET(str, pos), "2\n", 2);
		pos += 2;

		pos += pgp_symmetric_key_algorithm_print(packet->symmetric_key_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += pgp_aead_algorithm_print(packet->aead_algorithm_id, PTR_OFFSET(str, pos), size - pos, 1);
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Chunk Size: %hhu\n", packet->chunk_size);

		memcpy(PTR_OFFSET(str, pos), "Salt: ", 6);
		pos += 6;

		for (uint8_t i = 0; i < 32; ++i)
		{
			byte_t a, b;

			a = packet->salt[i] / 16;
			b = packet->salt[i] % 16;

			out[pos++] = hex_table[a];
			out[pos++] = hex_table[b];
		}

		out[pos] = '\n';
		pos += 1;

		memcpy(PTR_OFFSET(str, pos), "Tag: ", 5);
		pos += 5;

		for (uint8_t i = 0; i < 16; ++i)
		{
			byte_t a, b;

			a = packet->tag[i] / 16;
			b = packet->tag[i] % 16;

			out[pos++] = hex_table[a];
			out[pos++] = hex_table[b];
		}

		out[pos] = '\n';
		pos += 1;

		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->data_size);
	}
	else if (packet->version == PGP_SEIPD_V1)
	{
		memcpy(PTR_OFFSET(str, pos), "1\n", 2);
		pos += 2;

		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Encrypted Data (%u bytes)\n", packet->header.body_size - 1);
	}
	else
	{
		pos += snprintf(PTR_OFFSET(str, pos), size - pos, "%hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "SHA-1 Hash: ");
	pos += print_bytes(PTR_OFFSET(str, pos), size - pos, packet->sha1_hash, 20, 0, 20);

	return pos;
}

size_t pgp_padding_packet_print(pgp_padding_packet *packet, void *str, size_t size)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(packet->header, str, size, 0);
	pos += snprintf(PTR_OFFSET(str, pos), size - pos, "Padding Data (%u bytes)\n", packet->header.body_size);

	return pos;
}
