/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <pgp/pgp.h>
#include <pgp/algorithms.h>
#include <pgp/packet.h>
#include <pgp/seipd.h>
#include <pgp/session.h>
#include <pgp/signature.h>
#include <pgp/crypto.h>

#include <print.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static size_t pgp_signature_packet_body_print(pgp_signature_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options);

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

static size_t print_key(buffer_t *buffer, uint32_t indent, void *data, size_t size)
{
	if (size == PGP_KEY_ID_SIZE)
	{
		return print_format(buffer, indent, "Key ID: %^R\n", data, size);
	}

	return print_format(buffer, indent, "Key Fingerprint: %^R\n", data, size);
}

static size_t print_mpi(buffer_t *buffer, uint32_t indent, uint32_t options, char *prefix, mpi_t *mpi)
{
	if (options & PGP_PRINT_MPI_MINIMAL)
	{
		return print_format(buffer, indent, "%s (%hu bits): ...\n", prefix, mpi->bits);
	}

	return print_format(buffer, indent, "%s (%hu bits): %R\n", prefix, mpi->bits, mpi->bytes, CEIL_DIV(mpi->bits, 8));
}

static size_t print_timestamp(buffer_t *buffer, uint32_t indent, char *prefix, time_t timestamp)
{
	size_t pos = 0;
	char date_buffer[64] = {0};

	strftime(date_buffer, 64, "%B %d, %Y, %I:%M:%S %p (%z)", localtime(&timestamp));
	pos += print_format(buffer, indent, "%s: %s\n", prefix, date_buffer);

	return pos;
}

static const char *pgp_packet_header_name(pgp_packet_type type)
{
	switch (type)
	{
	case PGP_PKESK:
		return "Public Key Encrypted Session Key Packet";
	case PGP_SIG:
		return "Signature Packet";
	case PGP_SKESK:
		return "Symmetric Key Encrypted Session Key Packet";
	case PGP_OPS:
		return "One-Pass Signature Packet";
	case PGP_SECKEY:
		return "Secret Key Packet";
	case PGP_PUBKEY:
		return "Public Key Packet";
	case PGP_SECSUBKEY:
		return "Secret Subkey Packet";
	case PGP_COMP:
		return "Compressed Data Packet";
	case PGP_SED:
		return "Symmetrically Encrypted Data Packet (Obsolete)";
	case PGP_MARKER:
		return "Marker Packet";
	case PGP_LIT:
		return "Literal Data Packet";
	case PGP_TRUST:
		return "Trust Packet";
	case PGP_UID:
		return "User ID Packet";
	case PGP_PUBSUBKEY:
		return "Public Subkey Packet";
	case PGP_UAT:
		return "User Attribute Packet";
	case PGP_SEIPD:
		return "Symmetrically Encrypted and Integrity Protected Data Packet";
	case PGP_MDC:
		return "Modification Detection Code Packet (Deprecated)";
	case PGP_AEAD:
		return "Authenticated Encryption Data Packet Packet";
	case PGP_PADDING:
		return "Padding Packet";
	case PGP_KEYDEF:
		return "Key definition Packet (Private)";
	case PGP_KEYRING:
		return "Keyring Packet (Private)";
	case PGP_ARMOR:
		return "Armor Packet (Private)";
	default:
		return "Unknown Packet";
	}
}

size_t pgp_packet_header_print(pgp_packet_header *header, buffer_t *buffer, uint32_t indent)
{
	pgp_packet_header_format format = PGP_PACKET_HEADER_FORMAT(header->tag);
	pgp_packet_type type = pgp_packet_type_from_tag(header->tag);

	const char *name = pgp_packet_header_name(type);
	const char *old = NULL;
	const char *partial = NULL;

	if (header->partial_continue || header->partial_end)
	{
		return pgp_partial_packet_print((pgp_partial_packet *)header, buffer, indent);
	}

	// Mention if packet is having legacy header format
	if (format == PGP_LEGACY_HEADER)
	{
		old = " (Old)";
	}

	// Mention if packet is having partial data
	if (header->partial)
	{
		partial = " (Partial)";
	}

	return print_format(buffer, indent, "%s (Tag %hhu) (%zu bytes)%s%s\n", name, type, header->body_size, old, partial);
}

static size_t pgp_public_key_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_public_key_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		name = "RSA Encrypt or Sign";
		break;
	case PGP_RSA_ENCRYPT_ONLY:
		name = "RSA (Encrypt Only)";
		break;
	case PGP_RSA_SIGN_ONLY:
		name = "RSA (Sign Only)";
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		name = "Elgamal (Encrypt Only)";
		break;
	case PGP_DSA:
		name = "DSA";
		break;
	case PGP_ECDH:
		name = "ECDH";
		break;
	case PGP_ECDSA:
		name = "ECDSA";
		break;
	case PGP_EDDSA:
		name = "EdDSA";
		break;
	case PGP_X25519:
		name = "X25519";
		break;
	case PGP_X448:
		name = "X448";
		break;
	case PGP_ED25519:
		name = "Ed25519";
		break;
	case PGP_ED448:
		name = "Ed448";
		break;
	default:
		name = "Unknown Public Key Algorithm";
		break;
	}

	return print_format(buffer, indent, "Public-Key Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_kex_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_public_key_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		name = "RSA Encrypt or Sign";
		break;
	case PGP_RSA_ENCRYPT_ONLY:
		name = "RSA (Encrypt Only)";
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		name = "Elgamal (Encrypt Only)";
		break;
	case PGP_ECDH:
		name = "ECDH";
		break;
	case PGP_X25519:
		name = "X25519";
		break;
	case PGP_X448:
		name = "X448";
		break;
	default:
		name = "Unknown Key Exchange Algorithm";
		break;
	}

	return print_format(buffer, indent, "Key Exchange Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_signature_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_public_key_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
		name = "RSA Encrypt or Sign";
		break;
	case PGP_RSA_SIGN_ONLY:
		name = "RSA (Sign Only)";
		break;
	case PGP_DSA:
		name = "DSA";
		break;
	case PGP_ECDSA:
		name = "ECDSA";
		break;
	case PGP_EDDSA:
		name = "EdDSA";
		break;
	case PGP_ED25519:
		name = "Ed25519";
		break;
	case PGP_ED448:
		name = "Ed448";
		break;
	default:
		name = "Unknown Signature algorithm";
		break;
	}

	return print_format(buffer, indent, "Signature Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_symmetric_key_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_symmetric_key_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_PLAINTEXT:
		name = "Plaintext";
		break;
	case PGP_IDEA:
		name = "IDEA";
		break;
	case PGP_TDES:
		name = "TDES";
		break;
	case PGP_CAST5_128:
		name = "CAST5";
		break;
	case PGP_BLOWFISH:
		name = "Blowfish";
		break;
	case PGP_AES_128:
		name = "AES-128";
		break;
	case PGP_AES_192:
		name = "AES-192";
		break;
	case PGP_AES_256:
		name = "AES-256";
		break;
	case PGP_TWOFISH:
		name = "Twofish-256";
		break;
	case PGP_CAMELLIA_128:
		name = "Camellia-128";
		break;
	case PGP_CAMELLIA_192:
		name = "Camellia-192";
		break;
	case PGP_CAMELLIA_256:
		name = "Camellia-256";
		break;
	default:
		name = "Unknown Symmetric Key Algorithm";
		break;
	}

	return print_format(buffer, indent, "Cipher Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_aead_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_aead_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_AEAD_EAX:
		name = "EAX";
		break;
	case PGP_AEAD_OCB:
		name = "OCB";
		break;
	case PGP_AEAD_GCM:
		name = "GCM";
		break;
	default:
		name = "Unknown AEAD Algorithm";
		break;
	}

	return print_format(buffer, indent, "AEAD Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_cipher_aead_algorithm_pair_print(buffer_t *buffer, uint32_t indent, pgp_symmetric_key_algorithms cipher_algorithm,
												   pgp_aead_algorithms aead_algorithm)
{
	const char *cipher_name = NULL;
	const char *aead_name = NULL;

	switch (cipher_algorithm)
	{
	case PGP_PLAINTEXT:
		cipher_name = "Plaintext";
		break;
	case PGP_IDEA:
		cipher_name = "IDEA";
		break;
	case PGP_TDES:
		cipher_name = "TDES";
		break;
	case PGP_CAST5_128:
		cipher_name = "CAST5";
		break;
	case PGP_BLOWFISH:
		cipher_name = "Blowfish";
		break;
	case PGP_AES_128:
		cipher_name = "AES-128";
		break;
	case PGP_AES_192:
		cipher_name = "AES-192";
		break;
	case PGP_AES_256:
		cipher_name = "AES-256";
		break;
	case PGP_TWOFISH:
		cipher_name = "Twofish-256";
		break;
	case PGP_CAMELLIA_128:
		cipher_name = "Camellia-128";
		break;
	case PGP_CAMELLIA_192:
		cipher_name = "Camellia-192";
		break;
	case PGP_CAMELLIA_256:
		cipher_name = "Camellia-256";
		break;
	default:
		cipher_name = "Unknown";
		break;
	}

	switch (aead_algorithm)
	{
	case PGP_AEAD_EAX:
		aead_name = "EAX";
		break;
	case PGP_AEAD_OCB:
		aead_name = "OCB";
		break;
	case PGP_AEAD_GCM:
		aead_name = "GCM";
		break;
	default:
		aead_name = "Unknown";
		break;
	}

	return print_format(buffer, indent, "AEAD Ciphersuite: %s %s (%hhu %hhu)\n", cipher_name, aead_name, cipher_algorithm, aead_algorithm);
}

static size_t pgp_hash_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_hash_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_MD5:
		name = "MD5";
		break;
	case PGP_SHA1:
		name = "SHA-1";
		break;
	case PGP_RIPEMD_160:
		name = "RIPEMD-160";
		break;
	case PGP_SHA2_256:
		name = "SHA-256";
		break;
	case PGP_SHA2_384:
		name = "SHA-384";
		break;
	case PGP_SHA2_512:
		name = "SHA-512";
		break;
	case PGP_SHA2_224:
		name = "SHA-224";
		break;
	case PGP_SHA3_256:
		name = "SHA3-256";
		break;
	case PGP_SHA3_512:
		name = "SHA3-512";
		break;
	default:
		name = "Unknown Hash Algorithm";
		break;
	}

	return print_format(buffer, indent, "Hash Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_compression_algorithm_print(buffer_t *buffer, uint32_t indent, pgp_compression_algorithms algorithm)
{
	const char *name = NULL;

	switch (algorithm)
	{
	case PGP_UNCOMPRESSED:
		name = "Uncompressed";
		break;
	case PGP_DEFALTE:
		name = "Deflate";
		break;
	case PGP_ZLIB:
		name = "ZLIB";
		break;
	case PGP_BZIP2:
		name = "BZIP2";
		break;
	default:
		name = "Unknown";
		break;
	}

	return print_format(buffer, indent, "Compression Algorithm: %s (Tag %hhu)\n", name, algorithm);
}

static size_t pgp_curve_print(buffer_t *buffer, uint32_t indent, pgp_elliptic_curve_id curve, byte_t *oid, byte_t size)
{
	size_t pos = 0;

	pos += print_format(buffer, indent, "Elliptic Curve: ");

	switch (curve)
	{
	case PGP_EC_NIST_P256:
		pos += xprint(buffer, "NIST-P256 (2A 86 48 CE 3D 03 01 07)\n");
		break;
	case PGP_EC_NIST_P384:
		pos += xprint(buffer, "NIST-P384 (2B 81 04 00 22)\n");
		break;
	case PGP_EC_NIST_P521:
		pos += xprint(buffer, "NIST-P521 (2B 81 04 00 23)\n");
		break;
	case PGP_EC_BRAINPOOL_256R1:
		pos += xprint(buffer, "BRAINPOOL-P256R1 (2B 24 03 03 02 08 01 01 07)\n");
		break;
	case PGP_EC_BRAINPOOL_384R1:
		pos += xprint(buffer, "BRAINPOOL-P384R1 (2B 24 03 03 02 08 01 01 0B)\n");
		break;
	case PGP_EC_BRAINPOOL_512R1:
		pos += xprint(buffer, "BRAINPOOL-P512R1 (2B 24 03 03 02 08 01 01 0D)\n");
		break;
	case PGP_EC_CURVE25519:
	{
		if (size == 10)
		{
			pos += xprint(buffer, "Curve25519 (2B 06 01 04 01 97 55 01 05 01) (Legacy OID)\n");
		}
		else
		{
			pos += xprint(buffer, "Curve25519 (2B 65 6E)\n");
		}
	}
	break;
	case PGP_EC_CURVE448:
		pos += xprint(buffer, "Curve448 (2B 65 6F)\n");
		break;
	case PGP_EC_ED25519:
	{
		if (size == 9)
		{
			pos += xprint(buffer, "Ed25519 (2B 06 01 04 01 DA 47 0F 01) (Legacy OID)\n");
		}
		else
		{
			pos += xprint(buffer, "Ed25519 (2B 65 70)\n");
		}
	}
	break;
	case PGP_EC_ED448:
		pos += xprint(buffer, "Ed448 (2B 65 71)\n");
		break;
	default:
	{
		pos += xprint(buffer, "Unknown (% A[%^02hhx])\n", oid, size);
	}
	break;
	}

	return pos;
}

static size_t pgp_s2k_print(buffer_t *buffer, uint32_t indent, pgp_s2k *s2k)
{
	const char *name = NULL;
	size_t pos = 0;

	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
		name = "Simple S2K";
		break;
	case PGP_S2K_SALTED:
		name = "Salted S2K";
		break;
	case PGP_S2K_ITERATED:
		name = "Iterated and Salted S2K";
		break;
	case PGP_S2K_ARGON2:
		name = "Argon2 S2K";
		break;
	default:
		name = "Unknown S2K Specifier";
		break;
	}

	pos += print_format(buffer, indent, "S2K Specifier: %s (Tag %hhu)\n", name, s2k->id);

	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
		pos += pgp_hash_algorithm_print(buffer, indent + 1, s2k->simple.hash_id);
		break;
	case PGP_S2K_SALTED:
		pos += pgp_hash_algorithm_print(buffer, indent + 1, s2k->simple.hash_id);
		pos += print_format(buffer, indent + 1, "Salt: %R\n", s2k->salted.salt, 8);
		break;
	case PGP_S2K_ITERATED:
		pos += pgp_hash_algorithm_print(buffer, indent + 1, s2k->simple.hash_id);
		pos += print_format(buffer, indent + 1, "Salt: %R\n", s2k->iterated.salt, 8);
		pos += print_format(buffer, indent + 1, "Count: %u (Code %hhu)\n", IT_COUNT(s2k->iterated.count), s2k->iterated.count);
		break;
	case PGP_S2K_ARGON2:
		pos += print_format(buffer, indent + 1, "Salt: %R\n", s2k->argon2.salt, 16);
		pos += print_format(buffer, indent + 1, "Iterations: %hhu\n", s2k->argon2.t);
		pos += print_format(buffer, indent + 1, "Parallelism: %hhu\n", s2k->argon2.p);
		pos += print_format(buffer, indent + 1, "Memory: %hhu\n", s2k->argon2.m);
		break;
	default:
		pos += xprint(buffer, "Unknown S2K Specifier (Tag %hhu)\n", s2k->id);
		break;
	}

	return pos;
}

static size_t pgp_trust_print(buffer_t *buffer, uint32_t indent, pgp_trust_level trust)
{
	switch (trust)
	{
	case PGP_TRUST_NEVER:
		return print_format(buffer, indent, "Trust Level: Never\n");
	case PGP_TRUST_REVOKED:
		return print_format(buffer, indent, "Trust Level: Revoked\n");
	case PGP_TRUST_MARGINAL:
		return print_format(buffer, indent, "Trust Level: Marginal\n");
	case PGP_TRUST_FULL:
		return print_format(buffer, indent, "Trust Level: Full\n");
	case PGP_TRUST_ULTIMATE:
		return print_format(buffer, indent, "Trust Level: Ultimate\n");
	default:
		return print_format(buffer, indent, "Trust Level: Unknown\n");
	}
}

static size_t pgp_kdf_print(buffer_t *buffer, uint32_t indent, void *kdf)
{
	byte_t *in = kdf;
	size_t pos = 0;

	byte_t hash_algorithm_id = in[2];
	byte_t symmetric_key_algorithm_id = in[3];

	pos += print_format(buffer, indent, "ECDH KDF Parameters\n");
	pos += pgp_hash_algorithm_print(buffer, indent + 1, hash_algorithm_id);
	pos += pgp_symmetric_key_algorithm_print(buffer, indent + 1, symmetric_key_algorithm_id);

	return pos;
}

static size_t pgp_kex_print(buffer_t *buffer, uint32_t indent, uint32_t options, pgp_public_key_algorithms algorithm, void *kex,
							uint16_t size)
{
	size_t pos = 0;

	pos += print_format(buffer, indent, "Exchange Material\n");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	{
		pgp_rsa_kex *sk = kex;
		pos += print_mpi(buffer, indent + 1, options, "RSA m^e mod n", sk->c);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_kex *sk = kex;
		pos += print_mpi(buffer, indent + 1, options, "Elgamal g^k mod p", sk->r);
		pos += print_mpi(buffer, indent + 1, options, "Elgamal m*(y^k) mod p", sk->r);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_kex *sk = kex;
		pos += print_mpi(buffer, indent + 1, options, "ECDH Ephemeral Point", sk->ephemeral_point);
		pos += print_format(buffer, indent + 1, "ECDH Encrypted Session Key: %R\n", sk->encoded_session_key, sk->encoded_session_key_size);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_kex *sk = kex;
		byte_t octet_count = sk->octet_count;

		if (sk->symmetric_key_algorithm_id != 0)
		{
			pos += pgp_symmetric_key_algorithm_print(buffer, indent, sk->symmetric_key_algorithm_id);
			octet_count -= 1;
		}

		pos += print_format(buffer, indent + 1, "X25519 Ephemeral Key: %R\n", sk->ephemeral_key, 32);
		pos += print_format(buffer, indent + 1, "X25519 Encrypted Session Key: %R\n", sk->encrypted_session_key, octet_count);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_kex *sk = kex;
		byte_t octet_count = sk->octet_count;

		if (sk->symmetric_key_algorithm_id != 0)
		{
			pos += pgp_symmetric_key_algorithm_print(buffer, indent, sk->symmetric_key_algorithm_id);
			octet_count -= 1;
		}

		pos += print_format(buffer, indent + 1, "X448 Ephemeral Key: %R\n", sk->ephemeral_key, 56);
		pos += print_format(buffer, indent + 1, "X448 Encrypted Session Key: %R\n", sk->encrypted_session_key, octet_count);
	}
	break;
	default:
	{
		pos += print_format(buffer, indent + 1, "Unknown Session Key Material (%hu bytes)\n", size);
	}
	break;
	}

	return pos;
}

static size_t pgp_signature_print(buffer_t *buffer, uint32_t indent, uint32_t options, pgp_public_key_algorithms algorithm, void *sign,
								  uint16_t size)
{
	size_t pos = 0;

	pos += print_format(buffer, indent, "Signature Material\n");

	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_signature *sg = sign;
		pos += print_mpi(buffer, indent + 1, options, "RSA m^d mod n", sg->e);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_signature *sg = sign;
		pos += print_mpi(buffer, indent + 1, options, "DSA r", sg->r);
		pos += print_mpi(buffer, indent + 1, options, "DSA s", sg->s);
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_signature *sg = sign;
		pos += print_mpi(buffer, indent + 1, options, "ECDSA r", sg->r);
		pos += print_mpi(buffer, indent + 1, options, "ECDSA s", sg->s);
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_signature *sg = sign;
		pos += print_mpi(buffer, indent + 1, options, "EdDSA r", sg->r);
		pos += print_mpi(buffer, indent + 1, options, "EdDSA s", sg->s);
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_signature *sg = sign;
		pos += print_format(buffer, indent + 1, "Ed25519 Signature: %R\n", sg->sig, 64);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_signature *sg = sign;
		pos += print_format(buffer, indent + 1, "Ed448 Signature: %R\n", sg->sig, 114);
	}
	break;
	default:
	{
		pos += print_format(buffer, indent + 1, "Unknown Signature Material (%hu bytes)\n", size);
	}
	break;
	}
	return pos;
}

static size_t pgp_public_key_print(buffer_t *buffer, uint32_t indent, uint32_t options, pgp_public_key_algorithms public_key_algorithm,
								   void *public_key, uint16_t public_key_size)
{
	size_t pos = 0;

	pos += print_format(buffer, indent, "Key Material:\n");

	switch (public_key_algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = public_key;
		pos += print_mpi(buffer, indent + 1, options, "RSA modulus n", key->n);
		pos += print_mpi(buffer, indent + 1, options, "RSA public exponent e", key->e);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = public_key;
		pos += print_mpi(buffer, indent + 1, options, "Elgamal prime p", key->p);
		pos += print_mpi(buffer, indent + 1, options, "Elgamal group generator g", key->g);
		pos += print_mpi(buffer, indent + 1, options, "Elgamal public key y", key->y);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = public_key;
		pos += print_mpi(buffer, indent + 1, options, "DSA prime p", key->p);
		pos += print_mpi(buffer, indent + 1, options, "DSA group order q", key->q);
		pos += print_mpi(buffer, indent + 1, options, "DSA group generator g", key->g);
		pos += print_mpi(buffer, indent + 1, options, "DSA public key y", key->y);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = public_key;
		pos += pgp_curve_print(buffer, indent + 1, key->curve, key->oid, key->oid_size);
		pos += print_mpi(buffer, indent + 1, options, "MPI of public point", key->point);
		pos += pgp_kdf_print(buffer, indent + 1, &key->kdf);
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = public_key;
		pos += pgp_curve_print(buffer, indent + 1, key->curve, key->oid, key->oid_size);
		pos += print_mpi(buffer, indent + 1, options, "MPI of public point", key->point);
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_key *key = public_key;
		pos += pgp_curve_print(buffer, indent + 1, key->curve, key->oid, key->oid_size);
		pos += print_mpi(buffer, indent + 1, options, "MPI of public point", key->point);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *key = public_key;
		pos += print_format(buffer, indent + 1, "X25519 Public Key: %R\n", key->public_key, 32);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *key = public_key;
		pos += print_format(buffer, indent + 1, "X448 Public Key: %R\n", key->public_key, 56);
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = public_key;
		pos += print_format(buffer, indent + 1, "Ed25519 Public Key: %R\n", key->public_key, 32);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *key = public_key;
		pos += print_format(buffer, indent + 1, "Ed448 Public Key: %R\n", key->public_key, 57);
	}
	break;
	default:
		pos += print_format(buffer, indent + 1, "Unknown Public Key Material (%hu bytes)\n", public_key_size);
		break;
	}

	return pos;
}

static size_t pgp_private_key_print(buffer_t *buffer, uint32_t indent, uint32_t options, pgp_public_key_algorithms public_key_algorithm,
									void *private_key, uint16_t private_key_size)
{
	size_t pos = 0;

	pos += pgp_public_key_print(buffer, indent, options, public_key_algorithm, private_key, private_key_size);

	switch (public_key_algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = private_key;

		if (key->d == NULL || key->p == NULL || key->q == NULL || key->u == NULL)
		{
			pos += print_format(buffer, indent + 1, "RSA secret exponent d (Encrypted)\n");
			pos += print_format(buffer, indent + 1, "RSA secret prime p (Encrypted)\n");
			pos += print_format(buffer, indent + 1, "RSA secret prime q (Encrypted)\n");
			pos += print_format(buffer, indent + 1, "RSA (1/p mod q) u (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(buffer, indent + 1, options, "RSA secret exponent d", key->d);
			pos += print_mpi(buffer, indent + 1, options, "RSA secret prime p", key->p);
			pos += print_mpi(buffer, indent + 1, options, "RSA secret prime q", key->q);
			pos += print_mpi(buffer, indent + 1, options, "RSA (1/p mod q) u", key->u);
		}
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(buffer, indent + 1, "Elgamal secret exponent x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(buffer, indent + 1, options, "Elgamal secret exponent x", key->x);
		}
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(buffer, indent + 1, "DSA secret exponent x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(buffer, indent + 1, options, "DSA secret exponent x", key->x);
		}
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(buffer, indent + 1, "ECDH secret scalar x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(buffer, indent + 1, options, "ECDH secret scalar x", key->x);
		}
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(buffer, indent + 1, "ECDSA secret scalar x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(buffer, indent + 1, options, "ECDSA secret scalar x", key->x);
		}
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_key *key = private_key;

		if (key->x == NULL)
		{
			pos += print_format(buffer, indent + 1, "EdDSA secret scalar x (Encrypted)\n");
		}
		else
		{
			pos += print_mpi(buffer, indent + 1, options, "EdDSA secret scalar x", key->x);
		}
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *key = private_key;
		byte_t zero[32] = {0};

		if (memcmp(zero, key->private_key, 32) == 0)
		{
			pos += print_format(buffer, indent + 1, "X25519 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_format(buffer, indent + 1, "X25519 Secret Key: %R\n", key->private_key, 32);
		}
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *key = private_key;
		byte_t zero[56] = {0};

		if (memcmp(zero, key->private_key, 56) == 0)
		{
			pos += print_format(buffer, indent + 1, "X448 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_format(buffer, indent + 1, "X448 Secret Key: %R\n", key->private_key, 56);
		}
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = private_key;
		byte_t zero[32] = {0};

		if (memcmp(zero, key->private_key, 32) == 0)
		{
			pos += print_format(buffer, indent + 1, "Ed25519 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_format(buffer, indent + 1, "Ed25519 Secret Key: %R\n", key->private_key, 32);
		}
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *key = private_key;
		byte_t zero[57] = {0};

		if (memcmp(zero, key->private_key, 57) == 0)
		{
			pos += print_format(buffer, indent + 1, "Ed448 Secret Key (Encrypted)\n");
		}
		else
		{
			pos += print_format(buffer, indent + 1, "Ed448 Secret Key: %R\n", key->private_key, 57);
		}
	}
	break;
	default:
		pos += print_format(buffer, indent + 1, "Unknown Secret Key Material (%hu bytes)\n", private_key_size);
		break;
	}

	return pos;
}

static size_t pgp_signature_type_print(buffer_t *buffer, uint32_t indent, pgp_signature_type type)
{
	const char *name = NULL;

	switch (type)
	{
	case PGP_BINARY_SIGNATURE:
		name = "Binary Signature";
		break;
	case PGP_TEXT_SIGNATURE:
		name = "Text Signature";
		break;
	case PGP_STANDALONE_SIGNATURE:
		name = "Standalone Signature";
		break;
	case PGP_GENERIC_CERTIFICATION_SIGNATURE:
		name = "Generic Certification Signature";
		break;
	case PGP_PERSONA_CERTIFICATION_SIGNATURE:
		name = "Persona Certification Signature";
		break;
	case PGP_CASUAL_CERTIFICATION_SIGNATURE:
		name = "Casual Certification Signature";
		break;
	case PGP_POSITIVE_CERTIFICATION_SIGNATURE:
		name = "Positive Certification Signature";
		break;
	case PGP_ATTESTED_KEY_SIGNATURE:
		name = "Attested Key Signature";
		break;
	case PGP_SUBKEY_BINDING_SIGNATURE:
		name = "Subkey Binding Signature";
		break;
	case PGP_PRIMARY_KEY_BINDING_SIGNATURE:
		name = "Primary Key Binding Signature";
		break;
	case PGP_DIRECT_KEY_SIGNATURE:
		name = "Direct Key Signature";
		break;
	case PGP_KEY_REVOCATION_SIGNATURE:
		name = "Key Revocation Signature";
		break;
	case PGP_SUBKEY_REVOCATION_SIGNATURE:
		name = "Subkey Revocation Signature";
		break;
	case PGP_CERTIFICATION_REVOCATION_SIGNATURE:
		name = "Certificate Revocation Signature";
		break;
	case PGP_TIMESTAMP_SIGNATURE:
		name = "Timestamp Signature";
		break;
	case PGP_THIRD_PARTY_CONFIRMATION_SIGNATURE:
		name = "Third Party Confirmation Signature";
		break;
	default:
		name = "Unknown Signature Type";
		break;
	}

	return print_format(buffer, indent, "Signature Type: %s (Tag %#^.2x)\n", name, type);
}

static const char *pgp_signature_subpacket_name(pgp_signature_subpacket_type type)
{
	switch (type)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
		return "Signature Creation Time";
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
		return "Signature Expiration Time";
	case PGP_EXPORTABLE_SUBPACKET:
		return "Exportable Certification";
	case PGP_TRUST_SIGNATURE_SUBPACKET:
		return "Trust Signature";
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
		return "Regular Expression";
	case PGP_REVOCABLE_SUBPACKET:
		return "Revocable";
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
		return "Key Expiration Time";
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
		return "Preferred Symmetric Ciphers";
	case PGP_REVOCATION_KEY_SUBPACKET:
		return "Revocation Key";
	case PGP_ISSUER_KEY_ID_SUBPACKET:
		return "Issuer Key ID";
	case PGP_NOTATION_DATA_SUBPACKET:
		return "Notation Data";
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
		return "Preferred Hash Algorithms";
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
		return "Preferred Compression Algorithms";
	case PGP_KEY_SERVER_PREFERENCES_SUBPACKET:
		return "Key Server Preferences";
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
		return "Preferred Key Server";
	case PGP_PRIMARY_USER_ID_SUBPACKET:
		return "Primary User ID";
	case PGP_POLICY_URI_SUBPACKET:
		return "Policy URI";
	case PGP_KEY_FLAGS_SUBPACKET:
		return "Key Flags";
	case PGP_SIGNER_USER_ID_SUBPACKET:
		return "Signer's User ID";
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
		return "Reason for Revocation";
	case PGP_FEATURES_SUBPACKET:
		return "Features";
	case PGP_SIGNATURE_TARGET_SUBPACKET:
		return "Signature Target";
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
		return "Embedded Signature";
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
		return "Issuer Fingerprint";
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
		return "Preferred Encryption Modes";
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
		return "Intended Recipient Fingerprint";
	case PGP_ATTESTED_CERTIFICATIONS_SUBPACKET:
		return "Attested Certifications";
	case PGP_KEY_BLOCK_SUBPACKET:
		return "Key Block";
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
		return "Preferred AEAD Ciphersuites";
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
		return "Literal Data Mesh";
	case PGP_TRUST_ALIAS_SUBPACKET:
		return "Trust Alias";
	default:
		return "Unkown Signature Subpacket";
	}
}

static size_t pgp_signature_subpacket_header_print(pgp_subpacket_header header, buffer_t *buffer, uint32_t indent)
{
	pgp_signature_subpacket_type type = header.tag & PGP_SUBPACKET_TAG_MASK;

	const char *name = pgp_signature_subpacket_name(type);
	const char *critical = NULL;
	const char *deprecated = NULL;

	// Add critical bit
	if (header.tag & 0x80)
	{
		critical = " (Critical)";
	}

	// Add deprecated notifcation
	if (type == PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET || type == PGP_ATTESTED_CERTIFICATIONS_SUBPACKET)
	{
		deprecated = " (Deprecated)";
	}

	return print_format(buffer, indent, "%s (Tag %hhu) (%zu bytes)%s%s\n", name, type, header.body_size, critical, deprecated);
}

static size_t pgp_signature_subpacket_print(void *subpacket, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	pgp_subpacket_header *header = subpacket;
	pgp_signature_subpacket_type type = header->tag & PGP_SUBPACKET_TAG_MASK;

	size_t pos = 0;

	// Print the header
	pos += pgp_signature_subpacket_header_print(*header, buffer, indent);

	switch (type)
	{
	case PGP_SIGNATURE_CREATION_TIME_SUBPACKET:
	{
		pgp_signature_creation_time_subpacket *timestamp_subpacket = subpacket;
		pos += print_timestamp(buffer, indent + 1, "Creation Time", timestamp_subpacket->timestamp);
	}
	break;
	case PGP_SIGNATURE_EXPIRY_TIME_SUBPACKET:
	{
		pgp_signature_expiry_time_subpacket *timestamp_subpacket = subpacket;
		uint32_t expiry_seconds = timestamp_subpacket->duration;

		if (expiry_seconds == 0)
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: Never\n");
		}
		else if ((expiry_seconds % 31536000) == 0)
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: %u years\n", expiry_seconds / 31536000);
		}
		else if ((expiry_seconds % 86400) == 0)
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: %u days\n", expiry_seconds / 86400);
		}
		else
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: %u seconds\n", expiry_seconds);
		}
	}
	break;
	case PGP_EXPORTABLE_SUBPACKET:
	{
		pgp_exportable_subpacket *exportable_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Exportable: %s\n", exportable_subpacket->state ? "Yes" : "No");
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

		pos += print_format(buffer, indent + 1, "Trust Level: %hhu (%s)\n", trust_subpacket->trust_level, level);
		pos += print_format(buffer, indent + 1, "Trust Amount: %hhu (%s)\n", trust_subpacket->trust_amount, amount);
	}
	break;
	case PGP_REGULAR_EXPRESSION_SUBPACKET:
	{
		pgp_regular_expression_subpacket *re_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Regular Expression: %.*s\n", re_subpacket->header.body_size, re_subpacket->regex);
	}
	break;
	case PGP_REVOCABLE_SUBPACKET:
	{
		pgp_revocable_subpacket *revocable_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Revocable: %s\n", revocable_subpacket->state ? "Yes" : "No");
	}
	break;
	case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
	{
		pgp_key_expiration_time_subpacket *timestamp_subpacket = subpacket;
		uint32_t expiry_seconds = timestamp_subpacket->duration;

		if (expiry_seconds == 0)
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: Never\n");
		}
		else if ((expiry_seconds % 31536000) == 0)
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: %u years\n", expiry_seconds / 31536000);
		}
		else if ((expiry_seconds % 86400) == 0)
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: %u days\n", expiry_seconds / 86400);
		}
		else
		{
			pos += print_format(buffer, indent + 1, "Expiry Time: %u seconds\n", expiry_seconds);
		}
	}
	break;
	case PGP_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
	{
		pgp_preferred_symmetric_ciphers_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_symmetric_key_algorithm_print(buffer, indent + 1, preferred_subpacket->preferred_algorithms[i]);
		}
	}
	break;
	case PGP_REVOCATION_KEY_SUBPACKET:
	{
		pgp_revocation_key_subpacket *revocation_subpacket = subpacket;

		if (revocation_subpacket->revocation_class & PGP_REVOCATION_CLASS_NORMAL)
		{
			pos += print_format(buffer, indent + 1, "Revocation Class: Normal (0x80)\n");
		}
		if (revocation_subpacket->revocation_class & PGP_REVOCATION_CLASS_SENSITIVE)
		{
			pos += print_format(buffer, indent + 1, "Revocation Class: Sensitive (0x40)\n");
		}

		pos += pgp_public_key_algorithm_print(buffer, indent + 1, revocation_subpacket->algorithm_id);
		pos += print_key(buffer, indent + 1, revocation_subpacket->fingerprint, revocation_subpacket->header.body_size - 2);
	}
	break;
	case PGP_ISSUER_KEY_ID_SUBPACKET:
	{
		pgp_issuer_key_id_subpacket *key_id_subpacket = subpacket;
		pos += print_key(buffer, indent + 1, key_id_subpacket->key_id, 8);
	}
	break;
	case PGP_NOTATION_DATA_SUBPACKET:
	{
		pgp_notation_data_subpacket *notation_subpacket = subpacket;

		if (notation_subpacket->flags == 0)
		{
			pos += print_format(buffer, indent + 1, "Flag: None\n");
		}

		if (notation_subpacket->flags & PGP_NOTATION_DATA_UTF8)
		{
			pos += print_format(buffer, indent + 1, "Flag: UTF-8 text (0x80000000)\n");
		}

		pos += print_format(buffer, indent + 1, "Name (%hu bytes): %.*s\n", notation_subpacket->name_size, notation_subpacket->name_size,
							notation_subpacket->data);

		if (notation_subpacket->flags & PGP_NOTATION_DATA_UTF8)
		{
			pos += print_format(buffer, indent + 1, "Value (%hu bytes): %.*s\n", notation_subpacket->value_size,
								notation_subpacket->value_size, PTR_OFFSET(notation_subpacket->data, notation_subpacket->name_size));
		}
		else
		{
			pos += print_format(buffer, indent + 1, "Value (%hu bytes): %R\n", notation_subpacket->value_size,
								PTR_OFFSET(notation_subpacket->data, notation_subpacket->name_size), notation_subpacket->value_size);
		}
	}
	break;
	case PGP_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
	{
		pgp_preferred_hash_algorithms_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_hash_algorithm_print(buffer, indent + 1, preferred_subpacket->preferred_algorithms[i]);
		}
	}
	break;
	case PGP_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
	{
		pgp_preferred_compression_algorithms_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_compression_algorithm_print(buffer, indent + 1, preferred_subpacket->preferred_algorithms[i]);
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
				pos += print_format(buffer, indent + 1, "Flag: No Modify (0x80)\n");
				break;
			default:
				pos += print_format(buffer, indent + 1, "Flag: Unknown (0x%hhx)\n", ksp_subpacket->flags[i]);
				break;
			}
		}
	}
	break;
	case PGP_PREFERRED_KEY_SERVER_SUBPACKET:
	{
		pgp_preferred_key_server_subpacket *pks_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Preferred Key Server: %.*s\n", pks_subpacket->header.body_size, pks_subpacket->server);
	}
	break;
	case PGP_PRIMARY_USER_ID_SUBPACKET:
	{
		pgp_primary_user_id_subpacket *primary_uid_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Primary User Id: %s\n", primary_uid_subpacket->state ? "Yes" : "No");
	}
	break;
	case PGP_POLICY_URI_SUBPACKET:
	{
		pgp_policy_uri_subpacket *policy_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Policy URI: %.*s\n", policy_subpacket->header.body_size, policy_subpacket->policy);
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
					pos += print_format(buffer, indent + 1, "Flag: Certification Key (0x01)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_SIGN)
				{
					pos += print_format(buffer, indent + 1, "Flag: Signing Key (0x02)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_ENCRYPT_COM)
				{
					pos += print_format(buffer, indent + 1, "Flag: Communication Encryption Key (0x04)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_ENCRYPT_STORAGE)
				{
					pos += print_format(buffer, indent + 1, "Flag: Storage Encryption Key (0x08)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_PRIVATE_SPLIT)
				{
					pos += print_format(buffer, indent + 1, "Flag: Key Secret Split (0x10)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_AUTHENTICATION)
				{
					pos += print_format(buffer, indent + 1, "Flag: Authentication Key (0x20)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_PRIVATE_SHARED)
				{
					pos += print_format(buffer, indent + 1, "Flag: Key Secret Shared (0x80)\n");
				}
			}

			// Second Octet
			if (i == 1)
			{
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_RESTRICTED_ENCRYPT)
				{
					pos += print_format(buffer, indent + 1, "Flag: Restricted Encryption Key (0x04)\n");
				}
				if (key_flags_subpacket->flags[i] & PGP_KEY_FLAG_TIMESTAMP)
				{
					pos += print_format(buffer, indent + 1, "Flag: Timestamping Key (0x08)\n");
				}
			}
		}
	}
	break;
	case PGP_SIGNER_USER_ID_SUBPACKET:
	{
		pgp_signer_user_id_subpacket *signer_uid_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Signer User ID: %.*s\n", signer_uid_subpacket->header.body_size,
							signer_uid_subpacket->uid);
	}
	break;
	case PGP_REASON_FOR_REVOCATION_SUBPACKET:
	{
		pgp_reason_for_revocation_subpacket *revocation_subpacket = subpacket;

		switch (revocation_subpacket->code)
		{
		case PGP_REVOCATION_NO_REASON:
			pos += print_format(buffer, indent + 1, "Revoction Code: None (Tag 0)\n");
			break;
		case PGP_REVOCATION_KEY_SUPERSEDED:
			pos += print_format(buffer, indent + 1, "Revoction Code: Key Superseded (Tag 1)\n");
			break;
		case PGP_REVOCATION_KEY_COMPROMISED:
			pos += print_format(buffer, indent + 1, "Revoction Code: Key Compromised (Tag 2)\n");
			break;
		case PGP_REVOCATION_KEY_RETIRED:
			pos += print_format(buffer, indent + 1, "Revoction Code: Key Retired (Tag 3)\n");
			break;
		case PGP_REVOCATION_USER_ID_INVALID:
			pos += print_format(buffer, indent + 1, "Revoction Code: User ID Invalid (Tag 32)\n");
			break;
		default:
			pos += print_format(buffer, indent + 1, "Revoction Code: Unknown (Tag %hhu)\n", revocation_subpacket->code);
			break;
		}

		pos += print_format(buffer, indent + 1, "Revoction Reason: %.*s\n", revocation_subpacket->header.body_size - 1,
							revocation_subpacket->reason);
	}
	break;
	case PGP_FEATURES_SUBPACKET:
	{
		pgp_features_subpacket *features_subpacket = subpacket;

		for (uint32_t i = 0; i < features_subpacket->header.body_size; ++i)
		{
			byte_t flag = features_subpacket->flags[i];

			if (flag & PGP_FEATURE_MDC)
			{
				pos += print_format(buffer, indent + 1, "Feature: SEIPD-V1 (MDC) Supported (0x01)\n");
				flag &= ~PGP_FEATURE_MDC;
			}
			if (flag & PGP_FEATURE_AEAD)
			{
				pos += print_format(buffer, indent + 1, "Feature: AEAD Supported (0x02)\n");
				flag &= ~PGP_FEATURE_AEAD;
			}
			if (flag & PGP_FEATURE_KEY_V5)
			{
				pos += print_format(buffer, indent + 1, "Feature: V5 Keys Supported (0x04)\n");
				flag &= ~PGP_FEATURE_KEY_V5;
			}
			if (flag & PGP_FEATURE_SEIPD_V2)
			{
				pos += print_format(buffer, indent + 1, "Feature: SEIPD-V2 Supported (0x08)\n");
				flag &= ~PGP_FEATURE_SEIPD_V2;
			}

			if (flag != 0)
			{
				pos += print_format(buffer, indent + 1, "Feature: Unknown (0x%hhx)\n", flag);
			}
		}
	}
	break;
	case PGP_SIGNATURE_TARGET_SUBPACKET:
	{
		pgp_signature_target_subpacket *target_subpacket = subpacket;

		pos += pgp_signature_algorithm_print(buffer, indent + 1, target_subpacket->public_key_algorithm_id);
		pos += pgp_hash_algorithm_print(buffer, indent + 1, target_subpacket->hash_algorithm_id);
		pos += print_format(buffer, indent + 1, "Hash: %R\n", buffer, target_subpacket->hash, target_subpacket->header.body_size - 2);
	}
	break;
	case PGP_EMBEDDED_SIGNATURE_SUBPACKET:
	{
		pgp_embedded_signature_subpacket *embedded_subpacket = subpacket;
		pos += pgp_signature_packet_body_print(embedded_subpacket, buffer, indent + 1, options);
	}
	break;
	case PGP_ISSUER_FINGERPRINT_SUBPACKET:
	{
		pgp_issuer_fingerprint_subpacket *fingerprint_subpacket = subpacket;

		pos += print_format(buffer, indent + 1, "Key Version: %hhu\n", fingerprint_subpacket->version);
		pos += print_key(buffer, indent + 1, fingerprint_subpacket->fingerprint, fingerprint_subpacket->header.body_size - 1);
	}
	break;
	case PGP_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
	{
		pgp_preferred_encryption_modes_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < preferred_subpacket->header.body_size; ++i)
		{
			pos += pgp_aead_algorithm_print(buffer, indent + 1, preferred_subpacket->preferred_algorithms[i]);
		}
	}
	break;
	case PGP_RECIPIENT_FINGERPRINT_SUBPACKET:
	{
		pgp_recipient_fingerprint_subpacket *fingerprint_subpacket = subpacket;

		pos += print_format(buffer, indent + 1, "Key Version: %hhu\n", fingerprint_subpacket->version);
		pos += print_key(buffer, indent + 1, fingerprint_subpacket->fingerprint, fingerprint_subpacket->header.body_size - 1);
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
			pos += print_format(buffer, indent + 1, "Attestations:\n");

			for (uint16_t i = 0; i < hash_count; ++i)
			{
				pos += print_format(buffer, indent + 2, "%R\n", PTR_OFFSET(attestation_subpacket->hash, hash_size * i), hash_size);
			}
		}
		else
		{
			pos += print_format(buffer, indent + 1, "Attestations: %R\n", attestation_subpacket->hash, header->body_size);
		}
	}
	break;
	case PGP_KEY_BLOCK_SUBPACKET:
	{
		pgp_key_block_subpacket *key_block_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Octet: %hhu\n", key_block_subpacket->octet);
		pos += pgp_packet_stream_print(key_block_subpacket->certificate, buffer, indent + 1, options);
	}
	break;
	case PGP_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
	{
		pgp_preferred_aead_ciphersuites_subpacket *preferred_subpacket = subpacket;

		for (uint32_t i = 0; i < (preferred_subpacket->header.body_size / 2); i += 2)
		{
			pgp_symmetric_key_algorithms symmetric_algorithm = preferred_subpacket->preferred_algorithms[i];
			pgp_aead_algorithms aead_algorithm = preferred_subpacket->preferred_algorithms[i + 1];

			pos += pgp_cipher_aead_algorithm_pair_print(buffer, indent + 1, symmetric_algorithm, aead_algorithm);
		}
	}
	break;
	case PGP_LITERAL_DATA_META_HASH_SUBPACKET:
	{
		pgp_literal_data_meta_hash_subpacket *meta_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Octet: %hhu\n", meta_subpacket->octet);
		pos += print_format(buffer, indent + 1, "SHA256 Hash: %R\n", meta_subpacket->hash, 32);
	}
	break;
	case PGP_TRUST_ALIAS_SUBPACKET:
	{
		pgp_trust_alias_subpacket *trust_alias_subpacket = subpacket;
		pos += print_format(buffer, indent + 1, "Trust Alias: %.*s\n", trust_alias_subpacket->header.body_size,
							trust_alias_subpacket->alias);
	}
	break;
	default:
		break;
	}

	return pos;
}

size_t pgp_pkesk_packet_print(pgp_pkesk_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	indent += 1;

	if (packet->version != PGP_PKESK_V6 && packet->version != PGP_PKESK_V3)
	{
		pos += print_format(buffer, indent, "Version: %hhu (Unknown)\n", packet->version);
		return pos;
	}

	pos += print_format(buffer, indent, "Version: %hhu\n", packet->version);

	if (packet->version == PGP_PKESK_V6)
	{
		switch (packet->key_version)
		{
		case PGP_KEY_V2:
		case PGP_KEY_V3:
			pos += print_format(buffer, indent, "Key Version: %hhu (Deprecated)\n", packet->key_version);
			pos += print_key(buffer, indent, packet->key_fingerprint, PGP_KEY_V3_FINGERPRINT_SIZE);
			break;
		case PGP_KEY_V4:
			pos += print_format(buffer, indent, "Key Version: %hhu\n", packet->key_version);
			pos += print_key(buffer, indent, packet->key_fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE);
			break;
		case PGP_KEY_V5:
		case PGP_KEY_V6:
			pos += print_format(buffer, indent, "Key Version: %hhu\n", packet->key_version);
			pos += print_key(buffer, indent, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);
			break;
		default:
			pos += print_format(buffer, indent, "Key Version: %hhu (Unknown)\n", packet->key_version);
			break;
		}
	}
	else //(packet->version == PGP_PKESK_V3)
	{
		pos += print_key(buffer, indent, packet->key_id, 8);
	}

	pos += pgp_kex_algorithm_print(buffer, indent, packet->public_key_algorithm_id);
	pos += pgp_kex_print(buffer, indent, options, packet->public_key_algorithm_id, packet->encrypted_session_key,
						 packet->encrypted_session_key_octets);

	return pos;
}

size_t pgp_skesk_packet_print(pgp_skesk_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	indent += 1;

	if (packet->version != PGP_SKESK_V6 && packet->version != PGP_SKESK_V5 && packet->version != PGP_SKESK_V4)
	{
		pos += print_format(buffer, indent, "Version: %hhu (Unknown)\n", packet->version);
		return pos;
	}

	pos += print_format(buffer, indent, "Version: %hhu\n", packet->version);

	if (packet->version == PGP_SKESK_V6 || packet->version == PGP_SKESK_V5)
	{
		pos += pgp_symmetric_key_algorithm_print(buffer, indent, packet->symmetric_key_algorithm_id);
		pos += pgp_aead_algorithm_print(buffer, indent, packet->aead_algorithm_id);
		pos += pgp_s2k_print(buffer, indent, &packet->s2k);

		pos += print_format(buffer, indent, "IV: %R\n", packet->iv, packet->iv_size);
		pos += print_format(buffer, indent, "Tag: %R\n", packet->tag, packet->tag_size);
		pos += print_format(buffer, indent, "Encrypted Session Key: %R\n", packet->session_key, packet->session_key_size);
	}
	else // (packet->version == PGP_SKESK_V4)
	{
		pos += pgp_symmetric_key_algorithm_print(buffer, indent, packet->symmetric_key_algorithm_id);
		pos += pgp_s2k_print(buffer, indent, &packet->s2k);

		if (packet->session_key_size > 0)
		{
			pos += print_format(buffer, indent, "Encrypted Session Key: %R\n", packet->session_key, packet->session_key_size);
		}
	}

	return pos;
}

static size_t pgp_signature_packet_body_print(pgp_signature_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	if (packet->version == PGP_SIGNATURE_V6 || packet->version == PGP_SIGNATURE_V5 || packet->version == PGP_SIGNATURE_V4)
	{
		pos += print_format(buffer, indent, "Version: %hhu\n", packet->version);
		pos += pgp_signature_type_print(buffer, indent, packet->type);
		pos += pgp_signature_algorithm_print(buffer, indent, packet->public_key_algorithm_id);
		pos += pgp_hash_algorithm_print(buffer, indent, packet->hash_algorithm_id);

		if (packet->hashed_subpackets != NULL)
		{
			if (packet->hashed_subpackets->count > 0)
			{
				pos += print_format(buffer, indent, "Hashed Subpackets:\n");
			}

			for (uint32_t i = 0; i < packet->hashed_subpackets->count; ++i)
			{
				pos += pgp_signature_subpacket_print(packet->hashed_subpackets->packets[i], buffer, indent + 1, options);
			}
		}

		if (packet->unhashed_subpackets != NULL)
		{
			if (packet->unhashed_subpackets->count > 0)
			{
				pos += print_format(buffer, indent, "Unhashed Subpackets:\n");
			}

			for (uint32_t i = 0; i < packet->unhashed_subpackets->count; ++i)
			{
				pos += pgp_signature_subpacket_print(packet->unhashed_subpackets->packets[i], buffer, indent + 1, options);
			}
		}

		pos += print_format(buffer, indent, "Hash Check: %R\n", packet->quick_hash, 2);

		if (packet->version == PGP_SIGNATURE_V6)
		{
			pos += print_format(buffer, indent, "Salt: %R\n", packet->salt, packet->salt_size);
		}

		pos += pgp_signature_print(buffer, indent, options, packet->public_key_algorithm_id, packet->signature, packet->signature_octets);
	}
	else if (packet->version == PGP_SIGNATURE_V3)
	{
		pos += print_format(buffer, indent, "Version: 3 (Deprecated)\n");
		pos += pgp_signature_type_print(buffer, indent, packet->type);
		pos += print_timestamp(buffer, indent, "Signature Creation Time", packet->timestamp);
		pos += print_key(buffer, indent, packet->key_id, 8);
		pos += pgp_signature_algorithm_print(buffer, indent, packet->public_key_algorithm_id);
		pos += pgp_hash_algorithm_print(buffer, indent, packet->hash_algorithm_id);
		pos += print_format(buffer, indent, "Hash Check: %R\n", packet->quick_hash, 2);
		pos += pgp_signature_print(buffer, indent, options, packet->public_key_algorithm_id, packet->signature, packet->signature_octets);
	}
	else
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_signature_packet_print(pgp_signature_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	// Header
	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	// Body
	pos += pgp_signature_packet_body_print(packet, buffer, indent + 1, options);

	return pos;
}

size_t pgp_one_pass_signature_packet_print(pgp_one_pass_signature_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	if (packet->version == PGP_ONE_PASS_SIGNATURE_V6)
	{
		pos += print_format(buffer, indent + 1, "Version: 6\n");
		pos += pgp_signature_type_print(buffer, indent + 1, packet->type);
		pos += pgp_hash_algorithm_print(buffer, indent + 1, packet->hash_algorithm_id);
		pos += pgp_signature_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);

		pos += print_format(buffer, indent + 1, "Salt: %R\n", packet->salt, packet->salt_size);
		pos += print_key(buffer, indent + 1, packet->key_fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);

		pos += print_format(buffer, indent + 1, "Nested: %s\n", packet->nested ? "Yes" : "No");
	}
	else if (packet->version == PGP_ONE_PASS_SIGNATURE_V3)
	{
		pos += print_format(buffer, indent + 1, "Version: 3\n");
		pos += pgp_signature_type_print(buffer, indent + 1, packet->type);
		pos += pgp_hash_algorithm_print(buffer, indent + 1, packet->hash_algorithm_id);
		pos += pgp_signature_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);
		pos += print_key(buffer, indent + 1, packet->key_id, 8);

		pos += print_format(buffer, indent + 1, "Nested: %s\n", packet->nested ? "Yes" : "No");
	}
	else
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_public_key_packet_print(pgp_key_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5 || packet->version == PGP_KEY_V4)
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu\n", packet->version);
		pos += print_timestamp(buffer, indent + 1, "Key Creation Time", packet->key_creation_time);
		pos += pgp_public_key_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);
		pos += pgp_public_key_print(buffer, indent + 1, options, packet->public_key_algorithm_id, packet->key,
									packet->public_key_data_octets);
	}
	else if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu (Deprecated)\n", packet->version);
		pos += print_timestamp(buffer, indent + 1, "Key Creation Time", packet->key_creation_time);
		pos += print_format(buffer, indent + 1, "Key Expiry: %hu days\n", packet->key_expiry_days);
		pos += pgp_public_key_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);
		pos += pgp_public_key_print(buffer, indent + 1, options, packet->public_key_algorithm_id, packet->key,
									packet->public_key_data_octets);
	}
	else
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_secret_key_packet_print(pgp_key_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5 || packet->version == PGP_KEY_V4)
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu\n", packet->version);
		pos += print_timestamp(buffer, indent + 1, "Key Creation Time", packet->key_creation_time);
		pos += pgp_public_key_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);

		if (packet->s2k_usage != 0)
		{
			pos += print_format(buffer, indent + 1, "S2K Usage: ");
			switch (packet->s2k_usage)
			{
			case 253:
				pos += xprint(buffer, "AEAD (Tag 253)\n");
				break;
			case 254:
				pos += xprint(buffer, "CFB (Tag 254)\n");
				break;
			case 255:
				pos += xprint(buffer, "Malleable CFB (Tag 255) (Deprecated)\n");
				break;
			default:
				pos += xprint(buffer, "Legacy CFB (Tag 255) (Deprecated)\n");
				break;
			}

			pos += pgp_symmetric_key_algorithm_print(buffer, indent + 2, packet->symmetric_key_algorithm_id);

			if (packet->s2k_usage == 253)
			{
				pos += pgp_aead_algorithm_print(buffer, indent + 2, packet->aead_algorithm_id);
			}

			if (packet->s2k_usage == 253 || packet->s2k_usage == 254 || packet->s2k_usage == 255)
			{
				pos += pgp_s2k_print(buffer, indent + 2, &packet->s2k);
			}

			pos += print_format(buffer, indent + 2, "IV: %R\n", packet->iv, packet->iv_size);
		}

		pos += pgp_private_key_print(buffer, indent + 1, options, packet->public_key_algorithm_id, packet->key,
									 packet->private_key_data_octets);

		if (packet->s2k_usage == 0)
		{
			if (packet->version != PGP_KEY_V6)
			{
				pos += print_format(buffer, indent + 1, "Checksum: %R\n", &packet->key_checksum, 2);
			}
		}
	}
	else if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu (Deprecated)\n", packet->version);
		pos += print_timestamp(buffer, indent + 1, "Key Creation Time", packet->key_creation_time);
		pos += xprint(buffer, "Key Expiry: %hu days\n", packet->key_expiry_days);
		pos += pgp_public_key_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);

		if (packet->s2k_usage != 0)
		{
			pos += print_format(buffer, indent + 1, "S2K Usage: ");
			switch (packet->s2k_usage)
			{
			case 253:
				pos += xprint(buffer, "AEAD (Tag 253)\n");
				break;
			case 254:
				pos += xprint(buffer, "CFB (Tag 254)\n");
				break;
			case 255:
				pos += xprint(buffer, "Malleable CFB (Tag 255) (Deprecated)\n");
				break;
			default:
				pos += xprint(buffer, "Legacy CFB (Tag 255) (Deprecated)\n");
				break;
			}

			pos += pgp_symmetric_key_algorithm_print(buffer, indent + 2, packet->symmetric_key_algorithm_id);

			if (packet->s2k_usage == 253)
			{
				pos += pgp_aead_algorithm_print(buffer, indent + 2, packet->aead_algorithm_id);
			}

			if (packet->s2k_usage == 253 || packet->s2k_usage == 254 || packet->s2k_usage == 255)
			{
				pos += pgp_s2k_print(buffer, indent + 2, &packet->s2k);
			}

			pos += print_format(buffer, indent + 2, "IV: %R\n", packet->iv, packet->iv_size);
		}

		pos += pgp_private_key_print(buffer, indent + 1, options, packet->public_key_algorithm_id, packet->key,
									 packet->private_key_data_octets);

		if (packet->s2k_usage == 0)
		{
			pos += print_format(buffer, indent + 1, "Checksum: %R\n", &packet->key_checksum, 2);
		}
	}
	else
	{
		pos += print_format(buffer, indent + 1, "Version: %hhu (Unknown)\n", packet->version);
	}

	return pos;
}

size_t pgp_compressed_packet_print(pgp_compresed_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += pgp_compression_algorithm_print(buffer, indent + 1, packet->compression_algorithm_id);
	pos += print_format(buffer, indent + 1, "Data (%u bytes)\n", packet->header.body_size - 1);

	return pos;
}

size_t pgp_sed_packet_print(pgp_sed_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "Encrypted Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

size_t pgp_marker_packet_print(pgp_marker_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "Marker: %c%c%c\n", packet->marker[0], packet->marker[1], packet->marker[2]);

	return pos;
}

size_t pgp_literal_packet_print(pgp_literal_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;
	const char *name = NULL;

	switch (packet->format)
	{
	case PGP_LITERAL_DATA_BINARY:
		name = "Binary";
		break;
	case PGP_LITERAL_DATA_MIME:
		name = "Mime";
		break;
	case PGP_LITERAL_DATA_LOCAL:
		name = "Local";
		break;
	case PGP_LITERAL_DATA_TEXT:
		name = "Text";
		break;
	case PGP_LITERAL_DATA_UTF8:
		name = "UTF";
		break;
	default:
		name = "Unknown";
		break;
	}

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	indent += 1;

	pos += print_format(buffer, indent, "Format: %s (Tag '%c')\n", name, packet->format);

	if (packet->cleartext == 0)
	{
		pos += print_timestamp(buffer, indent, "Date", packet->date);
		pos += print_format(buffer, indent, "Filename (%u bytes): %.*s\n", packet->filename_size, packet->filename_size, packet->filename);
	}
	else
	{
		pos += print_format(buffer, indent, "Cleartext: True\n");

		if (packet->hash_algorithm != 0)
		{
			pos += pgp_hash_algorithm_print(buffer, indent + 1, packet->hash_algorithm);
		}
	}

	pos += print_format(buffer, indent, "Data (%u bytes)\n", packet->data_size);

	return pos;
}

size_t pgp_trust_packet_print(pgp_trust_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += pgp_trust_print(buffer, indent + 1, packet->level);

	return pos;
}

size_t pgp_user_id_packet_print(pgp_user_id_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "User ID: %.*s\n", packet->header.body_size, packet->user_data);

	return pos;
}

size_t pgp_user_attribute_packet_print(pgp_user_attribute_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	for (uint32_t i = 0; i < packet->subpackets->count; ++i)
	{
		pgp_subpacket_header *subpacket_header = packet->subpackets->packets[i];

		switch (subpacket_header->tag)
		{
		case PGP_USER_ATTRIBUTE_IMAGE:
		{
			pgp_user_attribute_image_subpacket *image_subpacket = packet->subpackets->packets[i];
			uint32_t image_size = image_subpacket->header.body_size - 16;

			pos += print_format(buffer, indent + 1, "User Attribute Image Subpacket (Tag 1)\n");
			pos += print_format(buffer, indent + 2, "Image Header Version: %hhu\n", image_subpacket->image_header_version);

			switch (image_subpacket->image_encoding)
			{
			case PGP_USER_ATTRIBUTE_IMAGE_JPEG:
			{
				pos += print_format(buffer, indent + 2, "Image Encoding: JPEG (Tag 1)\n");
			}
			break;
			default:
				pos += print_format(buffer, indent + 2, "Unknown Image Encoding (Tag %hhu)\n", image_subpacket->image_encoding);
			}

			pos += print_format(buffer, indent + 2, "Image Size: %u bytes\n", image_size);
		}
		break;
		case PGP_USER_ATTRIBUTE_UID:
		{
			pgp_user_attribute_uid_subpacket *uid_subpacket = packet->subpackets->packets[i];
			uint32_t uid_size = uid_subpacket->header.body_size;

			pos += print_format(buffer, indent + 1, "User Attribute Image User ID Subpacket (Tag 2)\n");
			pos += print_format(buffer, indent + 2, "User ID: %.*s\n", uid_size, uid_subpacket->user_data);
		}
		break;
		default:
			pos += print_format(buffer, indent + 1, "Unknown Subpacket (Tag %hhu) (%u bytes)\n", subpacket_header->tag,
								subpacket_header->body_size);
		}
	}

	return pos;
}

size_t pgp_seipd_packet_print(pgp_seipd_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	indent += 1;

	if (packet->version != PGP_SEIPD_V2 && packet->version != PGP_SEIPD_V1)
	{
		pos += print_format(buffer, indent, "Version: %hhu (Unknown)\n", packet->version);
		return pos;
	}

	pos += print_format(buffer, indent, "Version: %hhu\n", packet->version);

	if (packet->version == PGP_SEIPD_V2)
	{
		pos += pgp_symmetric_key_algorithm_print(buffer, indent, packet->symmetric_key_algorithm_id);
		pos += pgp_aead_algorithm_print(buffer, indent, packet->aead_algorithm_id);
		pos += print_format(buffer, indent, "Chunk Size: %u Code (%hhu)\n", PGP_CHUNK_SIZE(packet->chunk_size), packet->chunk_size);

		pos += print_format(buffer, indent, "Salt: %R\n", packet->salt, 32);
		pos += print_format(buffer, indent, "Tag: %R\n", packet->tag, packet->tag_size);
	}

	pos += print_format(buffer, indent, "Encrypted Data (%u bytes)\n", packet->data_size);

	return pos;
}

size_t pgp_mdc_packet_print(pgp_mdc_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "SHA-1 MDC: %R\n", packet->sha1_hash, 20);

	return pos;
}

size_t pgp_aead_packet_print(pgp_aead_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	indent += 1;

	if (packet->version != PGP_AEAD_V1)
	{
		pos += print_format(buffer, indent, "Version: %hhu (Unknown)\n", packet->version);
		return pos;
	}

	pos += print_format(buffer, indent, "Version: %hhu\n", packet->version);

	pos += pgp_symmetric_key_algorithm_print(buffer, indent, packet->symmetric_key_algorithm_id);
	pos += pgp_aead_algorithm_print(buffer, indent, packet->aead_algorithm_id);
	pos += print_format(buffer, indent, "Chunk Size: %u Code (%hhu)\n", PGP_CHUNK_SIZE(packet->chunk_size), packet->chunk_size);

	pos += print_format(buffer, indent, "IV: %R\n", packet->iv, pgp_aead_iv_size(packet->aead_algorithm_id));
	pos += print_format(buffer, indent, "Tag: %R\n", packet->tag, packet->tag_size);

	pos += print_format(buffer, indent, "Encrypted Data (%u bytes)\n", packet->data_size);

	return pos;
}

size_t pgp_padding_packet_print(pgp_padding_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "Padding Data (%u bytes)\n", packet->header.body_size);

	return pos;
}

static size_t print_capabilities(byte_t capabilities, buffer_t *buffer, uint32_t indent)
{
	byte_t comma_insert = 0;
	size_t pos = 0;

	pos += print_format(buffer, indent, "Capabilities: ");

	if (capabilities & PGP_KEY_FLAG_CERTIFY)
	{
		pos += writen(buffer, "Certify", 7);
		comma_insert = 1;
	}
	if (capabilities & PGP_KEY_FLAG_SIGN)
	{
		if (comma_insert)
		{
			pos += writen(buffer, ", ", 2);
		}

		pos += writen(buffer, "Sign", 4);
		comma_insert = 1;
	}
	if (capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
	{
		if (comma_insert)
		{
			pos += writen(buffer, ", ", 2);
		}

		pos += writen(buffer, "Encrypt", 7);
		comma_insert = 1;
	}
	if (capabilities & PGP_KEY_FLAG_AUTHENTICATION)
	{
		if (comma_insert)
		{
			pos += writen(buffer, ", ", 2);
		}

		pos += writen(buffer, "Authenticate", 12);
	}

	return pos;
}

static size_t print_flags(byte_t flags, buffer_t *buffer, uint32_t indent)
{
	byte_t comma_insert = 0;
	size_t pos = 0;

	pos += print_format(buffer, indent, "Flags: ");

	if (flags & PGP_KEY_FLAG_PRIVATE_SPLIT)
	{
		pos += writen(buffer, "Split", 5);
		comma_insert = 1;
	}
	if (flags & PGP_KEY_FLAG_PRIVATE_SHARED)
	{
		if (comma_insert)
		{
			pos += writen(buffer, ", ", 2);
		}

		pos += writen(buffer, "Shared", 7);
		comma_insert = 1;
	}
	if (flags & PGP_KEY_FLAG_TIMESTAMP)
	{
		if (comma_insert)
		{
			pos += writen(buffer, ", ", 2);
		}

		pos += writen(buffer, "Timestamp", 9);
		comma_insert = 1;
	}
	if (flags & PGP_KEY_FLAG_RESTRICTED_ENCRYPT)
	{
		if (comma_insert)
		{
			pos += writen(buffer, ", ", 2);
		}

		pos += writen(buffer, "Restricted", 10);
	}

	return pos;
}

size_t pgp_key_packet_print(pgp_key_packet *packet, buffer_t *buffer, uint32_t indent, uint32_t options)
{
	size_t pos = 0;
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	pos += print_format(buffer, indent + 1, "Version: %hhu\n", packet->version);
	pos += print_format(buffer, indent + 1, "Type: %s\n", packet->type == PGP_KEY_TYPE_PUBLIC ? "Public Key" : "Secret Key");
	pos += print_capabilities(packet->capabilities, buffer, indent + 1);
	pos += print_flags(packet->flags, buffer, indent + 1);

	if (pgp_key_fingerprint(packet, fingerprint, &fingerprint_size) == PGP_SUCCESS)
	{
		pos += print_key(buffer, indent + 1, fingerprint, fingerprint_size);
	}

	pos += print_timestamp(buffer, indent + 1, "Key Creation Time", packet->key_creation_time);

	if (packet->key_revocation_time != 0)
	{
		pos += print_timestamp(buffer, indent + 1, "Key Revocation Time", packet->key_revocation_time);
	}

	if (packet->key_expiry_seconds != 0)
	{
		pos += print_timestamp(buffer, indent + 1, "Key Expiry Time", packet->key_creation_time + packet->key_expiry_seconds);
	}
	else
	{
		pos += print_format(buffer, indent + 1, "Key Expiry Time: None\n");
	}

	pos += pgp_public_key_algorithm_print(buffer, indent + 1, packet->public_key_algorithm_id);

	if (packet->type == PGP_KEY_TYPE_PUBLIC)
	{
		pos += pgp_public_key_print(buffer, indent + 1, options, packet->public_key_algorithm_id, packet->key,
									packet->public_key_data_octets);

		return pos;
	}

	if (packet->s2k_usage != 0)
	{
		pos += print_format(buffer, indent + 1, "S2K Usage: ");
		switch (packet->s2k_usage)
		{
		case 253:
			pos += xprint(buffer, "AEAD (Tag 253)\n");
			break;
		case 254:
			pos += xprint(buffer, "CFB (Tag 254)\n");
			break;
		case 255:
			pos += xprint(buffer, "Malleable CFB (Tag 255) (Deprecated)\n");
			break;
		default:
			pos += xprint(buffer, "Legacy CFB (Tag 255) (Deprecated)\n");
			break;
		}

		pos += pgp_symmetric_key_algorithm_print(buffer, indent + 2, packet->symmetric_key_algorithm_id);

		if (packet->s2k_usage == 253)
		{
			pos += pgp_aead_algorithm_print(buffer, indent + 2, packet->aead_algorithm_id);
		}

		if (packet->s2k_usage == 253 || packet->s2k_usage == 254 || packet->s2k_usage == 255)
		{
			pos += pgp_s2k_print(buffer, indent + 2, &packet->s2k);
		}

		pos += print_format(buffer, indent + 2, "IV: %R\n", packet->iv, packet->iv_size);
	}

	pos += pgp_private_key_print(buffer, indent + 1, options, packet->public_key_algorithm_id, packet->key,
								 packet->private_key_data_octets);

	return pos;
}

static size_t pgp_user_info_print(pgp_user_info *user, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += print_format(buffer, indent, "User ID: %.*s\n", user->uid_octets, user->uid);
	pos += pgp_trust_print(buffer, indent, user->trust);

	if (user->features != 0)
	{
		pos += print_format(buffer, indent, "Supported Features:\n");

		if (user->features & PGP_FEATURE_MDC)
		{
			pos += print_format(buffer, indent + 1, "Feature: SEIPD-V1 (MDC) Supported (0x01)\n");
		}
		if (user->features & PGP_FEATURE_AEAD)
		{
			pos += print_format(buffer, indent + 1, "Feature: AEAD Supported (0x02)\n");
		}
		if (user->features & PGP_FEATURE_KEY_V5)
		{
			pos += print_format(buffer, indent + 1, "Feature: V5 Keys Supported (0x04)\n");
		}
		if (user->features & PGP_FEATURE_SEIPD_V2)
		{
			pos += print_format(buffer, indent + 1, "Feature: SEIPD-V2 Supported (0x08)\n");
		}
	}

	if (user->flags & PGP_KEY_SERVER_NO_MODIFY)
	{
		pos += print_format(buffer, indent, "Key Server Preferences: No Modify (0x80)\n");
	}

	if (user->server_octets > 0)
	{
		pos += print_format(buffer, indent, "Preferred Key Server: %.*s\n", user->server_octets, user->server);
	}

	if (user->hash_algorithm_preferences_octets > 0)
	{
		pos += print_format(buffer, indent, "Hash Alogrithm Preferences:\n");

		for (byte_t i = 0; i < user->hash_algorithm_preferences_octets; ++i)
		{
			pos += pgp_hash_algorithm_print(buffer, indent + 1, user->hash_algorithm_preferences[i]);
		}
	}

	if (user->cipher_algorithm_preferences_octets > 0)
	{
		pos += print_format(buffer, indent, "Cipher Alogrithm Preferences:\n");

		for (byte_t i = 0; i < user->cipher_algorithm_preferences_octets; ++i)
		{
			pos += pgp_symmetric_key_algorithm_print(buffer, indent + 1, user->cipher_algorithm_preferences[i]);
		}
	}

	if (user->compression_algorithm_preferences_octets > 0)
	{
		pos += print_format(buffer, indent, "Compression Alogrithm Preferences:\n");

		for (byte_t i = 0; i < user->compression_algorithm_preferences_octets; ++i)
		{
			pos += pgp_compression_algorithm_print(buffer, indent + 1, user->compression_algorithm_preferences[i]);
		}
	}

	if (user->cipher_modes_preferences_octets > 0)
	{
		pos += print_format(buffer, indent, "Encryption Mode Preferences:\n");

		for (byte_t i = 0; i < user->cipher_modes_preferences_octets; ++i)
		{
			pos += pgp_aead_algorithm_print(buffer, indent + 1, user->cipher_modes_preferences[i]);
		}
	}

	if (user->aead_algorithm_preferences_octets > 0)
	{
		pos += print_format(buffer, indent, "AEAD Preferences:\n");

		for (byte_t i = 0; i < user->aead_algorithm_preferences_octets; i += 2)
		{
			pos += pgp_cipher_aead_algorithm_pair_print(buffer, indent + 1, user->aead_algorithm_preferences[i / 2][0],
														user->aead_algorithm_preferences[i / 2][1]);
		}
	}

	return pos;
}

size_t pgp_keyring_packet_print(pgp_keyring_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "Key Version: %hhu\n", packet->key_version);
	pos += print_format(buffer, indent + 1, "Primary Key: %^R\n", packet->primary_fingerprint, packet->fingerprint_size);

	if (packet->subkey_count > 0)
	{
		pos += print_format(buffer, indent + 1, "Subkeys:\n");

		for (byte_t i = 0; i < packet->subkey_count; ++i)
		{
			pos += print_format(buffer, indent + 2, "%^R\n", PTR_OFFSET(packet->subkey_fingerprints, i * packet->fingerprint_size),
								packet->fingerprint_size);
		}
	}

	if (packet->users->count > 0)
	{
		pos += print_format(buffer, indent + 1, "User Information:\n");

		for (uint32_t i = 0; i < packet->users->count; ++i)
		{
			pos += pgp_user_info_print(packet->users->packets[i], buffer, indent + 2);
		}
	}

	return pos;
}

static size_t pgp_armor_header_print(const char *header, void *data, byte_t size, buffer_t *buffer, uint32_t indent)
{
	if (size == 0)
	{
		return 0;
	}

	return print_format(buffer, indent, "%s: %.*s\n", header, data, size);
}

size_t pgp_armor_packet_print(pgp_armor_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);

	pos += print_format(buffer, indent + 1, "Marker: %.*s\n", packet->marker_size, packet->marker);

	if ((packet->comment_size + packet->version_size + packet->charset_size + packet->message_id_size) == 0)
	{
		// No headers present
		return pos;
	}

	pos += print_format(buffer, indent + 1, "Headers:\n");

	pos += pgp_armor_header_print("Version", packet->version, packet->version_size, buffer, indent + 2);
	pos += pgp_armor_header_print("Comment", packet->comment, packet->comment_size, buffer, indent + 2);
	pos += pgp_armor_header_print("Charset", packet->charset, packet->charset_size, buffer, indent + 2);
	pos += pgp_armor_header_print("MessageID", packet->message_id, packet->message_id_size, buffer, indent + 2);

	return pos;
}

size_t pgp_partial_packet_print(pgp_partial_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	if (packet->header.partial_continue)
	{
		pos += print_format(buffer, indent, "Partial Packet (continue) (%zu bytes)\n", packet->header.body_size);
	}

	if (packet->header.partial_end)
	{
		pos += print_format(buffer, indent, "Partial Packet (end) (%zu bytes)\n", packet->header.body_size);
	}

	return pos;
}

size_t pgp_unknown_packet_print(pgp_unknown_packet *packet, buffer_t *buffer, uint32_t indent)
{
	size_t pos = 0;

	pos += pgp_packet_header_print(&packet->header, buffer, indent);
	pos += print_format(buffer, indent + 1, "Data (%u bytes)\n", packet->header.body_size);

	return pos;
}
