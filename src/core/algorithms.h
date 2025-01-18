/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ALGORITHMS_H
#define SPGP_ALGORITHMS_H

// Refer RFC 9580 - OpenPGP, Section 9 Constants

typedef enum _pgp_public_key_algorithms
{
	PGP_RSA_ENCRYPT_OR_SIGN = 1,
	PGP_RSA_ENCRYPT_ONLY = 2,
	PGP_RSA_SIGN_ONLY = 3,
	PGP_KYBER = 8,
	PGP_ELGAMAL_ENCRYPT_ONLY = 16,
	PGP_DSA = 17,
	PGP_ECDH = 18,
	PGP_ECDSA = 19,
	PGP_EDDSA_LEGACY = 22,
	PGP_X25519 = 25,
	PGP_X448 = 26,
	PGP_ED25519 = 27,
	PGP_ED448 = 28
} pgp_public_key_algorithms;

typedef enum _pgp_symmetric_key_algorithms
{
	PGP_PLAINTEXT = 0,
	PGP_IDEA = 1,
	PGP_TDES = 2,
	PGP_CAST5_128 = 3,
	PGP_BLOWFISH = 4,
	PGP_AES_128 = 7,
	PGP_AES_192 = 8,
	PGP_AES_256 = 9,
	PGP_TWOFISH = 10,
	PGP_CAMELLIA_128 = 11,
	PGP_CAMELLIA_192 = 12,
	PGP_CAMELLIA_256 = 13
} pgp_symmetric_key_algorithms;

typedef enum _pgp_compression_algorithms
{
	PGP_UNCOMPRESSED = 0,
	PGP_DEFALTE = 1,
	PGP_ZLIB = 2,
	PGP_BZIP2 = 3
} pgp_compression_algorithms;

typedef enum _pgp_hash_algorithms
{
	PGP_MD5 = 1,
	PGP_SHA1 = 2,
	PGP_RIPEMD_160 = 3,
	PGP_SHA2_256 = 8,
	PGP_SHA2_384 = 9,
	PGP_SHA2_512 = 10,
	PGP_SHA2_224 = 11,
	PGP_SHA3_256 = 12,
	PGP_SHA3_512 = 14
} pgp_hash_algorithms;

typedef enum _pgp_aead_algorithms
{
	PGP_AEAD_EAX = 1,
	PGP_AEAD_OCB = 2,
	PGP_AEAD_GCM = 3
} pgp_aead_algorithms;

typedef enum _pgp_elliptic_curve_id
{
	PGP_EC_NIST_P256 = 1,
	PGP_EC_NIST_P384 = 2,
	PGP_EC_NIST_P521 = 3,
	PGP_EC_BRAINPOOL_256R1 = 4,
	PGP_EC_BRAINPOOL_384R1 = 5,
	PGP_EC_BRAINPOOL_512R1 = 6,
	PGP_EC_ED25519_LEGACY = 7,
	PGP_EC_CURVE25519_LEGACY = 8,
} pgp_elliptic_curve_id;

#endif
