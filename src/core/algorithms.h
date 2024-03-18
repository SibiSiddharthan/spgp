#ifndef SPGP_ALGORITHMS_H
#define SPGP_ALGORITHMS_H

#include "macros.h"

typedef enum _public_key_algorithms
{
	PGP_RSA_ENCRYPT_OR_SIGN = 1,
	PGP_RSA_ENCRYPT_ONLY = 2,
	PGP_RSA_SIGN_ONLY = 3,
	PGP_ELGAMAL_ENCRYPT_ONLY = 16,
	PGP_DSA = 17,
	PGP_ECDH = 18,
	PGP_ECDSA = 19,
	PGP_ELGAMAL_ENCRYPT_OR_SIGN = 20,
	PGP_EDDSA_LEGACY = 22,
	PGP_X25519 = 25,
	PGP_X448 = 26,
	PGP_ED25519 = 27,
	PGP_ED448 = 28
} public_key_algorithms;

typedef enum _symmetric_key_algorithms
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
} symmetric_key_algorithms;

typedef enum _compression_algorithms
{
	UNCOMPRESSED = 0,
	DEFALTE = 1,
	ZLIB = 2,
	BZIP2 = 3
} compression_algorithms;

typedef enum _hash_algorithms
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
} hash_algorithms;

typedef enum _aead_algorithms
{
	PGP_AEAD_EAX = 1,
	PGP_AEAD_OCB = 2,
	PGP_AEAD_GCM = 3
} aead_algorithms;

#endif
