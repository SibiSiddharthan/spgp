/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <crypto.h>

#include <cipher.h>
#include <drbg.h>

void *pgp_drbg = NULL;

static cipher_algorithm pgp_algorithm_to_cipher_algorithm(pgp_symmetric_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_PLAINTEXT:
	case PGP_IDEA:
	case PGP_CAST5_128:
	case PGP_BLOWFISH:
		return 0; // Unimplemented
	case PGP_TDES:
		return CIPHER_TDES;
	case PGP_AES_128:
		return CIPHER_AES128;
	case PGP_AES_192:
		return CIPHER_AES192;
	case PGP_AES_256:
		return CIPHER_AES256;
	case PGP_TWOFISH:
		return CIPHER_TWOFISH256;
	case PGP_CAMELLIA_128:
		return CIPHER_CAMELLIA128;
	case PGP_CAMELLIA_192:
		return CIPHER_CAMELLIA192;
	case PGP_CAMELLIA_256:
		return CIPHER_CAMELLIA256;
	default:
		return 0;
	}
}

byte_t pgp_symmetric_cipher_algorithm_validate(pgp_symmetric_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_PLAINTEXT:
	case PGP_IDEA:
	case PGP_TDES:
	case PGP_CAST5_128:
	case PGP_BLOWFISH:
	case PGP_AES_128:
	case PGP_AES_192:
	case PGP_AES_256:
	case PGP_TWOFISH:
	case PGP_CAMELLIA_128:
	case PGP_CAMELLIA_192:
	case PGP_CAMELLIA_256:
		return 1;
	}

	return 0;
}

byte_t pgp_asymmetric_cipher_algorithm_validate(pgp_public_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	case PGP_ECDH:
	case PGP_X25519:
	case PGP_X448:
		return 1;
	}

	return 0;
}

byte_t pgp_signature_algorithm_validate(pgp_public_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	case PGP_DSA:
	case PGP_ECDSA:
	case PGP_EDDSA_LEGACY:
	case PGP_ED25519:
	case PGP_ED448:
		return 1;
	}

	return 0;
}

byte_t pgp_aead_algorithm_validate(pgp_aead_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_AEAD_EAX:
	case PGP_AEAD_OCB:
	case PGP_AEAD_GCM:
		return 1;
	}

	return 0;
}

byte_t pgp_symmetric_cipher_key_size(pgp_symmetric_key_algorithms algorithm)
{
	return (byte_t)cipher_key_size(pgp_algorithm_to_cipher_algorithm(algorithm));
}

byte_t pgp_symmetric_cipher_block_size(pgp_symmetric_key_algorithms algorithm)
{
	return (byte_t)cipher_block_size(pgp_algorithm_to_cipher_algorithm(algorithm));
}

byte_t pgp_aead_iv_size(pgp_aead_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_AEAD_EAX:
		return 16;
	case PGP_AEAD_OCB:
		return 15;
	case PGP_AEAD_GCM:
		return 12;
	}

	return 0;
}

uint32_t pgp_rand(void *buffer, uint32_t size)
{
	if (pgp_drbg == NULL)
	{
		pgp_drbg = hmac_drbg_new(NULL, HASH_SHA512, 1u << 12, "PGP", 3);

		if (pgp_drbg == NULL)
		{
			return 0;
		}
	}

	return hmac_drbg_generate(pgp_drbg, 0, NULL, 0, buffer, size);
}
