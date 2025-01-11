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
	default:
		return 0;
	}
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
	default:
		return 0;
	}
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
	default:
		return 0;
	}
}

byte_t pgp_aead_algorithm_validate(pgp_aead_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_AEAD_EAX:
	case PGP_AEAD_OCB:
	case PGP_AEAD_GCM:
		return 1;
	default:
		return 0;
	}
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
	default:
		return 0;
	}
}

size_t pgp_cfb_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, void *key, size_t key_size, void *iv, byte_t iv_size,
					   void *in, size_t in_size, void *out, size_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cipher_algorithm algorithm = 0;
	byte_t block_size = 0;

	algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);

	if (algorithm == 0)
	{
		return 0;
	}

	block_size = cipher_block_size(algorithm);

	if (block_size == 16)
	{
		cctx = cipher_init(buffer, 512, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb128_encrypt_init(cctx, PADDING_ZERO, iv, iv_size);

		if (cctx == NULL)
		{
			return 0;
		}

		return cipher_cfb128_encrypt_final(cctx, in, in_size, out, out_size);
	}
	else if (block_size == 8)
	{
		cctx = cipher_init(buffer, 512, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb64_encrypt_init(cctx, PADDING_ZERO, iv, iv_size);

		if (cctx == NULL)
		{
			return 0;
		}

		return cipher_cfb64_encrypt_final(cctx, in, in_size, out, out_size);
	}
	else
	{
		return 0;
	}

	return 0;
}

size_t pgp_cfb_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, void *key, size_t key_size, void *iv, byte_t iv_size,
					   void *in, size_t in_size, void *out, size_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cipher_algorithm algorithm = 0;
	byte_t block_size = 0;

	algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);

	if (algorithm == 0)
	{
		return 0;
	}

	block_size = cipher_block_size(algorithm);

	if (block_size == 16)
	{
		cctx = cipher_init(buffer, 512, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb128_decrypt_init(cctx, PADDING_ZERO, iv, iv_size);

		if (cctx == NULL)
		{
			return 0;
		}

		return cipher_cfb128_decrypt_final(cctx, in, in_size, out, out_size);
	}
	else if (block_size == 8)
	{
		cctx = cipher_init(buffer, 512, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb64_decrypt_init(cctx, PADDING_ZERO, iv, iv_size);

		if (cctx == NULL)
		{
			return 0;
		}

		return cipher_cfb64_decrypt_final(cctx, in, in_size, out, out_size);
	}
	else
	{
		return 0;
	}

	return 0;
}

size_t pgp_aead_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
						size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
						void *out, size_t out_size, void *tag, size_t tag_size)
{
	cipher_algorithm algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);
	byte_t expected_iv_size = pgp_aead_iv_size(aead_algorithm_id);
	byte_t block_size = cipher_block_size(algorithm);

	cipher_ctx *cctx = NULL;
	byte_t buffer[2048] = {0};

	// Preliminary checks
	if (algorithm == 0)
	{
		return 0;
	}

	if (block_size != 16)
	{
		return 0;
	}

	if (expected_iv_size == 0)
	{
		return 0;
	}

	if (expected_iv_size != iv_size)
	{
		return 0;
	}

	if (tag_size != PGP_AEAD_TAG_SIZE)
	{
		return 0;
	}

	if (out_size < in_size)
	{
		return 0;
	}

	cctx = cipher_init(buffer, 2048, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	switch (aead_algorithm_id)
	{
	case PGP_AEAD_EAX:
	{
		cipher_gcm_encrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_encrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	case PGP_AEAD_OCB:
	{
		cipher_gcm_encrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_encrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	case PGP_AEAD_GCM:
	{
		cipher_gcm_encrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_encrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	}

	return in_size;
}

size_t pgp_aead_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
						size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
						void *out, size_t out_size, void *tag, size_t tag_size)
{
	cipher_algorithm algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);
	byte_t expected_iv_size = pgp_aead_iv_size(aead_algorithm_id);
	byte_t block_size = cipher_block_size(algorithm);

	cipher_ctx *cctx = NULL;
	byte_t buffer[2048] = {0};

	// Preliminary checks
	if (algorithm == 0)
	{
		return 0;
	}

	if (block_size != 16)
	{
		return 0;
	}

	if (expected_iv_size == 0)
	{
		return 0;
	}

	if (expected_iv_size != iv_size)
	{
		return 0;
	}

	if (tag_size != PGP_AEAD_TAG_SIZE)
	{
		return 0;
	}

	if (out_size < in_size)
	{
		return 0;
	}

	cctx = cipher_init(buffer, 2048, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	switch (aead_algorithm_id)
	{
	case PGP_AEAD_EAX:
	{
		cipher_gcm_decrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_decrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	case PGP_AEAD_OCB:
	{
		cipher_gcm_decrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_decrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	case PGP_AEAD_GCM:
	{
		cipher_gcm_decrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_decrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	}

	return in_size;
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
