/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <crypto.h>

#include <cipher.h>
#include <drbg.h>

#include <rsa.h>
#include <eddsa.h>

#include <string.h>

void *pgp_drbg = NULL;

static bignum_t *mpi_to_bignum(mpi_t *mpi)
{
	bignum_t *bn = bignum_new(mpi->bits);

	if (bn == NULL)
	{
		return NULL;
	}

	bn = bignum_set_bytes_be(bn, mpi->bytes, CEIL_DIV(mpi->bits, 8));

	return bn;
}

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

byte_t pgp_public_cipher_algorithm_validate(pgp_public_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	case PGP_DSA:
	case PGP_ECDH:
	case PGP_ECDSA:
	case PGP_EDDSA_LEGACY:
	case PGP_X25519:
	case PGP_X448:
	case PGP_ED25519:
	case PGP_ED448:
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

byte_t pgp_hash_size(pgp_hash_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_MD5:
		return 16;
	case PGP_SHA1:
		return 20;
	case PGP_RIPEMD_160:
		return 20;
	case PGP_SHA2_256:
		return 32;
	case PGP_SHA2_384:
		return 48;
	case PGP_SHA2_512:
		return 64;
	case PGP_SHA2_224:
		return 28;
	case PGP_SHA3_256:
		return 32;
	case PGP_SHA3_512:
		return 64;
	default:
		return 0;
	}
}

byte_t pgp_hash_algorithm_validate(pgp_hash_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_MD5:
	case PGP_SHA1:
	case PGP_RIPEMD_160:
	case PGP_SHA2_256:
	case PGP_SHA2_384:
	case PGP_SHA2_512:
	case PGP_SHA2_224:
	case PGP_SHA3_256:
	case PGP_SHA3_512:
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

byte_t pgp_hash_salt_size(pgp_hash_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_SHA2_256:
		return 16;
	case PGP_SHA2_384:
		return 24;
	case PGP_SHA2_512:
		return 32;
	case PGP_SHA2_224:
		return 16;
	case PGP_SHA3_256:
		return 16;
	case PGP_SHA3_512:
		return 32;
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
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb128_encrypt_init(cctx, iv, iv_size);

		if (cctx == NULL)
		{
			return 0;
		}

		return cipher_cfb128_encrypt_final(cctx, in, in_size, out, out_size);
	}
	else if (block_size == 8)
	{
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb64_encrypt_init(cctx, iv, iv_size);

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
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb128_decrypt_init(cctx, iv, iv_size);

		if (cctx == NULL)
		{
			return 0;
		}

		return cipher_cfb128_decrypt_final(cctx, in, in_size, out, out_size);
	}
	else if (block_size == 8)
	{
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return 0;
		}

		cctx = cipher_cfb64_decrypt_init(cctx, iv, iv_size);

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

	cctx = cipher_init(buffer, 2048, CIPHER_AEAD_INIT, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	switch (aead_algorithm_id)
	{
	case PGP_AEAD_EAX:
	{
		cipher_eax_encrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_eax_encrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	case PGP_AEAD_OCB:
	{
		cipher_ocb_encrypt_init(cctx, tag_size, iv, iv_size, associated_data, ad_size);
		cipher_ocb_encrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
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

	cctx = cipher_init(buffer, 2048, CIPHER_AEAD_INIT, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	switch (aead_algorithm_id)
	{
	case PGP_AEAD_EAX:
	{
		cipher_eax_decrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_eax_decrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
	}
	break;
	case PGP_AEAD_OCB:
	{
		cipher_ocb_decrypt_init(cctx, tag_size, iv, iv_size, associated_data, ad_size);
		cipher_ocb_decrypt_final(cctx, in, in_size, out, out_size, tag, tag_size);
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

static rsa_key *pgp_rsa_key_convert(pgp_rsa_public_key *public_key, pgp_rsa_private_key *private_key)
{
	uint32_t bits = ROUND_UP(public_key->n->bits, 1024);

	rsa_key *key = NULL;
	bignum_t *n = NULL, *p = NULL, *q = NULL;
	bignum_t *e = NULL, *d = NULL;

	key = rsa_key_new(bits);

	if (key == NULL)
	{
		return NULL;
	}

	n = mpi_to_bignum(public_key->n);
	e = mpi_to_bignum(public_key->e);

	if (n == NULL || e == NULL)
	{
		bignum_delete(n);
		bignum_delete(e);
	}

	key->n = n;
	key->e = e;

	if (private_key != NULL)
	{
		d = mpi_to_bignum(private_key->d);
		p = mpi_to_bignum(private_key->p);
		q = mpi_to_bignum(private_key->q);

		key->d = d;
		key->p = p;
		key->q = q;
	}

	return key;
}

uint32_t pgp_rsa_encrypt_(pgp_rsa_public_key *public_key, void *in, uint32_t in_size, void *out, uint32_t out_size)
{
	uint32_t bytes = CEIL_DIV(public_key->n->bits, 8);
	uint32_t required_size = sizeof(mpi_t) + bytes;

	rsa_key *key = NULL;
	mpi_t *mpi = out;

	if (out_size < required_size)
	{
		return 0;
	}

	key = pgp_rsa_key_convert(public_key, NULL);

	if (key == NULL)
	{
		return 0;
	}

	rsa_encrypt_pkcs(key, in, in_size, PTR_OFFSET(out, sizeof(mpi_t)), bytes, NULL);

	mpi->bytes = PTR_OFFSET(mpi, sizeof(mpi_t));
	mpi->bits = mpi_bitcount(mpi->bytes, bytes);

	rsa_key_delete(key);

	return required_size;
}

uint32_t pgp_rsa_decrypt(pgp_rsa_public_key *public_key, pgp_rsa_private_key *private_key, void *in, uint32_t in_size, void *out,
						 uint32_t out_size)
{
	rsa_key *key = NULL;

	key = pgp_rsa_key_convert(public_key, private_key);

	if (key == NULL)
	{
		return 0;
	}

	rsa_decrypt_pkcs(key, in, in_size, out, out_size);

	rsa_key_delete(key);

	return 0;
}

pgp_ed25519_signature *pgp_ed25519_sign(pgp_ed25519_public_key *public_key, pgp_ed25519_private_key *private_key, void *hash,
										uint32_t hash_size)
{
	void *status = NULL;

	ed25519_key key = {0};
	pgp_ed25519_signature *sign = NULL;

	sign = malloc(sizeof(pgp_ed25519_signature));

	if (sign == NULL)
	{
		return NULL;
	}

	// Set the key
	memcpy(key.private_key, private_key->private_key, ED25519_KEY_OCTETS);
	memcpy(key.public_key, public_key->public_key, ED25519_KEY_OCTETS);

	status = ed25519_sign(&key, hash, hash_size, sign, sizeof(ed25519_signature));

	if (status == NULL)
	{
		free(sign);
		return NULL;
	}

	return sign;
}

uint32_t pgp_ed25519_verify(pgp_ed25519_signature *signature, pgp_ed25519_public_key *public_key, void *hash, uint32_t hash_size)
{
	uint32_t status = NULL;

	ed25519_key key = {0};
	ed25519_signature sign = {0};

	// Set the key
	memcpy(key.public_key, public_key->public_key, ED25519_KEY_OCTETS);

	// Set the signature
	memcpy(sign.sign, signature->sig, ED25519_SIGN_OCTETS);

	// TODO key validation
	status = ed25519_verify(&key, &sign, hash, hash_size);

	return status;
}

pgp_ed448_signature *pgp_ed448_sign(pgp_ed448_public_key *public_key, pgp_ed448_private_key *private_key, void *hash, uint32_t hash_size)
{
	void *status = NULL;

	ed448_key key = {0};
	pgp_ed448_signature *sign = NULL;

	sign = malloc(sizeof(pgp_ed448_signature));

	if (sign == NULL)
	{
		return NULL;
	}

	// Set the key
	memcpy(key.private_key, private_key->private_key, ED448_KEY_OCTETS);
	memcpy(key.public_key, public_key->public_key, ED448_KEY_OCTETS);

	status = ed448_sign(&key, NULL, 0, hash, hash_size, sign, sizeof(ed448_signature));

	if (status == NULL)
	{
		free(sign);
		return NULL;
	}

	return sign;
}

uint32_t pgp_ed448_verify(pgp_ed448_signature *signature, pgp_ed448_public_key *public_key, void *hash, uint32_t hash_size)
{
	uint32_t status = NULL;

	ed448_key key = {0};
	ed448_signature sign = {0};

	// Set the key
	memcpy(key.public_key, public_key->public_key, ED448_KEY_OCTETS);

	// Set the signature
	memcpy(sign.sign, signature->sig, ED448_SIGN_OCTETS);

	// TODO key validation
	status = ed448_verify(&key, &sign, NULL, 0, hash, hash_size);

	return status;
}
