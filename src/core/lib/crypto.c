/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>

#include <crypto.h>
#include <algorithms.h>

#include <bignum.h>
#include <ec.h>

#include <cipher.h>
#include <drbg.h>

#include <rsa.h>
#include <dsa.h>
#include <ecdsa.h>
#include <eddsa.h>
#include <x25519.h>
#include <x448.h>

#include <argon2.h>
#include <hkdf.h>

#include <bitscan.h>

#include <stdlib.h>
#include <string.h>

void *pgp_drbg = NULL;

static uint32_t bitcount_bytes(byte_t *bytes, uint32_t size)
{
	for (uint32_t i = 0; i < size; ++i)
	{
		if (bytes[i] == 0)
		{
			continue;
		}

		return ((size - (i + 1)) * 8) + (bsr_8(bytes[i]) + 1);
	}

	return 0;
}

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

static mpi_t *mpi_from_bignum(bignum_t *bn)
{
	mpi_t *mpi = mpi_new(bn->bits);

	if (mpi == NULL)
	{
		return NULL;
	}

	mpi->bits = bn->bits;
	bignum_get_bytes_be(bn, mpi->bytes, CEIL_DIV(mpi->bits, 8));

	return mpi;
}

static ec_point *mpi_to_ec_point(ec_group *group, mpi_t *mpi)
{
	void *result = NULL;
	ec_point *point = ec_point_new(group);

	if (point == NULL)
	{
		return NULL;
	}

	if (group->id == EC_CURVE25519 || group->id == EC_ED25519)
	{
		// Prefixed native (Ignore the first byte 0x40)
		result = ec_point_decode(group, point, PTR_OFFSET(mpi->bytes, 1), FLOOR_DIV(mpi->bits, 8));
	}
	else
	{
		// SEC point wire format
		result = ec_point_decode(group, point, mpi->bytes, CEIL_DIV(mpi->bits, 8));
	}

	if (result == NULL)
	{
		ec_point_delete(point);
		return NULL;
	}

	return point;
}

static mpi_t *mpi_from_ec_point(ec_group *group, ec_point *point)
{
	mpi_t *mpi = mpi_new(ROUND_UP(group->bits * 2, 8) + 8);

	if (mpi == NULL)
	{
		return NULL;
	}

	if (group->id == EC_CURVE25519 || group->id == EC_ED25519)
	{
		// Prefixed native
		ec_point_encode(group, point, PTR_OFFSET(mpi->bytes, 1), FLOOR_DIV(mpi->bits, 8), 0);

		mpi->bytes[1] = 0x40;
		mpi->bits = ROUND_UP(group->bits * 2, 8) + 7; // 0x40
	}
	else
	{
		// SEC point wire format
		ec_point_encode(group, point, mpi->bytes, CEIL_DIV(mpi->bits, 8), 0);
		mpi->bits = ROUND_UP(group->bits * 2, 8) + 3; // 0x04
	}

	return mpi;
}

static cipher_algorithm pgp_algorithm_to_cipher_algorithm(pgp_symmetric_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_PLAINTEXT:
	case PGP_IDEA:
	case PGP_BLOWFISH:
		return 0; // Unimplemented
	case PGP_CAST5_128:
		return CIPHER_CAST5;
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

static hash_algorithm pgp_algorithm_to_hash_algorithm(pgp_hash_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_MD5:
		return HASH_MD5;
	case PGP_SHA1:
		return HASH_SHA1;
	case PGP_RIPEMD_160:
		return HASH_RIPEMD160;
	case PGP_SHA2_256:
		return HASH_SHA256;
	case PGP_SHA2_384:
		return HASH_SHA384;
	case PGP_SHA2_512:
		return HASH_SHA512;
	case PGP_SHA2_224:
		return HASH_SHA224;
	case PGP_SHA3_256:
		return HASH_SHA3_256;
	case PGP_SHA3_512:
		return HASH_SHA3_512;
	default:
		return 0;
	}
}

static curve_id pgp_ec_curve_to_curve_id(pgp_elliptic_curve_id id)
{
	switch (id)
	{
	case PGP_EC_NIST_P256:
		return EC_NIST_P256;
	case PGP_EC_NIST_P384:
		return EC_NIST_P384;
	case PGP_EC_NIST_P521:
		return EC_NIST_P521;
	case PGP_EC_BRAINPOOL_256R1:
		return EC_BRAINPOOL_256R1;
	case PGP_EC_BRAINPOOL_384R1:
		return EC_BRAINPOOL_384R1;
	case PGP_EC_BRAINPOOL_512R1:
		return EC_BRAINPOOL_512R1;
	case PGP_EC_CURVE25519:
		return EC_CURVE25519;
	case PGP_EC_CURVE448:
		return EC_CURVE448;
	case PGP_EC_ED25519:
		return EC_ED25519;
	case PGP_EC_ED448:
		return EC_ED448;
	default:
		return 0;
	}
}

static pgp_elliptic_curve_id pgp_curve_id_to_ec_curve(curve_id id)
{
	switch (id)
	{
	case EC_NIST_P256:
		return PGP_EC_NIST_P256;
	case EC_NIST_P384:
		return PGP_EC_NIST_P384;
	case EC_NIST_P521:
		return PGP_EC_NIST_P521;
	case EC_BRAINPOOL_256R1:
		return PGP_EC_BRAINPOOL_256R1;
	case EC_BRAINPOOL_384R1:
		return PGP_EC_BRAINPOOL_384R1;
	case EC_BRAINPOOL_512R1:
		return PGP_EC_BRAINPOOL_512R1;
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
	case PGP_EDDSA:
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
	case PGP_EDDSA:
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

byte_t pgp_elliptic_curve(byte_t *oid, byte_t size)
{
	curve_id id = ec_curve_decode_oid(oid, size);

	if (id == 0)
	{
		// Check legacy curves
		if (size == 9 && memcmp(oid, "\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01", 9) == 0)
		{
			return PGP_EC_ED25519;
		}

		if (size == 10 && memcmp(oid, "\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01", 10) == 0)
		{
			return PGP_EC_CURVE25519;
		}

		return 0;
	}

	return pgp_curve_id_to_ec_curve(id);
}

pgp_error_t pgp_hash_new(pgp_hash_t **ctx, pgp_hash_algorithms hash_algorithm_id)
{
	hash_ctx *hctx = NULL;
	hash_algorithm algorithm = 0;

	algorithm = pgp_algorithm_to_hash_algorithm(hash_algorithm_id);

	if (algorithm == 0)
	{
		return PGP_UNSUPPORTED_HASH_ALGORITHM;
	}

	hctx = hash_new(algorithm);

	if (hctx == NULL)
	{
		return PGP_NO_MEMORY;
	}

	*ctx = (void *)hctx;

	return PGP_SUCCESS;
}

void pgp_hash_delete(pgp_hash_t *ctx)
{
	hash_delete((hash_ctx *)ctx);
}

void pgp_hash_reset(pgp_hash_t *ctx)
{
	hash_reset((hash_ctx *)ctx);
}

pgp_hash_t *pgp_hash_dup(pgp_hash_t *ctx)
{
	return (void *)hash_dup((void *)ctx);
}

void pgp_hash_update(pgp_hash_t *ctx, void *data, size_t size)
{
	hash_update((hash_ctx *)ctx, data, size);
}

uint32_t pgp_hash_final(pgp_hash_t *ctx, void *hash, size_t size)
{
	return hash_final((hash_ctx *)ctx, hash, size);
}

pgp_error_t pgp_hash(pgp_hash_algorithms algorithm, void *data, size_t data_size, void *hash, byte_t hash_size)
{
	pgp_error_t status = 0;
	pgp_hash_t *hctx = NULL;

	status = pgp_hash_new(&hctx, algorithm);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	pgp_hash_update(hctx, data, data_size);
	pgp_hash_final(hctx, hash, hash_size);

	return PGP_SUCCESS;
}

pgp_error_t pgp_cfb_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, void *key, size_t key_size, void *iv, byte_t iv_size,
							void *in, size_t in_size, void *out, size_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cipher_algorithm algorithm = 0;
	byte_t block_size = 0;

	algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);
	block_size = cipher_block_size(algorithm);

	if (algorithm == 0)
	{
		return PGP_UNSUPPORTED_CIPHER_ALGORITHM;
	}

	if (out_size < in_size)
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	if (iv_size != block_size)
	{
		return PGP_INVALID_CFB_IV_SIZE;
	}

	if (block_size == 16)
	{
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return PGP_NO_MEMORY;
		}

		cipher_cfb128_encrypt_init(cctx, iv, iv_size);
		cipher_cfb128_encrypt_final(cctx, in, in_size, out, out_size);
	}

	if (block_size == 8)
	{
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return PGP_NO_MEMORY;
		}

		cipher_cfb64_encrypt_init(cctx, iv, iv_size);
		cipher_cfb64_encrypt_final(cctx, in, in_size, out, out_size);
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_cfb_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, void *key, size_t key_size, void *iv, byte_t iv_size,
							void *in, size_t in_size, void *out, size_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cipher_algorithm algorithm = 0;
	byte_t block_size = 0;

	algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);
	block_size = cipher_block_size(algorithm);

	if (algorithm == 0)
	{
		return PGP_UNSUPPORTED_CIPHER_ALGORITHM;
	}

	if (out_size < in_size)
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	if (iv_size != block_size)
	{
		return PGP_INVALID_CFB_IV_SIZE;
	}

	if (block_size == 16)
	{
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return PGP_NO_MEMORY;
		}

		cipher_cfb128_decrypt_init(cctx, iv, iv_size);
		cipher_cfb128_decrypt_final(cctx, in, in_size, out, out_size);
	}

	if (block_size == 8)
	{
		cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

		if (cctx == NULL)
		{
			return PGP_NO_MEMORY;
		}

		cipher_cfb64_decrypt_init(cctx, iv, iv_size);
		cipher_cfb64_decrypt_final(cctx, in, in_size, out, out_size);
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
							 size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
							 void *out, size_t out_size)
{
	cipher_algorithm algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);
	byte_t expected_iv_size = pgp_aead_iv_size(aead_algorithm_id);
	byte_t block_size = cipher_block_size(algorithm);

	cipher_ctx *cctx = NULL;
	byte_t buffer[2048] = {0};

	// Preliminary checks
	if (algorithm == 0)
	{
		return PGP_UNSUPPORTED_CIPHER_ALGORITHM;
	}

	if (block_size != 16)
	{
		return PGP_INVALID_AEAD_CIPHER_PAIR;
	}

	if (expected_iv_size == 0)
	{
		return PGP_UNSUPPORTED_AEAD_ALGORITHM;
	}

	if (expected_iv_size != iv_size)
	{
		return PGP_INVALID_AEAD_IV_SIZE;
	}

	if (out_size < (in_size + PGP_AEAD_TAG_SIZE))
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	cctx = cipher_init(buffer, 2048, CIPHER_AEAD_INIT, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return PGP_NO_MEMORY;
	}

	switch (aead_algorithm_id)
	{
	case PGP_AEAD_EAX:
	{
		cipher_eax_encrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_eax_encrypt_final(cctx, in, in_size, out, in_size, PTR_OFFSET(out, in_size), PGP_AEAD_TAG_SIZE);
	}
	break;
	case PGP_AEAD_OCB:
	{
		cipher_ocb_encrypt_init(cctx, PGP_AEAD_TAG_SIZE, iv, iv_size, associated_data, ad_size);
		cipher_ocb_encrypt_final(cctx, in, in_size, out, in_size, PTR_OFFSET(out, in_size), PGP_AEAD_TAG_SIZE);
	}
	break;
	case PGP_AEAD_GCM:
	{
		cipher_gcm_encrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_encrypt_final(cctx, in, in_size, out, in_size, PTR_OFFSET(out, in_size), PGP_AEAD_TAG_SIZE);
	}
	break;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_aead_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
							 size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
							 void *out, size_t out_size)
{
	cipher_algorithm algorithm = pgp_algorithm_to_cipher_algorithm(symmetric_key_algorithm_id);
	byte_t expected_iv_size = pgp_aead_iv_size(aead_algorithm_id);
	byte_t block_size = cipher_block_size(algorithm);

	cipher_ctx *cctx = NULL;
	byte_t buffer[2048] = {0};

	byte_t tag[PGP_AEAD_TAG_SIZE] = {0};

	// Preliminary checks
	if (algorithm == 0)
	{
		return PGP_UNSUPPORTED_CIPHER_ALGORITHM;
	}

	if (block_size != 16)
	{
		return PGP_INVALID_AEAD_CIPHER_PAIR;
	}

	if (expected_iv_size == 0)
	{
		return PGP_UNSUPPORTED_AEAD_ALGORITHM;
	}

	if (expected_iv_size != iv_size)
	{
		return PGP_INVALID_AEAD_IV_SIZE;
	}

	if (out_size < (in_size - PGP_AEAD_TAG_SIZE))
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	cctx = cipher_init(buffer, 2048, CIPHER_AEAD_INIT, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return PGP_NO_MEMORY;
	}

	switch (aead_algorithm_id)
	{
	case PGP_AEAD_EAX:
	{
		cipher_eax_decrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_eax_decrypt_final(cctx, in, in_size, out, out_size, tag, PGP_AEAD_TAG_SIZE);
	}
	break;
	case PGP_AEAD_OCB:
	{
		cipher_ocb_decrypt_init(cctx, PGP_AEAD_TAG_SIZE, iv, iv_size, associated_data, ad_size);
		cipher_ocb_decrypt_final(cctx, in, in_size, out, out_size, tag, PGP_AEAD_TAG_SIZE);
	}
	break;
	case PGP_AEAD_GCM:
	{
		cipher_gcm_decrypt_init(cctx, iv, iv_size, associated_data, ad_size);
		cipher_gcm_decrypt_final(cctx, in, in_size, out, out_size, tag, PGP_AEAD_TAG_SIZE);
	}
	break;
	}

	// Check the tag
	if (memcmp(PTR_OFFSET(in, in_size - PGP_AEAD_TAG_SIZE), tag, PGP_AEAD_TAG_SIZE) != 0)
	{
		return PGP_AEAD_TAG_MISMATCH;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_rand(void *buffer, uint32_t size)
{
	if (pgp_drbg == NULL)
	{
		pgp_drbg = hmac_drbg_new(NULL, HASH_SHA512, 1u << 12, "PGP", 3);

		if (pgp_drbg == NULL)
		{
			return PGP_RAND_ERROR;
		}
	}

	if (hmac_drbg_generate(pgp_drbg, 0, NULL, 0, buffer, size) != size)
	{
		return PGP_RAND_ERROR;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_rsa_generate_key(pgp_rsa_key **key, uint32_t bits)
{
	pgp_error_t status = 0;

	rsa_key *rsa_key = NULL;
	pgp_rsa_key *pgp_key = NULL;
	bignum_t *e = NULL;

	bits = ROUND_UP(bits, 1024);

	if (bits > 4096)
	{
		status = PGP_RSA_KEY_UNSUPPORTED_BIT_SIZE;
		goto fail;
	}

	e = bignum_new(64);

	if (e == NULL)
	{
		status = PGP_NO_MEMORY;
		goto fail;
	}

	// Use default e
	bignum_set_word(e, 65537);
	rsa_key = rsa_key_generate(bits, e);

	if (rsa_key == NULL)
	{
		status = PGP_RSA_KEY_GENERATION_FAILURE;
		goto fail;
	}

	pgp_key = pgp_rsa_key_new();

	if (pgp_key == NULL)
	{
		status = PGP_NO_MEMORY;
		goto fail;
	}

	pgp_key->n = mpi_from_bignum(rsa_key->n);
	pgp_key->e = mpi_from_bignum(rsa_key->e);
	pgp_key->d = mpi_from_bignum(rsa_key->d);
	pgp_key->p = mpi_from_bignum(rsa_key->p);
	pgp_key->q = mpi_from_bignum(rsa_key->q);
	pgp_key->u = mpi_from_bignum(rsa_key->iqmp);

	if (pgp_key->n == NULL || pgp_key->e == NULL || pgp_key->d == NULL || pgp_key->p == NULL || pgp_key->q == NULL || pgp_key->u == NULL)
	{
		status = PGP_NO_MEMORY;
		goto fail;
	}

	*key = pgp_key;
	status = PGP_SUCCESS;

end:
	bignum_delete(e);
	rsa_key_delete(rsa_key);

	return status;

fail:
	pgp_rsa_key_delete(pgp_key);
	goto end;
}

pgp_error_t pgp_dsa_generate_key(pgp_dsa_key **key, uint32_t bits)
{
	dsa_group *group = NULL;
	dsa_key *dsa_key = NULL;
	pgp_dsa_key *pgp_key = NULL;

	uint32_t p_bits = ROUND_UP(bits, 1024);
	uint32_t q_bits = 0;

	switch (p_bits)
	{
	case 1024:
		q_bits = 160;
		break;
	case 2048:
		q_bits = 224;
		break;
	case 3072:
		q_bits = 256;
		break;
	default:
		return PGP_DSA_KEY_UNSUPPORTED_BIT_SIZE;
	}

	group = dsa_group_generate(p_bits, q_bits);

	if (group == NULL)
	{
		return PGP_DSA_KEY_GENERATION_FAILURE;
	}

	dsa_key = dsa_key_generate(group, NULL);

	if (dsa_key == NULL)
	{
		dsa_group_delete(group);
		return PGP_DSA_KEY_GENERATION_FAILURE;
	}

	pgp_key = pgp_dsa_key_new();

	if (pgp_key == NULL)
	{
		dsa_key_delete(dsa_key);
		return PGP_NO_MEMORY;
	}

	pgp_key->p = mpi_from_bignum(dsa_key->group->p);
	pgp_key->q = mpi_from_bignum(dsa_key->group->q);
	pgp_key->g = mpi_from_bignum(dsa_key->group->g);
	pgp_key->x = mpi_from_bignum(dsa_key->x);
	pgp_key->y = mpi_from_bignum(dsa_key->y);

	dsa_key_delete(dsa_key);

	if (pgp_key->p == NULL || pgp_key->q == NULL || pgp_key->g == NULL || pgp_key->x == NULL || pgp_key->y == NULL)
	{
		pgp_dsa_key_delete(pgp_key);
		return PGP_NO_MEMORY;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_elgamal_generate_key(pgp_elgamal_key **key, uint32_t bits)
{
	dh_group *group = NULL;
	dh_key *dh_key = NULL;
	pgp_elgamal_key *pgp_key = NULL;

	bits = ROUND_UP(bits, 1024);

	if (bits > 4096)
	{
		return PGP_ELGAMAL_KEY_UNSUPPORTED_BIT_SIZE;
	}

	switch (bits)
	{
	case 1024:
		group = dh_group_new(DH_MODP_1024); // Use modp group for this alone
		break;
	case 2048:
		group = dh_group_new(DH_FFDHE_2048);
		break;
	case 3072:
		group = dh_group_new(DH_FFDHE_3072);
		break;
	case 4096:
		group = dh_group_new(DH_FFDHE_4096);
		break;
	}

	if (group == NULL)
	{
		return PGP_NO_MEMORY;
	}

	dh_key = dh_key_generate(group, NULL);

	if (dh_key == NULL)
	{
		dh_group_delete(group);
		return PGP_NO_MEMORY;
	}

	pgp_key = pgp_elgamal_key_new();

	if (pgp_key == NULL)
	{
		dh_key_delete(dh_key);
		return PGP_NO_MEMORY;
	}

	pgp_key->p = mpi_from_bignum(dh_key->group->p);
	pgp_key->g = mpi_from_bignum(dh_key->group->g);
	pgp_key->x = mpi_from_bignum(dh_key->x);
	pgp_key->y = mpi_from_bignum(dh_key->y);

	dh_key_delete(dh_key);

	if (pgp_key->p == NULL || pgp_key->g == NULL || pgp_key->x == NULL || pgp_key->y == NULL)
	{
		pgp_elgamal_key_delete(pgp_key);
		return PGP_NO_MEMORY;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

static pgp_error_t pgp_ec_key_generate(ec_key **key, curve_id id)
{
	ec_group *group = NULL;
	ec_key *ec_key = NULL;

	group = ec_group_new(id);

	if (group == NULL)
	{
		return PGP_NO_MEMORY;
	}

	ec_key = ec_key_generate(group, NULL);

	if (ec_key == NULL)
	{
		ec_group_delete(group);
		return PGP_ELLIPTIC_CURVE_KEY_GENERATION_FAILURE;
	}

	*key = ec_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_ecdsa_generate_key(pgp_ecdsa_key **key, pgp_elliptic_curve_id curve)
{
	pgp_error_t status = 0;

	ec_key *ec_key = NULL;
	pgp_ecdsa_key *pgp_key = NULL;
	curve_id id = pgp_ec_curve_to_curve_id(curve);

	if (id == 0)
	{
		return PGP_UNSUPPORTED_ELLIPTIC_CURVE;
	}

	status = pgp_ec_key_generate(&ec_key, id);

	if (status != PGP_SUCCESS)
	{
		if (status == PGP_ELLIPTIC_CURVE_KEY_GENERATION_FAILURE)
		{
			status = PGP_ECDSA_KEY_GENERATION_FAILURE;
		}

		return status;
	}

	pgp_key = pgp_ecdsa_key_new();

	if (pgp_key == NULL)
	{
		ec_key_delete(ec_key);
		return PGP_NO_MEMORY;
	}

	pgp_key->curve = curve;
	pgp_key->oid_size = (byte_t)ec_curve_encode_oid(id, pgp_key->oid, 16);
	pgp_key->point = mpi_from_ec_point(ec_key->eg, ec_key->q);
	pgp_key->x = mpi_from_bignum(ec_key->d);

	ec_key_delete(ec_key);

	if (pgp_key->point == NULL || pgp_key->x == NULL)
	{
		pgp_ecdsa_key_delete(pgp_key);
		return PGP_NO_MEMORY;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_eddsa_generate_key(pgp_eddsa_key **key, pgp_elliptic_curve_id curve, byte_t legacy_oid)
{
	void *result = NULL;

	pgp_eddsa_key *pgp_key = NULL;
	curve_id id = pgp_ec_curve_to_curve_id(curve);

	pgp_key = pgp_ecdsa_key_new();

	if (pgp_key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	if (curve == PGP_ED25519)
	{
		uint32_t bits = 256 + 7;
		ed25519_key ed25519_key = {0};
		byte_t zero[ED25519_KEY_OCTETS] = {0};

		result = ed25519_key_generate(&ed25519_key, zero);

		if (result == NULL)
		{
			pgp_ecdsa_key_delete(pgp_key);
			return PGP_EDDSA_KEY_GENERATION_FAILURE;
		}

		pgp_key->curve = curve;

		if (legacy_oid)
		{
			pgp_key->oid_size = 9;
			memcpy(pgp_key->oid, "\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01", 9);
		}
		else
		{
			pgp_key->oid_size = (byte_t)ec_curve_encode_oid(id, pgp_key->oid, 16);
		}

		pgp_key->point = mpi_new(bits);
		pgp_key->x = mpi_new(bits);

		if (pgp_key->point == NULL || pgp_key->x == NULL)
		{
			pgp_ecdsa_key_delete(pgp_key);
			return PGP_NO_MEMORY;
		}

		// Set the public point
		pgp_key->point->bits = bits;
		pgp_key->point->bytes[0] = 0x40;
		memcpy(&pgp_key->point->bytes[1], ed25519_key.public_key, ED25519_KEY_OCTETS);

		// Set the private scalar
		pgp_key->x->bits = bits;
		pgp_key->x->bytes[0] = 0x40;
		memcpy(&pgp_key->x->bytes[1], ed25519_key.private_key, ED25519_KEY_OCTETS);

		*key = pgp_key;
		return PGP_SUCCESS;
	}

	if (curve == PGP_ED448)
	{
		uint32_t bits = 448 + 7;
		ed448_key ed448_key = {0};
		byte_t zero[ED448_KEY_OCTETS] = {0};

		result = ed448_key_generate(&ed448_key, zero);

		if (result == NULL)
		{
			pgp_ecdsa_key_delete(pgp_key);
			return PGP_EDDSA_KEY_GENERATION_FAILURE;
		}

		pgp_key->curve = curve;
		pgp_key->oid_size = (byte_t)ec_curve_encode_oid(id, pgp_key->oid, 16);

		pgp_key->point = mpi_new(bits);
		pgp_key->x = mpi_new(bits);

		if (pgp_key->point == NULL || pgp_key->x == NULL)
		{
			pgp_ecdsa_key_delete(pgp_key);
			return PGP_NO_MEMORY;
		}

		// Set the public point
		pgp_key->point->bits = bits;
		pgp_key->point->bytes[0] = 0x40;
		memcpy(&pgp_key->point->bytes[1], ed448_key.public_key, ED448_KEY_OCTETS);

		// Set the private scalar
		pgp_key->x->bits = bits;
		pgp_key->x->bytes[0] = 0x40;
		memcpy(&pgp_key->x->bytes[1], ed448_key.private_key, ED448_KEY_OCTETS);

		*key = pgp_key;
		return PGP_SUCCESS;
	}

	// Unreachable
	return PGP_UNSUPPORTED_EDWARDS_CURVE;
}

pgp_error_t pgp_ecdh_generate_key(pgp_ecdh_key **key, pgp_elliptic_curve_id curve, byte_t hash_algorithm_id,
								  byte_t symmetric_key_algorithm_id, byte_t legacy_oid)
{
	pgp_error_t status = 0;

	ec_key *ec_key = NULL;
	pgp_ecdh_key *pgp_key = NULL;
	curve_id id = pgp_ec_curve_to_curve_id(curve);

	if (id == 0)
	{
		return PGP_UNSUPPORTED_ELLIPTIC_CURVE;
	}

	status = pgp_ec_key_generate(&ec_key, id);

	if (status != PGP_SUCCESS)
	{
		if (status == PGP_ELLIPTIC_CURVE_KEY_GENERATION_FAILURE)
		{
			status = PGP_ECDSA_KEY_GENERATION_FAILURE;
		}

		return status;
	}

	pgp_key = pgp_ecdh_key_new();

	if (pgp_key == NULL)
	{
		ec_key_delete(ec_key);
		return PGP_NO_MEMORY;
	}

	if (curve == PGP_EC_CURVE25519 && legacy_oid)
	{
		pgp_key->oid_size = 10;
		memcpy(pgp_key->oid, "\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01", 10);
	}
	else
	{
		pgp_key->oid_size = (byte_t)ec_curve_encode_oid(id, pgp_key->oid, 16);
	}

	pgp_key->point = mpi_from_ec_point(ec_key->eg, ec_key->q);
	pgp_key->x = mpi_from_bignum(ec_key->d);

	pgp_key->kdf.size = 3;
	pgp_key->kdf.extensions = 1;
	pgp_key->kdf.hash_algorithm_id = hash_algorithm_id;
	pgp_key->kdf.symmetric_key_algorithm_id = symmetric_key_algorithm_id;

	ec_key_delete(ec_key);

	if (pgp_key->point == NULL || pgp_key->x == NULL)
	{
		pgp_ecdh_key_delete(pgp_key);
		return PGP_NO_MEMORY;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_x25519_generate_key(pgp_x25519_key **key)
{
	void *result = NULL;

	pgp_x25519_key *pgp_key = NULL;
	byte_t zero[X25519_KEY_OCTETS] = {0};

	pgp_key = malloc(sizeof(pgp_x25519_key));

	if (pgp_key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	result = x25519_key_generate((x25519_key *)key, zero);

	if (result == NULL)
	{
		free(pgp_key);
		return PGP_X25519_KEY_GENERATION_FAILURE;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_x448_generate_key(pgp_x448_key **key)
{
	void *result = NULL;

	pgp_x448_key *pgp_key = NULL;
	byte_t zero[X448_KEY_OCTETS] = {0};

	pgp_key = malloc(sizeof(pgp_x448_key));

	if (pgp_key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	result = x448_key_generate((x448_key *)key, zero);

	if (result == NULL)
	{
		free(pgp_key);
		return PGP_X448_KEY_GENERATION_FAILURE;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_ed25519_generate_key(pgp_ed25519_key **key)
{
	void *result = NULL;

	pgp_ed25519_key *pgp_key = NULL;
	byte_t zero[ED25519_KEY_OCTETS] = {0};

	pgp_key = malloc(sizeof(pgp_ed25519_key));

	if (pgp_key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	result = ed25519_key_generate((ed25519_key *)key, zero);

	if (result == NULL)
	{
		free(pgp_key);
		return PGP_ED25519_KEY_GENERATION_FAILURE;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

pgp_error_t pgp_ed448_generate_key(pgp_ed448_key **key)
{
	void *result = NULL;

	pgp_ed448_key *pgp_key = NULL;
	byte_t zero[ED448_KEY_OCTETS] = {0};

	pgp_key = malloc(sizeof(pgp_ed448_key));

	if (pgp_key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	result = ed448_key_generate((ed448_key *)key, zero);

	if (result == NULL)
	{
		free(pgp_key);
		return PGP_ED25519_KEY_GENERATION_FAILURE;
	}

	*key = pgp_key;

	return PGP_SUCCESS;
}

static uint16_t session_key_checksum(byte_t *session_key, byte_t session_key_size)
{
	uint16_t checksum = 0;

	for (uint16_t i = 0; i < session_key_size; ++i)
	{
		checksum += session_key[i];
	}

	return checksum;
}

static byte_t session_key_encode(byte_t padding, byte_t symmetric_algorithm_id, byte_t *session_key, byte_t session_key_size, byte_t *out)
{
	byte_t pos = 0;
	uint16_t checksum = session_key_checksum(session_key, session_key_size);

	// 1-octet symmetric algorithm id (Only V3 PKESK)
	if (symmetric_algorithm_id != 0)
	{
		out[pos] = symmetric_algorithm_id;
		pos += 1;
	}

	// session key octets
	memcpy(out + pos, session_key, session_key_size);
	pos += session_key_size;

	// 2-octets checksum
	out[pos++] = (checksum >> 8) & 0xFF;
	out[pos++] = checksum & 0xFF;

	// Pad to multiple of 8 bytes
	if (padding && (pos % 8) != 0)
	{
		byte_t padding_byte = 8 - (pos % 8);

		memset(out + pos, padding_byte, padding_byte);
		pos += padding_byte;
	}

	return pos;
}

static pgp_error_t session_key_decode(byte_t padding, byte_t *symmetric_algorithm_id, byte_t *encoded_session_key,
									  byte_t encoded_session_key_size, byte_t *decoded_session_key, byte_t *decoded_session_key_size)
{
	byte_t session_key_size = 0;
	byte_t offset = 0;
	uint16_t checksum = 0;

	// 1-octet symmetric algorithm id (Only V3 PKESK)
	if (symmetric_algorithm_id != NULL)
	{
		*symmetric_algorithm_id = encoded_session_key[offset];
		offset += 1;
	}

	// Check padding
	if (padding)
	{
		byte_t padding_byte = 0;

		padding_byte = (8 - (offset + 2));
		session_key_size = encoded_session_key_size - 8;

		if (encoded_session_key_size - (session_key_size + offset + 2) != padding_byte)
		{
			return PGP_SESSION_KEY_MALFORMED_PADDING;
		}

		for (byte_t i = session_key_size + offset + 2; i < encoded_session_key_size; ++i)
		{
			if (encoded_session_key[i] != (8 - (offset + 2)))
			{
				return PGP_SESSION_KEY_MALFORMED_PADDING;
			}
		}
	}
	else
	{
		session_key_size = encoded_session_key_size - (offset + 2);
	}

	// Check checksum
	checksum = session_key_checksum(PTR_OFFSET(encoded_session_key, offset), session_key_size);

	if (((checksum >> 8) & 0xFF) != encoded_session_key[offset + session_key_size] ||
		(checksum & 0xFF) != encoded_session_key[offset + session_key_size + 1])
	{
		return PGP_SESSION_KEY_CHECKSUM_MISMATCH;
	}

	// Copy the session key
	if (*decoded_session_key_size < session_key_size)
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	memcpy(decoded_session_key, encoded_session_key + offset, session_key_size);
	*decoded_session_key_size = session_key_size;

	return PGP_SUCCESS;
}

static pgp_rsa_kex *pgp_rsa_kex_new(uint32_t bits)
{
	pgp_rsa_kex *kex = NULL;

	kex = malloc(sizeof(pgp_rsa_kex) + mpi_size(bits));

	if (kex == NULL)
	{
		return NULL;
	}

	memset(kex, 0, sizeof(pgp_rsa_kex) + mpi_size(bits));

	// Initialize the MPI
	kex->c = mpi_init(PTR_OFFSET(kex, sizeof(pgp_rsa_kex)), mpi_size(bits), bits);

	return kex;
}

static void pgp_rsa_kex_delete(pgp_rsa_kex *kex)
{
	free(kex);
}

pgp_error_t pgp_rsa_kex_encrypt(pgp_rsa_kex **kex, pgp_rsa_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
								byte_t session_key_size)
{
	uint32_t result = 0;

	rsa_key *key = NULL;
	pgp_rsa_kex *rsa_kex = NULL;

	byte_t encoded_session_key[64] = {0};
	uint16_t encoded_session_key_size = 0;

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->e = mpi_to_bignum(pgp_key->e);

	if (key->n == NULL || key->e == NULL)
	{
		rsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	rsa_kex = pgp_rsa_kex_new(pgp_key->n->bits);

	if (rsa_kex == NULL)
	{
		rsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	encoded_session_key_size = session_key_encode(0, symmetric_key_algorithm_id, session_key, session_key_size, encoded_session_key);
	result = rsa_encrypt_pkcs(key, encoded_session_key, encoded_session_key_size, rsa_kex->c->bytes, CEIL_DIV(pgp_key->n->bits, 8), NULL);

	rsa_key_delete(key);

	if (result == 0)
	{
		pgp_rsa_kex_delete(rsa_kex);
		return PGP_RSA_ENCRYPTION_FAILURE;
	}

	// Count the bits
	rsa_kex->c->bits = bitcount_bytes(rsa_kex->c->bytes, result);

	// Set the kex
	*kex = rsa_kex;

	return PGP_SUCCESS;
}

pgp_error_t pgp_rsa_kex_decrypt(pgp_rsa_kex *kex, pgp_rsa_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
								byte_t *session_key_size)
{
	uint32_t result = 0;

	rsa_key *key = NULL;
	byte_t buffer[64] = {0};

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->d = mpi_to_bignum(pgp_key->d);
	key->p = mpi_to_bignum(pgp_key->p);
	key->q = mpi_to_bignum(pgp_key->q);

	if (key->n == NULL || key->d == NULL || key->p == NULL || key->q == NULL)
	{
		rsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	result = rsa_decrypt_pkcs(key, kex->c->bytes, CEIL_DIV(kex->c->bits, 8), buffer, 64);

	rsa_key_delete(key);

	if (result == 0)
	{
		return PGP_RSA_DECRYPTION_FAILURE;
	}

	return session_key_decode(0, symmetric_key_algorithm_id, buffer, result, session_key, session_key_size);
}

static uint32_t pgp_ecdh_kdf(pgp_hash_algorithms algorithm, void *key, uint32_t key_size, void *input, size_t input_size, void *derived_key,
							 uint32_t derived_key_size)
{
	hash_ctx *hctx = NULL;

	byte_t buffer[512] = {0};
	byte_t iv[4] = {0x00, 0x00, 0x00, 0x01};

	hctx = hash_init(buffer, 512, pgp_algorithm_to_hash_algorithm(algorithm));

	if (hctx == NULL)
	{
		return 0;
	}

	hash_update(hctx, iv, 4);
	hash_update(hctx, key, key_size);
	hash_update(hctx, input, input_size);
	hash_final(hctx, derived_key, derived_key_size);

	return derived_key_size;
}

static uint32_t pgp_ecdh_derive_kw_key(pgp_ecdh_key *pgp_key, bignum_t *x, byte_t *fingerprint, byte_t fingerprint_size,
									   byte_t *key_wrap_key)
{
	byte_t hash_algorithm_id = 0;
	byte_t key_wrap_key_size = 0;

	byte_t xcoord[128] = {0};
	byte_t xcoord_size = 0;

	byte_t kdf_input[128] = {0};
	byte_t kdf_input_size = 0;

	switch (pgp_key->curve)
	{
	case PGP_EC_NIST_P256:
	case PGP_EC_BRAINPOOL_256R1:
	case PGP_EC_CURVE25519:
		hash_algorithm_id = PGP_SHA2_256;
		key_wrap_key_size = AES128_KEY_SIZE;
		break;
	case PGP_EC_NIST_P384:
	case PGP_EC_BRAINPOOL_384R1:
		hash_algorithm_id = PGP_SHA2_384;
		key_wrap_key_size = AES192_KEY_SIZE;
		break;
	case PGP_EC_NIST_P521:
	case PGP_EC_BRAINPOOL_512R1:
	case PGP_EC_CURVE448:
		hash_algorithm_id = PGP_SHA2_512;
		key_wrap_key_size = AES256_KEY_SIZE;
		break;
	default:
		// Unreachable
		break;
	}

	// Curve OID
	kdf_input[kdf_input_size] = pgp_key->oid_size;
	kdf_input_size += 1;

	memcpy(kdf_input + kdf_input_size, pgp_key->oid, pgp_key->oid_size);
	kdf_input_size += pgp_key->oid_size;

	// ECDH Algorithm
	kdf_input[kdf_input_size] = PGP_ECDH;
	kdf_input_size += 1;

	// KDF Parameters
	kdf_input[kdf_input_size++] = pgp_key->kdf.size;
	kdf_input[kdf_input_size++] = pgp_key->kdf.extensions;
	kdf_input[kdf_input_size++] = pgp_key->kdf.hash_algorithm_id;
	kdf_input[kdf_input_size++] = pgp_key->kdf.symmetric_key_algorithm_id;

	// "Anonymous Sender"
	memcpy(kdf_input + kdf_input_size, "Anonymous Sender    ", 20);
	kdf_input_size += 20;

	// Fingerprint
	memcpy(kdf_input + kdf_input_size, fingerprint, fingerprint_size);
	kdf_input_size += fingerprint_size;

	// Shared point
	xcoord_size = bignum_get_bytes_be(x, xcoord, 128);

	return pgp_ecdh_kdf(hash_algorithm_id, xcoord, xcoord_size, kdf_input, kdf_input_size, key_wrap_key, key_wrap_key_size);
}

static uint32_t pgp_ecdh_kw_encrypt(void *key, uint32_t key_size, void *in, uint32_t in_size, void *out, uint32_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512] = {0};

	cipher_algorithm algorithm = 0;

	switch (key_size)
	{
	case 16:
		algorithm = CIPHER_AES128;
		break;
	case 24:
		algorithm = CIPHER_AES192;
		break;
	case 32:
		algorithm = CIPHER_AES256;
		break;
		// Unreachable
	default:
		return 0;
	}

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_key_wrap_encrypt(cctx, in, in_size, out, out_size);
}

static uint32_t pgp_ecdh_kw_decrypt(void *key, uint32_t key_size, void *in, uint32_t in_size, void *out, uint32_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512] = {0};

	cipher_algorithm algorithm = 0;

	switch (key_size)
	{
	case 16:
		algorithm = CIPHER_AES128;
		break;
	case 24:
		algorithm = CIPHER_AES192;
		break;
	case 32:
		algorithm = CIPHER_AES256;
		break;
		// Unreachable
	default:
		return 0;
	}

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_key_wrap_decrypt(cctx, in, in_size, out, out_size);
}

pgp_error_t pgp_ecdh_kex_encrypt(pgp_ecdh_kex **kex, pgp_ecdh_key *pgp_key, byte_t symmetric_key_algorithm_id, byte_t *fingerprint,
								 byte_t fingerprint_size, void *session_key, byte_t session_key_size)
{
	pgp_ecdh_kex *ec_kex = NULL;
	ec_group *group = NULL;
	ec_key *ephemeral_key = NULL;
	ec_point *shared_point = NULL;
	ec_point *public_point = NULL;

	byte_t encoded_session_key[64] = {0};
	byte_t wrapped_session_key[64] = {0};
	byte_t encoded_session_key_size = 0;
	byte_t wrapped_session_key_size = 0;

	byte_t key_wrap_key[32] = {0};
	byte_t key_wrap_key_size = 0;

	curve_id id = pgp_ec_curve_to_curve_id(pgp_key->curve);

	if (id == 0)
	{
		return PGP_UNSUPPORTED_ELLIPTIC_CURVE;
	}

	group = ec_group_new(id);

	if (group == NULL)
	{
		return PGP_NO_MEMORY;
	}

	// Generate ephemeral key
	ephemeral_key = ec_key_generate(group, NULL);

	if (ephemeral_key == NULL)
	{
		ec_group_delete(group);
		return PGP_NO_MEMORY;
	}

	public_point = ec_point_new(group);
	shared_point = ec_point_new(group);

	if (public_point == NULL || shared_point == NULL)
	{
		ec_point_delete(public_point);
		ec_point_delete(shared_point);
		ec_key_delete(ephemeral_key);

		return PGP_NO_MEMORY;
	}

	// Compute shared point
	public_point = ec_point_decode(group, public_point, pgp_key->point->bytes, CEIL_DIV(pgp_key->point->bits, 8));
	shared_point = ec_point_multiply(group, shared_point, public_point, ephemeral_key->d);

	// Encode the session key
	encoded_session_key_size = session_key_encode(1, symmetric_key_algorithm_id, session_key, session_key_size, encoded_session_key);

	// Derive key wrap key
	key_wrap_key_size = pgp_ecdh_derive_kw_key(pgp_key, shared_point->x, fingerprint, fingerprint_size, key_wrap_key);

	// Key wrap
	wrapped_session_key_size =
		pgp_ecdh_kw_encrypt(key_wrap_key, key_wrap_key_size, encoded_session_key, encoded_session_key_size, wrapped_session_key, 64);

	ec_kex = malloc(sizeof(pgp_ecdh_kex));

	if (kex == NULL)
	{
		ec_point_delete(shared_point);
		ec_point_delete(public_point);
		ec_key_delete(ephemeral_key);

		return PGP_NO_MEMORY;
	}

	memset(kex, 0, sizeof(pgp_ecdh_kex));

	ec_kex->ephemeral_point = mpi_from_ec_point(ephemeral_key->eg, ephemeral_key->q);
	ec_kex->encoded_session_key_size = wrapped_session_key_size;
	memcpy(ec_kex->encoded_session_key, wrapped_session_key, wrapped_session_key_size);

	ec_point_delete(shared_point);
	ec_point_delete(public_point);
	ec_key_delete(ephemeral_key);

	*kex = ec_kex;
	return PGP_SUCCESS;
}

pgp_error_t pgp_ecdh_kex_decrypt(pgp_ecdh_kex *kex, pgp_ecdh_key *pgp_key, byte_t *symmetric_key_algorithm_id, byte_t *fingerprint,
								 byte_t fingerprint_size, void *session_key, byte_t *session_key_size)
{
	ec_group *group = NULL;
	ec_point *shared_point = NULL;
	ec_point *public_point = NULL;
	bignum_t *d = NULL;

	byte_t encoded_session_key[64] = {0};
	byte_t encoded_session_key_size = kex->encoded_session_key_size;

	byte_t key_wrap_key[32] = {0};
	byte_t key_wrap_key_size = 0;

	curve_id id = pgp_ec_curve_to_curve_id(pgp_key->curve);

	if (id == 0)
	{
		return PGP_UNSUPPORTED_ELLIPTIC_CURVE;
	}

	if (*session_key_size < kex->encoded_session_key_size - 16)
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	group = ec_group_new(id);

	if (group == NULL)
	{
		return PGP_NO_MEMORY;
	}

	d = mpi_to_bignum(pgp_key->x);
	public_point = ec_point_new(group);
	shared_point = ec_point_new(group);

	if (d == NULL || public_point == NULL || shared_point == NULL)
	{
		bignum_delete(d);
		ec_point_delete(public_point);
		ec_point_delete(shared_point);
		ec_group_delete(group);

		return PGP_NO_MEMORY;
	}

	// Compute shared point
	public_point = ec_point_decode(group, public_point, kex->ephemeral_point->bytes, CEIL_DIV(kex->ephemeral_point->bits, 8));
	shared_point = ec_point_multiply(group, shared_point, public_point, d);

	// Derive key wrap key
	key_wrap_key_size = pgp_ecdh_derive_kw_key(pgp_key, shared_point->x, fingerprint, fingerprint_size, key_wrap_key);

	// Key wrap
	encoded_session_key_size = pgp_ecdh_kw_decrypt(key_wrap_key, key_wrap_key_size, kex->encoded_session_key, kex->encoded_session_key_size,
												   encoded_session_key, encoded_session_key_size);

	ec_point_delete(shared_point);
	ec_point_delete(public_point);
	ec_group_delete(group);
	bignum_delete(d);

	if (encoded_session_key_size == 0)
	{
		return PGP_ECDH_DECRYPTION_FAILURE;
	}

	return session_key_decode(1, symmetric_key_algorithm_id, encoded_session_key, encoded_session_key_size, session_key, session_key_size);
}

pgp_error_t pgp_x25519_kex_encrypt(pgp_x25519_kex **kex, pgp_x25519_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
								   byte_t session_key_size)
{
	pgp_x25519_kex *xkex = NULL;

	x25519_key ephemeral_key = {0};
	byte_t zero[X25519_KEY_OCTETS] = {0};
	byte_t shared_secret[X25519_KEY_OCTETS] = {0};
	byte_t hkdf_input[3 * X25519_KEY_OCTETS] = {0};
	uint16_t pos = 0;

	byte_t key_wrap_key[AES128_KEY_SIZE] = {0};

	// Generate shared secret using epehermal key
	x25519_key_generate(&ephemeral_key, zero);
	x25519(shared_secret, pgp_key->public_key, ephemeral_key.private_key);

	if (memcmp(shared_secret, zero, X25519_KEY_OCTETS) == 0)
	{
		return PGP_X25519_ENCRYPTION_FAILURE;
	}

	memcpy(hkdf_input + pos, ephemeral_key.public_key, X25519_KEY_OCTETS);
	pos += X25519_KEY_OCTETS;

	memcpy(hkdf_input + pos, pgp_key->public_key, X25519_KEY_OCTETS);
	pos += X25519_KEY_OCTETS;

	memcpy(hkdf_input + pos, shared_secret, X25519_KEY_OCTETS);
	pos += X25519_KEY_OCTETS;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X25519", 14, key_wrap_key, AES128_KEY_SIZE);

	xkex = malloc(sizeof(pgp_x25519_kex));

	if (kex == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(kex, 0, sizeof(pgp_x25519_kex));
	memcpy(xkex->ephemeral_key, ephemeral_key.public_key, X25519_KEY_OCTETS);

	// V3 PKESK
	if (symmetric_key_algorithm_id != 0)
	{
		xkex->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		xkex->octet_count += 1;
	}

	xkex->octet_count +=
		aes128_key_wrap_encrypt(key_wrap_key, AES128_KEY_SIZE, session_key, session_key_size, xkex->encrypted_session_key, 40);

	*kex = xkex;
	return PGP_SUCCESS;
}

pgp_error_t pgp_x25519_kex_decrypt(pgp_x25519_kex *kex, pgp_x25519_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
								   byte_t *session_key_size)
{
	uint32_t result = 0;

	byte_t zero[X25519_KEY_OCTETS] = {0};
	byte_t shared_secret[X25519_KEY_OCTETS] = {0};
	byte_t hkdf_input[3 * X25519_KEY_OCTETS] = {0};
	byte_t octet_count = kex->octet_count;
	uint16_t pos = 0;

	byte_t key_wrap_key[AES128_KEY_SIZE] = {0};

	x25519(shared_secret, kex->ephemeral_key, pgp_key->private_key);

	if (memcmp(shared_secret, zero, X25519_KEY_OCTETS) == 0)
	{
		return PGP_X25519_DECRYPTION_FAILURE;
	}

	memcpy(hkdf_input + pos, kex->ephemeral_key, X25519_KEY_OCTETS);
	pos += X25519_KEY_OCTETS;

	memcpy(hkdf_input + pos, pgp_key->public_key, X25519_KEY_OCTETS);
	pos += X25519_KEY_OCTETS;

	memcpy(hkdf_input + pos, shared_secret, X25519_KEY_OCTETS);
	pos += X25519_KEY_OCTETS;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X25519", 14, key_wrap_key, AES128_KEY_SIZE);

	if (symmetric_key_algorithm_id != NULL)
	{
		*symmetric_key_algorithm_id = kex->symmetric_key_algorithm_id;
		octet_count -= 1;
	}

	if (*session_key_size < (octet_count - 8))
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	result =
		aes128_key_wrap_decrypt(key_wrap_key, AES128_KEY_SIZE, kex->encrypted_session_key, octet_count, session_key, *session_key_size);

	if (result == 0)
	{
		return PGP_X25519_DECRYPTION_FAILURE;
	}

	*session_key_size = (byte_t)result;

	return PGP_SUCCESS;
}

pgp_error_t pgp_x448_kex_encrypt(pgp_x448_kex **kex, pgp_x448_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
								 byte_t session_key_size)
{
	pgp_x448_kex *xkex = NULL;

	x448_key ephemeral_key = {0};
	byte_t zero[X448_KEY_OCTETS] = {0};
	byte_t shared_secret[X448_KEY_OCTETS] = {0};
	byte_t hkdf_input[3 * X448_KEY_OCTETS] = {0};
	uint16_t pos = 0;

	byte_t key_wrap_key[AES256_KEY_SIZE] = {0};

	x448_key_generate(&ephemeral_key, zero);
	x448(shared_secret, pgp_key->public_key, ephemeral_key.private_key);

	if (memcmp(shared_secret, zero, X448_KEY_OCTETS) == 0)
	{
		return PGP_X448_ENCRYPTION_FAILURE;
	}

	memcpy(hkdf_input + pos, ephemeral_key.public_key, X448_KEY_OCTETS);
	pos += X448_KEY_OCTETS;

	memcpy(hkdf_input + pos, pgp_key->public_key, X448_KEY_OCTETS);
	pos += X448_KEY_OCTETS;

	memcpy(hkdf_input + pos, shared_secret, X448_KEY_OCTETS);
	pos += X448_KEY_OCTETS;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X448", 12, key_wrap_key, AES256_KEY_SIZE);

	kex = malloc(sizeof(pgp_x448_kex));

	if (kex == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(kex, 0, sizeof(pgp_x448_kex));
	memcpy(xkex->ephemeral_key, ephemeral_key.public_key, X448_KEY_OCTETS);

	if (symmetric_key_algorithm_id != 0)
	{
		xkex->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		xkex->octet_count += 1;
	}

	xkex->octet_count +=
		aes256_key_wrap_encrypt(key_wrap_key, AES256_KEY_SIZE, session_key, session_key_size, xkex->encrypted_session_key, 40);

	*kex = xkex;
	return PGP_SUCCESS;
}

pgp_error_t pgp_x448_kex_decrypt(pgp_x448_kex *kex, pgp_x448_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
								 byte_t *session_key_size)
{
	uint32_t result = 0;

	byte_t zero[X448_KEY_OCTETS] = {0};
	byte_t shared_secret[X448_KEY_OCTETS] = {0};
	byte_t hkdf_input[3 * X448_KEY_OCTETS] = {0};
	byte_t octet_count = kex->octet_count;
	uint16_t pos = 0;

	byte_t key_wrap_key[AES256_KEY_SIZE] = {0};

	x448(shared_secret, kex->ephemeral_key, pgp_key->private_key);

	if (memcmp(shared_secret, zero, X25519_KEY_OCTETS) == 0)
	{
		return PGP_X448_DECRYPTION_FAILURE;
	}

	memcpy(hkdf_input + pos, kex->ephemeral_key, X448_KEY_OCTETS);
	pos += X448_KEY_OCTETS;

	memcpy(hkdf_input + pos, pgp_key->public_key, X448_KEY_OCTETS);
	pos += X448_KEY_OCTETS;

	memcpy(hkdf_input + pos, shared_secret, X448_KEY_OCTETS);
	pos += X448_KEY_OCTETS;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X448", 12, key_wrap_key, AES256_KEY_SIZE);

	if (symmetric_key_algorithm_id != NULL)
	{
		*symmetric_key_algorithm_id = kex->symmetric_key_algorithm_id;
		octet_count -= 1;
	}

	if (*session_key_size < (octet_count - 8))
	{
		return PGP_BUFFER_TOO_SMALL;
	}

	result =
		aes256_key_wrap_decrypt(key_wrap_key, AES256_KEY_SIZE, kex->encrypted_session_key, octet_count, session_key, *session_key_size);

	if (result == 0)
	{
		return PGP_X448_DECRYPTION_FAILURE;
	}

	*session_key_size = (byte_t)result;

	return PGP_SUCCESS;
}

static pgp_rsa_signature *pgp_rsa_signature_new(uint16_t bits)
{
	pgp_rsa_signature *sign = NULL;

	sign = malloc(sizeof(pgp_rsa_signature) + mpi_size(bits));

	if (sign == NULL)
	{
		return NULL;
	}

	memset(sign, 0, sizeof(pgp_rsa_signature) + mpi_size(bits));

	// Initialize the MPI
	sign->e = mpi_init(PTR_OFFSET(sign, sizeof(pgp_rsa_signature)), mpi_size(bits), bits);

	return sign;
}

static void pgp_rsa_signature_delete(pgp_rsa_signature *sign)
{
	free(sign);
}

static pgp_dsa_signature *pgp_dsa_signature_new(uint16_t bits)
{
	pgp_dsa_signature *sign = NULL;

	sign = malloc(sizeof(pgp_dsa_signature) + (2 * mpi_size(bits)));

	if (sign == NULL)
	{
		return NULL;
	}

	memset(sign, 0, sizeof(pgp_dsa_signature) + mpi_size(bits));

	// Initialize the MPIs
	sign->r = mpi_init(PTR_OFFSET(sign, sizeof(pgp_dsa_signature)), mpi_size(bits), bits);
	sign->s = mpi_init(PTR_OFFSET(sign, sizeof(pgp_dsa_signature) + mpi_size(bits)), mpi_size(bits), bits);

	return sign;
}

static void pgp_dsa_signature_delete(pgp_dsa_signature *sign)
{
	free(sign);
}

pgp_error_t pgp_rsa_sign(pgp_rsa_signature **signature, pgp_rsa_key *pgp_key, byte_t hash_algorithm_id, void *hash, uint32_t hash_size)
{
	void *result = NULL;

	rsa_key *key = NULL;
	pgp_rsa_signature *pgp_sign = NULL;
	rsa_signature sign = {0};

	hash_algorithm algorithm = pgp_algorithm_to_hash_algorithm(hash_algorithm_id);

	if (algorithm == 0)
	{
		return PGP_UNKNOWN_HASH_ALGORITHM;
	}

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->d = mpi_to_bignum(pgp_key->d);
	key->p = mpi_to_bignum(pgp_key->p);
	key->q = mpi_to_bignum(pgp_key->q);

	if (key->n == NULL || key->d == NULL || key->p == NULL || key->q == NULL)
	{
		rsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	pgp_sign = pgp_rsa_signature_new(pgp_key->n->bits);

	if (pgp_sign == NULL)
	{
		rsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	sign.size = CEIL_DIV(pgp_key->n->bits, 8);
	sign.sign = pgp_sign->e->bytes;

	result = rsa_sign_pkcs(key, &sign, algorithm, hash, hash_size);

	rsa_key_delete(key);

	if (result == NULL)
	{
		pgp_rsa_signature_delete(pgp_sign);
		return PGP_RSA_SIGNATURE_GENERATION_FAILURE;
	}

	pgp_sign->e->bits = sign.bits;
	*signature = pgp_sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_rsa_verify(pgp_rsa_signature *signature, pgp_rsa_key *pgp_key, byte_t hash_algorithm_id, void *hash, uint32_t hash_size)
{
	uint32_t status;

	rsa_key *key = NULL;
	rsa_signature sign = {0};
	hash_algorithm algorithm = pgp_algorithm_to_hash_algorithm(hash_algorithm_id);

	if (algorithm == 0)
	{
		return PGP_UNKNOWN_HASH_ALGORITHM;
	}

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return PGP_NO_MEMORY;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->e = mpi_to_bignum(pgp_key->e);

	if (key->n == NULL || key->e == NULL)
	{
		rsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	sign.bits = signature->e->bits;
	sign.size = CEIL_DIV(signature->e->bits, 8);
	sign.sign = signature->e->bytes;

	status = rsa_verify_pkcs(key, &sign, algorithm, hash, hash_size);

	rsa_key_delete(key);

	if (status == 0)
	{
		return PGP_BAD_SIGNATURE;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_dsa_sign(pgp_dsa_signature **signature, pgp_dsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	void *result = NULL;

	dsa_group *group = NULL;
	dsa_key *key = NULL;
	pgp_dsa_signature *pgp_sign = NULL;
	dsa_signature sign = {0};

	bignum_t *p = NULL, *q = NULL, *g = NULL, *x = NULL;

	p = mpi_to_bignum(pgp_key->p);
	q = mpi_to_bignum(pgp_key->q);
	g = mpi_to_bignum(pgp_key->g);
	x = mpi_to_bignum(pgp_key->x);

	if (p == NULL || q == NULL || g == NULL || x == NULL)
	{
		bignum_delete(p);
		bignum_delete(q);
		bignum_delete(g);
		bignum_delete(x);

		return PGP_NO_MEMORY;
	}

	group = dh_group_custom_new(p, q, g);

	if (group == NULL)
	{
		bignum_delete(p);
		bignum_delete(q);
		bignum_delete(g);
		bignum_delete(x);

		return PGP_NO_MEMORY;
	}

	key = dsa_key_new(group, x, NULL);

	if (key == NULL)
	{
		dsa_group_delete(group);
		bignum_delete(x);

		return PGP_NO_MEMORY;
	}

	pgp_sign = pgp_dsa_signature_new(pgp_key->q->bits);

	if (pgp_sign == NULL)
	{
		dsa_key_delete(key);
		return PGP_NO_MEMORY;
	}

	sign.r.size = CEIL_DIV(pgp_sign->r->bits, 8);
	sign.s.size = CEIL_DIV(pgp_sign->s->bits, 8);

	sign.r.sign = pgp_sign->r->bytes;
	sign.s.sign = pgp_sign->s->bytes;

	result = dsa_sign(key, &sign, NULL, 0, hash, hash_size);

	dsa_key_delete(key);

	if (result == NULL)
	{
		pgp_dsa_signature_delete(pgp_sign);
		return PGP_DSA_SIGNATURE_GENERATION_FAILURE;
	}

	pgp_sign->r->bits = sign.r.bits;
	pgp_sign->s->bits = sign.s.bits;

	*signature = pgp_sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_dsa_verify(pgp_dsa_signature *signature, pgp_dsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	dsa_group *group = NULL;
	dsa_key *key = NULL;
	dsa_signature sign = {0};

	bignum_t *p = NULL, *q = NULL, *g = NULL, *y = NULL;

	p = mpi_to_bignum(pgp_key->p);
	q = mpi_to_bignum(pgp_key->q);
	g = mpi_to_bignum(pgp_key->g);
	y = mpi_to_bignum(pgp_key->y);

	if (p == NULL || q == NULL || g == NULL || y == NULL)
	{
		bignum_delete(p);
		bignum_delete(q);
		bignum_delete(g);
		bignum_delete(y);

		return PGP_NO_MEMORY;
	}

	group = dh_group_custom_new(p, q, g);

	if (group == NULL)
	{
		bignum_delete(p);
		bignum_delete(q);
		bignum_delete(g);
		bignum_delete(y);

		return PGP_NO_MEMORY;
	}

	key = dsa_key_new(group, NULL, y);

	if (key == NULL)
	{
		dsa_group_delete(group);
		bignum_delete(y);

		return PGP_NO_MEMORY;
	}

	sign.r.size = CEIL_DIV(signature->r->bits, 8);
	sign.s.size = CEIL_DIV(signature->s->bits, 8);

	sign.r.sign = signature->r->bytes;
	sign.s.sign = signature->s->bytes;

	status = dsa_verify(key, &sign, hash, hash_size);

	dsa_key_delete(key);

	if (status == 0)
	{
		return PGP_BAD_SIGNATURE;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_ecdsa_sign(pgp_ecdsa_signature **signature, pgp_ecdsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	void *result = NULL;

	ec_group *group = NULL;
	ec_key *key = NULL;
	pgp_ecdsa_signature *pgp_sign = NULL;
	ecdsa_signature sign = {0};
	bignum_t *d = NULL;

	curve_id id = pgp_ec_curve_to_curve_id(pgp_key->curve);

	if (id == 0)
	{
		return PGP_UNSUPPORTED_ELLIPTIC_CURVE;
	}

	d = mpi_to_bignum(pgp_key->x);

	if (d == NULL)
	{
		bignum_delete(d);
		return PGP_NO_MEMORY;
	}

	group = ec_group_new(id);

	if (group == NULL)
	{
		bignum_delete(d);
		return PGP_NO_MEMORY;
	}

	key = ec_key_new(group, d, NULL);

	if (key == NULL)
	{
		ec_group_delete(group);
		bignum_delete(d);

		return PGP_NO_MEMORY;
	}

	// ecdsa and dsa share the same structure
	pgp_sign = pgp_dsa_signature_new(group->bits);

	if (pgp_sign == NULL)
	{
		ec_key_delete(key);
		return PGP_NO_MEMORY;
	}

	sign.r.size = CEIL_DIV(pgp_sign->r->bits, 8);
	sign.s.size = CEIL_DIV(pgp_sign->s->bits, 8);

	sign.r.sign = pgp_sign->r->bytes;
	sign.s.sign = pgp_sign->s->bytes;

	result = ecdsa_sign(key, &sign, NULL, 0, hash, hash_size);

	ec_key_delete(key);

	if (result == NULL)
	{
		pgp_dsa_signature_delete(pgp_sign);
		return PGP_ECDSA_SIGNATURE_GENERATION_FAILURE;
	}

	pgp_sign->r->bits = sign.r.bits;
	pgp_sign->s->bits = sign.s.bits;

	*signature = pgp_sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_ecdsa_verify(pgp_ecdsa_signature *signature, pgp_ecdsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	ec_group *group = NULL;
	ec_key *key = NULL;
	ecdsa_signature sign = {0};

	ec_point *q = NULL;

	curve_id id = pgp_ec_curve_to_curve_id(pgp_key->curve);

	if (id == 0)
	{
		return PGP_UNSUPPORTED_ELLIPTIC_CURVE;
	}

	group = ec_group_new(id);

	if (group == NULL)
	{
		return PGP_NO_MEMORY;
	}

	q = mpi_to_ec_point(group, pgp_key->point);
	key = ec_key_new(group, NULL, q);

	if (key == NULL)
	{
		ec_group_delete(group);
		return PGP_NO_MEMORY;
	}

	sign.r.size = CEIL_DIV(signature->r->bits, 8);
	sign.s.size = CEIL_DIV(signature->s->bits, 8);

	sign.r.sign = signature->r->bytes;
	sign.s.sign = signature->s->bytes;

	status = ecdsa_verify(key, &sign, hash, hash_size);

	ec_key_delete(key);

	if (status == 0)
	{
		return PGP_BAD_SIGNATURE;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_eddsa_sign(pgp_eddsa_signature **signature, pgp_eddsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	void *status = NULL;
	pgp_eddsa_signature *pgp_sign = NULL;

	if (pgp_key->curve == PGP_ED25519)
	{
		ed25519_key edkey = {0};
		ed25519_signature edsign = {0};

		byte_t r_offset = 0;
		byte_t s_offset = 0;

		// eddsa and dsa share the same structure
		pgp_sign = pgp_dsa_signature_new(256);

		if (pgp_sign == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memcpy(edkey.private_key, pgp_key->x->bytes, ED25519_KEY_OCTETS);
		memcpy(edkey.public_key, PTR_OFFSET(pgp_key->point->bytes, 1), ED25519_KEY_OCTETS);

		status = ed25519_sign(&edkey, &edsign, hash, hash_size);

		if (status == NULL)
		{
			pgp_dsa_signature_delete(pgp_sign);
			return PGP_EDDSA_SIGNATURE_GENERATION_FAILURE;
		}

		pgp_sign->r->bits = bitcount_bytes(edsign.sign, ED25519_KEY_OCTETS);
		pgp_sign->s->bits = bitcount_bytes(PTR_OFFSET(edsign.sign, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);

		r_offset = ED25519_KEY_OCTETS - CEIL_DIV(pgp_sign->r->bits, 8);
		s_offset = ED25519_KEY_OCTETS - CEIL_DIV(pgp_sign->s->bits, 8);

		memcpy(pgp_sign->r->bytes, PTR_OFFSET(edsign.sign, r_offset), ED25519_KEY_OCTETS - r_offset);
		memcpy(pgp_sign->s->bytes, PTR_OFFSET(edsign.sign, ED25519_KEY_OCTETS + s_offset), ED25519_KEY_OCTETS - s_offset);

		*signature = pgp_sign;

		return PGP_SUCCESS;
	}

	if (pgp_key->curve == PGP_ED448)
	{
		ed448_key edkey = {0};
		ed448_signature edsign = {0};

		byte_t r_offset = 0;
		byte_t s_offset = 0;

		// eddsa and dsa share the same structure
		pgp_sign = pgp_dsa_signature_new(456);

		if (pgp_sign == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memcpy(edkey.private_key, pgp_key->x->bytes, ED448_KEY_OCTETS);
		memcpy(edkey.public_key, PTR_OFFSET(pgp_key->point->bytes, 1), ED448_KEY_OCTETS);

		status = ed448_sign(&edkey, &edsign, NULL, 0, hash, hash_size);

		if (status == NULL)
		{
			pgp_dsa_signature_delete(pgp_sign);
			return PGP_EDDSA_SIGNATURE_GENERATION_FAILURE;
		}

		pgp_sign->r->bits = bitcount_bytes(edsign.sign, ED448_KEY_OCTETS);
		pgp_sign->s->bits = bitcount_bytes(PTR_OFFSET(edsign.sign, ED448_KEY_OCTETS), ED448_KEY_OCTETS);

		r_offset = ED448_KEY_OCTETS - CEIL_DIV(pgp_sign->r->bits, 8);
		s_offset = ED448_KEY_OCTETS - CEIL_DIV(pgp_sign->s->bits, 8);

		memcpy(pgp_sign->r->bytes, PTR_OFFSET(edsign.sign, r_offset), ED448_KEY_OCTETS - r_offset);
		memcpy(pgp_sign->s->bytes, PTR_OFFSET(edsign.sign, ED448_KEY_OCTETS + s_offset), ED448_KEY_OCTETS - s_offset);

		*signature = pgp_sign;

		return PGP_SUCCESS;
	}

	return PGP_UNSUPPORTED_EDWARDS_CURVE;
}

pgp_error_t pgp_eddsa_verify(pgp_eddsa_signature *signature, pgp_eddsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	if (pgp_key->curve == PGP_ED25519)
	{
		ed25519_key edkey = {0};
		ed25519_signature edsign = {0};

		byte_t r_offset = ED25519_KEY_OCTETS - CEIL_DIV(signature->r->bits, 8);
		byte_t s_offset = ED25519_KEY_OCTETS - CEIL_DIV(signature->s->bits, 8);

		// Copy signature
		memcpy(PTR_OFFSET(edsign.sign, r_offset), signature->r->bytes, ED25519_KEY_OCTETS - r_offset);
		memcpy(PTR_OFFSET(edsign.sign, ED25519_KEY_OCTETS + s_offset), signature->s->bytes, ED25519_KEY_OCTETS - s_offset);

		// Copy public key
		memcpy(edkey.public_key, PTR_OFFSET(pgp_key->point->bytes, 1), ED25519_KEY_OCTETS);

		status = ed25519_verify(&edkey, &edsign, hash, hash_size);

		if (status == 0)
		{
			return PGP_BAD_SIGNATURE;
		}

		return PGP_SUCCESS;
	}

	if (pgp_key->curve == PGP_ED448)
	{
		ed448_key edkey = {0};
		ed448_signature edsign = {0};

		byte_t r_offset = ED448_KEY_OCTETS - CEIL_DIV(signature->r->bits, 8);
		byte_t s_offset = ED448_KEY_OCTETS - CEIL_DIV(signature->s->bits, 8);

		// Copy signature
		memcpy(PTR_OFFSET(edsign.sign, r_offset), signature->r->bytes, ED448_KEY_OCTETS - r_offset);
		memcpy(PTR_OFFSET(edsign.sign, ED448_KEY_OCTETS + s_offset), signature->s->bytes, ED448_KEY_OCTETS - s_offset);

		// Copy public key
		memcpy(edkey.public_key, PTR_OFFSET(pgp_key->point->bytes, 1), ED448_KEY_OCTETS);

		status = ed448_verify(&edkey, &edsign, NULL, 0, hash, hash_size);

		if (status == 0)
		{
			return PGP_BAD_SIGNATURE;
		}

		return PGP_SUCCESS;
	}

	return PGP_UNSUPPORTED_EDWARDS_CURVE;
}

pgp_error_t pgp_ed25519_sign(pgp_ed25519_signature **signature, pgp_ed25519_key *pgp_key, void *hash, uint32_t hash_size)
{
	void *status = NULL;
	pgp_ed25519_signature *pgp_sign = NULL;

	pgp_sign = malloc(sizeof(pgp_ed25519_signature));

	if (pgp_sign == NULL)
	{
		return PGP_NO_MEMORY;
	}

	status = ed25519_sign((ed25519_key *)pgp_key, (ed25519_signature *)pgp_sign, hash, hash_size);

	if (status == NULL)
	{
		free(pgp_sign);
		return PGP_ED25519_SIGNATURE_GENERATION_FAILURE;
	}

	*signature = pgp_sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_ed25519_verify(pgp_ed25519_signature *signature, pgp_ed25519_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	// TODO key validation
	status = ed25519_verify((ed25519_key *)pgp_key, (ed25519_signature *)signature, hash, hash_size);

	if (status == 0)
	{
		return PGP_BAD_SIGNATURE;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_ed448_sign(pgp_ed448_signature **signature, pgp_ed448_key *pgp_key, void *hash, uint32_t hash_size)
{
	void *status = NULL;
	pgp_ed448_signature *pgp_sign = NULL;

	pgp_sign = malloc(sizeof(pgp_ed448_signature));

	if (pgp_sign == NULL)
	{
		return PGP_NO_MEMORY;
	}

	status = ed448_sign((ed448_key *)pgp_key, (ed448_signature *)pgp_sign, NULL, 0, hash, hash_size);

	if (status == NULL)
	{
		free(pgp_sign);
		return PGP_ED448_SIGNATURE_GENERATION_FAILURE;
	}

	*signature = pgp_sign;

	return PGP_SUCCESS;
}

pgp_error_t pgp_ed448_verify(pgp_ed448_signature *signature, pgp_ed448_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	// TODO key validation
	status = ed448_verify((ed448_key *)pgp_key, (ed448_signature *)signature, NULL, 0, hash, hash_size);

	if (status == 0)
	{
		return PGP_BAD_SIGNATURE;
	}

	return PGP_SUCCESS;
}

uint32_t pgp_argon2(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
					uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size)
{
	return argon2id(password, password_size, salt, salt_size, parallel, memory, iterations, secret, secret_size, data, data_size, key,
					key_size);
}

uint32_t pgp_hkdf(pgp_hash_algorithms algorithm, void *key, uint32_t key_size, void *salt, size_t salt_size, void *info, size_t info_size,
				  void *derived_key, uint32_t derived_key_size)
{
	return hkdf(pgp_algorithm_to_hash_algorithm(algorithm), key, key_size, salt, salt_size, info, info_size, derived_key, derived_key_size);
}
