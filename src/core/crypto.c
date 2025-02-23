/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>

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

#include <hkdf.h>

#include <stdlib.h>
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
	case PGP_EC_ED25519_LEGACY:
		return EC_ED25519;
	case PGP_EC_CURVE25519_LEGACY:
		return EC_CURVE25519;
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

byte_t pgp_elliptic_curve(byte_t *oid, byte_t size)
{
	curve_id id = ec_curve_decode_oid(oid, size);

	if (id == 0)
	{
		// Check legacy curves
		if (size == 9 && memcmp(oid, "\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01", 9) == 0)
		{
			return PGP_EC_ED25519_LEGACY;
		}

		if (size == 10 && memcmp(oid, "\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01", 10) == 0)
		{
			return PGP_EC_CURVE25519_LEGACY;
		}

		return 0;
	}

	return pgp_curve_id_to_ec_curve(id);
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

void *pgp_rsa_generate_key(uint32_t bits)
{
	rsa_key *key = NULL;
	pgp_rsa_key *pgp_key = NULL;

	pgp_key = malloc(sizeof(pgp_rsa_key));

	if (pgp_key == NULL)
	{
		return NULL;
	}

	memset(pgp_key, 0, sizeof(pgp_rsa_key));

	// Use default e
	key = rsa_key_generate(bits, NULL);

	if (key == NULL)
	{
		free(pgp_key);
		return NULL;
	}

	pgp_key->n = mpi_from_bignum(key->n);
	pgp_key->e = mpi_from_bignum(key->e);
	pgp_key->d = mpi_from_bignum(key->d);
	pgp_key->p = mpi_from_bignum(key->p);
	pgp_key->q = mpi_from_bignum(key->q);
	pgp_key->u = mpi_from_bignum(key->iqmp);

	rsa_key_delete(key);

	return pgp_key;
}

void *pgp_ecdsa_generate_key(pgp_elliptic_curve_id curve)
{
	ec_group *group = NULL;
	ec_key *key = NULL;
	pgp_ecdsa_key *pgp_key = NULL;

	curve_id id = pgp_ec_curve_to_curve_id(curve);
	uint16_t bits = 0;

	if (id == 0)
	{
		return NULL;
	}

	pgp_key = malloc(sizeof(pgp_ecdsa_key));

	if (pgp_key == NULL)
	{
		return NULL;
	}

	memset(pgp_key, 0, sizeof(pgp_ecdsa_key));

	group = ec_group_new(id);

	if (group == NULL)
	{
		free(pgp_key);
		return NULL;
	}

	key = ec_key_generate(group, NULL);

	if (key == NULL)
	{
		ec_group_delete(group);
		free(pgp_key);
		return NULL;
	}

	pgp_key->curve = curve;
	pgp_key->oid_size = (byte_t)ec_curve_encode_oid(id, pgp_key->oid, 16);
	pgp_key->x = mpi_from_bignum(key->d);

	bits = (2 * group->bits) + 3;
	pgp_key->point = mpi_new((2 * group->bits) + 3);
	ec_point_encode(group, key->q, pgp_key->point->bytes, CEIL_DIV(bits, 8), 0);
	pgp_key->point->bits = bits;

	ec_key_delete(key);

	return pgp_key;
}

void *pgp_ecdh_generate_key(pgp_elliptic_curve_id curve, byte_t hash_algorithm_id, byte_t symmetric_key_algorithm_id)
{
	ec_group *group = NULL;
	ec_key *key = NULL;
	pgp_ecdh_key *pgp_key = NULL;

	curve_id id = pgp_ec_curve_to_curve_id(curve);
	uint16_t bits = 0;

	if (id == 0)
	{
		return NULL;
	}

	pgp_key = malloc(sizeof(pgp_ecdh_key));

	if (pgp_key == NULL)
	{
		return NULL;
	}

	memset(pgp_key, 0, sizeof(pgp_ecdh_key));

	group = ec_group_new(id);

	if (group == NULL)
	{
		free(pgp_key);
		return NULL;
	}

	key = ec_key_generate(group, NULL);

	if (key == NULL)
	{
		ec_group_delete(group);
		free(pgp_key);
		return NULL;
	}

	pgp_key->curve = curve;
	pgp_key->oid_size = (byte_t)ec_curve_encode_oid(id, pgp_key->oid, 16);
	pgp_key->x = mpi_from_bignum(key->d);

	bits = (2 * group->bits) + 3;
	pgp_key->point = mpi_new((2 * group->bits) + 3);
	ec_point_encode(group, key->q, pgp_key->point->bytes, CEIL_DIV(bits, 8), 0);
	pgp_key->point->bits = bits;

	pgp_key->kdf.size = 3;
	pgp_key->kdf.extensions = 1;
	pgp_key->kdf.hash_algorithm_id = hash_algorithm_id;
	pgp_key->kdf.symmetric_key_algorithm_id = symmetric_key_algorithm_id;

	ec_key_delete(key);

	return pgp_key;
}

void pgp_x25519_generate_key(pgp_x25519_key *key)
{
	x25519_key_generate((x25519_key *)key);
}

void pgp_x448_generate_key(pgp_x448_key *key)
{
	x448_key_generate((x448_key *)key);
}

void pgp_ed25519_generate_key(pgp_ed25519_key *key)
{
	byte_t zero[ED25519_KEY_OCTETS] = {0};

	ed25519_key_generate((ed25519_key *)key, zero);
}

void pgp_ed448_generate_key(pgp_ed448_key *key)
{
	byte_t zero[ED448_KEY_OCTETS] = {0};

	ed448_key_generate((ed448_key *)key, zero);
}

pgp_rsa_kex *pgp_rsa_kex_encrypt(pgp_rsa_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key, byte_t session_key_size)
{
	uint32_t result = 0;

	rsa_key *key = NULL;
	pgp_rsa_kex *kex = NULL;
	byte_t *ps = session_key;

	byte_t buffer[64] = {0};
	uint16_t pos = 0;
	uint16_t checksum = 0;

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return 0;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->d = mpi_to_bignum(pgp_key->e);

	if (symmetric_key_algorithm_id != 0)
	{
		buffer[pos] = symmetric_key_algorithm_id;
		pos += 1;
	}

	memcpy(buffer + pos, session_key, session_key_size);
	pos += session_key_size;

	for (uint16_t i = 0; i < session_key_size; ++i)
	{
		checksum += ps[i];
	}

	buffer[pos] = (checksum >> 8) & 0xFF;
	buffer[pos + 1] = checksum & 0xFF;
	pos += 2;

	kex = malloc(sizeof(pgp_rsa_kex) + mpi_size(pgp_key->n->bits));

	if (kex == NULL)
	{
		rsa_key_delete(key);
		return NULL;
	}

	memset(kex, 0, sizeof(pgp_rsa_kex) + mpi_size(pgp_key->n->bits));
	kex->c = mpi_init(PTR_OFFSET(kex, sizeof(pgp_rsa_kex)), mpi_size(pgp_key->n->bits), pgp_key->n->bits);

	result = rsa_encrypt_pkcs(key, buffer, pos, kex->c->bytes, CEIL_DIV(pgp_key->n->bits, 8), NULL);

	rsa_key_delete(key);

	if (result == 0)
	{
		free(kex);
		return NULL;
	}

	return kex;
}

uint32_t pgp_rsa_kex_decrypt(pgp_rsa_kex *kex, pgp_rsa_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
							 uint32_t session_key_size)
{
	uint32_t result = 0;
	uint16_t checksum = 0;
	uint16_t offset = 0;

	rsa_key *key = NULL;
	byte_t buffer[64] = {0};

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return 0;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->d = mpi_to_bignum(pgp_key->d);

	result = rsa_decrypt_pkcs(key, kex->c->bytes, CEIL_DIV(kex->c->bits, 8), buffer, 64);

	if (symmetric_key_algorithm_id == NULL)
	{
		for (uint16_t i = 0; i < (result - 2); ++i)
		{
			checksum += buffer[i];
		}
	}
	else
	{
		offset = 1;
		*symmetric_key_algorithm_id = buffer[0];

		for (uint16_t i = 1; i < (result - 2); ++i)
		{
			checksum += buffer[i];
		}
	}

	if (checksum == ((buffer[result - 2] << 8) + buffer[result - 1]))
	{
		result -= (2 + offset);

		if (session_key_size >= result)
		{
			memcpy(session_key, buffer + offset, result);
		}
		else
		{
			result = 0;
		}
	}
	else
	{
		result = 0;
	}

	rsa_key_delete(key);

	return result;
}

static void pgp_ecdh_kdf_paramters(curve_id id, pgp_hash_algorithms *hid, pgp_symmetric_key_algorithms *cid)
{
	switch (id)
	{
	case PGP_EC_NIST_P256:
	case PGP_EC_BRAINPOOL_256R1:
	case PGP_EC_CURVE25519_LEGACY:
		*hid = PGP_SHA2_256;
		*cid = PGP_AES_128;
		break;
	case PGP_EC_NIST_P384:
	case PGP_EC_BRAINPOOL_384R1:
		*hid = PGP_SHA2_384;
		*cid = PGP_AES_192;
		break;
	case PGP_EC_NIST_P521:
	case PGP_EC_BRAINPOOL_512R1:
		*hid = PGP_SHA2_512;
		*cid = PGP_AES_256;
		break;
	default:
		break;
	}
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

static uint32_t pgp_ecdh_kw_encrypt(pgp_symmetric_key_algorithms algorithm, void *key, uint32_t key_size, void *in, uint32_t in_size,
									void *out, uint32_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512] = {0};

	cctx = cipher_init(buffer, 512, 0, pgp_algorithm_to_cipher_algorithm(algorithm), key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cipher_key_wrap_encrypt(cctx, in, in_size, out, out_size);

	return in_size + 8;
}

static uint32_t pgp_ecdh_kw_decrypt(pgp_symmetric_key_algorithms algorithm, void *key, uint32_t key_size, void *in, uint32_t in_size,
									void *out, uint32_t out_size)
{
	cipher_ctx *cctx = NULL;
	byte_t buffer[512] = {0};

	cctx = cipher_init(buffer, 512, 0, pgp_algorithm_to_cipher_algorithm(algorithm), key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cipher_key_wrap_decrypt(cctx, in, in_size, out, out_size);

	return in_size + 8;
	return in_size - 8;
}

pgp_ecdh_kex *pgp_ecdh_kex_encrypt(pgp_ecdh_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key, byte_t session_key_size)
{
	pgp_ecdh_kex *kex = NULL;
	ec_group *group = NULL;
	ec_key *ephemeral_key = NULL;
	ec_point *shared_point = NULL;
	ec_point *public_point = NULL;

	pgp_hash_algorithms hash_algorithm_id = 0;
	pgp_symmetric_key_algorithms cipher_algorithm_id = 0;
	curve_id id = pgp_ec_curve_to_curve_id(pgp_key->curve);

	byte_t *ps = session_key;
	byte_t pos = 0;
	uint16_t session_key_checksum = 0;

	byte_t encoded_session_key[64] = {0};
	byte_t wrapped_session_key[64] = {0};
	byte_t encoded_session_key_size = ROUND_UP(session_key_size, 8);
	byte_t wrapped_session_key_size = encoded_session_key_size + 8;

	byte_t xcoord[128] = {0};
	byte_t xcoord_size = 0;

	byte_t key_wrap_key[32] = {0};
	byte_t kdf_input[128] = {0};
	byte_t key_wrap_key_size = 0;
	byte_t kdf_input_size = 0;

	if (id == 0)
	{
		return NULL;
	}

	pgp_ecdh_kdf_paramters(pgp_key->curve, &hash_algorithm_id, &cipher_algorithm_id);

	group = ec_group_new(id);

	if (group == NULL)
	{
		return NULL;
	}

	// Generate ephemeral key
	ephemeral_key = ec_key_generate(group, NULL);

	if (ephemeral_key == NULL)
	{
		ec_group_delete(group);
		return NULL;
	}

	// Compute shared point
	public_point = ec_point_decode(group, NULL, pgp_key->point->bytes, CEIL_DIV(pgp_key->point->bits, 8));
	shared_point = ec_point_multiply(group, NULL, public_point, ephemeral_key->d);

	xcoord_size = bignum_get_bytes_be(shared_point->x, xcoord, 128);

	// Encode the session key
	if (symmetric_key_algorithm_id != 0)
	{
		encoded_session_key[pos++] = symmetric_key_algorithm_id;
	}

	memcpy(encoded_session_key + pos, session_key, session_key_size);
	pos += session_key_size;

	for (byte_t i = 0; i < session_key_size; ++i)
	{
		session_key_checksum += ps[i];
	}

	encoded_session_key[pos++] = (session_key_checksum >> 16) & 0xFF;
	encoded_session_key[pos++] = session_key_checksum & 0xFF;

	memset(encoded_session_key + pos, encoded_session_key_size - pos, encoded_session_key_size - pos);

	// Derive key
	switch (cipher_algorithm_id)
	{
	case PGP_AES_128:
		key_wrap_key_size = AES128_KEY_SIZE;
		break;
	case PGP_AES_192:
		key_wrap_key_size = AES192_KEY_SIZE;
		break;
	case PGP_AES_256:
		key_wrap_key_size = AES256_KEY_SIZE;
		break;
	default:
		break;
	}

	pos = 0;

	// Curve OID
	kdf_input[pos] = pgp_key->oid_size;
	pos += 1;

	memcpy(kdf_input + pos, pgp_key->oid, pgp_key->oid_size);
	pos += pgp_key->oid_size;

	// ECDH Algorithm
	kdf_input[pos] = PGP_ECDH;
	pos += 1;

	// KDF Parameters
	kdf_input[pos++] = pgp_key->kdf.size;
	kdf_input[pos++] = pgp_key->kdf.extensions;
	kdf_input[pos++] = pgp_key->kdf.hash_algorithm_id;
	kdf_input[pos++] = pgp_key->kdf.symmetric_key_algorithm_id;

	// "Anonymous Sender"
	memcpy(kdf_input + pos, "Anonymous Sender    ", 20);
	pos += 20;

	// TODO: Fingerptint

	kdf_input_size = pos;

	pgp_ecdh_kdf(hash_algorithm_id, xcoord, xcoord_size, kdf_input, kdf_input_size, key_wrap_key, key_wrap_key_size);

	// Key wrap
	pgp_ecdh_kw_encrypt(cipher_algorithm_id, key_wrap_key, key_wrap_key_size, encoded_session_key, encoded_session_key_size,
						wrapped_session_key, wrapped_session_key_size);

	kex = malloc(sizeof(pgp_ecdh_kex));

	if (kex == NULL)
	{
		ec_point_delete(shared_point);
		ec_point_delete(public_point);
		ec_key_delete(ephemeral_key);
	}

	memset(kex, 0, sizeof(pgp_ecdh_kex));

	// TODO MPI
	kex->encoded_session_key_size = wrapped_session_key_size;
	memcpy(kex->encoded_session_key, wrapped_session_key, wrapped_session_key_size);

	ec_point_delete(shared_point);
	ec_point_delete(public_point);
	ec_key_delete(ephemeral_key);

	return kex;
}

uint32_t pgp_ecdh_kex_decrypt(pgp_ecdh_kex *kex, pgp_ecdh_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
							  uint32_t session_key_size)
{
	ec_group *group = NULL;
	ec_point *shared_point = NULL;
	ec_point *public_point = NULL;
	bignum_t *d = NULL;

	pgp_hash_algorithms hash_algorithm_id = 0;
	pgp_symmetric_key_algorithms cipher_algorithm_id = 0;
	curve_id id = pgp_ec_curve_to_curve_id(pgp_key->curve);

	byte_t pos = 0;
	uint16_t session_key_checksum = 0;

	byte_t encoded_session_key[64] = {0};
	byte_t encoded_session_key_size = ROUND_UP(session_key_size, 8);

	byte_t xcoord[128] = {0};
	byte_t xcoord_size = 0;

	byte_t key_wrap_key[32] = {0};
	byte_t kdf_input[128] = {0};
	byte_t key_wrap_key_size = 0;
	byte_t kdf_input_size = 0;

	if (id == 0)
	{
		return 0;
	}

	pgp_ecdh_kdf_paramters(pgp_key->curve, &hash_algorithm_id, &cipher_algorithm_id);

	group = ec_group_new(id);

	if (group == NULL)
	{
		return 0;
	}

	// Compute shared point
	d = mpi_to_bignum(pgp_key->x);
	public_point = ec_point_decode(group, NULL, kex->ephemeral_point->bytes, CEIL_DIV(kex->ephemeral_point->bits, 8));
	shared_point = ec_point_multiply(group, NULL, public_point, d);

	xcoord_size = bignum_get_bytes_be(shared_point->x, xcoord, 128);

	// Derive key
	switch (cipher_algorithm_id)
	{
	case PGP_AES_128:
		key_wrap_key_size = AES128_KEY_SIZE;
		break;
	case PGP_AES_192:
		key_wrap_key_size = AES192_KEY_SIZE;
		break;
	case PGP_AES_256:
		key_wrap_key_size = AES256_KEY_SIZE;
		break;
	default:
		break;
	}

	pos = 0;

	// Curve OID
	kdf_input[pos] = pgp_key->oid_size;
	pos += 1;

	memcpy(kdf_input + pos, pgp_key->oid, pgp_key->oid_size);
	pos += pgp_key->oid_size;

	// ECDH Algorithm
	kdf_input[pos] = PGP_ECDH;
	pos += 1;

	// KDF Parameters
	kdf_input[pos++] = pgp_key->kdf.size;
	kdf_input[pos++] = pgp_key->kdf.extensions;
	kdf_input[pos++] = pgp_key->kdf.hash_algorithm_id;
	kdf_input[pos++] = pgp_key->kdf.symmetric_key_algorithm_id;

	// "Anonymous Sender"
	memcpy(kdf_input + pos, "Anonymous Sender    ", 20);
	pos += 20;

	// TODO: Fingerptint

	kdf_input_size = pos;

	pgp_ecdh_kdf(hash_algorithm_id, xcoord, xcoord_size, kdf_input, kdf_input_size, key_wrap_key, key_wrap_key_size);

	// Key wrap
	pgp_ecdh_kw_decrypt(cipher_algorithm_id, key_wrap_key, key_wrap_key_size, kex->encoded_session_key, kex->encoded_session_key_size,
						encoded_session_key, encoded_session_key_size);

	// TODO V3 algorithm assignment.
	// TODO parse
	for (byte_t i = 0; i < session_key_size; ++i)
	{
		session_key_checksum += encoded_session_key[i];
	}

	ec_point_delete(shared_point);
	ec_point_delete(public_point);
	ec_group_delete(group);
	bignum_delete(d);

	return 0;
}

pgp_x25519_kex *pgp_x25519_kex_encrypt(pgp_x25519_key *key, byte_t symmetric_key_algorithm_id, void *session_key, byte_t session_key_size)
{
	pgp_x25519_kex *kex = NULL;

	pgp_x25519_key ephemeral_key = {0};
	byte_t shared_secret[X25519_OCTET_SIZE] = {0};
	byte_t hkdf_input[3 * X25519_OCTET_SIZE] = {0};
	uint16_t pos = 0;

	byte_t key_wrap_key[AES128_KEY_SIZE] = {0};

	kex = malloc(sizeof(pgp_x25519_kex));

	if (kex == NULL)
	{
		return NULL;
	}

	memset(kex, 0, sizeof(pgp_x25519_kex));

	pgp_x25519_generate_key(&ephemeral_key);
	x25519(shared_secret, key->public_key, ephemeral_key.private_key);

	memcpy(hkdf_input + pos, ephemeral_key.public_key, X25519_OCTET_SIZE);
	pos += X25519_OCTET_SIZE;

	memcpy(hkdf_input + pos, key->public_key, X25519_OCTET_SIZE);
	pos += X25519_OCTET_SIZE;

	memcpy(hkdf_input + pos, shared_secret, X25519_OCTET_SIZE);
	pos += X25519_OCTET_SIZE;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X25519", 14, key_wrap_key, AES128_KEY_SIZE);

	memcpy(kex->ephemeral_key, ephemeral_key.public_key, X25519_OCTET_SIZE);

	if (symmetric_key_algorithm_id != 0)
	{
		kex->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		kex->octet_count += 1;
	}

	kex->octet_count +=
		aes128_key_wrap_encrypt(key_wrap_key, AES128_KEY_SIZE, session_key, session_key_size, kex->encrypted_session_key, 40);

	return kex;
}

uint32_t pgp_x25519_kex_decrypt(pgp_x25519_kex *kex, pgp_x25519_key *key, byte_t *symmetric_key_algorithm_id, void *session_key,
								uint32_t session_key_size)
{
	uint32_t result = 0;

	byte_t shared_secret[X25519_OCTET_SIZE] = {0};
	byte_t hkdf_input[3 * X25519_OCTET_SIZE] = {0};
	uint16_t pos = 0;

	byte_t key_wrap_key[AES128_KEY_SIZE] = {0};

	x25519(shared_secret, kex->ephemeral_key, key->private_key);

	memcpy(hkdf_input + pos, kex->ephemeral_key, X25519_OCTET_SIZE);
	pos += X25519_OCTET_SIZE;

	memcpy(hkdf_input + pos, key->public_key, X25519_OCTET_SIZE);
	pos += X25519_OCTET_SIZE;

	memcpy(hkdf_input + pos, shared_secret, X25519_OCTET_SIZE);
	pos += X25519_OCTET_SIZE;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X25519", 14, key_wrap_key, AES128_KEY_SIZE);

	if (symmetric_key_algorithm_id != NULL)
	{
		*symmetric_key_algorithm_id = kex->symmetric_key_algorithm_id;
		kex->octet_count -= 1;
	}

	result =
		aes128_key_wrap_decrypt(key_wrap_key, AES128_KEY_SIZE, kex->encrypted_session_key, kex->octet_count, session_key, session_key_size);

	return result;
}

pgp_x448_kex *pgp_x448_kex_encrypt(pgp_x448_key *key, byte_t symmetric_key_algorithm_id, void *session_key, byte_t session_key_size)
{
	pgp_x448_kex *kex = NULL;

	pgp_x448_key ephemeral_key = {0};
	byte_t shared_secret[X448_OCTET_SIZE] = {0};
	byte_t hkdf_input[3 * X448_OCTET_SIZE] = {0};
	uint16_t pos = 0;

	byte_t key_wrap_key[AES256_KEY_SIZE] = {0};

	kex = malloc(sizeof(pgp_x448_kex));

	if (kex == NULL)
	{
		return NULL;
	}

	memset(kex, 0, sizeof(pgp_x448_kex));

	pgp_x448_generate_key(&ephemeral_key);
	x448(shared_secret, key->public_key, ephemeral_key.private_key);

	memcpy(hkdf_input + pos, ephemeral_key.public_key, X448_OCTET_SIZE);
	pos += X448_OCTET_SIZE;

	memcpy(hkdf_input + pos, key->public_key, X448_OCTET_SIZE);
	pos += X448_OCTET_SIZE;

	memcpy(hkdf_input + pos, shared_secret, X448_OCTET_SIZE);
	pos += X448_OCTET_SIZE;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X448", 12, key_wrap_key, AES256_KEY_SIZE);

	memcpy(kex->ephemeral_key, ephemeral_key.public_key, X448_OCTET_SIZE);

	if (symmetric_key_algorithm_id != 0)
	{
		kex->symmetric_key_algorithm_id = symmetric_key_algorithm_id;
		kex->octet_count += 1;
	}

	kex->octet_count +=
		aes256_key_wrap_encrypt(key_wrap_key, AES256_KEY_SIZE, session_key, session_key_size, kex->encrypted_session_key, 40);

	return kex;
}

uint32_t pgp_x448_kex_decrypt(pgp_x448_kex *kex, pgp_x448_key *key, byte_t *symmetric_key_algorithm_id, void *session_key,
							  uint32_t session_key_size)
{
	uint32_t result = 0;

	byte_t shared_secret[X448_OCTET_SIZE] = {0};
	byte_t hkdf_input[3 * X448_OCTET_SIZE] = {0};
	uint16_t pos = 0;

	byte_t key_wrap_key[AES256_KEY_SIZE] = {0};

	x448(shared_secret, kex->ephemeral_key, key->private_key);

	memcpy(hkdf_input + pos, kex->ephemeral_key, X448_OCTET_SIZE);
	pos += X448_OCTET_SIZE;

	memcpy(hkdf_input + pos, key->public_key, X448_OCTET_SIZE);
	pos += X448_OCTET_SIZE;

	memcpy(hkdf_input + pos, shared_secret, X448_OCTET_SIZE);
	pos += X448_OCTET_SIZE;

	hkdf(HASH_SHA256, hkdf_input, pos, NULL, 0, "OpenPGP X448", 12, key_wrap_key, AES256_KEY_SIZE);

	if (symmetric_key_algorithm_id != NULL)
	{
		*symmetric_key_algorithm_id = kex->symmetric_key_algorithm_id;
		kex->octet_count -= 1;
	}

	result =
		aes256_key_wrap_decrypt(key_wrap_key, AES256_KEY_SIZE, kex->encrypted_session_key, kex->octet_count, session_key, session_key_size);

	return result;
}

pgp_rsa_signature *pgp_rsa_sign(pgp_rsa_key *pgp_key, byte_t hash_algorithm_id, void *hash, uint32_t hash_size)
{
	void *result = NULL;

	rsa_key *key = NULL;
	pgp_rsa_signature *pgp_sign = NULL;
	rsa_signature sign = {0};

	hash_algorithm algorithm = pgp_algorithm_to_hash_algorithm(hash_algorithm_id);

	if (algorithm == 0)
	{
		return 0;
	}

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return NULL;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->d = mpi_to_bignum(pgp_key->d);

	pgp_sign = malloc(sizeof(pgp_rsa_signature) + mpi_size(pgp_key->n->bits));

	if (pgp_sign == NULL)
	{
		rsa_key_delete(key);
		return NULL;
	}

	memset(pgp_sign, 0, sizeof(pgp_rsa_signature) + mpi_size(pgp_key->n->bits));

	pgp_sign->e = mpi_init(PTR_OFFSET(pgp_sign, sizeof(pgp_rsa_signature)), mpi_size(pgp_key->n->bits), pgp_key->n->bits);

	sign.size = CEIL_DIV(pgp_key->n->bits, 8);
	sign.sign = pgp_sign->e->bytes;

	result = rsa_sign_pkcs(key, algorithm, hash, hash_size, &sign, 0);

	rsa_key_delete(key);

	if (result == NULL)
	{
		return NULL;
	}

	pgp_sign->e->bits = sign.bits;

	return pgp_sign;
}

uint32_t pgp_rsa_verify(pgp_rsa_signature *signature, pgp_rsa_key *pgp_key, byte_t hash_algorithm_id, void *hash, uint32_t hash_size)
{
	uint32_t status;

	rsa_key *key = NULL;
	rsa_signature sign = {0};
	hash_algorithm algorithm = pgp_algorithm_to_hash_algorithm(hash_algorithm_id);

	if (algorithm == 0)
	{
		return 0;
	}

	key = rsa_key_new(pgp_key->n->bits);

	if (key == NULL)
	{
		return 0;
	}

	key->n = mpi_to_bignum(pgp_key->n);
	key->e = mpi_to_bignum(pgp_key->e);

	sign.bits = signature->e->bits;
	sign.size = CEIL_DIV(signature->e->bits, 8);
	sign.sign = signature->e->bytes;

	status = rsa_verify_pkcs(key, &sign, algorithm, hash, hash_size);

	rsa_key_delete(key);

	return status;
}

pgp_dsa_signature *pgp_dsa_sign(pgp_dsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	void *result = NULL;

	dsa_key *key = NULL;
	pgp_dsa_signature *pgp_sign = NULL;
	dsa_signature sign = {0};

	key = dsa_key_new(pgp_key->p->bits, pgp_key->q->bits);

	if (key == NULL)
	{
		return NULL;
	}

	pgp_sign = malloc(sizeof(pgp_dsa_signature) + (2 * mpi_size(pgp_key->q->bits)));

	if (pgp_sign == NULL)
	{
		dsa_key_delete(key);
		return NULL;
	}

	memset(pgp_sign, 0, sizeof(pgp_dsa_signature) + mpi_size(pgp_key->q->bits));

	pgp_sign->r = mpi_init(PTR_OFFSET(pgp_sign, sizeof(pgp_dsa_signature)), mpi_size(pgp_key->q->bits), pgp_key->q->bits);
	pgp_sign->s = mpi_init(PTR_OFFSET(pgp_sign, sizeof(pgp_dsa_signature) + mpi_size(pgp_key->q->bits)), mpi_size(pgp_key->q->bits),
						   pgp_key->q->bits);

	key->p = mpi_to_bignum(pgp_key->p);
	key->q = mpi_to_bignum(pgp_key->q);
	key->g = mpi_to_bignum(pgp_key->g);

	key->x = mpi_to_bignum(pgp_key->x);
	key->y = mpi_to_bignum(pgp_key->y);

	sign.r.size = CEIL_DIV(pgp_sign->r->bits, 8);
	sign.s.size = CEIL_DIV(pgp_sign->s->bits, 8);

	sign.r.sign = pgp_sign->r->bytes;
	sign.s.sign = pgp_sign->s->bytes;

	result = dsa_sign(key, NULL, 0, hash, hash_size, &sign, 0);

	dsa_key_delete(key);

	if (result == NULL)
	{
		return NULL;
	}

	pgp_sign->r->bits = sign.r.bits;
	pgp_sign->s->bits = sign.s.bits;

	return pgp_sign;
}

uint32_t pgp_dsa_verify(pgp_dsa_signature *signature, pgp_dsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	dsa_key *key = NULL;
	dsa_signature sign = {0};

	key = dsa_key_new(pgp_key->p->bits, pgp_key->q->bits);

	if (key == NULL)
	{
		return 0;
	}

	key->p = mpi_to_bignum(pgp_key->p);
	key->q = mpi_to_bignum(pgp_key->q);
	key->g = mpi_to_bignum(pgp_key->g);

	key->y = mpi_to_bignum(pgp_key->y);

	sign.r.size = CEIL_DIV(signature->r->bits, 8);
	sign.s.size = CEIL_DIV(signature->s->bits, 8);

	sign.r.sign = signature->r->bytes;
	sign.s.sign = signature->s->bytes;

	status = dsa_verify(key, &sign, hash, hash_size);

	dsa_key_delete(key);

	return status;
}

pgp_dsa_signature *pgp_ecdsa_sign(pgp_ecdsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	ec_key *key = NULL;
	ecdsa_signature *sign = NULL;
	pgp_ecdsa_signature *pgp_sign = NULL;

	bignum_t *d = mpi_to_bignum(pgp_key->x);
	ec_point *q = NULL;

	key = ec_key_new(NULL, d, q);

	if (key == NULL)
	{
		return NULL;
	}

	pgp_sign = malloc(sizeof(pgp_ecdsa_signature));

	sign = ecdsa_sign(key, NULL, 0, hash, hash_size, NULL, 0);

	if (sign == NULL)
	{
		return NULL;
	}

	// pgp_sign->r = mpi_from_bn(NULL, sign->r);
	// pgp_sign->s = mpi_from_bn(NULL, sign->s);

	ec_key_delete(key);

	return pgp_sign;
}

uint32_t pgp_ecdsa_verify(pgp_ecdsa_signature *signature, pgp_ecdsa_key *pgp_key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	ec_key *key = NULL;
	ecdsa_signature sign = {0};

	ec_point *q = NULL;

	key = ec_key_new(NULL, NULL, q);

	if (key == NULL)
	{
		return 0;
	}

	// sign.r = mpi_to_bignum(signature->r);
	// sign.s = mpi_to_bignum(signature->s);

	status = ecdsa_verify(key, &sign, hash, hash_size);

	// bignum_delete(sign.r);
	// bignum_delete(sign.s);

	ec_key_delete(key);

	return status;
}

pgp_ed25519_signature *pgp_ed25519_sign(pgp_ed25519_key *key, void *hash, uint32_t hash_size)
{
	void *status = NULL;
	pgp_ed25519_signature *sign = NULL;

	sign = malloc(sizeof(pgp_ed25519_signature));

	if (sign == NULL)
	{
		return NULL;
	}

	status = ed25519_sign((ed25519_key *)key, hash, hash_size, sign, sizeof(ed25519_signature));

	if (status == NULL)
	{
		free(sign);
		return NULL;
	}

	return sign;
}

uint32_t pgp_ed25519_verify(pgp_ed25519_signature *signature, pgp_ed25519_key *key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	// TODO key validation
	status = ed25519_verify((ed25519_key *)key, (ed25519_signature *)signature, hash, hash_size);

	return status;
}

pgp_ed448_signature *pgp_ed448_sign(pgp_ed448_key *key, void *hash, uint32_t hash_size)
{
	void *status = NULL;
	pgp_ed448_signature *sign = NULL;

	sign = malloc(sizeof(pgp_ed448_signature));

	if (sign == NULL)
	{
		return NULL;
	}

	status = ed448_sign((ed448_key *)key, NULL, 0, hash, hash_size, sign, sizeof(ed448_signature));

	if (status == NULL)
	{
		free(sign);
		return NULL;
	}

	return sign;
}

uint32_t pgp_ed448_verify(pgp_ed448_signature *signature, pgp_ed448_key *key, void *hash, uint32_t hash_size)
{
	uint32_t status = 0;

	// TODO key validation
	status = ed448_verify((ed448_key *)key, (ed448_signature *)signature, NULL, 0, hash, hash_size);

	return status;
}
