/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <drbg.h>
#include <hash.h>
#include <rsa.h>
#include <sha.h>
#include <md5.h>
#include <ripemd.h>
#include <bignum-internal.h>

#include <bitscan.h>
#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>

static uint32_t rsa_public_op(rsa_key *key, void *in, size_t in_size, void *out, size_t out_size)
{
	bignum_t *t = NULL;
	size_t ctx_size = bignum_size(key->bits);
	size_t output_size = key->bits / 8;

	if (key->n == NULL || key->e == NULL)
	{
		return 0;
	}

	if (in_size > (key->bits / 8))
	{
		return 0;
	}

	if (out_size < (key->bits / 8))
	{
		return 0;
	}

	bignum_ctx_start(key->bctx, ctx_size);

	t = bignum_ctx_allocate_bignum(key->bctx, key->bits);
	t = bignum_set_bytes_be(t, in, in_size);
	t = bignum_modexp(key->bctx, t, t, key->e, key->n);

	bignum_get_bytes_be_padded(t, out, output_size);

	bignum_ctx_end(key->bctx);

	return output_size;
}

static uint32_t rsa_private_op(rsa_key *key, void *in, size_t in_size, void *out, size_t out_size)
{
	bignum_t *t = NULL;
	size_t ctx_size = bignum_size(key->bits);
	size_t output_size = key->bits / 8;

	if (key->n == NULL || key->d == NULL)
	{
		return 0;
	}

	if (in_size > (key->bits / 8))
	{
		return 0;
	}

	if (out_size < (key->bits / 8))
	{
		return 0;
	}

	bignum_ctx_start(key->bctx, ctx_size);

	t = bignum_ctx_allocate_bignum(key->bctx, key->bits);
	t = bignum_set_bytes_be(t, in, in_size);
	t = bignum_modexp(key->bctx, t, t, key->d, key->n);

	bignum_get_bytes_be_padded(t, out, output_size);

	bignum_ctx_end(key->bctx);

	return output_size;
}

rsa_key *rsa_key_generate(uint32_t bits, bignum_t *e)
{
	rsa_key *key = NULL;
	bignum_t *pm1 = NULL, *qm1 = NULL, *pmq = NULL, *lcm = NULL;
	bignum_t *phi = NULL, *gcd = NULL, *one = NULL;
	uint32_t prime_bits = ROUND_UP(bits, 1024) / 2;
	size_t ctx_size = (4 * bignum_size(prime_bits)) + (2 * bignum_size(2 * prime_bits)) + bignum_size(1);

	// Validate e
	if (e->bits < 16 || e->bits > 256)
	{
		return NULL;
	}

	// Reject if e is even
	if (e->words[0] % 2 == 0)
	{
		return NULL;
	}

	bits = ROUND_UP(bits, 1024);
	key = rsa_key_new(bits);

	if (key == NULL)
	{
		return NULL;
	}

	bignum_ctx_start(key->bctx, ctx_size);

	pm1 = bignum_ctx_allocate_bignum(key->bctx, prime_bits);
	qm1 = bignum_ctx_allocate_bignum(key->bctx, prime_bits);
	pmq = bignum_ctx_allocate_bignum(key->bctx, prime_bits);
	lcm = bignum_ctx_allocate_bignum(key->bctx, prime_bits);

	phi = bignum_ctx_allocate_bignum(key->bctx, 2 * prime_bits);
	gcd = bignum_ctx_allocate_bignum(key->bctx, 2 * prime_bits);

	one = bignum_ctx_allocate_bignum(key->bctx, 1);

	bignum_one(one);

retry:
	// Generate p,q
	while (1)
	{
		// Regenerate q for each retry
		bignum_zero(key->q);

		while (bignum_is_probable_prime(key->bctx, key->p) == 0)
		{
			bignum_rand(NULL, key->p, prime_bits);
		}

		while (bignum_is_probable_prime(key->bctx, key->q) == 0)
		{
			bignum_rand(NULL, key->q, prime_bits);
		}

		pmq = bignum_sub(pmq, key->p, key->q);

		if (pmq->bits < (prime_bits - 100))
		{
			continue;
		}

		pm1 = bignum_sub(pm1, key->p, one);
		qm1 = bignum_sub(pm1, key->q, one);

		// phi = (p-1) * (q-1)
		phi = bignum_mul(key->bctx, phi, pm1, qm1);
		gcd = bignum_gcd(key->bctx, gcd, phi, e);

		if (gcd->bits != 1)
		{
			continue;
		}
	}

	bignum_copy(key->e, e);

	// n = p * q
	key->n = bignum_mul(key->bctx, key->n, key->p, key->q);

	// d = (1/e) % lcm(p-1,q-1)
	lcm = bignum_gcd(key->bctx, lcm, pm1, qm1);
	lcm = bignum_div(key->bctx, lcm, phi, lcm);
	key->d = bignum_modinv(key->bctx, key->d, key->e, lcm);

	if (key->d->bits <= prime_bits)
	{
		goto retry;
	}

	// Fill the CRT factors
	key->dmp1 = bignum_mod(key->bctx, key->dmp1, key->d, pm1);
	key->dmq1 = bignum_mod(key->bctx, key->dmq1, key->d, qm1);
	key->iqmp = bignum_modinv(key->bctx, key->iqmp, key->q, key->p);

	bignum_ctx_end(key->bctx);

	return key;
}

rsa_key *rsa_key_new(uint32_t bits)
{
	rsa_key *key = NULL;
	uint32_t required_size = 0;
	uint32_t bctx_size = 0;
	uint32_t bignums_size = 0;

	bits = ROUND_UP(bits, 1024);
	bctx_size += 16 * (bits * 2) / 8; // For bctx

	bignums_size = bignum_size(bits)           // n
				   + 2 * bignum_size(bits)     // d,e
				   + 2 * bignum_size(bits / 2) // p,q
				   + 3 * bignum_size(bits / 2) // crt
				   + bignum_size(bits)         // mu
		;

	required_size = sizeof(rsa_key) + bctx_size + bignums_size;

	key = malloc(required_size);

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, required_size);

	key->size = required_size;
	key->bits = bits;

	key->bctx = bignum_ctx_init(PTR_OFFSET(key, sizeof(rsa_key) + bignums_size), bctx_size);

	return key;
}

void rsa_key_delete(rsa_key *key)
{
	memset(key, 0, key->size);
	free(key);
}

rsa_key *rsa_key_set_basic(rsa_key *key, bignum_t *n, bignum_t *d, bignum_t *e)
{
	uint32_t n_offset = sizeof(rsa_key);
	uint32_t d_offset = n_offset + bignum_size(n->bits);
	uint32_t e_offset = d_offset + bignum_size(d->bits);

	key->n = bignum_init(PTR_OFFSET(key, n_offset), bignum_size(key->bits), n->bits);
	key->d = bignum_init(PTR_OFFSET(key, d_offset), bignum_size(key->bits), d->bits);
	key->e = bignum_init(PTR_OFFSET(key, e_offset), bignum_size(key->bits), e->bits);

	if (key->n == NULL || key->d == NULL || key->e == NULL)
	{
		return NULL;
	}

	bignum_copy(key->n, n);
	bignum_copy(key->d, d);
	bignum_copy(key->e, e);

	return key;
}

rsa_key *rsa_key_set_factors(rsa_key *key, bignum_t *p, bignum_t *q)
{
	uint32_t p_offset = sizeof(rsa_key) + (3 * bignum_size(key->bits));
	uint32_t q_offset = p_offset + bignum_size(p->bits);

	key->p = bignum_init(PTR_OFFSET(key, p_offset), bignum_size(key->bits / 2), p->bits);
	key->q = bignum_init(PTR_OFFSET(key, q_offset), bignum_size(key->bits / 2), q->bits);

	if (key->p == NULL || key->q == NULL)
	{
		return NULL;
	}

	bignum_copy(key->p, p);
	bignum_copy(key->q, q);

	return key;
}

rsa_key *rsa_key_set_crt(rsa_key *key, bignum_t *dmp1, bignum_t *dmq1, bignum_t *iqmp)
{
	uint32_t dmp1_offset = sizeof(rsa_key) + (3 * bignum_size(key->bits)) + (2 * bignum_size(key->bits / 2));
	uint32_t dmq1_offset = dmp1_offset + bignum_size(dmp1->bits);
	uint32_t iqmp_offset = dmq1_offset + bignum_size(dmq1->bits);

	key->dmp1 = bignum_init(PTR_OFFSET(key, dmp1_offset), bignum_size(key->bits / 2), dmp1->bits);
	key->dmq1 = bignum_init(PTR_OFFSET(key, dmq1_offset), bignum_size(key->bits / 2), dmq1->bits);
	key->iqmp = bignum_init(PTR_OFFSET(key, iqmp_offset), bignum_size(key->bits / 2), iqmp->bits);

	if (key->dmp1 == NULL || key->dmq1 == NULL || key->iqmp == NULL)
	{
		return NULL;
	}

	bignum_copy(key->dmp1, dmp1);
	bignum_copy(key->dmq1, dmq1);
	bignum_copy(key->iqmp, iqmp);

	return key;
}

uint32_t rsa_public_encrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return rsa_public_op(key, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint32_t rsa_public_decrypt(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return rsa_public_op(key, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

uint32_t rsa_private_encrypt(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	return rsa_private_op(key, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

uint32_t rsa_private_decrypt(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	return rsa_private_op(key, ciphertext, ciphertext_size, plaintext, plaintext_size);
}

static inline void xor_bytes(byte_t *a, byte_t *b, size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		a[i] ^= b[i];
	}
}

static inline void zero_top_bits(byte_t *em, bignum_t *n)
{
	uint32_t em_bits = ROUND_UP(n->bits, 1024);
	uint32_t pos = 0;

	for (pos = 0;; ++pos)
	{
		if (em[pos] != 0)
		{
			em_bits -= 8 - (bsr_8(em[pos]) + 1);
			break;
		}

		em_bits -= 8;
	}

	pos = 0;

	while (em_bits >= n->bits)
	{
		em[pos / 8] &= 0xFF ^ (1 << (7 - (pos % 8)));

		++pos;
		--em_bits;
	}
}

static void MGF_XOR(hash_ctx *hctx, byte_t *seed, size_t seed_size, byte_t *output, size_t output_size)
{
	size_t accumulated = 0;
	uint32_t counter = 0;

	while (accumulated < output_size)
	{
		counter = BSWAP_32(counter);

		hash_reset(hctx);

		hash_update(hctx, seed, seed_size);
		hash_update(hctx, &counter, 4);
		hash_final(hctx, NULL, hctx->hash_size);

		xor_bytes(output + accumulated, hctx->hash, MIN(output_size - accumulated, hctx->hash_size));

		accumulated += hctx->hash_size;

		counter = BSWAP_32(counter);
		++counter;
	}
}

int32_t rsa_encrypt_oaep(rsa_key *key, hash_ctx *hctx_label, hash_ctx *hctx_mask, drbg_ctx *drbg, void *label, size_t label_size,
						 void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	int32_t status = 0;

	// Sizes
	size_t key_size = key->bits / 8;
	size_t hash_size = hctx_label != NULL ? hctx_label->hash_size : SHA1_HASH_SIZE;
	size_t max_plaintext_size = key_size - (2 * hash_size) - 2;
	size_t ps_size = key_size - (plaintext_size + (2 * hash_size) + 2);
	size_t db_size = key_size - (hash_size + 1);
	size_t seed_size = hash_size;
	size_t em_size = key_size;

	// Offsets
	size_t seed_offset = 1;
	size_t masked_seed_offset = seed_offset;
	size_t db_offset = masked_seed_offset + hash_size;
	size_t masked_db_offset = db_offset;
	size_t ps_offset = db_offset + hash_size;
	size_t message_offset = ps_offset + ps_size + 1;
	size_t label_hash_offset = db_offset;

	size_t ctx_size = em_size;
	size_t default_hash_ctx_size = 0;

	void *hctx = NULL;
	byte_t *em = NULL;

	// Length checking.
	if (plaintext_size > max_plaintext_size)
	{
		return -1;
	}

	if (ciphertext_size < key_size)
	{
		return -1;
	}

	// Check Hash
	if (hctx_label == NULL || hctx_mask == NULL)
	{
		default_hash_ctx_size = hash_ctx_size(HASH_SHA1);
		ctx_size += default_hash_ctx_size;
	}

	// Setup the DRBG
	if (drbg == NULL)
	{
		drbg = get_default_drbg();
	}

	bignum_ctx_start(key->bctx, ctx_size);

	// Allocate for EM
	em = bignum_ctx_allocate_raw(key->bctx, em_size);

	// If no hashes are specified use SHA-1
	if (hctx_label == NULL || hctx_mask == NULL)
	{
		hctx = bignum_ctx_allocate_raw(key->bctx, default_hash_ctx_size);
		hctx = hash_init(hctx, default_hash_ctx_size, HASH_SHA1);

		if (hctx_label == NULL)
		{
			hctx_label = hctx;
		}

		if (hctx_mask == NULL)
		{
			hctx_mask = hctx;
		}
	}

	// Constructing EM
	memset(em, 0, em_size);

	// Hash the label
	hash_reset(hctx_label);

	if (label_size > 0)
	{
		hash_update(hctx_label, label, label_size);
	}

	// Copy label_hash
	hash_final(hctx_label, em + label_hash_offset, hctx_label->hash_size);

	// PS length zeroes already done by memset.

	// 0x1 following PS
	em[message_offset - 1] = 0x1;

	// Copy Message
	memcpy(em + message_offset, plaintext, plaintext_size);

	if (hctx_mask == NULL)
	{
		hctx_mask = hash_init(hctx, default_hash_ctx_size, HASH_SHA1);
	}

	// Generate seed
	drbg_generate(drbg, 0, NULL, 0, em + seed_offset, seed_size);

	// Construct Masked DB.
	MGF_XOR(hctx_mask, em + seed_offset, seed_size, em + db_offset, db_size);

	// Construct Masked Seed
	MGF_XOR(hctx_mask, em + masked_db_offset, db_size, em + masked_seed_offset, seed_size);

	// Encryption
	status = rsa_public_encrypt(key, em, em_size, ciphertext, ciphertext_size);

	bignum_ctx_end(key->bctx);

	return status;
}

int32_t rsa_decrypt_oaep(rsa_key *key, hash_ctx *hctx_label, hash_ctx *hctx_mask, void *label, size_t label_size, void *ciphertext,
						 size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	int32_t status = -1;

	// Sizes
	size_t key_size = key->bits / 8;
	size_t hash_size = hctx_label != NULL ? hctx_label->hash_size : SHA1_HASH_SIZE;
	size_t db_size = key_size - (hash_size + 1);
	size_t seed_size = hash_size;
	size_t em_size = key_size;

	// Offsets
	size_t seed_offset = 1;
	size_t masked_seed_offset = seed_offset;
	size_t db_offset = masked_seed_offset + hash_size;
	size_t masked_db_offset = db_offset;
	size_t ps_offset = db_offset + hash_size;
	size_t label_hash_offset = db_offset;

	size_t message_offset = 0;
	size_t message_size = 0;

	size_t ctx_size = em_size;
	size_t default_hash_ctx_size = 0;

	void *hctx = NULL;
	byte_t *em = NULL;

	// Length checking.
	if (ciphertext_size > key_size)
	{
		return -1;
	}

	if (key_size < (2 * hash_size + 2))
	{
		return -1;
	}

	// Check Hash
	if (hctx_label == NULL || hctx_mask == NULL)
	{
		default_hash_ctx_size = hash_ctx_size(HASH_SHA1);
		ctx_size += default_hash_ctx_size;
	}

	bignum_ctx_start(key->bctx, ctx_size);

	// Allocate for EM
	em = bignum_ctx_allocate_raw(key->bctx, em_size);
	memset(em, 0, em_size);

	// If no hashes are specified use SHA-1
	if (hctx_label == NULL || hctx_mask == NULL)
	{
		hctx = bignum_ctx_allocate_raw(key->bctx, default_hash_ctx_size);
		hctx = hash_init(hctx, default_hash_ctx_size, HASH_SHA1);

		if (hctx_label == NULL)
		{
			hctx_label = hctx;
		}

		if (hctx_mask == NULL)
		{
			hctx_mask = hctx;
		}
	}

	// Decryption
	rsa_private_decrypt(key, ciphertext, ciphertext_size, em, em_size);

	// Decode EM
	MGF_XOR(hctx_mask, em + masked_db_offset, db_size, em + masked_seed_offset, seed_size);
	MGF_XOR(hctx_mask, em + seed_offset, seed_size, em + masked_db_offset, db_size);

	// Hash the label
	hash_reset(hctx_label);

	if (label_size > 0)
	{
		hash_update(hctx_label, label, label_size);
	}

	hash_final(hctx_label, NULL, hctx_label->hash_size);

	// Check if first byte is 0x00.
	if (em[0] != 0x00)
	{
		goto end;
	}

	// Check label hash.
	if (memcmp(hctx_label->hash, em + label_hash_offset, hash_size) != 0)
	{
		goto end;
	}

	// Check for 0x01.
	for (size_t pos = ps_offset; pos < em_size; ++pos)
	{
		if (em[pos] == 0x00)
		{
			continue;
		}

		if (em[pos] == 0x01)
		{
			message_offset = pos + 1;
			message_size = em_size - message_offset;
			break;
		}
	}

	if (message_offset == 0)
	{
		goto end;
	}

	if (plaintext_size < message_size)
	{
		goto end;
	}

	// Copy the message to plaintext.
	memcpy(plaintext, em + message_offset, message_size);
	status = message_size;

end:
	bignum_ctx_end(key->bctx);
	return status;
}

int32_t rsa_encrypt_pkcs(rsa_key *key, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size, drbg_ctx *drbg)
{
	int32_t status = 0;

	// Sizes
	size_t key_size = key->bits / 8;
	size_t ps_size = key_size - plaintext_size - 3;
	size_t em_size = key_size;

	// Offsets
	size_t ps_offset = 2;
	size_t message_offset = ps_offset + ps_size + 1;

	byte_t *em = NULL;

	// Length checking
	if (plaintext_size > key_size - 11)
	{
		return -1;
	}

	if (ciphertext_size < key_size)
	{
		return -1;
	}

	// Setup the DRBG
	if (drbg == NULL)
	{
		drbg = get_default_drbg();
	}

	bignum_ctx_start(key->bctx, em_size);

	// Allocate for EM
	em = bignum_ctx_allocate_raw(key->bctx, em_size);
	memset(em, 0, em_size);

	// Construct EM
	em[0] = 0x00;
	em[1] = 0x02;
	em[ps_offset + ps_size] = 0x00;

	// Randomize PS with nonzero octests
retry:
	drbg_generate(drbg, 0, NULL, 0, em + ps_offset, ps_size);

	for (size_t pos = ps_offset; pos < ps_size + ps_offset; ++pos)
	{
		if (em[pos] == 0x00)
		{
			goto retry;
		}
	}

	memcpy(em + message_offset, plaintext, plaintext_size);

	// Encryption
	status = rsa_public_encrypt(key, em, em_size, ciphertext, ciphertext_size);

	bignum_ctx_end(key->bctx);

	return status;
}

int32_t rsa_decrypt_pkcs(rsa_key *key, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	int32_t status = -1;

	// Sizes
	size_t key_size = key->bits / 8;
	size_t em_size = key_size;

	size_t message_offset = 0;
	size_t message_size = 0;
	size_t ps_size = 0;

	byte_t *em = NULL;

	// Length checking.
	if (ciphertext_size > key_size)
	{
		return -1;
	}

	bignum_ctx_start(key->bctx, em_size);

	// Allocate for EM
	em = bignum_ctx_allocate_raw(key->bctx, em_size);
	memset(em, 0, em_size);

	// Decryption
	rsa_private_decrypt(key, ciphertext, ciphertext_size, em, em_size);

	// Verification
	if (em[0] != 0x00 || em[1] != 0x02)
	{
		goto end;
	}

	for (size_t pos = 2; pos < key_size; ++pos)
	{
		if (em[pos] == 0x00)
		{
			message_offset = pos + 1;
			message_size = key_size - message_offset;
			ps_size = key_size - message_size - 3;

			break;
		}

		++ps_size;
	}

	if (ps_size < 8)
	{
		goto end;
	}

	if (plaintext_size < message_size)
	{
		goto end;
	}

	// Copy the message to plaintext.
	memcpy(plaintext, em + message_offset, message_size);
	status = message_size;

end:
	bignum_ctx_end(key->bctx);
	return status;
}

static inline rsa_pss_ctx *rsa_pss_new(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, void *salt,
									   size_t salt_size)
{
	rsa_pss_ctx *rctx = NULL;

	// Parameter checking
	if (key == NULL)
	{
		return NULL;
	}

	if (hctx_message == NULL)
	{
		return NULL;
	}

	if ((key->bits / 8) < (hctx_message->hash_size + salt_size + 2))
	{
		return NULL;
	}

	rctx = (rsa_pss_ctx *)malloc(sizeof(rsa_pss_ctx));

	if (rctx == NULL)
	{
		return NULL;
	}

	rctx->key = key;
	rctx->hctx_message = hctx_message;
	rctx->hctx_mask = hctx_mask;
	rctx->drbg = drbg;
	rctx->salt = salt;
	rctx->salt_size = salt_size;

	hash_reset(rctx->hctx_message);

	if (rctx->hctx_mask != NULL)
	{
		hash_reset(rctx->hctx_mask);
	}

	return rctx;
}

static inline void rsa_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, void *salt,
								 size_t salt_size)
{
	rctx->key = key;
	rctx->hctx_message = hctx_message;
	rctx->hctx_mask = hctx_mask;
	rctx->drbg = drbg;
	rctx->salt = salt;
	rctx->salt_size = salt_size;

	hash_reset(rctx->hctx_message);

	if (rctx->hctx_mask != NULL)
	{
		hash_reset(rctx->hctx_mask);
	}
}

rsa_pss_ctx *rsa_sign_pss_new(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, void *salt, size_t salt_size)
{
	return rsa_pss_new(key, hctx_message, hctx_mask, drbg, salt, salt_size);
}

void rsa_sign_pss_delete(rsa_pss_ctx *rctx)
{
	memset(rctx, 0, sizeof(rsa_pss_ctx));
	free(rctx);
}

void rsa_sign_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, void *salt,
						size_t salt_size)
{
	rsa_pss_reset(rctx, key, hctx_message, hctx_mask, drbg, salt, salt_size);
}

void rsa_sign_pss_update(rsa_pss_ctx *rctx, void *message, size_t size)
{
	hash_update(rctx->hctx_message, message, size);
}

rsa_signature *rsa_sign_pss_final(rsa_pss_ctx *rctx, void *signature, size_t size)
{
	rsa_signature *rsign = signature;

	// Sizes
	size_t key_size = rctx->key->bits / 8;
	size_t hash_size = rctx->hctx_message->hash_size;
	size_t salt_size = rctx->salt_size;

	size_t ps_size = key_size - (salt_size + hash_size + 2);
	size_t db_size = key_size - (hash_size + 1);
	size_t em_size = key_size;

	size_t salt_offset = ps_size + 1;
	size_t hash_offset = db_size;

	size_t ctx_size = em_size;
	size_t default_hash_ctx_size = 0;

	size_t signature_size = sizeof(rsa_signature) + key_size;

	byte_t *hash = NULL;
	byte_t *salt = NULL;
	byte_t *em = NULL;

	// Check Hash
	if (rctx->hctx_mask == NULL)
	{
		default_hash_ctx_size = hash_ctx_size(HASH_SHA1);
		ctx_size += default_hash_ctx_size;
	}

	// Allocate for the signature
	if (rsign == NULL)
	{
		rsign = malloc(signature_size);
	}
	else
	{
		if (size < signature_size)
		{
			return NULL;
		}
	}

	if (rsign == NULL)
	{
		return NULL;
	}

	bignum_ctx_start(rctx->key->bctx, ctx_size);

	// If mask hash is not specified use SHA-1
	if (rctx->hctx_mask == NULL)
	{
		rctx->hctx_mask = bignum_ctx_allocate_raw(rctx->key->bctx, default_hash_ctx_size);
		rctx->hctx_mask = hash_init(rctx->hctx_mask, default_hash_ctx_size, HASH_SHA1);
	}

	em = bignum_ctx_allocate_raw(rctx->key->bctx, em_size);
	memset(em, 0, em_size);

	em[ps_size] = 0x01;
	em[em_size - 1] = 0xBC;

	hash = em + hash_offset;
	salt = em + salt_offset;

	// Finish hashing the message.
	hash_final(rctx->hctx_message, hash, hash_size);
	hash_reset(rctx->hctx_message);

	// Generate H'
	uint64_t zero = 0;

	hash_update(rctx->hctx_message, &zero, 8);
	hash_update(rctx->hctx_message, hash, hash_size);

	// Generate the salt
	if (salt_size > 0)
	{
		if (rctx->salt != NULL)
		{
			memcpy(salt, rctx->salt, rctx->salt_size);
		}
		else
		{
			if (rctx->drbg == NULL)
			{
				rctx->drbg = get_default_drbg();
			}

			drbg_generate(rctx->drbg, 0, NULL, 0, salt, salt_size);
		}

		hash_update(rctx->hctx_message, salt, salt_size);
	}

	hash_final(rctx->hctx_message, hash, hash_size);

	// DB Mask
	MGF_XOR(rctx->hctx_mask, hash, hash_size, em, db_size);

	// Zero the top bits to ensure em < n
	zero_top_bits(em, rctx->key->n);

	// Generate the signature.
	memset(rsign, 0, sizeof(rsa_signature) + key_size);
	rsign->size = key_size;
	rsign->sign = (byte_t *)rsign + sizeof(rsa_signature);

	rsign->bits = rsa_private_encrypt(rctx->key, em, em_size, rsign->sign, rsign->size);

	bignum_ctx_end(rctx->key->bctx);

	if (rsign->bits < 0)
	{
		free(rsign);
		return NULL;
	}

	return rsign;
}

rsa_signature *rsa_sign_pss(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, drbg_ctx *drbg, void *salt, size_t salt_size,
							void *message, size_t message_size, void *signature, size_t signature_size)
{
	rsa_pss_ctx *rctx = rsa_sign_pss_new(key, hctx_message, hctx_mask, drbg, salt, salt_size);
	rsa_signature *rsign = NULL;

	if (rctx == NULL)
	{
		return NULL;
	}

	rsa_sign_pss_update(rctx, message, message_size);
	rsign = rsa_sign_pss_final(rctx, signature, signature_size);

	rsa_sign_pss_delete(rctx);

	return rsign;
}

rsa_pss_ctx *rsa_verify_pss_new(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size)
{
	return rsa_pss_new(key, hctx_message, hctx_mask, NULL, NULL, salt_size);
}

void rsa_verify_pss_delete(rsa_pss_ctx *rctx)
{
	memset(rctx, 0, sizeof(rsa_pss_ctx));
	free(rctx);
}

void rsa_verify_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size)
{
	rsa_pss_reset(rctx, key, hctx_message, hctx_mask, NULL, NULL, salt_size);
}

void rsa_verify_pss_update(rsa_pss_ctx *rctx, void *message, size_t size)
{
	hash_update(rctx->hctx_message, message, size);
}

uint32_t rsa_verify_pss_final(rsa_pss_ctx *rctx, rsa_signature *rsign)
{
	int32_t status = 0;

	// Sizes
	size_t key_size = rctx->key->bits / 8;
	size_t hash_size = rctx->hctx_message->hash_size;
	size_t salt_size = rctx->salt_size;

	size_t ps_size = key_size - (salt_size + hash_size + 2);
	size_t db_size = key_size - (hash_size + 1);
	size_t em_size = key_size;

	size_t salt_offset = ps_size + 1;
	size_t hash_offset = db_size;

	size_t ctx_size = em_size + hash_size;
	size_t default_hash_ctx_size = 0;

	byte_t *mhash = NULL;
	byte_t *hash = NULL;
	byte_t *salt = NULL;
	byte_t *em = NULL;

	// Length checking
	if (rsign->size > key_size)
	{
		return 0;
	}

	if (rsign->size < hash_size + salt_size + 2)
	{
		return 0;
	}

	// Check Hash
	if (rctx->hctx_mask == NULL)
	{
		default_hash_ctx_size = hash_ctx_size(HASH_SHA1);
		ctx_size += default_hash_ctx_size;
	}

	bignum_ctx_start(rctx->key->bctx, ctx_size);

	// If mask hash is not specified use SHA-1
	if (rctx->hctx_mask == NULL)
	{
		rctx->hctx_mask = bignum_ctx_allocate_raw(rctx->key->bctx, default_hash_ctx_size);
		rctx->hctx_mask = hash_init(rctx->hctx_mask, default_hash_ctx_size, HASH_SHA1);
	}

	em = bignum_ctx_allocate_raw(rctx->key->bctx, em_size);
	memset(em, 0, em_size);

	hash = em + hash_offset;
	salt = em + salt_offset;

	// Decryption
	rsa_public_decrypt(rctx->key, rsign->sign, rsign->size, em, em_size);

	// Verification
	if (em[em_size - 1] != 0xBC)
	{
		goto end;
	}

	// DB Mask
	MGF_XOR(rctx->hctx_mask, hash, hash_size, em, db_size);

	// Check for zeros
	for (size_t pos = 0; pos < ps_size; ++pos)
	{
		if (em[pos] != 0x00)
		{
			goto end;
		}
	}

	// Check for 0x01
	if (em[ps_size] != 0x01)
	{
		goto end;
	}

	// Compare hashes.
	mhash = bignum_ctx_allocate_raw(rctx->key->bctx, hash_size);
	memset(em, 0, hash_size);

	hash_final(rctx->hctx_message, mhash, hash_size);
	hash_reset(rctx->hctx_message);

	uint64_t zero = 0;

	hash_update(rctx->hctx_message, &zero, 8);
	hash_update(rctx->hctx_message, mhash, hash_size);
	hash_update(rctx->hctx_message, salt, salt_size);

	hash_final(rctx->hctx_message, mhash, hash_size);

	if (memcmp(hash, mhash, hash_size) != 0)
	{
		goto end;
	}

	status = 1;

end:
	bignum_ctx_end(rctx->key->bctx);
	return status;
}

uint32_t rsa_verify_pss(rsa_key *key, hash_ctx *hctx_message, hash_ctx *hctx_mask, size_t salt_size, void *message, size_t size,
						rsa_signature *rsign)
{
	int32_t status = 0;
	rsa_pss_ctx *rctx = rsa_verify_pss_new(key, hctx_message, hctx_mask, salt_size);

	if (rctx == NULL)
	{
		return status;
	}

	rsa_verify_pss_update(rctx, message, size);
	status = rsa_verify_pss_final(rctx, rsign);

	rsa_verify_pss_delete(rctx);

	return status;
}

static uint32_t get_digest_info_size(hash_algorithm algorithm)
{
	switch (algorithm)
	{
	case HASH_MD5:
		return 18 + MD5_HASH_SIZE;
	case HASH_RIPEMD160:
		return 15 + RIPEMD160_HASH_SIZE;
	case HASH_SHA1:
		return 15 + SHA1_HASH_SIZE;
	case HASH_SHA224:
		return 19 + SHA224_HASH_SIZE;
	case HASH_SHA256:
		return 19 + SHA256_HASH_SIZE;
	case HASH_SHA384:
		return 19 + SHA384_HASH_SIZE;
	case HASH_SHA512:
		return 19 + SHA512_HASH_SIZE;
	case HASH_SHA512_224:
		return 19 + SHA512_224_HASH_SIZE;
	case HASH_SHA512_256:
		return 19 + SHA512_256_HASH_SIZE;
	case HASH_SHA3_224:
		return 19 + SHA3_224_HASH_SIZE;
	case HASH_SHA3_256:
		return 19 + SHA3_256_HASH_SIZE;
	case HASH_SHA3_384:
		return 19 + SHA3_384_HASH_SIZE;
	case HASH_SHA3_512:
		return 19 + SHA3_512_HASH_SIZE;
	default:
		return 0;
	}
}

static uint32_t get_digest_info_prefix(hash_algorithm algorithm, void *ptr)
{
	switch (algorithm)
	{
	case HASH_MD5:
		memcpy(ptr, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10", 18);
		return 18;
	case HASH_RIPEMD160:
		memcpy(ptr, "\x30\x21\x30\x09\x06\x05\x2b\x24\x03\x02\x01\x05\x00\x04\x14", 15);
	case HASH_SHA1:
		return 15;
		memcpy(ptr, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 15);
		return 15;
	case HASH_SHA224:
		memcpy(ptr, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c", 19);
		return 19;
	case HASH_SHA256:
		memcpy(ptr, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 19);
		return 19;
	case HASH_SHA384:
		memcpy(ptr, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30", 19);
		return 19;
	case HASH_SHA512:
		memcpy(ptr, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40", 19);
		return 19;
	case HASH_SHA512_224:
		memcpy(ptr, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00\x04\x1c", 19);
		return 19;
	case HASH_SHA512_256:
		memcpy(ptr, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00\x04\x20", 19);
		return 19;
	case HASH_SHA3_224:
		memcpy(ptr, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07\x05\x00\x04\x40", 19);
		return 19;
	case HASH_SHA3_256:
		memcpy(ptr, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00\x04\x40", 19);
		return 19;
	case HASH_SHA3_384:
		memcpy(ptr, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00\x04\x40", 19);
		return 19;
	case HASH_SHA3_512:
		memcpy(ptr, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00\x04\x40", 19);
		return 19;
	default:
		return 0;
	}
}

static inline rsa_pkcs_ctx *rsa_pkcs_new(rsa_key *key, hash_ctx *hctx)
{
	rsa_pkcs_ctx *rctx = NULL;
	uint32_t der_size = 0;

	// Parameter checking
	if (key == NULL)
	{
		return NULL;
	}

	if (hctx == NULL)
	{
		return NULL;
	}

	der_size = get_digest_info_size(hctx->algorithm);

	if (der_size == 0)
	{
		return NULL;
	}

	if ((key->bits / 8) < der_size + 11)
	{
		return NULL;
	}

	rctx = (rsa_pkcs_ctx *)malloc(sizeof(rsa_pkcs_ctx));

	if (rctx == NULL)
	{
		return NULL;
	}

	rctx->key = key;
	rctx->hctx = hctx;
	rctx->digest_info_size = der_size;

	hash_reset(rctx->hctx);

	return rctx;
}

static inline void rsa_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx)
{
	rctx->key = key;
	rctx->hctx = hctx;
	rctx->digest_info_size = get_digest_info_size(hctx->algorithm);

	hash_reset(rctx->hctx);
}

rsa_pkcs_ctx *rsa_sign_pkcs_new(rsa_key *key, hash_ctx *hctx)
{
	return rsa_pkcs_new(key, hctx);
}

void rsa_sign_pkcs_delete(rsa_pkcs_ctx *rctx)
{
	memset(rctx, 0, sizeof(rsa_pkcs_ctx));
	free(rctx);
}

void rsa_sign_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx)
{
	rsa_pkcs_reset(rctx, key, hctx);
}

void rsa_sign_pkcs_update(rsa_pkcs_ctx *rctx, void *message, size_t size)
{
	hash_update(rctx->hctx, message, size);
}

rsa_signature *rsa_sign_pkcs_final(rsa_pkcs_ctx *rctx, void *signature, size_t size)
{
	rsa_signature *rsign = signature;

	// Sizes
	size_t key_size = rctx->key->bits / 8;
	size_t hash_size = rctx->hctx->hash_size;
	size_t digest_info_size = rctx->digest_info_size;
	size_t em_size = key_size;
	size_t ps_size = key_size - digest_info_size - 3;
	size_t signature_size = sizeof(rsa_signature) + key_size;

	size_t ps_offset = 2;
	size_t digest_info_offset = em_size - digest_info_size;
	size_t hash_offset = em_size - hash_size;

	byte_t *em = NULL;

	// Allocate for the signature
	if (rsign == NULL)
	{
		rsign = malloc(signature_size);
	}
	else
	{
		if (size < signature_size)
		{
			return NULL;
		}
	}

	if (rsign == NULL)
	{
		return NULL;
	}

	bignum_ctx_start(rctx->key->bctx, em_size);

	// Allocate for EM
	em = bignum_ctx_allocate_raw(rctx->key->bctx, em_size);
	memset(em, 0, em_size);

	em[0] = 0x00;
	em[1] = 0x01;

	memset(em + ps_offset, 0xFF, ps_size);

	// Finish Hash
	get_digest_info_prefix(rctx->hctx->algorithm, em + digest_info_offset);
	hash_final(rctx->hctx, em + hash_offset, hash_size);

	// Generate the signature.
	memset(rsign, 0, sizeof(rsa_signature) + key_size);
	rsign->size = key_size;
	rsign->sign = (byte_t *)rsign + sizeof(rsa_signature);

	rsign->bits = rsa_private_encrypt(rctx->key, em, em_size, rsign->sign, rsign->size);

	bignum_ctx_end(rctx->key->bctx);

	if (rsign->bits < 0)
	{
		free(rsign);
		return NULL;
	}

	return rsign;
}

rsa_signature *rsa_sign_pkcs(rsa_key *key, hash_ctx *hctx, void *message, size_t message_size, void *signature, size_t signature_size)
{
	rsa_pkcs_ctx *rctx = rsa_sign_pkcs_new(key, hctx);
	rsa_signature *rsign = NULL;

	if (rctx == NULL)
	{
		return NULL;
	}

	rsa_sign_pkcs_update(rctx, message, message_size);
	rsign = rsa_sign_pkcs_final(rctx, signature, signature_size);

	rsa_sign_pkcs_delete(rctx);

	return rsign;
}

rsa_pkcs_ctx *rsa_verify_pkcs_new(rsa_key *key, hash_ctx *hctx)
{
	return rsa_pkcs_new(key, hctx);
}

void rsa_verify_pkcs_delete(rsa_pkcs_ctx *rctx)
{
	memset(rctx, 0, sizeof(rsa_pkcs_ctx));
	free(rctx);
}

void rsa_verify_pkcs_reset(rsa_pkcs_ctx *rctx, rsa_key *key, hash_ctx *hctx)
{
	rsa_pkcs_reset(rctx, key, hctx);
}

void rsa_verify_pkcs_update(rsa_pkcs_ctx *rctx, void *message, size_t size)
{
	hash_update(rctx->hctx, message, size);
}

uint32_t rsa_verify_pkcs_final(rsa_pkcs_ctx *rctx, rsa_signature *rsign)
{
	int32_t status = 0;

	// Sizes
	size_t key_size = rctx->key->bits / 8;
	size_t hash_size = rctx->hctx->hash_size;
	size_t digest_info_size = rctx->digest_info_size;
	size_t em_size = key_size;
	size_t ps_size = key_size - digest_info_size - 3;

	size_t ps_offset = 2;
	size_t digest_info_offset = em_size - digest_info_size;
	size_t hash_offset = em_size - hash_size;

	size_t ctx_size = 2 * em_size;

	byte_t *em = NULL;
	byte_t *emp = NULL;

	bignum_ctx_start(rctx->key->bctx, ctx_size);

	// Allocate for EM'
	emp = bignum_ctx_allocate_raw(rctx->key->bctx, em_size);
	memset(emp, 0, em_size);

	em[0] = 0x00;
	em[1] = 0x01;

	memset(em + ps_offset, 0xFF, ps_size);

	// Finish Hash
	get_digest_info_prefix(rctx->hctx->algorithm, em + digest_info_offset);
	hash_final(rctx->hctx, emp + hash_offset, hash_size);

	// Allocate for EM
	em = bignum_ctx_allocate_raw(rctx->key->bctx, em_size);

	// Decryption
	rsa_public_decrypt(rctx->key, rsign->sign, rsign->size, em, em_size);

	if (memcmp(em, emp, em_size) != 0)
	{
		goto end;
	}

	status = 1;

end:
	bignum_ctx_end(rctx->key->bctx);
	return status;
}

uint32_t rsa_verify_pkcs(rsa_key *key, hash_ctx *hctx, rsa_signature *rsign, void *message, size_t size)
{
	int32_t status = 0;
	rsa_pkcs_ctx *rctx = rsa_verify_pkcs_new(key, hctx);

	if (rctx == NULL)
	{
		return status;
	}

	rsa_verify_pkcs_update(rctx, message, size);
	status = rsa_verify_pkcs_final(rctx, rsign);

	rsa_verify_pkcs_delete(rctx);

	return status;
}
