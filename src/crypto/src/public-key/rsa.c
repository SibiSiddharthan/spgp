/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <byteswap.h>

#include <bignum.h>
#include <rsa.h>

bignum_t *rsa_public_encrypt(rsa_key *key, bignum_t *plain)
{
	if (key->bits < plain->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->e == NULL)
	{
		return NULL;
	}

	return bignum_modexp(plain, key->e, key->n);
}

bignum_t *rsa_public_decrypt(rsa_key *key, bignum_t *cipher)
{
	if (key->bits < cipher->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->e == NULL)
	{
		return NULL;
	}

	return bignum_modexp(cipher, key->e, key->n);
}

bignum_t *rsa_private_encrypt(rsa_key *key, bignum_t *plain)
{
	if (key->bits < plain->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->d == NULL)
	{
		return NULL;
	}

	return bignum_modexp(plain, key->d, key->n);
}

bignum_t *rsa_private_decrypt(rsa_key *key, bignum_t *cipher)
{
	if (key->bits < cipher->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->d == NULL)
	{
		return NULL;
	}

	return bignum_modexp(cipher, key->d, key->n);
}

static inline void xor_bytes(byte_t *a, byte_t *b, size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		a[i] ^= b[i];
	}
}

static buffer_t *MGF(mgf *mask, size_t size)
{
	buffer_t *output = NULL;
	hash_ctx *hctx = mask->hash;
	size_t accumulated = 0;
	uint32_t counter = 0;

	if (size > (1ull << 32))
	{
		return NULL;
	}

	output = malloc(sizeof(buffer_t) + size + hctx->hash_size); // Extra

	if (output == NULL)
	{
		return NULL;
	}

	output->data = (byte_t *)output + sizeof(buffer_t);
	output->size = size;
	output->capacity = size + hctx->hash_size;

	while (accumulated < size)
	{
		counter = BSWAP_32(counter);

		hash_update(hctx, mask->seed->data, mask->seed->size);
		hash_update(hctx, &counter, 4);
		hash_final(hctx, output->data + accumulated, output->capacity - accumulated);
		hash_reset(hctx);

		accumulated += hctx->hash_size;

		counter = BSWAP_32(counter);
		++counter;
	}

	// Truncate if necessary.
	if (accumulated > size)
	{
		memset(output->data + size, 0, accumulated - size);
	}

	return output;
}

int32_t rsa_encrypt_oaep(rsa_key *key, buffer_t *plaintext, buffer_t *label, buffer_t *ciphertext, oaep_options *options)
{
	int32_t status = -1;
	size_t key_size = key->bits / 8;
	size_t hash_size = options->hash->hash_size;
	hash_ctx *hctx = options->hash;
	mgf *mask = options->mask;

	size_t ps_size = key_size - (plaintext->size + (2 * hash_size) + 2);
	size_t db_size = key_size - (hash_size + 1);
	size_t em_size = key_size;
	size_t pos = 0;

	buffer_t empty_label = {0};
	byte_t hash[64] = {0};
	byte_t seed[64] = {0};
	buffer_t bseed = {seed, hash_size, 64};

	buffer_t *mseed = NULL;
	buffer_t *mdb = NULL;
	byte_t *db = NULL;
	byte_t *em = NULL;

	bignum_t *p = NULL, *c = NULL;

	// Zero length label.
	if (label == NULL)
	{
		label = &empty_label;
	}

	// Length checking.
	if (plaintext->size > (key_size - (2 * hash_size) - 2))
	{
		return -1;
	}

	if (ciphertext->capacity < key_size)
	{
		return -1;
	}

	hash_update(hctx, label->data, label->size);
	hash_final(hctx, hash, hctx->hash_size);

	db = (byte_t *)malloc(db_size);
	em = (byte_t *)malloc(em_size);

	if (db == NULL || em == NULL)
	{
		goto cleanup;
	}

	// Construct DB.
	pos = 0;

	memcpy(db, hash, hctx->hash_size);
	pos += hctx->hash_size;

	memset(db + pos, 0, ps_size);
	pos += ps_size;

	db[pos++] = 0x01;

	memcpy(db + pos, plaintext->data, plaintext->size);
	pos += plaintext->size;

	// Construct Masked DB.
	// TODO random seed
	mask->seed = &bseed;
	mdb = MGF(mask, db_size);

	if (mdb == NULL)
	{
		goto cleanup;
	}

	xor_bytes(mdb->data, db, db_size);

	// Construct Masked Seed.
	mask->seed = mdb;
	mseed = MGF(mask, hash_size);

	if (mseed == NULL)
	{
		goto cleanup;
	}

	xor_bytes(mseed->data, bseed.data, hash_size);

	// Construct EM.
	pos = 0;

	em[pos++] = 0x00;

	memcpy(em + pos, mseed->data, hash_size);
	pos += hash_size;

	memcpy(em + pos, mdb->data, db_size);
	pos += db_size;

	// Encryption
	p = bignum_new(em_size * 8);

	if (p == NULL)
	{
		goto cleanup;
	}
	bignum_set_bytes_be(p, em, em_size);

	c = rsa_public_encrypt(key, p);

	if (c == NULL)
	{
		goto cleanup;
	}

	bignum_get_bytes_be(c, ciphertext->data, ciphertext->capacity);

	status = 0;

cleanup:
	free(mseed);
	free(db);
	free(mdb);
	free(em);
	bignum_secure_free(p);
	bignum_secure_free(c);

	return status;
}

int32_t rsa_decrypt_oaep(rsa_key *key, buffer_t *ciphertext, buffer_t *label, buffer_t *plaintext, oaep_options *options)
{
	int32_t status = -1;
	size_t key_size = key->bits / 8;
	size_t hash_size = options->hash->hash_size;
	hash_ctx *hctx = options->hash;
	mgf *mask = options->mask;

	size_t db_size = key_size - (hash_size + 1);
	size_t em_size = key_size;
	size_t pos = 0;

	buffer_t empty_label = {0};
	byte_t hash[64] = {0};

	buffer_t mseed = {0};
	buffer_t mdb = {0};
	buffer_t *seedm = NULL;
	buffer_t *dbm = NULL;
	byte_t *em = NULL;

	bignum_t *p = NULL, *c = NULL;

	// Zero length label.
	if (label == NULL)
	{
		label = &empty_label;
	}

	// Length checking.
	if (ciphertext->size != key_size)
	{
		return -1;
	}

	if (key_size < (2 * hash_size + 2))
	{
		return -1;
	}

	hash_update(hctx, label->data, label->size);
	hash_final(hctx, hash, hctx->hash_size);

	em = (byte_t *)malloc(em_size);

	if (em == NULL)
	{
		goto cleanup;
	}

	// Decryption
	c = bignum_new(key_size);

	if (c == NULL)
	{
		goto cleanup;
	}

	bignum_set_bytes_be(c, ciphertext->data, ciphertext->size);

	p = rsa_private_decrypt(key, c);

	if (p == NULL)
	{
		goto cleanup;
	}

	bignum_get_bytes_be(p, em, em_size);

	if (em[0] != 0x00)
	{
		goto cleanup;
	}

	mseed.data = &em[1];
	mseed.size = hash_size;
	mseed.capacity = hash_size;

	mdb.data = &em[1 + hash_size];
	mdb.size = db_size;
	mdb.capacity = db_size;

	// Construct DB.
	mask->seed = &mdb;
	seedm = MGF(mask, hash_size);

	xor_bytes(seedm->data, mseed.data, hash_size);

	mask->seed = seedm;
	dbm = MGF(mask, db_size);

	xor_bytes(dbm->data, mdb.data, db_size);

	if (memcmp(dbm->data, hash, hash_size) != 0)
	{
		goto cleanup;
	}

	for (pos = hash_size;; ++pos)
	{
		if (pos == dbm->size)
		{
			goto cleanup;
		}

		if (dbm->data[pos] == 0x00)
		{
			continue;
		}

		if (dbm->data[pos] == 0x01)
		{
			++pos;
			break;
		}
	}

	if (plaintext->capacity < (dbm->size - pos))
	{
		goto cleanup;
	}

	plaintext->size = dbm->size - pos;
	memcpy(plaintext->data, &dbm->data[pos], plaintext->size);

	status = 0;

cleanup:
	free(em);
	free(seedm);
	free(dbm);
	bignum_secure_free(p);
	bignum_secure_free(c);

	return status;
}

int32_t rsa_encrypt_pkcs(rsa_key *key, buffer_t *plaintext, buffer_t *ciphertext)
{
	int32_t status = -1;
	size_t key_size = key->bits / 8;
	size_t ps_size = key_size - plaintext->size - 3;
	size_t em_size = key_size;

	byte_t *ps = NULL;
	byte_t *em = NULL;

	size_t pos = 0;

	bignum_t *p = NULL, *c = NULL;

	// Length checking
	if (plaintext->size > key_size - 11)
	{
		return -1;
	}

	if (ciphertext->capacity < key_size)
	{
		return -1;
	}

	ps = (byte_t *)malloc(ps_size);

	if (ps == NULL)
	{
		goto cleanup;
	}

	// TODO randomize ps
	em = (byte_t *)malloc(em_size);

	if (em == NULL)
	{
		goto cleanup;
	}

	// Construct EM
	em[pos++] = 0x00;
	em[pos++] = 0x02;

	memcpy(em + pos, ps, ps_size);
	pos += ps_size;

	em[pos++] = 0x00;
	memcpy(em + pos, plaintext->data, plaintext->size);
	pos += ps_size;

	// Encryption
	p = bignum_new(em_size * 8);

	if (p == NULL)
	{
		goto cleanup;
	}

	bignum_set_bytes_be(p, em, em_size);

	c = rsa_public_encrypt(key, p);

	if (c == NULL)
	{
		goto cleanup;
	}

	bignum_get_bytes_be(c, ciphertext->data, ciphertext->capacity);

	status = 0;

cleanup:
	free(ps);
	free(em);
	bignum_secure_free(p);
	bignum_secure_free(c);

	return status;
}

int32_t rsa_decrypt_pkcs(rsa_key *key, buffer_t *ciphertext, buffer_t *plaintext)
{
	int32_t status = -1;
	size_t key_size = key->bits / 8;
	size_t em_size = key_size;
	size_t ps_size = 0;

	byte_t *em = NULL;

	size_t pos = 0;

	bignum_t *p = NULL, *c = NULL;

	// Length checking.
	if (ciphertext->size != key_size)
	{
		return -1;
	}

	em = (byte_t *)malloc(em_size);

	if (em == NULL)
	{
		return -1;
	}

	// Decryption
	c = bignum_new(key_size);

	if (c == NULL)
	{
		goto cleanup;
	}

	bignum_set_bytes_be(c, ciphertext->data, ciphertext->size);

	p = rsa_private_decrypt(key, c);

	if (p == NULL)
	{
		goto cleanup;
	}

	bignum_get_bytes_be(p, em, em_size);

	// Verification
	if (em[0] != 0x00 || em[1] != 0x02)
	{
		goto cleanup;
	}

	for (pos = 2;; ++pos)
	{
		if (pos == key_size)
		{
			goto cleanup;
		}

		if (em[pos] == 0x00)
		{
			++pos;
			break;
		}

		++ps_size;
	}

	if (ps_size < 8)
	{
		goto cleanup;
	}

	if (plaintext->capacity < key_size - pos)
	{
		goto cleanup;
	}

	plaintext->size = key_size - pos;
	memcpy(plaintext->data, em + pos, plaintext->size);

	status = 0;

cleanup:
	free(em);
	bignum_secure_free(p);
	bignum_secure_free(c);

	return status;
}

static inline rsa_pss_ctx *rsa_pss_init(rsa_key *key, hash_ctx *hctx, mgf *mask, size_t salt_size)
{
	rsa_pss_ctx *rctx = (rsa_pss_ctx *)malloc(sizeof(rsa_pss_ctx));

	if (rctx == NULL)
	{
		return NULL;
	}

	rctx->key = key;
	rctx->hctx = hctx;
	rctx->mask = mask;
	rctx->salt_size = salt_size;

	return rctx;
}

rsa_pss_ctx *rsa_sign_pss_init(rsa_key *key, hash_ctx *hctx, mgf *mask, size_t salt_size)
{
	return rsa_pss_init(key, hctx, mask, salt_size);
}

void rsa_sign_pss_free(rsa_pss_ctx *rctx)
{
	memset(rctx, 0, sizeof(rsa_pss_ctx));
	free(rctx);
}

void rsa_sign_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx, mgf *mask)
{
	rctx->key = key;
	rctx->hctx = hctx;
	rctx->mask = mask;
}

void rsa_sign_pss_update(rsa_pss_ctx *rctx, void *message, size_t size)
{
	hash_update(rctx->hctx, message, size);
}

rsa_signature *rsa_sign_pss_final(rsa_pss_ctx *rctx)
{
	size_t key_size = rctx->key->bits / 8;
	size_t hash_size = rctx->hctx->hash_size;
	size_t salt_size = rctx->salt_size;

	rsa_signature *rsign = NULL;
	byte_t hash[MAX_HASH_SIZE] = {0};
	byte_t hashp[MAX_HASH_SIZE] = {0};
	byte_t salt[64] = {0};

	size_t mp_size = 8 + hash_size + salt_size;
	size_t ps_size = key_size - (salt_size + hash_size + 2);
	size_t db_size = key_size - (hash_size + 1);
	size_t em_size = key_size;

	buffer_t bhashp = {hashp, hash_size, MAX_HASH_SIZE};
	buffer_t *mdb = NULL;

	byte_t *mp = NULL;
	byte_t *db = NULL;
	byte_t *em = NULL;

	bignum_t *m = NULL;
	bignum_t *s = NULL;

	size_t pos = 0;

	if (key_size < hash_size + salt_size + 2)
	{
		return NULL;
	}

	hash_final(rctx->hctx, hash, hash_size);
	hash_reset(rctx->hctx);

	// TODO generate random salt

	// Construct M'
	pos = 0;
	mp = (byte_t *)malloc(mp_size);

	if (mp == NULL)
	{
		goto cleanup;
	}

	memset(mp, 0, 8);
	pos += 8;

	memcpy(mp + pos, hash, hash_size);
	pos += hash_size;

	if (salt_size > 0)
	{
		memcpy(mp + pos, salt, salt_size);
		pos += salt_size;
	}

	hash_update(rctx->hctx, mp, mp_size);
	hash_final(rctx->hctx, hashp, hash_size);

	// Construct DB
	pos = 0;
	db = (byte_t *)malloc(db_size);

	if (db == NULL)
	{
		goto cleanup;
	}

	memset(db, 0, ps_size);
	pos += ps_size;

	db[pos++] = 0x01;

	if (salt_size > 0)
	{
		memcpy(db + pos, salt, salt_size);
		pos += salt_size;
	}

	rctx->mask->seed = &bhashp;
	mdb = MGF(rctx->mask, db_size);

	xor_bytes(db, mdb->data, db_size);

	// Construct EM
	pos = 0;
	em = (byte_t *)malloc(em_size);

	if (em == NULL)
	{
		goto cleanup;
	}

	memcpy(em, db, db_size);
	pos += db_size;

	memcpy(em + pos, hashp, hash_size);
	pos += hash_size;

	em[pos++] = 0xBC;

	// Signature
	m = bignum_new(em_size * 8);

	if (m == NULL)
	{
		goto cleanup;
	}

	bignum_set_bytes_be(m, em, em_size);

	s = rsa_private_encrypt(rctx->key, m);

	if (s == NULL)
	{
		goto cleanup;
	}

	rsign = (rsa_signature *)malloc(key_size + 8);

	if (rsign == NULL)
	{
		goto cleanup;
	}

	rsign->size = key_size;
	bignum_get_bytes_be(s, rsign->sign, key_size);

cleanup:
	free(mp);
	free(db);
	free(em);
	bignum_secure_free(m);
	bignum_secure_free(s);

	return rsign;
}

rsa_signature *rsa_sign_pss(rsa_key *key, hash_ctx *hctx, mgf *mask, size_t salt_size, void *message, size_t size)
{
	rsa_pss_ctx *rctx = rsa_sign_pss_init(key, hctx, mask, salt_size);
	rsa_signature *rsign = NULL;

	if (rctx == NULL)
	{
		return NULL;
	}

	rsa_sign_pss_update(rctx, message, size);
	rsign = rsa_sign_pss_final(rctx);

	rsa_sign_pss_free(rctx);

	return rsign;
}

rsa_pss_ctx *rsa_verify_pss_init(rsa_key *key, hash_ctx *hctx, mgf *mask, size_t salt_size)
{
	return rsa_pss_init(key, hctx, mask, salt_size);
}

void rsa_verify_pss_free(rsa_pss_ctx *rctx)
{
	memset(rctx, 0, sizeof(rsa_pss_ctx));
	free(rctx);
}

void rsa_verify_pss_reset(rsa_pss_ctx *rctx, rsa_key *key, hash_ctx *hctx, mgf *mask)
{
	rctx->key = key;
	rctx->hctx = hctx;
	rctx->mask = mask;
}

void rsa_verify_pss_update(rsa_pss_ctx *rctx, void *message, size_t size)
{
	hash_update(rctx->hctx, message, size);
}

int32_t rsa_verify_pss_final(rsa_pss_ctx *rctx, rsa_signature *rsign)
{
	int32_t status = -1;

	size_t key_size = rctx->key->bits / 8;
	size_t hash_size = rctx->hctx->hash_size;
	size_t salt_size = rctx->salt_size;

	byte_t hash[MAX_HASH_SIZE] = {0};
	byte_t hashp[MAX_HASH_SIZE] = {0};

	size_t mp_size = 8 + hash_size + salt_size;
	size_t ps_size = key_size - (salt_size + hash_size + 2);
	size_t db_size = key_size - (hash_size + 1);
	size_t em_size = key_size;

	buffer_t bhashp = {NULL, hash_size, MAX_HASH_SIZE};
	buffer_t *dbm = NULL;

	byte_t *mp = NULL;
	byte_t *mdb = NULL;
	byte_t *em = NULL;

	bignum_t *m = NULL;
	bignum_t *s = NULL;

	size_t pos = 0;

	if (rsign->size != key_size)
	{
		return -1;
	}

	if (key_size < hash_size + salt_size + 2)
	{
		return -1;
	}

	em = (byte_t *)malloc(em_size);

	if (em == NULL)
	{
		goto cleanup;
	}

	// Verification
	s = bignum_new(key_size);

	if (s == NULL)
	{
		goto cleanup;
	}

	bignum_set_bytes_be(s, rsign->sign, rsign->size);

	m = rsa_public_decrypt(rctx->key, s);

	if (m == NULL)
	{
		goto cleanup;
	}

	bignum_get_bytes_be(m, em, em_size);

	if (em[em_size - 1] != 0xBC)
	{
		goto cleanup;
	}

	mdb = em;
	bhashp.data = em + db_size;

	rctx->mask->seed = &bhashp;
	dbm = MGF(rctx->mask, db_size);

	xor_bytes(mdb, dbm->data, db_size);

	for (size_t i = 0; i < ps_size; ++i)
	{
		if (mdb[i] != 0x00)
		{
			goto cleanup;
		}
	}

	hash_final(rctx->hctx, hash, hash_size);
	hash_reset(rctx->hctx);

	// Construct M'
	pos = 0;
	mp = (byte_t *)malloc(mp_size);

	if (mp == NULL)
	{
		goto cleanup;
	}

	memset(mp, 0, 8);
	pos += 8;

	memcpy(mp + pos, hash, hash_size);
	pos += hash_size;

	if (salt_size > 0)
	{
		memcpy(mp + pos, mdb + ps_size, salt_size);
		pos += salt_size;
	}

	hash_update(rctx->hctx, mp, mp_size);
	hash_final(rctx->hctx, hashp, hash_size);

	if (memcmp(hashp, bhashp.data, hash_size) != 0)
	{
		goto cleanup;
	}

	status = 0;

cleanup:
	free(mp);
	free(em);
	bignum_secure_free(m);
	bignum_secure_free(s);

	return status;
}

int32_t rsa_verify_pss(rsa_key *key, hash_ctx *hctx, mgf *mask, size_t salt_size, void *message, size_t size, rsa_signature *rsign)
{
	int32_t status = -1;
	rsa_pss_ctx *rctx = rsa_verify_pss_init(key, hctx, mask, salt_size);

	if (rctx == NULL)
	{
		return status;
	}

	rsa_verify_pss_update(rctx, message, size);
	status = rsa_verify_pss_final(rctx, rsign);

	rsa_verify_pss_free(rctx);

	return status;
}
