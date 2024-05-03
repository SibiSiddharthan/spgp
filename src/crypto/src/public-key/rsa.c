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

	if (label->size > options->hash->max_input_size)
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
	bignum_set_bytes_be(p, em, em_size);

	c = rsa_public_encrypt(key, p);
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

	if (label->size > options->hash->max_input_size)
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
	bignum_set_bytes_be(c, ciphertext->data, ciphertext->size);

	p = rsa_private_decrypt(key, c);
	bignum_set_bytes_be(p, em, em_size);

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
