/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license->
   Refer to the LICENSE file at the root directory for details->
*/

#include <pgp/pgp.h>
#include <pgp/s2k.h>
#include <pgp/algorithms.h>
#include <pgp/crypto.h>

#include <string.h>

uint32_t pgp_s2k_read(pgp_s2k *s2k, void *data, size_t size)
{
	byte_t *in = data;
	uint32_t pos = 0;

	if (size < 1)
	{
		return 0;
	}

	// 1 octet id
	LOAD_8(&s2k->id, in + pos);
	pos += 1;

	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
	{
		if (size < 2)
		{
			return 0;
		}

		// 1 octet hash algorithm id
		LOAD_8(&s2k->simple.hash_id, in + pos);
		pos += 1;

		return pos;
	}
	case PGP_S2K_SALTED:
	{
		if (size < 10)
		{
			return 0;
		}

		// 1 octet hash algorithm id
		LOAD_8(&s2k->salted.hash_id, in + pos);
		pos += 1;

		// 8 octet salt
		LOAD_64(&s2k->salted.salt, in + pos);
		pos += 8;

		return pos;
	}
	case PGP_S2K_ITERATED:
	{
		if (size < 11)
		{
			return 0;
		}

		// 1 octet hash algorithm id
		LOAD_8(&s2k->iterated.hash_id, in + pos);
		pos += 1;

		// 8 octet salt
		LOAD_64(&s2k->iterated.salt, in + pos);
		pos += 8;

		// 1 octet iteration count
		LOAD_8(&s2k->iterated.count, in + pos);
		pos += 1;

		return pos;
	}
	case PGP_S2K_ARGON2:
	{
		if (size < 20)
		{
			return 0;
		}

		// 16 octet salt
		memcpy(&s2k->argon2.salt, in + pos, 16);
		pos += 16;

		// 1 octet number of passes
		LOAD_8(&s2k->argon2.t, in + pos);
		pos += 1;

		// 1 octet degree of parallelism
		LOAD_8(&s2k->argon2.p, in + pos);
		pos += 1;

		// 1 octet memory size
		LOAD_8(&s2k->argon2.m, in + pos);
		pos += 1;

		return pos;
	}
	default:
		return 0;
	}
}

uint32_t pgp_s2k_write(pgp_s2k *s2k, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	// 1 octet id
	LOAD_8(out + pos, &s2k->id);
	pos += 1;

	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
	{
		// 1 octet hash algorithm id
		LOAD_8(out + pos, &s2k->simple.hash_id);
		pos += 1;

		return pos;
	}
	case PGP_S2K_SALTED:
	{
		// 1 octet hash algorithm id
		LOAD_8(out + pos, &s2k->salted.hash_id);
		pos += 1;

		// 8 octet salt
		LOAD_64(out + pos, &s2k->salted.salt);
		pos += 8;

		return pos;
	}
	case PGP_S2K_ITERATED:
	{
		// 1 octet hash algorithm id
		LOAD_8(out + pos, &s2k->iterated.hash_id);
		pos += 1;

		// 8 octet salt
		LOAD_64(out + pos, &s2k->iterated.salt);
		pos += 8;

		// 1 octet iteration count
		LOAD_8(out + pos, &s2k->iterated.count);
		pos += 1;

		return pos;
	}
	case PGP_S2K_ARGON2:
	{

		// 16 octet salt
		memcpy(out + pos, &s2k->argon2.salt, 16);
		pos += 16;

		// 1 octet number of passes
		LOAD_8(out + pos, &s2k->argon2.t);
		pos += 1;

		// 1 octet degree of parallelism
		LOAD_8(out + pos, &s2k->argon2.p);
		pos += 1;

		// 1 octet memory size
		LOAD_8(out + pos, &s2k->argon2.m);
		pos += 1;

		return pos;
	}
	}

	// Unreachable
	return 0;
}

pgp_s2k *pgp_s2k_simple_init(pgp_s2k *s2k, byte_t hash_id)
{
	s2k->id = PGP_S2K_SIMPLE;
	s2k->simple.hash_id = hash_id;

	return s2k;
}

pgp_s2k *pgp_s2k_salted_init(pgp_s2k *s2k, byte_t hash_id, byte_t salt[8])
{
	s2k->id = PGP_S2K_SALTED;
	s2k->salted.hash_id = hash_id;
	memcpy(&s2k->salted.salt, salt, 8);

	return s2k;
}

pgp_s2k *pgp_s2k_iterated_init(pgp_s2k *s2k, byte_t hash_id, byte_t salt[8], byte_t count)
{
	s2k->id = PGP_S2K_ITERATED;
	s2k->iterated.hash_id = hash_id;
	s2k->iterated.count = count;
	memcpy(&s2k->iterated.salt, salt, 8);

	return s2k;
}

pgp_s2k *pgp_s2k_argon2_init(pgp_s2k *s2k, byte_t salt[16], byte_t t, byte_t p, byte_t m)
{
	s2k->id = PGP_S2K_ARGON2;
	s2k->argon2.t = t;
	s2k->argon2.p = p;
	s2k->argon2.m = m;
	memcpy(&s2k->argon2.salt, salt, 16);

	return s2k;
}

static pgp_error_t s2k_simple_hash(pgp_hash_algorithms algorithm, void *password, uint32_t password_size, void *key, uint32_t key_size)
{
	pgp_error_t status = 0;
	pgp_hash_t *hctx = NULL;
	byte_t hash_size = pgp_hash_size(algorithm);

	uint32_t output = 0;
	uint32_t iteration = 0;

	status = pgp_hash_new(&hctx, algorithm);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	while (output < key_size)
	{
		for (uint32_t i = 0; i < iteration; ++i)
		{
			pgp_hash_update(hctx, "\x00", 1);
		}

		pgp_hash_update(hctx, password, password_size);
		pgp_hash_final(hctx, PTR_OFFSET(key, output), MIN(key_size - output, hash_size));

		pgp_hash_reset(hctx);

		output += MIN(key_size - output, hash_size);
	}

	pgp_hash_delete(hctx);

	return PGP_SUCCESS;
}

static pgp_error_t s2k_salted_hash(pgp_hash_algorithms algorithm, void *password, uint32_t password_size, byte_t salt[8], void *key,
								   uint32_t key_size)
{
	pgp_error_t status = 0;
	pgp_hash_t *hctx = NULL;
	byte_t hash_size = pgp_hash_size(algorithm);

	uint32_t output = 0;
	uint32_t iteration = 0;

	status = pgp_hash_new(&hctx, algorithm);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	while (output < key_size)
	{
		for (uint32_t i = 0; i < iteration; ++i)
		{
			pgp_hash_update(hctx, "\x00", 1);
		}

		pgp_hash_update(hctx, salt, 8);
		pgp_hash_update(hctx, password, password_size);
		pgp_hash_final(hctx, PTR_OFFSET(key, output), MIN(key_size - output, hash_size));

		pgp_hash_reset(hctx);

		output += MIN(key_size - output, hash_size);
	}

	pgp_hash_delete(hctx);

	return PGP_SUCCESS;
}

static pgp_error_t s2k_iterated_hash(pgp_hash_algorithms algorithm, void *password, uint32_t password_size, byte_t salt[8], uint32_t count,
									 void *key, uint32_t key_size)
{
	pgp_error_t status = 0;
	pgp_hash_t *hctx = NULL;
	byte_t hash_size = pgp_hash_size(algorithm);

	uint32_t output = 0;
	uint32_t iteration = 0;

	status = pgp_hash_new(&hctx, algorithm);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Atleast 1 full salt || password is hashed.
	if (count < (password_size + 16))
	{
		count = password_size + 16;
	}

	while (output < key_size)
	{
		uint32_t input = 0;

		for (uint32_t i = 0; i < iteration; ++i)
		{
			pgp_hash_update(hctx, "\x00", 1);
		}

		while (input < count)
		{
			pgp_hash_update(hctx, salt, MIN(count - input, 8));
			input += MIN(count - input, 8);

			pgp_hash_update(hctx, password, MIN(count - input, password_size));
			input += MIN(count - input, password_size);
		}

		pgp_hash_final(hctx, PTR_OFFSET(key, output), MIN(key_size - output, hash_size));

		pgp_hash_reset(hctx);

		output += MIN(key_size - output, hash_size);
	}

	pgp_hash_delete(hctx);

	return PGP_SUCCESS;
}

static pgp_error_t s2k_argon2_hash(void *password, uint32_t password_size, byte_t salt[16], uint32_t parallel, uint32_t memory,
								   uint32_t iterations, void *key, uint32_t key_size)
{
	if (pgp_argon2(password, password_size, salt, 16, parallel, memory, iterations, NULL, 0, NULL, 0, key, key_size) != key_size)
	{
		return PGP_ARGON2_HASH_ERROR;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_s2k_hash(pgp_s2k *s2k, void *password, uint32_t password_size, void *key, uint32_t key_size)
{
	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
		return s2k_simple_hash(s2k->simple.hash_id, password, password_size, key, key_size);
	case PGP_S2K_SALTED:
		return s2k_salted_hash(s2k->salted.hash_id, password, password_size, s2k->salted.salt, key, key_size);
	case PGP_S2K_ITERATED:
		return s2k_iterated_hash(s2k->iterated.hash_id, password, password_size, s2k->iterated.salt, IT_COUNT(s2k->iterated.count), key,
								 key_size);
	case PGP_S2K_ARGON2:
		return s2k_argon2_hash(password, password_size, s2k->argon2.salt, s2k->argon2.p, s2k->argon2.m, s2k->argon2.t, key, key_size);
	}

	// Unreachable
	return 0;
}
