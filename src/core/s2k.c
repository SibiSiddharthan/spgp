/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license->
   Refer to the LICENSE file at the root directory for details->
*/

#include <spgp.h>
#include <s2k.h>

#include <string.h>

uint32_t pgp_s2k_size(pgp_s2k *s2k)
{
	switch (s2k->id)
	{
	case pgp_simple_s2k:
		return 2;
	case pgp_salted_s2k:
		return 10;
	case pgp_iterated_s2k:
		return 11;
	case pgp_argon2:
		return 20;
	}
}

pgp_s2k *pgp_s2k_read(pgp_s2k *s2k, void *data, size_t size)
{
	byte_t *in = data;
	uint32_t pos = 0;

	if (size < 1)
	{
		return NULL;
	}

	// 1 octet id
	LOAD_8(&s2k->id, in + pos);
	pos += 1;

	switch (s2k->id)
	{
	case pgp_simple_s2k:
	{
		if (size < 2)
		{
			return NULL;
		}

		// 1 octet hash algorithm id
		LOAD_8(&s2k->simple_s2k.hash_id, in + pos);
		pos += 1;

		return s2k;
	}
	case pgp_salted_s2k:
	{
		if (size < 10)
		{
			return NULL;
		}

		// 1 octet hash algorithm id
		LOAD_8(&s2k->salted_s2k.hash_id, in + pos);
		pos += 1;

		// 8 octet salt
		LOAD_64(&s2k->salted_s2k.salt, in + pos);
		pos += 8;

		return s2k;
	}
	case pgp_iterated_s2k:
	{

		if (size < 11)
		{
			return NULL;
		}

		// 1 octet hash algorithm id
		LOAD_8(&s2k->iterated_s2k.hash_id, in + pos);
		pos += 1;

		// 8 octet salt
		LOAD_64(&s2k->iterated_s2k.salt, in + pos);
		pos += 8;

		// 1 octet iteration count
		LOAD_8(&s2k->iterated_s2k.count, in + pos);
		pos += 1;

		return s2k;
	}
	case pgp_argon2:
	{
		if (size < 20)
		{
			return NULL;
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

		return s2k;
	}
	default:
		return NULL;
	}
}

uint32_t pgp_s2k_write(pgp_s2k *s2k, void *ptr)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	switch (s2k->id)
	{
	case pgp_simple_s2k:
	{
		// 1 octet id
		LOAD_8(out + pos, &s2k->id);
		pos += 1;

		// 1 octet hash algorithm id
		LOAD_8(out + pos, &s2k->simple_s2k.hash_id);
		pos += 1;

		return pos;
	}
	case pgp_salted_s2k:
	{
		// 1 octet id
		LOAD_8(out + pos, &s2k->id);
		pos += 1;

		// 1 octet hash algorithm id
		LOAD_8(out + pos, &s2k->salted_s2k.hash_id);
		pos += 1;

		// 8 octet salt
		LOAD_64(out + pos, &s2k->salted_s2k.salt);
		pos += 8;

		return pos;
	}
	case pgp_iterated_s2k:
	{

		// 1 octet hash algorithm id
		LOAD_8(out + pos, &s2k->iterated_s2k.hash_id);
		pos += 1;

		// 8 octet salt
		LOAD_64(out + pos, &s2k->iterated_s2k.salt);
		pos += 8;

		// 1 octet iteration count
		LOAD_8(out + pos, &s2k->iterated_s2k.count);
		pos += 1;

		return pos;
	}
	case pgp_argon2:
	{
		// 1 octet id
		LOAD_8(out + pos, &s2k->id);
		pos += 1;

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
}
