/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kas.h>

uint32_t ff_dh(dh_key *self_key, bignum_t *public_key, void *shared_secret, uint32_t size)
{
	uint32_t result = 0;

	bignum_t *r = NULL;
	bignum_t *pm1 = NULL;

	if (size < CEIL_DIV(self_key->p_bits, 8))
	{
		return 0;
	}

	r = bignum_new(self_key->p_bits);
	pm1 = bignum_new(self_key->p_bits);

	if (r == NULL || pm1 == NULL)
	{
		goto end;
	}

	r = bignum_modexp(self_key->bctx, r, public_key, self_key->x, self_key->p);
	pm1 = bignum_usub_word(pm1, pm1, 1);

	if ((r->bits == 0) || bignum_cmp(r, pm1) == 0)
	{
		goto end;
	}

	result = bignum_get_bytes_be_padded(r, shared_secret, size);

end:
	bignum_delete(r);
	bignum_delete(pm1);

	return result;
}

uint32_t ec_dh(ec_key *self_key, ec_point *public_key, void *shared_secret, uint32_t size)
{
	uint32_t result = 0;

	ec_point *r = NULL;
	bignum_t *d = NULL;

	if (size < CEIL_DIV(self_key->eg->bits, 8))
	{
		return 0;
	}

	r = ec_point_new(self_key->eg);
	d = bignum_new(self_key->eg->bits);

	if (r == NULL || d == NULL)
	{
		goto end;
	}

	// TODO: Optimize this
	bignum_set_word(d, self_key->eg->cofactor);
	d = bignum_modmul(self_key->eg->bctx, d, d, self_key->d, self_key->eg->n);
	r = ec_point_multiply(self_key->eg, r, public_key, d);

	if (ec_point_is_identity(self_key->eg, r))
	{
		goto end;
	}

	result = bignum_get_bytes_be_padded(r->x, shared_secret, size);

end:
	ec_point_delete(r);
	bignum_delete(d);

	return result;
}
