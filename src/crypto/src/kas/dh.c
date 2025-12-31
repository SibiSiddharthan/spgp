/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kas.h>
#include <bitscan.h>

uint32_t ff_dh(dh_key *self_key, bignum_t *public_key, void *shared_secret, uint32_t size)
{
	uint32_t result = 0;

	bignum_t *r = NULL;
	bignum_t *pm1 = NULL;

	if (size < CEIL_DIV(self_key->group->p->bits, 8))
	{
		return 0;
	}

	r = bignum_new(self_key->group->p->bits);
	pm1 = bignum_new(self_key->group->p->bits);

	if (r == NULL || pm1 == NULL)
	{
		goto end;
	}

	r = bignum_modexp(self_key->group->bctx, r, public_key, self_key->x, self_key->group->p);
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

	uint32_t w = BSF_32(self_key->eg->cofactor);
	ec_point *r = NULL;
	bignum_t *d = NULL;

	if (size < CEIL_DIV(self_key->eg->bits, 8))
	{
		return 0;
	}

	r = ec_point_new(self_key->eg);
	d = bignum_new(self_key->eg->bits + w);

	if (r == NULL || d == NULL)
	{
		goto end;
	}

	d = bignum_copy(d, self_key->d);
	d = bignum_lshift(d, d, w);
	d = bignum_mod(self_key->eg->bctx, d, d, self_key->eg->n);

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
