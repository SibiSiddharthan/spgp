/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kas.h>
#include <bitscan.h>
#include <bignum-internal.h>

uint32_t ff_mqv(dh_key *self_static_key, bignum_t *self_ephemeral_private_key, bignum_t *self_ephemeral_public_key,
				bignum_t *static_pulbic_key, bignum_t *ephermal_public_key, void *shared_secret, uint32_t size)
{
	uint32_t result = 0;

	uint32_t w = CEIL_DIV(self_static_key->q->bits, 2);
	bignum_t *r = NULL, *s = NULL, *u = NULL, *v = NULL, *pm1 = NULL;

	uint32_t ctx_size = 4 * bignum_size(self_static_key->p_bits) + bignum_size(self_static_key->q_bits);

	bignum_ctx_start(self_static_key->bctx, ctx_size);

	u = bignum_ctx_allocate_bignum(self_static_key->bctx, self_static_key->p_bits);
	v = bignum_ctx_allocate_bignum(self_static_key->bctx, self_static_key->p_bits);
	r = bignum_ctx_allocate_bignum(self_static_key->bctx, self_static_key->p_bits);
	pm1 = bignum_ctx_allocate_bignum(self_static_key->bctx, self_static_key->p_bits);
	s = bignum_ctx_allocate_bignum(self_static_key->bctx, self_static_key->q_bits);

	u = bignum_copy(u, self_ephemeral_public_key);
	u = bignum_umod2p(u, w);
	u = bignum_set_bit(u, w);

	v = bignum_copy(v, ephermal_public_key);
	v = bignum_umod2p(v, w);
	v = bignum_set_bit(u, w);

	s = bignum_modmul(self_static_key->bctx, s, u, self_static_key->x, self_static_key->q);
	s = bignum_modadd(self_static_key->bctx, s, s, self_ephemeral_private_key, self_static_key->q);

	r = bignum_modexp(self_static_key->bctx, r, static_pulbic_key, v, self_static_key->p);
	r = bignum_modmul(self_static_key->bctx, r, r, v, self_static_key->p);
	r = bignum_modexp(self_static_key->bctx, r, r, s, self_static_key->p);

	pm1 = bignum_copy(pm1, self_static_key->p);
	pm1 = bignum_usub_word(pm1, pm1, 1);

	if ((r->bits == 0) || bignum_cmp(r, pm1) == 0)
	{
		goto end;
	}

	result = bignum_get_bytes_be_padded(r, shared_secret, size);

end:
	bignum_ctx_end(self_static_key->bctx);

	return result;
}

uint32_t ec_mqv(ec_key *self_static_key, bignum_t *self_ephemeral_private_key, ec_point *self_ephemeral_public_key,
				ec_point *static_pulbic_key, ec_point *ephermal_public_key, void *shared_secret, uint32_t size)
{
	uint32_t result = 0;

	uint32_t f = CEIL_DIV(self_static_key->eg->n->bits, 2);
	uint32_t g = BSF_32(self_static_key->eg->cofactor);
	bignum_t *s = NULL, *u = NULL, *v = NULL, *x = NULL, *y = NULL;
	ec_point r = {0};

	uint32_t ctx_size = 5 * bignum_size(self_static_key->eg->bits + 1);

	bignum_ctx_start(self_static_key->eg->bctx, ctx_size);

	u = bignum_ctx_allocate_bignum(self_static_key->eg->bctx, self_static_key->eg->bits + 1);
	v = bignum_ctx_allocate_bignum(self_static_key->eg->bctx, self_static_key->eg->bits + 1);
	s = bignum_ctx_allocate_bignum(self_static_key->eg->bctx, self_static_key->eg->bits + 1);
	x = bignum_ctx_allocate_bignum(self_static_key->eg->bctx, self_static_key->eg->bits + 1);
	y = bignum_ctx_allocate_bignum(self_static_key->eg->bctx, self_static_key->eg->bits + 1);

	u = bignum_copy(u, self_ephemeral_public_key->x);
	u = bignum_umod2p(u, f);
	u = bignum_set_bit(u, f);

	v = bignum_copy(v, ephermal_public_key->x);
	v = bignum_umod2p(v, f);
	v = bignum_set_bit(u, f);

	s = bignum_modmul(self_static_key->eg->bctx, s, u, self_static_key->d, self_static_key->eg->n);
	s = bignum_modadd(self_static_key->eg->bctx, s, s, self_ephemeral_private_key, self_static_key->eg->n);
	s = bignum_lshift(s, s, g);
	s = bignum_mod(self_static_key->eg->bctx, s, s, self_static_key->eg->n);

	r.x = x;
	r.y = y;

	ec_point_multiply(self_static_key->eg, &r, static_pulbic_key, v);
	ec_point_add(self_static_key->eg, &r, &r, ephermal_public_key);
	ec_point_multiply(self_static_key->eg, &r, &r, s);

	if (ec_point_is_identity(self_static_key->eg, &r))
	{
		goto end;
	}

	result = bignum_get_bytes_be_padded(r.x, shared_secret, size);

end:
	bignum_ctx_end(self_static_key->eg->bctx);

	return result;
}
