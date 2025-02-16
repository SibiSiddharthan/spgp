/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kas.h>
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
