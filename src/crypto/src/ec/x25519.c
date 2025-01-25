/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <bignum-internal.h>
#include <x25519.h>
#include <drbg.h>

#include "curves/montgomery.h"

#include <xor.h>

#include <string.h>

#define GET_BIT(K, I) ((K[(I) / 8] >> (I) % 8) & 0x1)

#define CSWAP(swap, x, y)                                           \
	{                                                               \
		uintptr_t mask = 0 - swap;                                  \
		uintptr_t dummy = mask & ((uintptr_t)(x) ^ (uintptr_t)(y)); \
                                                                    \
		(x) = (void *)((uintptr_t)(x) ^ dummy);                     \
		(y) = (void *)((uintptr_t)(y) ^ dummy);                     \
	}

static void x25519_decode_scalar(byte_t k[X25519_OCTET_SIZE])
{
	// Set the 3 least significant bits of first byte to 0
	k[0] &= 248;

	// Set the most significant bit of the last byte to 0
	k[31] &= 127;

	// Set the second most significant bit of the last byte to 1
	k[31] |= 64;
}

void x25519(byte_t v[X25519_OCTET_SIZE], byte_t u[X25519_OCTET_SIZE], byte_t k[X25519_OCTET_SIZE])
{
	bignum_t p = {.bits = 255, .flags = 0, .resize = 0, .sign = 1, .size = X25519_OCTET_SIZE, .words = (bn_word_t *)curve25519_p_words};
	const uint32_t a24 = 121665;

	bignum_ctx *bctx = NULL;

	bignum_t *x1 = NULL, *x2 = NULL, *x3 = NULL;
	bignum_t *z2 = NULL, *z3 = NULL;
	bignum_t *pm2 = NULL, *t24 = NULL;

	bignum_t *a = NULL;
	bignum_t *b = NULL;
	bignum_t *c = NULL;
	bignum_t *d = NULL;
	bignum_t *e = NULL;

	bignum_t *aa = NULL;
	bignum_t *bb = NULL;
	bignum_t *da = NULL;
	bignum_t *cb = NULL;

	byte_t ucopy[X25519_OCTET_SIZE] = {0};
	byte_t kcopy[X25519_OCTET_SIZE] = {0};

	uintptr_t swap = 0;

	byte_t kt = 0;
	byte_t t = 0;

	size_t ctx_size = 16 * bignum_size(X25519_BITS);

	// Zero output
	memset(v, 0, X25519_OCTET_SIZE);

	// Initialize arena
	bctx = bignum_ctx_new(ctx_size + 128);

	if (bctx == NULL)
	{
		return;
	}

	bignum_ctx_start(bctx, ctx_size);

	x1 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	x2 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	x3 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);

	z2 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	z3 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);

	pm2 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	t24 = bignum_ctx_allocate_bignum(bctx, X25519_BITS);

	a = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	b = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	c = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	d = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	e = bignum_ctx_allocate_bignum(bctx, X25519_BITS);

	aa = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	bb = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	da = bignum_ctx_allocate_bignum(bctx, X25519_BITS);
	cb = bignum_ctx_allocate_bignum(bctx, X25519_BITS);

	// Decode u and k
	memcpy(ucopy, u, X25519_OCTET_SIZE);
	memcpy(kcopy, k, X25519_OCTET_SIZE);

	x25519_decode_scalar(ucopy);
	x25519_decode_scalar(kcopy);

	// Initialization
	bignum_set_bytes_le(x1, ucopy, X25519_OCTET_SIZE);
	bignum_set_word(x2, 1);
	bignum_copy(x3, x1);

	bignum_set_word(z2, 0);
	bignum_set_word(z3, 1);

	bignum_set_word(t24, a24);

	for (uint32_t i = 0; i < X25519_BITS; ++i)
	{
		t = X25519_BITS - (i + 1);
		kt = GET_BIT(kcopy, t);

		swap ^= kt;

		CSWAP(swap, x2, x3);
		CSWAP(swap, z2, z3);

		swap = kt;

		a = bignum_modadd(bctx, a, x2, z2, &p);
		aa = bignum_modsqr(bctx, aa, a, &p);
		b = bignum_modsub(bctx, b, x2, z2, &p);
		bb = bignum_modsqr(bctx, bb, b, &p);
		e = bignum_modsub(bctx, e, aa, bb, &p);
		c = bignum_modadd(bctx, c, x3, z3, &p);
		d = bignum_modsub(bctx, d, x3, z3, &p);
		da = bignum_modmul(bctx, da, d, a, &p);
		cb = bignum_modmul(bctx, cb, c, b, &p);

		x3 = bignum_modadd(bctx, x3, da, cb, &p);
		x3 = bignum_modsqr(bctx, x3, x3, &p);

		z3 = bignum_modsub(bctx, z3, da, cb, &p);
		z3 = bignum_modsqr(bctx, z3, z3, &p);
		z3 = bignum_modmul(bctx, z3, x1, z3, &p);

		x2 = bignum_modmul(bctx, x2, aa, bb, &p);

		z2 = bignum_copy(z2, e);
		z2 = bignum_modmul(bctx, z2, z2, t24, &p);
		z2 = bignum_modadd(bctx, z2, aa, z2, &p);
		z2 = bignum_modmul(bctx, z2, e, z2, &p);
	}

	CSWAP(swap, x2, x3);
	CSWAP(swap, z2, z3);

	bignum_copy(pm2, &p);
	bignum_usub_word(pm2, pm2, 2);

	x1 = bignum_modexp(bctx, x1, z2, pm2, &p);
	x1 = bignum_modmul(bctx, x1, x1, x2, &p);

	memcpy(v, x1->words, X25519_OCTET_SIZE);

	// Cleanup
	bignum_ctx_end(bctx);
	bignum_ctx_delete(bctx);
}

uint32_t x25519_key_generate(x25519_key *key)
{
	uint32_t result = 0;
	drbg_ctx *drbg = get_default_drbg();

	byte_t base[X25519_OCTET_SIZE] = {0};
	base[0] = 0x09;

	if (drbg == NULL)
	{
		return -1u;
	}

	result = drbg_generate(drbg, 0, "X25519 Key Generation", 21, key->private_key, X25519_OCTET_SIZE);

	if (result != X25519_OCTET_SIZE)
	{
		return -1u;
	}

	x25519(key->public_key, base, key->private_key);

	return 0;
}
