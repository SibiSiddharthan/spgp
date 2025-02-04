/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <bignum-internal.h>

static uint32_t miller_rabin_primality_test(bignum_ctx *bctx, bignum_t *n, uint32_t count)
{
	uint32_t k = 0;
	bignum_t *nm1 = NULL, *q = NULL, *a = NULL, *d = NULL;

	nm1 = bignum_ctx_allocate_bignum(bctx, n->bits);
	q = bignum_ctx_allocate_bignum(bctx, n->bits);
	a = bignum_ctx_allocate_bignum(bctx, n->bits);
	d = bignum_ctx_allocate_bignum(bctx, n->bits);

	bignum_copy(nm1, n);
	bignum_usub_word(nm1, nm1, 1);

	k = bignum_ctz(nm1);
	q = bignum_rshift(q, nm1, k);

	for (uint32_t i = 0; i < count; ++i)
	{
		a = bignum_rand_max(NULL, a, n);
		d = bignum_gcd(bctx, d, a, n);

		// Check if greater than 1
		if (d->bits > 1)
		{
			return 0;
		}

		a = bignum_modexp(bctx, a, a, q, n);

		if (a->bits == 1 || bignum_cmp(nm1, a) == 0)
		{
			// a = 1 mod n or -1 mod n
			goto next_witness;
		}

		for (uint32_t j = 1; j < k; ++j)
		{
			a = bignum_modsqr(bctx, a, a, n);

			if (bignum_cmp(nm1, a) == 0)
			{
				// a = -1 mod n
				goto next_witness;
			}

			if (a->bits == 1)
			{
				// a = 1 mod n
				return 0;
			}
		}

		return 0;

	next_witness:
		continue;
	}

	return 1;
}

uint32_t bignum_is_probable_prime(bignum_ctx *bctx, bignum_t *bn)
{
	uint32_t status;
	size_t ctx_size = 0;

	bignum_ctx *obctx = bctx;

	// Handle prime numbers upto 127
	if (bn->bits <= 7)
	{
		switch (bn->words[0])
		{
		case 2:
		case 3:
		case 5:
		case 7:
		case 11:
		case 13:
		case 17:
		case 19:
		case 23:
		case 29:
		case 31:
		case 37:
		case 41:
		case 43:
		case 47:
		case 53:
		case 59:
		case 61:
		case 67:
		case 71:
		case 73:
		case 79:
		case 83:
		case 89:
		case 97:
		case 101:
		case 103:
		case 107:
		case 109:
		case 113:
		case 127:
			return 1;
		}

		return 0;
	}

	// Check zero
	if (bn->bits == 0)
	{
		return 0;
	}

	// Check if even
	if (bn->words[0] % 2 == 0)
	{
		return 0;
	}

	// Check divisibility by 5
	if (bn->words[0] % 5 == 0)
	{
		return 0;
	}

	// 4 Temporaries
	ctx_size = 4 * bignum_size(bn->bits);

	if (obctx == NULL)
	{

		bctx = bignum_ctx_new(ctx_size);

		if (bctx == NULL)
		{
			return -1;
		}
	}

	bignum_ctx_start(bctx, ctx_size);

	status = miller_rabin_primality_test(bctx, bn, 80);

	bignum_ctx_end(bctx);

	if (obctx == NULL)
	{
		bignum_ctx_delete(bctx);
	}

	return status;
}
