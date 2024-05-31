/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <intrin.h>
#include <bignum.h>
#include <minmax.h>

void bignum_add_words(bignum_t *r, bignum_t *a, bignum_t *b)
{
	uint64_t count = MIN(a->bits, b->bits) / 64;
	uint64_t pos = 0;
	uint8_t carry = 0;
	bignum_t *c = NULL;

	for (pos = 0; pos < count; ++pos)
	{
		carry = _addcarryx_u64(carry, a->qwords[pos], b->qwords[pos], r->qwords[pos]);
	}

	count = MAX(a->bits, b->bits) / 64;

	if (a->bits >= b->bits)
	{
		c = a;
	}
	else
	{
		c = b;
	}

	for (; pos < count; ++pos)
	{
		carry = _addcarryx_u64(0, c->qwords[pos], carry, r->qwords[pos]);
	}

	if(carry)
	{
		r->qwords[count] = 1;
	}
}
