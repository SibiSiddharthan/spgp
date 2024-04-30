/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>
#include <bignum.h>
#include <minmax.h>

static void bignum_add_qwords(bignum_t *r, bignum_t *a, bignum_t *b)
{
	uint64_t count = MIN(a->size, b->size) / 8;
	uint64_t pos = 0;
	uint64_t carry = 0;
	bignum_t *c = NULL;

	for (pos = 0; pos < count; ++pos)
	{
		r->qwords[pos] = a->qwords[pos] + b->qwords[pos] + carry;
		carry = (r->qwords[pos] < a->qwords[pos]) || (r->qwords[pos] < b->qwords[pos]);
	}

	count = MAX(a->size, b->size) / 8;

	if (a->size >= b->size)
	{
		c = a;
	}
	else
	{
		c = b;
	}

	for (; pos < count; ++pos)
	{
		r->qwords[pos] = c->qwords[pos] + carry;
		carry = (r->qwords[pos] < c->qwords[pos]);
	}
}

bignum_t *bignum_add(bignum_t *a, bignum_t *b)
{
	bignum_t *result = NULL;
	uint32_t bits = MAX(a->bits, b->bits) + 1;

	result = bignum_new(bits);
	bignum_add_qwords(result, a, b);

	return result;
}
