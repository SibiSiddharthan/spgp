/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <ec.h>

#include <ptr.h>

#include <stdlib.h>
#include <string.h>

ec_point *ec_point_new(ec_group *eg)
{
	ec_point *point = NULL;
	uint32_t bits = eg->bits;

	point = malloc(sizeof(ec_point) + (2 * bignum_size(bits)));

	if (point == NULL)
	{
		return NULL;
	}

	memset(point, 0, sizeof(ec_point) + (2 * bignum_size(bits)));

	point->x = PTR_OFFSET(point, sizeof(ec_point));
	bignum_init(point->x, bignum_size(bits), bits);

	point->y = PTR_OFFSET(point, sizeof(ec_point) + bignum_size(bits));
	bignum_init(point->y, bignum_size(bits), bits);

	return point;
}

ec_point *ec_point_copy(ec_point *dst, ec_point *src)
{
	void *result = NULL;

	if (dst == src)
	{
		return dst;
	}

	result = bignum_copy(dst->x, src->x);

	if (result == NULL)
	{
		return NULL;
	}

	result = bignum_copy(dst->y, src->y);

	if (result == NULL)
	{
		return NULL;
	}

	return dst;
}

void ec_point_infinity(ec_group *g, ec_point *r)
{
	bignum_zero(r->x);
	bignum_zero(r->y);
}

void ec_point_delete(ec_point *ep)
{
	free(ep);
}
