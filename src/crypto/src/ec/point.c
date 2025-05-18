/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ec.h>
#include <bignum.h>

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

void ec_point_identity(ec_group *g, ec_point *r)
{
	g->_make_identity(g, r);
}

void ec_point_delete(ec_point *ep)
{
	free(ep);
}

uint32_t ec_point_encode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size, uint32_t compression)
{
	return eg->_encode(eg, ep, buffer, size, compression);
}

ec_point *ec_point_decode(ec_group *eg, ec_point *ep, void *buffer, uint32_t size)
{
	return eg->_decode(eg, ep, buffer, size);
}

ec_point *ec_point_add(ec_group *g, ec_point *r, ec_point *a, ec_point *b)
{
	return g->_add(g, r, a, b);
}

ec_point *ec_point_double(ec_group *g, ec_point *r, ec_point *a)
{
	return g->_double(g, r, a);
}

ec_point *ec_point_multiply(ec_group *g, ec_point *r, ec_point *a, bignum_t *n)
{
	return g->_multiply(g, r, a, n);
}

uint32_t ec_point_on_curve(ec_group *g, ec_point *a)
{
	return g->_on_curve(g, a);
}

uint32_t ec_point_is_identity(ec_group *g, ec_point *a)
{
	return g->_is_identity(g, a);
}
