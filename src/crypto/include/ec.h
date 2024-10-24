/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_EC_H
#define CRYPTO_EC_H

#include <bignum.h>

typedef enum _curve_id
{

} curve_id;

typedef struct _ec_point
{
	curve_id id;
	bignum_t *x, *y;

	bignum_t (*_add)(bignum_ctx *, bignum_t *, bignum_t *, bignum_t *, bignum_t *, bignum_t *, bignum_t *);
	bignum_t (*_double)(bignum_ctx *, bignum_t *, bignum_t *, bignum_t *, bignum_t *);
	bignum_t (*_check)(bignum_ctx *, bignum_t *, bignum_t *);

} ec_point;

inline size_t ec_point_size(uint32_t bits)
{
	return sizeof(ec_point) + (2 * bignum_size(bits));
}

ec_point *ec_point_init(void *ptr, size_t size, curve_id id);
ec_point *ec_point_new(curve_id id);
ec_point *ec_point_copy(ec_point *dst_p, ec_point *src_p);
ec_point *bignum_dup(bignum_ctx *bctx, ec_point *p);
void ec_point_delete(ec_point *bn);

ec_point *ec_point_add(bignum_ctx *bctx, ec_point *r, ec_point *a, ec_point *b);
ec_point *ec_point_dbl(bignum_ctx *bctx, ec_point *r, ec_point *a);
ec_point *ec_point_mul(bignum_ctx *bctx, ec_point *r, ec_point *a, bignum_t *n);

uint32_t ec_point_check(bignum_ctx *bctx, ec_point *a);

#endif
