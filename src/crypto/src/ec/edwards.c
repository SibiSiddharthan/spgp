/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

#include <ptr.h>

#include <string.h>

uint32_t ec_edwards_point_is_identity(ec_point *a)
{
	// (x,y) = (0,1)
	if (a->x->bits == 0 && a->y->bits == 1)
	{
		return 1;
	}

	return 0;
}

