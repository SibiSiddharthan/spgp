/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ec.h>
#include <bignum.h>
#include <bignum-internal.h>

#include <stdlib.h>
#include <string.h>

ec_key *ec_key_new(ec_group *eg, bignum_t *d, ec_point *q)
{
	ec_key *key = malloc(sizeof(ec_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(ec_key));

	key->eg = eg;
	key->d = d;
	key->q = q;

	return key;
}

void ec_key_delete(ec_key *ek)
{
	ec_group_delete(ek->eg);
	ec_point_delete(ek->q);
	bignum_delete(ek->d);
	free(ek);
}

ec_key *ec_key_generate(ec_group *eg, bignum_t *d)
{
	ec_key *key = NULL;

	key = malloc(sizeof(ec_key));

	if (key == NULL)
	{
		free(key);
	}

	memset(key, 0, sizeof(ec_key));

	// Generate private key
	if (d == NULL)
	{
		d = bignum_rand_max(NULL, d, eg->n);

		if (d == NULL)
		{
			free(key);
			return NULL;
		}
	}
	else
	{
		if (bignum_cmp_abs(d, eg->n) >= 0)
		{
			free(key);
			return NULL;
		}
	}

	// Set the group
	key->eg = eg;

	// Set the private key
	key->d = d;

	// Calculate the public key
	key->q = ec_point_multiply(eg, key->q, eg->g, d);

	return key;
}

uint32_t ec_public_key_validate(ec_key *ek, uint32_t full)
{
	bignum_t *p = ek->eg->p;

	// Check if point is not at infinity
	if (ec_point_is_identity(ek->eg, ek->q))
	{
		return 0;
	}

	// Check if Qx, Qy is less than p
	if (bignum_cmp(ek->q->x, p) >= 0 || bignum_cmp(ek->q->y, p))
	{
		return 0;
	}

	// Check if point is on curve
	if (ec_point_on_curve(ek->eg, ek->q) == 0)
	{
		return 0;
	}

	// Check if [n]Q = O
	if (full)
	{
		ec_point *inf = NULL;

		inf = ec_point_multiply(ek->eg, NULL, ek->q, ek->eg->n);

		if (ec_point_is_identity(ek->eg, inf) != 0)
		{
			ec_point_delete(inf);
			return 0;
		}

		ec_point_delete(inf);
	}

	return 1;
}
