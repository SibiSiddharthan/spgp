/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

#include <round.h>

#include <drbg.h>

ec_key *ec_key_generate(ec_key *ek, ec_group *eg)
{
	ec_prime_curve *parameters = eg->parameters;

	ec_point g = {.x = parameters->gx, .y = parameters->gy};
	uint32_t bytes = CEIL_DIV(eg->bits, 8);

	drbg_ctx *drbg = get_default_drbg();

	byte_t buffer[64] = {0};

	if (ek == NULL)
	{
		ek = ec_key_new(eg);

		if (ek == NULL)
		{
			return NULL;
		}
	}

	if (drbg == NULL)
	{
		return NULL;
	}

	// Generate private key
	while (1)
	{
		// Generate random bytes
		drbg_generate(drbg, 0, NULL, 0, buffer, bytes);

		// The generated key should less than the order of the elliptic curve
		bignum_set_bytes_be(ek->d, buffer, bytes);

		if (bignum_cmp_abs(ek->d, parameters->n) < 0)
		{
			break;
		}
	}

	// Calculate the public key
	ek->q = ec_point_multiply(eg, ek->q, &g, ek->d);

	return ek;
}

uint32_t ec_public_key_validate(ec_key *ek, uint32_t full)
{
	ec_prime_curve *parameters = ek->eg->parameters;
	bignum_t *p = parameters->p;

	// Check if point is not at infinity
	if (ec_point_at_infinity(ek->eg, ek->q))
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

		inf = ec_point_multiply(ek->eg, NULL, ek->q, parameters->n);

		if (ec_point_at_infinity(ek->eg, inf) != 0)
		{
			ec_point_delete(inf);
			return 0;
		}

		ec_point_delete(inf);
	}

	return 1;
}
