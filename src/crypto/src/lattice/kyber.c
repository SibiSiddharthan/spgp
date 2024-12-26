/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <kyber.h>
#include <round.h>
#include <ptr.h>

#include <stdlib.h>
#include <string.h>

#define SET_BIT(x, p, v) x[(p) / 8] |= ((v) << ((p) % 8))
#define GET_BIT(x, p)    ((x[(p) / 8] >> ((p) % 8)) & 0x1)

static void byte_encode(void *out, void *in, uint8_t d)
{
	uint16_t *f = in;
	uint8_t *b = out;
	uint16_t m = d < 12 ? (1 << d) : KYBER_Q;

	for (uint16_t i = 0; i < KYBER_N; ++i)
	{
		uint16_t a = f[i] % m;

		for (uint16_t j = 0; j < d; ++j)
		{
			SET_BIT(b, (i * d) + j, a % 2);
			a >>= 1;
		}
	}
}

static void byte_decode(void *out, void *in, uint8_t d)
{
	uint16_t *f = out;
	uint8_t *b = in;
	uint16_t m = d < 12 ? (1 << d) : KYBER_Q;

	for (uint16_t i = 0; i < KYBER_N; ++i)
	{
		uint16_t a = 0;

		for (uint16_t j = 0; j < d; ++j)
		{
			a = GET_BIT(b, (i * d) + j) << j;
		}

		f[i] = a % m;
	}
}

