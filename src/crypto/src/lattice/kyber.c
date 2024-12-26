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

static void sample_ntt(shake256_ctx *xof, uint16_t f[256], uint8_t b[34])
{
	byte_t c[3];
	byte_t out[3 * 256] = {0};
	uint16_t j = 0;
	uint16_t d1 = 0, d2 = 0;

	shake256_reset(xof, 2 * 256);
	shake256_update(xof, b, 34);
	shake256_final(xof, out, 3 * 256);

	while (j < 256)
	{
		// Copyt 3 bytes
		c[0] = out[j * 3];
		c[1] = out[(j * 3) + 1];
		c[2] = out[(j * 3) + 2];

		d1 = c[0] + (256 * (c[1] % 16));
		d2 = (c[1] / 16) + (16 * c[2]);

		if (d1 < KYBER_Q)
		{
			f[j] = d1;
			j += 1;
		}
		if (d2 < KYBER_Q && j < 256)
		{
			f[j] = d2;
			j += 1;
		}
	}
}

static void sample_polycbd(uint16_t f[256], uint8_t *b, uint8_t e)
{
	for (uint16_t i = 0; i < KYBER_N; ++i)
	{
		uint16_t x = 0, y = 0;

		for (uint16_t j = 0; j < e; ++j)
		{
			x += GET_BIT(b, (2 * i * e) + j);
		}

		for (uint16_t j = 0; j < e; ++j)
		{
			y += GET_BIT(b, (2 * i * e) + e + j);
		}

		f[i] = x >= y ? ((x - y) % KYBER_Q) : (KYBER_Q - ((y - x) % KYBER_Q));
	}
}
