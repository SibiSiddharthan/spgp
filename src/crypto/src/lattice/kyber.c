/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

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

static const uint16_t Z[128] = {
	1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,  2786, 3260, 569,  1746, 296,  2447, 1339, 1476, 3046, 56,
	2240, 1333, 1426, 2094, 535,  2882, 2393, 2879, 1974, 821,  289,  331,  3253, 1756, 1197, 2304, 2277, 2055, 650,  1977, 2513, 632,
	2865, 33,   1320, 1915, 2319, 1435, 807,  452,  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,  2474, 3110, 1227, 910,  17,   2761,
	583,  2649, 1637, 723,  2288, 1100, 1409, 2662, 3281, 233,  756,  2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952,  1461, 2687,
	939,  2308, 2437, 2388, 733,  2337, 268,  641,  1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063, 319,  2773, 757,  2099, 561,
	2466, 2594, 2804, 1092, 403,  1026, 1143, 2150, 2775, 886,  1722, 1212, 1874, 1029, 2110, 2935, 885,  2154};

static const uint16_t Zi[128] = {17,   -17,   2761, -2761, 583,  -583,  2649, -2649, 1637, -1637, 723,  -723,  2288, -2288, 1100, -1100,
								 1409, -1409, 2662, -2662, 3281, -3281, 233,  -233,  756,  -756,  2156, -2156, 3015, -3015, 3050, -3050,
								 1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, 1847, -1847, 952,  -952,  1461, -1461, 2687, -2687,
								 939,  -939,  2308, -2308, 2437, -2437, 2388, -2388, 733,  -733,  2337, -2337, 268,  -268,  641,  -641,
								 1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220, 375,  -375,  2549, -2549, 2090, -2090, 1645, -1645,
								 1063, -1063, 319,  -319,  2773, -2773, 757,  -757,  2099, -2099, 561,  -561,  2466, -2466, 2594, -2594,
								 2804, -2804, 1092, -1092, 403,  -403,  1026, -1026, 1143, -1143, 2150, -2150, 2775, -2775, 886,  -886,
								 1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029, 2110, -2110, 2935, -2935, 885,  -885,  2154, -2154};

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

static void ntt(uint16_t fo[256], uint16_t fi[256])
{
	uint16_t i = 1;
	uint16_t z = 0;
	uint16_t t = 0;

	memcpy(fo, fi, 256 * sizeof(uint16_t));

	for (uint16_t l = 128; l >= 2; l /= 2)
	{
		for (uint16_t s = 0; s < 256; s += 2 * l)
		{
			z = Z[i];
			i += 1;

			for (uint16_t j = s; j < (s + l); ++j)
			{
				t = (z * fo[j + l]) % KYBER_Q;
				fo[j + l] = fo[j] >= t ? ((fo[j] - t) % KYBER_Q) : (KYBER_Q - ((t - fo[j]) % KYBER_Q));
				fo[j] = (fo[j] + t) % KYBER_Q;
			}
		}
	}
}

static void intt(uint16_t fo[256], uint16_t fi[256])
{
	uint16_t i = 127;
	uint16_t z = 0;
	uint16_t t = 0;

	memcpy(fo, fi, 256 * sizeof(uint16_t));

	for (uint16_t l = 2; l <= 128; l *= 2)
	{
		for (uint16_t s = 0; s < 256; s += 2 * l)
		{
			z = Z[i];
			i -= 1;

			for (uint16_t j = s; j < (s + l); ++j)
			{
				t = fo[j];
				fo[j] = (fo[j + l] + t) % KYBER_Q;
				fo[j + l] = fo[j + l] >= t ? ((fo[j + l] - t) % KYBER_Q) : (KYBER_Q - ((t - fo[j + l]) % KYBER_Q));
				fo[j + l] = (z * fo[j + l]) % KYBER_Q;
			}
		}
	}

	for (uint16_t j = 0; j < 256; ++j)
	{
		fo[j] = (fo[j] * 3303) % KYBER_Q;
	}
}

static inline uint32_t basecase_multiply(uint16_t a0, uint16_t a1, uint16_t b0, uint16_t b1, uint16_t g)
{
	uint32_t c = 0;
	uint16_t c0 = 0, c1 = 0;

	c0 = ((a0 * b0) + (a1 * b1 * g)) % KYBER_Q;
	c1 = ((a0 * b1) + (a1 * b0)) % KYBER_Q;

	c = (uint32_t)c0 + ((uint32_t)c1 << 16);

	return c;
}

static void multiply_ntt(uint16_t h[256], uint16_t f[256], uint16_t g[256])
{
	uint32_t c = 0;

	for (uint16_t i = 0; i < 128; ++i)
	{
		c = basecase_multiply(f[2 * i], f[(2 * i) + 1], g[2 * i], g[(2 * i) + 1], Zi[i]);

		h[2 * i] = c & 0xFFFF;
		h[(2 * i) + 1] = (c >> 16) & 0xFFFF;
	}
}

void kyber_keygen(kyber_key *key, byte_t seed[32])
{
	byte_t hash[SHA3_512_HASH_SIZE] = {0};
	byte_t sample_ntt_seed[34] = {0};
	byte_t sample_polycbd_seed[33] = {0};
	byte_t sample_polycbd_input[256] = {0};

	uint8_t n = 0;
	uint16_t p = 0;

	uint16_t *A = NULL;
	uint16_t *S = NULL;
	uint16_t *E = NULL;
	uint16_t *T = NULL;

	sha3_512_reset(key->g);
	sha3_512_update(key->g, seed, 32);
	sha3_512_update(key->g, &key->k, 1);
	sha3_512_final(key->g, hash);

	memcpy(sample_ntt_seed, hash, 32);
	memcpy(sample_polycbd_seed, PTR_OFFSET(hash, 32), 32);

	A = malloc(key->k * key->k * sizeof(uint16_t));

	if (A == NULL)
	{
		return;
	}

	for (uint8_t i = 0; i < key->k; ++i)
	{
		for (uint8_t j = 0; j < key->k; ++j)
		{
			sample_ntt_seed[32] = j;
			sample_ntt_seed[33] = i;

			sample_ntt(key->h, A + ((i * key->k) + j) * 256, sample_ntt_seed);
		}
	}

	S = malloc(key->k * sizeof(uint16_t));

	if (S == NULL)
	{
		return;
	}

	for (uint8_t i = 0; i < key->k; ++i)
	{
		shake256_reset(key->h, 64 * key->e1);
		shake256_update(key->h, sample_polycbd_seed, 32);
		shake256_update(key->h, &n, 1);
		shake256_final(key->h, sample_polycbd_input, 64 * key->e1);

		sample_polycbd(S + (i * 256), sample_polycbd_input, key->e1);

		++n;
	}

	E = malloc(key->k * sizeof(uint16_t));

	if (E == NULL)
	{
		return;
	}

	for (uint8_t i = 0; i < key->k; ++i)
	{
		shake256_reset(key->h, 64 * key->e1);
		shake256_update(key->h, sample_polycbd_seed, 32);
		shake256_update(key->h, &n, 1);
		shake256_final(key->h, sample_polycbd_input, 64 * key->e1);

		sample_polycbd(E + (i * 256), sample_polycbd_input, key->e1);

		++n;
	}

	for (uint8_t i = 0; i < key->k; ++i)
	{
		ntt(S + (i * 256), S + (i * 256));
		ntt(E + (i * 256), E + (i * 256));
	}

	T = malloc(key->k * sizeof(uint16_t));

	if (T == NULL)
	{
		return;
	}

	for (uint8_t i = 0; i < key->k; ++i)
	{
		multiply_ntt(T + (i * 256), A + ((i * key->k)) * 256, S + (i * 256));
	}

	p = 0;

	for (uint8_t i = 0; i < key->k; ++i)
	{
		byte_encode(PTR_OFFSET(key->ek, p), T + (i * 256), 12);
	}

	memcpy(PTR_OFFSET(key->ek, p), sample_ntt_seed, 32);

	p = 0;

	for (uint8_t i = 0; i < key->k; ++i)
	{
		byte_encode(PTR_OFFSET(key->dk, p), S + (i * 256), 12);
	}
}
