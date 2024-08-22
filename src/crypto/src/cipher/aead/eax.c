/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <types.h>
#include <byteswap.h>
#include <minmax.h>
#include <round.h>

typedef struct _eax_ctx
{
	byte_t b[16];
	byte_t p[16];
	byte_t n[16];
	byte_t h[16];
	byte_t c[16];

	byte_t tag_size;
	size_t data_size;
	size_t ad_size;

	void *key;
	void (*encrypt)(void *key, void *plaintext, void *ciphertext);
} eax_ctx;

static inline void double_block(byte_t r[16], byte_t b[16])
{
	uint64_t *u = (uint64_t *)b;
	uint64_t *v = (uint64_t *)r;

	v[0] = BSWAP_64(u[0]);
	v[1] = BSWAP_64(u[1]);

	v[0] = (v[0] << 1) | (v[1] >> 63);
	v[1] = v[1] << 1;

	v[0] = BSWAP_64(v[0]);
	v[1] = BSWAP_64(v[1]);

	r[15] ^= 0x87;
}

static void omac(eax_ctx *ectx, byte_t mac[16], uint64_t n, void *message, size_t size)
{
	size_t pos = 0;
	size_t count = 0;

	uint64_t *m = (uint64_t *)mac;
	uint64_t *in = (uint64_t *)message;

	m[0] = 0;
	m[1] = BSWAP_64(n);

	ectx->encrypt(ectx->key, mac, mac);

	for (pos = 0; pos < (size - 16); pos += 16, ++count)
	{
		m[0] ^= in[count];
		m[1] ^= in[count + 1];

		ectx->encrypt(ectx->key, mac, mac);
	}

	if (size % 16 == 0)
	{
		uint64_t *b = (uint64_t *)ectx->b;

		// Last block
		m[0] ^= b[0] ^ in[count];
		m[1] ^= b[1] ^ in[count + 1];

		ectx->encrypt(ectx->key, mac, mac);
	}
	else
	{
		byte_t buffer[16] = {0};
		size_t remaining = size - pos;
		uint64_t *p = (uint64_t *)ectx->p;
		uint64_t *b = (uint64_t *)buffer;

		memcpy(buffer, &in[count], remaining);
		buffer[remaining] = 0x80;

		// Last block
		m[0] ^= p[0] ^ b[0];
		m[1] ^= p[1] ^ b[1];

		ectx->encrypt(ectx->key, mac, mac);
	}
}

uint64_t ectr_update(eax_ctx *ectx, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = (uint32_t *)((byte_t *)ectx->n + 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];
	uint64_t *b = (uint64_t *)buffer;
	uint64_t *c = (uint64_t *)ectx->c;

	// Make sure input is a multiple of block_size
	if (in_size % block_size != 0)
	{
		return 0;
	}

	if (out_size < in_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		uint64_t *x = (uint64_t *)(pin + processed);
		uint64_t *y = (uint64_t *)(pout + processed);

		ectx->encrypt(ectx->key, ectx->n, buffer);

		y[0] = b[0] ^ x[0];
		y[1] = b[1] ^ x[1];

		++counter;
		*pc = BSWAP_32(counter);

		c[0] ^= x[0];
		c[1] ^= x[1];

		ectx->encrypt(ectx->key, ectx->c, ectx->c);

		result += block_size;
		processed += block_size;
	}

	return result;
}

uint64_t ectr_final(eax_ctx *ectx, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = (uint32_t *)((byte_t *)ectx->n + 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];
	uint64_t *b = (uint64_t *)buffer;
	uint64_t *c = (uint64_t *)ectx->c;

	if (out_size < in_size)
	{
		return 0;
	}

	while (processed + (2 * block_size) <= in_size)
	{
		uint64_t *x = (uint64_t *)(pin + processed);
		uint64_t *y = (uint64_t *)(pout + processed);

		ectx->encrypt(ectx->key, ectx->n, buffer);

		y[0] = b[0] ^ x[0];
		y[1] = b[1] ^ x[1];

		++counter;
		*pc = BSWAP_32(counter);

		c[0] ^= x[0];
		c[1] ^= x[1];

		ectx->encrypt(ectx->key, ectx->c, ectx->c);

		result += block_size;
		processed += block_size;
	}

	remaining = in_size - processed;

	if (remaining == block_size)
	{
		uint64_t *x = (uint64_t *)(pin + processed);
		uint64_t *y = (uint64_t *)(pout + processed);
		uint64_t *bb = (uint64_t *)ectx->b;

		ectx->encrypt(ectx->key, ectx->n, buffer);

		y[0] = b[0] ^ x[0];
		y[1] = b[1] ^ x[1];

		c[0] ^= x[0] ^ bb[0];
		c[1] ^= x[1] ^ bb[1];

		ectx->encrypt(ectx->key, ectx->c, ectx->c);
	}
	else
	{
		uint64_t *p = (uint64_t *)ectx->p;

		ectx->encrypt(ectx->key, ectx->n, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		memset(buffer, 0, 16);
		memcpy(buffer, pin + processed, remaining);
		buffer[remaining] = 0x80;

		c[0] ^= p[0] ^ b[0];
		c[1] ^= p[1] ^ b[1];

		ectx->encrypt(ectx->key, ectx->c, ectx->c);
	}

	result += remaining;

	return result;
}

int32_t eax_init(eax_ctx *ectx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size)
{
	byte_t buffer[16] = {0};
	byte_t l[16] = {0};

	if (tag_size > 16)
	{
		return -1;
	}

	// Initialize L
	ectx->encrypt(ectx->key, buffer, l);

	// Initialize B
	double_block(ectx->b, l);

	// Initialize P
	double_block(ectx->p, ectx->b);

	// Initialize N
	omac(ectx, ectx->n, 0, nonce, nonce_size);

	// Initialize H
	omac(ectx, ectx->h, 1, header, header_size);

	// Initialize C
	ectx->c[15] = 0x2;
	ectx->encrypt(ectx->key, ectx->c, ectx->c);

	ectx->tag_size = tag_size;

	return 0;
}

uint64_t eax_ae_update(eax_ctx *ectx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	result = ectr_update(ectx, plaintext, plaintext_size, ciphertext, ciphertext_size);
	ectx->data_size += result;

	return result;
}

uint64_t eax_ae_final(eax_ctx *ectx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	byte_t tag[16];

	uint64_t *t = (uint64_t *)tag;
	uint64_t *n = (uint64_t *)ectx->n;
	uint64_t *h = (uint64_t *)ectx->h;
	uint64_t *c = (uint64_t *)ectx->c;

	if (ciphertext_size < (plaintext_size + ectx->tag_size))
	{
		return 0;
	}

	result = ectr_final(ectx, plaintext, plaintext_size, ciphertext, ciphertext_size);
	ectx->data_size += result;

	t[0] = n[0] ^ c[0] ^ h[0];
	t[1] = n[1] ^ c[1] ^ h[1];

	memcpy((byte_t *)ciphertext + result, tag, ectx->tag_size);

	return result + ectx->tag_size;
}

uint64_t eax_ad_update(eax_ctx *ectx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;

	result = ectr_update(ectx, ciphertext, ciphertext_size, plaintext, plaintext_size);
	ectx->data_size += result;

	return result;
}

uint64_t eax_ad_final(eax_ctx *ectx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	byte_t actual_tag[16];
	byte_t expected_tag[16];

	uint64_t *t = (uint64_t *)expected_tag;
	uint64_t *n = (uint64_t *)ectx->n;
	uint64_t *h = (uint64_t *)ectx->h;
	uint64_t *c = (uint64_t *)ectx->c;

	memcpy(actual_tag, (byte_t *)plaintext + (plaintext_size - ectx->tag_size), ectx->tag_size);

	result = ectr_final(ectx, plaintext, plaintext_size - ectx->tag_size, ciphertext, ciphertext_size);
	ectx->data_size += result;

	t[0] = n[0] ^ c[0] ^ h[0];
	t[1] = n[1] ^ c[1] ^ h[1];

	if (memcmp(actual_tag, expected_tag, ectx->tag_size) != 0)
	{
		return 0;
	}

	return result;
}
