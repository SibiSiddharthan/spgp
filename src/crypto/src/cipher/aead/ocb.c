/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <types.h>
#include <bitscan.h>
#include <byteswap.h>
#include <minmax.h>
#include <round.h>

#include "double-block.h"

// See NIST SP 800-38D Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (OCB) and GMAC

typedef struct _ocb_ctx
{
	byte_t ls[16][66];
	byte_t offset[16];
	byte_t checksum[16];
	byte_t osum[16];

	uint8_t max_ntz;
	uint8_t tag_size;
	size_t block_count;

	size_t data_size;
	size_t ad_size;

	void *key;
	void (*encrypt)(void *key, void *plaintext, void *ciphertext);
	void (*decrypt)(void *key, void *ciphertext, void *plaintext);
} ocb_ctx;

static void calculate_hash(ocb_ctx *octx, void *associated_data, size_t ad_size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;
	byte_t buffer[16];

	byte_t *p = (byte_t *)associated_data;

	uint64_t *b = (uint64_t *)buffer;
	uint64_t *a = (uint64_t *)associated_data;
	uint64_t *o = (uint64_t *)octx->offset;
	uint64_t *s = (uint64_t *)octx->osum;
	uint64_t *l;

	uint8_t ntz = 0;

	while (processed + block_size <= ad_size)
	{
		ntz = BSF_64(octx->block_count);

		if (ntz > octx->max_ntz)
		{
			double_block(octx->ls[2 + ntz], octx->ls[1 + ntz]);
			octx->max_ntz += 1;
		}

		l = (uint64_t *)octx->ls[2 + ntz];

		o[0] ^= l[0];
		o[1] ^= l[1];

		b[0] = o[0] ^ a[0];
		b[1] = o[1] ^ a[1];

		octx->encrypt(octx->key, buffer, buffer);

		s[0] ^= b[0];
		s[1] ^= b[1];

		processed += block_size;
		octx->block_count += 1;
	}

	remaining = ad_size - processed;

	if (remaining > 0)
	{
		l = (uint64_t *)octx->ls[0];

		o[0] ^= l[0];
		o[1] ^= l[1];

		for (uint8_t i = 0; i < remaining; ++i)
		{
			buffer[i] = p[processed + i] ^ octx->offset[i];
		}

		buffer[remaining] = 0x80 ^ octx->offset[remaining];

		octx->encrypt(octx->key, buffer, buffer);

		s[0] ^= b[0];
		s[1] ^= b[1];

		processed += remaining;
	}
}

uint64_t ocb_encrypt_update(ocb_ctx *octx, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t buffer[16];

	uint64_t *b = (uint64_t *)buffer;
	uint64_t *pi = (uint64_t *)pin;
	uint64_t *po = (uint64_t *)pout;
	uint64_t *o = (uint64_t *)octx->offset;
	uint64_t *c = (uint64_t *)octx->checksum;
	uint64_t *l;

	uint8_t ntz = 0;

	// Make sure input is a multiple of block_size
	if (in_size % block_size != 0)
	{
		return 0;
	}

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		ntz = BSF_64(octx->block_count);

		if (ntz > octx->max_ntz)
		{
			double_block(octx->ls[2 + ntz], octx->ls[1 + ntz]);
			octx->max_ntz += 1;
		}

		l = (uint64_t *)octx->ls[2 + ntz];

		o[0] ^= l[0];
		o[1] ^= l[1];

		b[0] = o[0] ^ pi[0];
		b[1] = o[1] ^ pi[1];

		octx->encrypt(octx->key, buffer, buffer);

		po[0] = b[0] ^ o[0];
		po[1] = b[1] ^ o[1];

		c[0] ^= pi[0];
		c[1] ^= pi[1];

		result += block_size;
		processed += block_size;
		octx->block_count += 1;
	}

	return result;
}

uint64_t ocb_decrypt_update(ocb_ctx *octx, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t buffer[16];

	uint64_t *b = (uint64_t *)buffer;
	uint64_t *pi = (uint64_t *)pin;
	uint64_t *po = (uint64_t *)pout;
	uint64_t *o = (uint64_t *)octx->offset;
	uint64_t *c = (uint64_t *)octx->checksum;
	uint64_t *l;

	uint8_t ntz = 0;

	// Make sure input is a multiple of block_size
	if (in_size % block_size != 0)
	{
		return 0;
	}

	if (in_size < out_size)
	{
		return 0;
	}

	while (processed < in_size)
	{
		ntz = BSF_64(octx->block_count);

		if (ntz > octx->max_ntz)
		{
			double_block(octx->ls[2 + ntz], octx->ls[1 + ntz]);
			octx->max_ntz += 1;
		}

		l = (uint64_t *)octx->ls[2 + ntz];

		o[0] ^= l[0];
		o[1] ^= l[1];

		b[0] = o[0] ^ pi[0];
		b[1] = o[1] ^ pi[1];

		octx->encrypt(octx->key, buffer, buffer);

		po[0] = b[0] ^ o[0];
		po[1] = b[1] ^ o[1];

		c[0] ^= po[0];
		c[1] ^= po[1];

		result += block_size;
		processed += block_size;
		octx->block_count += 1;
	}

	return result;
}

uint64_t ocb_encrypt_final(ocb_ctx *octx, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t buffer[16];

	uint64_t *b = (uint64_t *)buffer;
	uint64_t *pi = (uint64_t *)pin;
	uint64_t *po = (uint64_t *)pout;
	uint64_t *o = (uint64_t *)octx->offset;
	uint64_t *c = (uint64_t *)octx->checksum;
	uint64_t *l;

	uint8_t ntz = 0;

	if (out_size < (in_size + octx->tag_size))
	{
		return 0;
	}

	while (processed + block_size <= in_size)
	{
		ntz = BSF_64(octx->block_count);

		if (ntz > octx->max_ntz)
		{
			double_block(octx->ls[2 + ntz], octx->ls[1 + ntz]);
			octx->max_ntz += 1;
		}

		l = (uint64_t *)octx->ls[2 + ntz];

		o[0] ^= l[0];
		o[1] ^= l[1];

		b[0] = o[0] ^ pi[0];
		b[1] = o[1] ^ pi[1];

		octx->encrypt(octx->key, buffer, buffer);

		po[0] = b[0] ^ o[0];
		po[1] = b[1] ^ o[1];

		c[0] ^= pi[0];
		c[1] ^= pi[1];

		result += block_size;
		processed += block_size;
		octx->block_count += 1;
	}

	remaining = in_size - processed;

	if (remaining > 0)
	{
		l = (uint64_t *)octx->ls[0];

		o[0] ^= l[0];
		o[1] ^= l[1];

		octx->encrypt(octx->key, octx->offset, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		for (uint8_t i = 0; i < remaining; ++i)
		{
			octx->checksum[i] ^= pin[processed + i];
		}

		octx->checksum[remaining] ^= 0x80;

		processed += remaining;
		result += remaining;
	}

	l = (uint64_t *)octx->ls[1];

	b[0] = c[0] ^ o[0] ^ l[0];
	b[1] = c[1] ^ o[1] ^ l[1];

	octx->encrypt(octx->key, buffer, buffer);

	for (uint8_t i = 0; i < octx->tag_size; ++i)
	{
		pout[processed + i] = octx->osum[i] ^ buffer[i];
	}

	result += octx->tag_size;

	return result;
}

uint64_t ocb_decrypt_final(ocb_ctx *octx, void *in, size_t in_size, void *out, size_t out_size)
{
	const uint16_t block_size = 16;

	uint64_t result = 0;
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t buffer[16] = {0};
	byte_t tag[16] = {0};

	uint64_t *b = (uint64_t *)buffer;
	uint64_t *t = (uint64_t *)tag;
	uint64_t *pi = (uint64_t *)pin;
	uint64_t *po = (uint64_t *)pout;
	uint64_t *o = (uint64_t *)octx->offset;
	uint64_t *c = (uint64_t *)octx->checksum;
	uint64_t *s = (uint64_t *)octx->osum;
	uint64_t *l;

	uint8_t ntz = 0;

	if (out_size < (in_size - octx->tag_size))
	{
		return 0;
	}

	while (processed + block_size <= (in_size - octx->tag_size))
	{
		ntz = BSF_64(octx->block_count);

		if (ntz > octx->max_ntz)
		{
			double_block(octx->ls[2 + ntz], octx->ls[1 + ntz]);
			octx->max_ntz += 1;
		}

		l = (uint64_t *)octx->ls[2 + ntz];

		o[0] ^= l[0];
		o[1] ^= l[1];

		b[0] = o[0] ^ pi[0];
		b[1] = o[1] ^ pi[1];

		octx->decrypt(octx->key, buffer, buffer);

		po[0] = b[0] ^ o[0];
		po[1] = b[1] ^ o[1];

		c[0] ^= pi[0];
		c[1] ^= pi[1];

		result += block_size;
		processed += block_size;
		octx->block_count += 1;
	}

	remaining = (in_size - octx->tag_size) - processed;

	if (remaining > 0)
	{
		l = (uint64_t *)octx->ls[0];

		o[0] ^= l[0];
		o[1] ^= l[1];

		octx->encrypt(octx->key, octx->offset, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		for (uint8_t i = 0; i < remaining; ++i)
		{
			octx->checksum[i] ^= pin[processed + i];
		}

		octx->checksum[remaining] ^= 0x80;

		processed += remaining;
		result += remaining;
	}

	l = (uint64_t *)octx->ls[1];

	b[0] = c[0] ^ o[0] ^ l[0];
	b[1] = c[1] ^ o[1] ^ l[1];

	octx->encrypt(octx->key, buffer, buffer);

	t[0] = b[0] ^ s[0];
	t[1] = b[1] ^ s[1];

	if (memcmp(tag, pin + (in_size - octx->tag_size), octx->tag_size) != 0)
	{
		return 0;
	}

	result += octx->tag_size;

	return result;
}

int32_t ocb_init(ocb_ctx *octx, void *nonce, size_t nonce_size, void *associated_data, size_t ad_size, size_t tag_size)
{
	byte_t zero[16] = {0};
	byte_t buffer[16] = {0};
	byte_t stretch[24] = {0};
	byte_t bottom = 0;

	// Check IV size
	if (nonce_size > 15)
	{
		return -1;
	}

	if (tag_size > 16)
	{
		return -1;
	}

	// Initialize L
	octx->encrypt(octx->key, zero, octx->ls[0]); // L*
	double_block(octx->ls[1], octx->ls[0]);      // L$
	double_block(octx->ls[2], octx->ls[1]);      // L0

	// Calculate sum
	calculate_hash(octx, associated_data, ad_size);

	// Initialize offset
	memset(octx->offset, 0, 16);

	buffer[0] = (tag_size % 128) << 1;
	buffer[15 - nonce_size] |= 0x1;
	memcpy(buffer + (16 - nonce_size), nonce, nonce_size);

	bottom = buffer[15] & 0x3F;
	buffer[15] ^= bottom;

	octx->encrypt(octx->key, buffer, stretch);

	for (uint8_t i = 16; i < 24; ++i)
	{
		stretch[i] = stretch[i - 16] ^ stretch[i - 15];
	}

	// Very very rare.
	if (bottom % 8 == 0)
	{
		memcpy(octx->offset, stretch + (bottom / 8), 16);
	}

	for (uint8_t i = 0; i < 16; ++i)
	{
		octx->offset[i] = (stretch[i + (bottom / 8)] << (bottom % 8)) | (stretch[i + 1 + (bottom / 8)] >> (8 - (bottom % 8)));
	}

	return 0;
}

uint64_t ocb_ae_update(ocb_ctx *octx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	result = ocb_encrypt_update(octx, plaintext, plaintext_size, ciphertext, ciphertext_size);
	octx->data_size += result;

	return result;
}

uint64_t ocb_ae_final(ocb_ctx *octx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	result = ocb_encrypt_final(octx, plaintext, plaintext_size, ciphertext, ciphertext_size);

	return result;
}

uint64_t ocb_ad_update(ocb_ctx *octx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;

	result = ocb_decrypt_update(octx, ciphertext, ciphertext_size, plaintext, plaintext_size);

	return result;
}

uint64_t ocb_ad_final(ocb_ctx *octx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	result = ocb_decrypt_final(octx, plaintext, plaintext_size, ciphertext, ciphertext_size);

	return result;
}