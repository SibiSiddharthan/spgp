/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <xor.h>

// Refer A Conventional Authenticated-Encryption Mode

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

static void omac(cipher_ctx *cctx, byte_t mac[16], uint64_t n, void *message, size_t size)
{
	size_t processed = 0;

	byte_t *in = (byte_t *)message;
	uint64_t *m = (uint64_t *)mac;

	m[0] = 0;
	m[1] = BSWAP_64(n);

	cctx->_encrypt(cctx->_ctx, mac, mac);

	for (processed = 0; processed < (size - 16); processed += 16)
	{
		XOR16(mac, mac, in + processed);
		cctx->_encrypt(cctx->_ctx, mac, mac);
	}

	if (size % 16 == 0)
	{
		// Last block
		XOR16(mac, cctx->eax.b, in + processed);
		cctx->_encrypt(cctx->_ctx, mac, mac);
	}
	else
	{
		byte_t buffer[16] = {0};
		size_t remaining = size - processed;

		memcpy(buffer, in + processed, remaining);
		buffer[remaining] = 0x80;

		// Last block
		XOR16(mac, cctx->eax.p, buffer);
		cctx->_encrypt(cctx->_ctx, mac, mac);
	}
}

static uint64_t ectr_update(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = PTR_OFFSET(cctx->eax.n, 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];

	while (processed < size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->eax.n, buffer);
		XOR16(pout + processed, pin + processed, buffer);

		XOR16(cctx->eax.c, cctx->eax.c, pout + processed);
		cctx->_encrypt(cctx->_ctx, cctx->eax.c, cctx->eax.c);

		++counter;
		*pc = BSWAP_32(counter);

		processed += block_size;
	}

	return processed;
}

uint64_t ectr_final(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t remaining = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = PTR_OFFSET(cctx->eax.n, 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];

	while (processed + (2 * block_size) <= size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->eax.n, buffer);
		XOR16(pout + processed, pin + processed, buffer);

		XOR16(cctx->eax.c, cctx->eax.c, pout + processed);
		cctx->_encrypt(cctx->_ctx, cctx->eax.c, cctx->eax.c);

		++counter;
		*pc = BSWAP_32(counter);

		processed += block_size;
	}

	remaining = size - processed;

	if (remaining == block_size)
	{
		cctx->_encrypt(cctx->_ctx, cctx->eax.n, buffer);
		XOR16(pout + processed, pin + processed, buffer);

		XOR16(cctx->eax.c, cctx->eax.b, pout + processed);
		cctx->_encrypt(cctx->_ctx, cctx->eax.c, cctx->eax.c);
	}
	else
	{
		cctx->_encrypt(cctx->_ctx, cctx->eax.n, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		memset(buffer, 0, 16);
		memcpy(buffer, pin + processed, remaining);
		buffer[remaining] = 0x80;

		XOR16(cctx->eax.c, cctx->eax.p, buffer);
		cctx->_encrypt(cctx->_ctx, cctx->eax.c, cctx->eax.c);
	}

	processed += remaining;

	return processed;
}

static cipher_ctx *cipher_eax_init_common(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header,
										  size_t header_size)
{
	byte_t buffer[16] = {0};
	byte_t l[16] = {0};

	if (tag_size > 16)
	{
		return NULL;
	}

	// Initialize L
	cctx->_encrypt(cctx->_ctx, buffer, l);

	// Initialize B
	double_block(cctx->eax.b, l);

	// Initialize P
	double_block(cctx->eax.p, cctx->eax.b);

	// Initialize N
	omac(cctx, cctx->eax.n, 0, nonce, nonce_size);

	// Initialize H
	omac(cctx, cctx->eax.h, 1, header, header_size);

	// Initialize C
	cctx->eax.c[15] = 0x2;
	cctx->_encrypt(cctx->_ctx, cctx->eax.c, cctx->eax.c);

	cctx->eax.tag_size = tag_size;

	return 0;
}

cipher_ctx *cipher_eax_encrypt_init(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size)
{
	return cipher_eax_init_common(cctx, tag_size, nonce, nonce_size, header, header_size);
}

uint64_t cipher_eax_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	result = ectr_update(cctx, plaintext, ciphertext, ROUND_DOWN(plaintext_size, cctx->block_size));
	cctx->eax.data_size += result;

	return result;
}

uint64_t cipher_eax_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;
	byte_t tag[16];

	if (ciphertext_size < (plaintext_size + cctx->eax.tag_size))
	{
		return 0;
	}

	result = ectr_final(cctx, plaintext, ciphertext, plaintext_size);
	cctx->eax.data_size += result;

	XOR16(tag, cctx->eax.n, cctx->eax.c);
	XOR16(tag, tag, cctx->eax.h);

	memcpy((byte_t *)ciphertext + result, tag, cctx->eax.tag_size);

	return result + cctx->eax.tag_size;
}
uint64_t cipher_eax_encrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size,
							void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	cctx = cipher_eax_init_common(cctx, tag_size, nonce, nonce_size, header, header_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_eax_encrypt_final(cctx, plaintext, plaintext_size, ciphertext, ciphertext_size);
}

cipher_ctx *cipher_eax_decrypt_init(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size)
{
	return cipher_eax_init_common(cctx, tag_size, nonce, nonce_size, header, header_size);
}

uint64_t cipher_eax_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	result = ectr_update(cctx, ciphertext, plaintext, ROUND_DOWN(ciphertext_size, cctx->block_size));
	cctx->eax.data_size += result;

	return result;
}

uint64_t cipher_eax_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;
	byte_t actual_tag[16];
	byte_t expected_tag[16];

	if (plaintext_size < (ciphertext_size - cctx->eax.tag_size))
	{
		return 0;
	}

	memcpy(actual_tag, (byte_t *)ciphertext + (ciphertext_size - cctx->eax.tag_size), cctx->eax.tag_size);

	result = ectr_final(cctx, ciphertext, plaintext, ciphertext_size - cctx->eax.tag_size);
	cctx->eax.data_size += result;

	XOR16(expected_tag, cctx->eax.n, cctx->eax.c);
	XOR16(expected_tag, expected_tag, cctx->eax.h);

	if (memcmp(actual_tag, expected_tag, cctx->eax.tag_size) != 0)
	{
		return 0;
	}

	return result;
}

uint64_t cipher_eax_decrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *header, size_t header_size,
							void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	cctx = cipher_eax_init_common(cctx, tag_size, nonce, nonce_size, header, header_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_eax_decrypt_final(cctx, ciphertext, ciphertext_size, plaintext, plaintext_size);
}
