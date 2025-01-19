/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

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

#include "double-block.h"

// Refer A Conventional Authenticated-Encryption Mode

static void omac(cipher_ctx *cctx, byte_t mac[16], uint64_t n, void *message, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *in = (byte_t *)message;
	uint64_t *m = (uint64_t *)mac;

	byte_t buffer[16] = {0};

	m[0] = 0;
	m[1] = BSWAP_64(n);

	cctx->_encrypt(cctx->_key, mac, mac);

	while ((processed + block_size) < size)
	{
		XOR16(mac, mac, in + processed);
		cctx->_encrypt(cctx->_key, mac, mac);

		processed += block_size;
	}

	remaining = size - processed;

	// Last block
	if (remaining == block_size)
	{
		XOR16(buffer, in + processed, cctx->eax.b);
		XOR16(mac, mac, buffer);
		cctx->_encrypt(cctx->_key, mac, mac);
	}
	else
	{
		memcpy(buffer, in + processed, remaining);
		buffer[remaining] = 0x80;

		XOR16(buffer, buffer, cctx->eax.p);
		XOR16(mac, mac, buffer);
		cctx->_encrypt(cctx->_key, mac, mac);
	}
}

static void ohash_update(cipher_ctx *cctx, void *message, size_t size)
{
	const uint16_t block_size = 16;

	byte_t *in = message;
	uint64_t processed = 0;

	while (processed <= size)
	{
		if (cctx->eax.t_size == block_size)
		{
			XOR16(cctx->eax.c, cctx->eax.c, cctx->eax.t);
			cctx->_encrypt(cctx->_key, cctx->eax.c, cctx->eax.c);

			cctx->eax.t_size = 0;
		}

		memcpy(cctx->eax.t, in + processed, block_size);
		cctx->eax.t_size += block_size;

		processed += block_size;
	}
}

static void ohash_final(cipher_ctx *cctx, void *message, size_t size)
{
	const uint16_t block_size = 16;

	byte_t *in = message;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	while ((processed + block_size) <= size)
	{
		if (cctx->eax.t_size == block_size)
		{
			XOR16(cctx->eax.c, cctx->eax.c, cctx->eax.t);
			cctx->_encrypt(cctx->_key, cctx->eax.c, cctx->eax.c);

			cctx->eax.t_size = 0;
		}

		memcpy(cctx->eax.t, in + processed, block_size);
		cctx->eax.t_size += block_size;

		processed += block_size;
	}

	remaining = size - processed;

	// Last block
	if (remaining == 0)
	{
		if (cctx->eax.t_size == block_size)
		{
			XOR16(cctx->eax.t, cctx->eax.t, cctx->eax.b);
			XOR16(cctx->eax.c, cctx->eax.c, cctx->eax.t);
			cctx->_encrypt(cctx->_key, cctx->eax.c, cctx->eax.c);

			cctx->eax.t_size = 0;
		}
	}
	else
	{
		if (cctx->eax.t_size == block_size)
		{
			XOR16(cctx->eax.c, cctx->eax.c, cctx->eax.t);
			cctx->_encrypt(cctx->_key, cctx->eax.c, cctx->eax.c);

			cctx->eax.t_size = 0;
		}

		memset(cctx->eax.t, 0, 16);
		memcpy(cctx->eax.t, in + processed, remaining);
		cctx->eax.t[remaining] = 0x80;

		XOR16(cctx->eax.t, cctx->eax.t, cctx->eax.p);
		XOR16(cctx->eax.c, cctx->eax.c, cctx->eax.t);
		cctx->_encrypt(cctx->_key, cctx->eax.c, cctx->eax.c);
	}
}

uint64_t ectr_update(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t remaining = 0;
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	uint32_t *pc = PTR_OFFSET(cctx->eax.icb, 12);
	uint32_t counter = BSWAP_32(*pc);

	byte_t buffer[16];

	while ((processed + block_size) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->eax.icb, buffer);
		XOR16(pout + processed, pin + processed, buffer);

		++counter;
		*pc = BSWAP_32(counter);

		processed += block_size;
	}

	remaining = size - processed;

	// Last block
	if (remaining > 0)
	{
		cctx->_encrypt(cctx->_key, cctx->eax.icb, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		processed += remaining;
	}

	return processed;
}

static cipher_ctx *cipher_eax_init_common(cipher_ctx *cctx, void *nonce, size_t nonce_size, void *header, size_t header_size)
{
	byte_t buffer[16] = {0};
	byte_t l[16] = {0};

	memset(&cctx->eax, 0, sizeof(cctx->eax));

	// Initialize L
	cctx->_encrypt(cctx->_key, buffer, l);

	// Initialize B
	double_block(cctx->eax.b, l);

	// Initialize P
	double_block(cctx->eax.p, cctx->eax.b);

	// Initialize N
	omac(cctx, cctx->eax.n, 0, nonce, nonce_size);
	memcpy(cctx->eax.icb, cctx->eax.n, 16);

	// Initialize H
	omac(cctx, cctx->eax.h, 1, header, header_size);

	// Initialize T
	cctx->eax.t[15] = 0x2;
	cctx->eax.t_size = 16;

	return cctx;
}

cipher_ctx *cipher_eax_encrypt_init(cipher_ctx *cctx, void *nonce, size_t nonce_size, void *header, size_t header_size)
{
	return cipher_eax_init_common(cctx, nonce, nonce_size, header, header_size);
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

	ohash_update(cctx, ciphertext, ROUND_DOWN(plaintext_size, cctx->block_size));

	return result;
}

uint64_t cipher_eax_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
								  void *tag, byte_t tag_size)
{
	uint64_t result = 0;
	byte_t computed_tag[16] = {0};

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	result = ectr_update(cctx, plaintext, ciphertext, plaintext_size);
	cctx->eax.data_size += result;

	ohash_final(cctx, ciphertext, plaintext_size);

	XOR16(computed_tag, cctx->eax.n, cctx->eax.c);
	XOR16(computed_tag, computed_tag, cctx->eax.h);

	memcpy(tag, computed_tag, MIN(tag_size, 16));

	return result;
}

uint64_t cipher_eax_encrypt(cipher_ctx *cctx, void *nonce, size_t nonce_size, void *header, size_t header_size, void *plaintext,
							size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag, byte_t tag_size)
{
	cctx = cipher_eax_init_common(cctx, nonce, nonce_size, header, header_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_eax_encrypt_final(cctx, plaintext, plaintext_size, ciphertext, ciphertext_size, tag, tag_size);
}

cipher_ctx *cipher_eax_decrypt_init(cipher_ctx *cctx, void *nonce, size_t nonce_size, void *header, size_t header_size)
{
	return cipher_eax_init_common(cctx, nonce, nonce_size, header, header_size);
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

	ohash_update(cctx, ciphertext, ROUND_DOWN(ciphertext_size, cctx->block_size));

	return result;
}

uint64_t cipher_eax_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
								  void *tag, byte_t tag_size)
{
	uint64_t result = 0;
	byte_t computed_tag[16] = {0};

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	result = ectr_update(cctx, ciphertext, plaintext, ciphertext_size);
	cctx->eax.data_size += result;

	ohash_final(cctx, ciphertext, ciphertext_size);

	XOR16(computed_tag, cctx->eax.n, cctx->eax.c);
	XOR16(computed_tag, computed_tag, cctx->eax.h);

	memcpy(tag, computed_tag, MIN(tag_size, 16));

	return result;
}

uint64_t cipher_eax_decrypt(cipher_ctx *cctx, void *nonce, size_t nonce_size, void *header, size_t header_size, void *ciphertext,
							size_t ciphertext_size, void *plaintext, size_t plaintext_size, void *tag, byte_t tag_size)
{
	cctx = cipher_eax_init_common(cctx, nonce, nonce_size, header, header_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_eax_decrypt_final(cctx, ciphertext, ciphertext_size, plaintext, plaintext_size, tag, tag_size);
}

static uint64_t eax_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header,
								   size_t header_size, void *in, size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_eax_encrypt(cctx, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag, tag_size);
}

static uint64_t eax_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header,
								   size_t header_size, void *in, size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_eax_decrypt(cctx, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag, tag_size);
}

uint64_t aes128_eax_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header, size_t header_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return eax_encrypt_common(CIPHER_AES128, key, key_size, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes128_eax_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header, size_t header_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return eax_decrypt_common(CIPHER_AES128, key, key_size, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_eax_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header, size_t header_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return eax_encrypt_common(CIPHER_AES192, key, key_size, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_eax_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header, size_t header_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return eax_decrypt_common(CIPHER_AES192, key, key_size, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_eax_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header, size_t header_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return eax_encrypt_common(CIPHER_AES256, key, key_size, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_eax_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *header, size_t header_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return eax_decrypt_common(CIPHER_AES256, key, key_size, nonce, nonce_size, header, header_size, in, in_size, out, out_size, tag,
							  tag_size);
}
