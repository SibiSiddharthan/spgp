/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cipher.h>
#include <bitscan.h>
#include <xor.h>

#include <stdlib.h>
#include <string.h>

#include "double-block.h"

// Refer RFC 7253 : The OCB Authenticated-Encryption Algorithm

static void calculate_hash(cipher_ctx *cctx, void *associated_data, size_t ad_size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t buffer[16] = {0};
	byte_t offset[16] = {0};

	byte_t *pdata = associated_data;

	uint64_t block_count = 0;
	uint8_t ntz = 0;

	while (processed + block_size <= ad_size)
	{
		ntz = block_count == 0 ? 0 : (BSF_64(block_count) + 1);

		if (ntz > cctx->ocb->max_ntz)
		{
			double_block(cctx->ocb->ls[2 + ntz], cctx->ocb->ls[1 + ntz]);
			cctx->ocb->max_ntz += 1;
		}

		XOR16(offset, offset, cctx->ocb->ls[2 + ntz]);
		XOR16(buffer, offset, pdata + processed);

		cctx->_encrypt(cctx->_key, buffer, buffer);
		XOR16(cctx->ocb->osum, cctx->ocb->osum, buffer);

		processed += block_size;
		block_count += 1;
	}

	remaining = ad_size - processed;

	if (remaining > 0)
	{
		memset(buffer, 0, block_size);

		XOR16(offset, offset, cctx->ocb->ls[0]);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			buffer[i] = pdata[processed + i] ^ offset[i];
		}

		buffer[remaining] = 0x80 ^ offset[remaining];

		for (uint8_t i = remaining + 1; i < block_size; ++i)
		{
			buffer[i] = offset[i];
		}

		cctx->_encrypt(cctx->_key, buffer, buffer);
		XOR16(cctx->ocb->osum, cctx->ocb->osum, buffer);

		processed += remaining;
	}
}

static void ocb_checksum_update(cipher_ctx *cctx, void *data, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	while ((processed + block_size) <= size)
	{
		XOR16(cctx->ocb->checksum, cctx->ocb->checksum, PTR_OFFSET(data, processed));
		processed += block_size;
	}

	remaining = size - processed;

	if (remaining > 0)
	{
		byte_t *pdata = data;

		for (uint8_t i = 0; i < remaining; ++i)
		{
			cctx->ocb->checksum[i] ^= pdata[processed + i];
		}

		cctx->ocb->checksum[remaining] ^= 0x80;
	}
}

uint64_t octr_update(cipher_ctx *cctx, void (*cipher_op)(void *, void *, void *), void *in, void *out, size_t size)
{
	const uint16_t block_size = 16;

	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t buffer[16];

	uint8_t ntz = 0;

	while ((processed + block_size) <= size)
	{
		ntz = cctx->ocb->block_count == 0 ? 0 : (BSF_64(cctx->ocb->block_count) + 1);

		if (ntz > cctx->ocb->max_ntz)
		{
			double_block(cctx->ocb->ls[2 + ntz], cctx->ocb->ls[1 + ntz]);
			cctx->ocb->max_ntz += 1;
		}

		XOR16(cctx->ocb->offset, cctx->ocb->offset, cctx->ocb->ls[2 + ntz]);
		XOR16(buffer, cctx->ocb->offset, pin + processed);

		cipher_op(cctx->_key, buffer, buffer);

		XOR16(pout + processed, buffer, cctx->ocb->offset);

		processed += block_size;
		cctx->ocb->block_count += 1;
	}

	remaining = size - processed;

	if (remaining > 0)
	{
		XOR16(cctx->ocb->offset, cctx->ocb->offset, cctx->ocb->ls[0]);

		cctx->_encrypt(cctx->_key, cctx->ocb->offset, buffer);

		for (uint8_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ buffer[i];
		}

		processed += remaining;
	}

	return processed;
}

static cipher_ctx *cipher_ocb_init_common(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *associated_data,
										  size_t ad_size)
{
	byte_t zero[16] = {0};
	byte_t buffer[16] = {0};
	byte_t stretch[24] = {0};
	byte_t bottom = 0;

	size_t required_aead_ctx_size = sizeof(*((cipher_ctx *)NULL)->ocb);

	// Check paramters size
	if (cctx->block_size != 16)
	{
		return NULL;
	}

	if (nonce_size > 15)
	{
		return NULL;
	}

	if (tag_size > 16)
	{
		return NULL;
	}

	if (cctx->aead == NULL)
	{
		cctx->aead_size = required_aead_ctx_size;
		cctx->aead = malloc(cctx->aead_size);

		if (cctx->aead == NULL)
		{
			return NULL;
		}
	}

	if (cctx->aead_size < required_aead_ctx_size)
	{
		return NULL;
	}

	memset(cctx->ocb, 0, required_aead_ctx_size);

	cctx->ocb->tag_size = tag_size;

	// Initialize L
	cctx->_encrypt(cctx->_key, zero, cctx->ocb->ls[0]); // L*
	double_block(cctx->ocb->ls[1], cctx->ocb->ls[0]);   // L$
	double_block(cctx->ocb->ls[2], cctx->ocb->ls[1]);   // L0

	// Calculate sum
	calculate_hash(cctx, associated_data, ad_size);

	// Initialize offset
	memset(cctx->ocb->offset, 0, 16);

	buffer[0] = ((tag_size * 8) % 128) << 1;
	buffer[15 - nonce_size] |= 0x1;
	memcpy(buffer + (16 - nonce_size), nonce, nonce_size);

	bottom = buffer[15] & 0x3F;
	buffer[15] ^= bottom;

	cctx->_encrypt(cctx->_key, buffer, stretch);

	for (uint8_t i = 16; i < 24; ++i)
	{
		stretch[i] = stretch[i - 16] ^ stretch[i - 15];
	}

	for (uint8_t i = 0; i < 16; ++i)
	{
		for (uint8_t j = 0; j < 8; ++j)
		{
			cctx->ocb->offset[i] |= (stretch[((i * 8) + j + bottom) / 8] >> (7 - ((j + bottom) % 8))) << (7 - j);
		}
	}

	return cctx;
}

cipher_ctx *cipher_ocb_encrypt_init(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *associated_data,
									size_t ad_size)
{
	return cipher_ocb_init_common(cctx, tag_size, nonce, nonce_size, associated_data, ad_size);
}

uint64_t cipher_ocb_encrypt_update(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	uint64_t result = 0;

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	result = octr_update(cctx, cctx->_encrypt, plaintext, ciphertext, ROUND_DOWN(plaintext_size, cctx->block_size));
	cctx->ocb->data_size += result;

	ocb_checksum_update(cctx, plaintext, result);

	return result;
}

uint64_t cipher_ocb_encrypt_final(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size,
								  void *tag, byte_t tag_size)
{
	uint64_t result = 0;
	byte_t computed_tag[16];

	if (ciphertext_size < plaintext_size)
	{
		return 0;
	}

	if (tag_size < cctx->ocb->tag_size)
	{
		return 0;
	}

	result = octr_update(cctx, cctx->_encrypt, plaintext, ciphertext, plaintext_size);
	cctx->ocb->data_size += result;

	ocb_checksum_update(cctx, plaintext, result);

	XOR16(computed_tag, cctx->ocb->checksum, cctx->ocb->offset);
	XOR16(computed_tag, computed_tag, cctx->ocb->ls[1]);

	cctx->_encrypt(cctx->_key, computed_tag, computed_tag);

	XOR16(computed_tag, computed_tag, cctx->ocb->osum);

	memcpy(tag, computed_tag, cctx->ocb->tag_size);

	return result;
}

uint64_t cipher_ocb_encrypt(cipher_ctx *cctx, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *plaintext,
							size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag, byte_t tag_size)
{
	cctx = cipher_ocb_init_common(cctx, tag_size, nonce, nonce_size, associated_data, ad_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ocb_encrypt_final(cctx, plaintext, plaintext_size, ciphertext, ciphertext_size, tag, tag_size);
}

cipher_ctx *cipher_ocb_decrypt_init(cipher_ctx *cctx, byte_t tag_size, void *nonce, size_t nonce_size, void *associated_data,
									size_t ad_size)
{
	return cipher_ocb_init_common(cctx, tag_size, nonce, nonce_size, associated_data, ad_size);
}

uint64_t cipher_ocb_decrypt_update(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint64_t result = 0;

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	result = octr_update(cctx, cctx->_decrypt, ciphertext, plaintext, ROUND_DOWN(ciphertext_size, cctx->block_size));
	cctx->ocb->data_size += result;

	ocb_checksum_update(cctx, plaintext, result);

	return result;
}

uint64_t cipher_ocb_decrypt_final(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size,
								  void *tag, byte_t tag_size)
{
	uint64_t result = 0;
	byte_t computed_tag[16];

	if (plaintext_size < ciphertext_size)
	{
		return 0;
	}

	if (tag_size < cctx->ocb->tag_size)
	{
		return 0;
	}

	result = octr_update(cctx, cctx->_decrypt, ciphertext, plaintext, ciphertext_size);
	cctx->ocb->data_size += result;

	ocb_checksum_update(cctx, plaintext, result);

	XOR16(computed_tag, cctx->ocb->checksum, cctx->ocb->offset);
	XOR16(computed_tag, computed_tag, cctx->ocb->ls[1]);

	cctx->_encrypt(cctx->_key, computed_tag, computed_tag);

	XOR16(computed_tag, computed_tag, cctx->ocb->osum);

	memcpy(tag, computed_tag, cctx->ocb->tag_size);

	return result;
}

uint64_t cipher_ocb_decrypt(cipher_ctx *cctx, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *ciphertext,
							size_t ciphertext_size, void *plaintext, size_t plaintext_size, void *tag, byte_t tag_size)
{
	cctx = cipher_ocb_init_common(cctx, tag_size, nonce, nonce_size, associated_data, ad_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ocb_decrypt_final(cctx, ciphertext, ciphertext_size, plaintext, plaintext_size, tag, tag_size);
}

static uint64_t ocb_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size,
								   void *associated_data, size_t ad_size, void *in, size_t in_size, void *out, size_t out_size, void *tag,
								   byte_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[2048];

	cctx = cipher_init(buffer, 2048, CIPHER_AEAD_INIT, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ocb_encrypt(cctx, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag, tag_size);
}

static uint64_t ocb_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size,
								   void *associated_data, size_t ad_size, void *in, size_t in_size, void *out, size_t out_size, void *tag,
								   byte_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[2048];

	cctx = cipher_init(buffer, 2048, CIPHER_AEAD_INIT, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ocb_decrypt(cctx, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag, tag_size);
}

uint64_t aes128_ocb_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ocb_encrypt_common(CIPHER_AES128, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes128_ocb_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ocb_decrypt_common(CIPHER_AES128, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_ocb_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ocb_encrypt_common(CIPHER_AES192, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_ocb_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ocb_decrypt_common(CIPHER_AES192, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_ocb_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ocb_encrypt_common(CIPHER_AES256, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_ocb_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ocb_decrypt_common(CIPHER_AES256, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}
