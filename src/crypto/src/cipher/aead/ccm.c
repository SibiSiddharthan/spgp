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
#include <round.h>
#include <xor.h>

// See NIST SP 800-38C Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality

static uint64_t generate_payload_blocks(byte_t *ptr, byte_t *nonce, size_t nonce_size, byte_t *associated_data, size_t ad_size,
										byte_t *payload, size_t payload_size, byte_t t, byte_t q)
{
	size_t pos = 0;
	byte_t flag = 0;

	// Bit 6 is adata
	flag |= (ad_size > 0) << 6;

	// Bits 3,4,5 is t
	flag |= (((t - 2) / 2) & 0x7) << 3;

	// Bits 0,1,2 is q
	flag |= (q - 1) & 0x7;

	// First block.
	ptr[pos] = flag;
	pos += 1;

	memcpy(ptr + pos, nonce, nonce_size);
	pos += nonce_size;

	memcpy(ptr + pos, &payload_size, q);
	pos += q;

	// Associated data blocks
	if (ad_size > 0)
	{
		// 2 octets
		if (ad_size < (65536 - 256))
		{
			ptr[pos] = ad_size >> 8;
			ptr[pos + 1] = ad_size & 0xFF;

			pos += 2;
		}
		// 6 octets
		else if (ad_size < (1ull << 32))
		{
			uint32_t size = BSWAP_32(ad_size);

			ptr[pos] = 0xFF;
			ptr[pos + 1] = 0xFE;
			memcpy(ptr + pos + 2, &size, 4);

			pos += 6;
		}
		// 10 octets
		else
		{
			uint64_t size = BSWAP_64(ad_size);

			ptr[pos] = 0xFF;
			ptr[pos + 1] = 0xFF;
			memcpy(ptr + pos + 2, &size, 8);

			pos += 10;
		}

		memcpy(ptr + pos, associated_data, ad_size);
		pos += ad_size;

		// Pad with zeroes
		if (pos % 16 != 0)
		{
			memset(ptr + pos, 0, pos % 16);
			pos += (pos % 16);
		}
	}

	// Payload
	memcpy(ptr + pos, payload, payload_size);

	// Pad with zeroes
	if (pos % 16 != 0)
	{
		memset(ptr + pos, 0, pos % 16);
		pos += (pos % 16);
	}

	return pos;
}

static void generate_counter_blocks(byte_t *ptr, size_t counter_size, byte_t *nonce, size_t nonce_size, byte_t q)
{
	size_t pos = 0;
	size_t count = counter_size / 16;
	byte_t flag = (q - 1) & 0x7;

	for (uint64_t i = 0; i < count; ++i)
	{
		ptr[pos] = flag;
		pos += 1;

		memcpy(ptr + pos, nonce, nonce_size);
		pos += nonce_size;

		memcpy(ptr + pos, &i, q);
		pos += q;
	}
}

static void generate_tag(cipher_ctx *cctx, void *in, size_t in_size, void *tag, size_t tag_size)
{
	size_t count = in_size / 16;
	size_t processed = 0;

	byte_t buffer[16];
	byte_t *pin = in;

	cctx->_encrypt(cctx->_ctx, pin, buffer);

	for (size_t i = 1; i < count; ++i)
	{
		XOR16(buffer, buffer, pin + processed);
		cctx->_encrypt(cctx->_ctx, buffer, buffer);
	}

	memcpy(tag, buffer, MIN(tag_size, 16));
}

static void encrypt_counters(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	size_t count = size / 16;
	size_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	for (size_t i = 0; i < count; ++i)
	{
		cctx->_encrypt(cctx->_ctx, pin + processed, pout + processed);
	}
}

uint64_t cipher_ccm_encrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size,
							void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	byte_t *blocks = NULL;

	byte_t tag[16] = {0};
	byte_t t = 0;
	byte_t n = 0;
	byte_t q = 0;

	size_t blocks_size = ROUND_UP(10 + ad_size, 16) + ROUND_UP(plaintext_size, 16) + 16;
	size_t counters_size = ROUND_UP(plaintext_size, 16) + 16;
	size_t payload_blocks_size = 0;

	byte_t *pin = plaintext;
	byte_t *pout = ciphertext;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (ciphertext_size < (plaintext_size + tag_size))
	{
		return 0;
	}

	t = tag_size;
	n = nonce_size;
	q = 15 - n;

	// Allowed tag lengths {4, 6, 8, 10, 12, 14, 16}
	if ((t / 2) < 2 || (t / 2) > 8)
	{
		return 0;
	}

	// Allowed nonce lengths {7, 8, 9, 10, 11, 12, 13}
	if (n < 7 || n > 13)
	{
		return 0;
	}

	// Invalid plaintext size
	if (plaintext_size > (1ull << (8 * q)))
	{
		return 0;
	}

	// Allocate for blocks only.
	blocks = malloc(blocks_size);

	if (blocks == NULL)
	{
		return 0;
	}

	// Generate tag
	memset(blocks, 0, blocks_size);

	payload_blocks_size = generate_payload_blocks(blocks, nonce, nonce_size, associated_data, ad_size, plaintext, plaintext_size, t, q);
	generate_tag(cctx, blocks, payload_blocks_size, tag, tag_size);

	// Generate counters
	memset(blocks, 0, blocks_size);

	generate_counter_blocks(blocks, counters_size, nonce, nonce_size, q);
	encrypt_counters(cctx, blocks, blocks, counters_size);

	// Output ciphertext.
	for (size_t i = 0; i < plaintext_size; ++i)
	{
		pout[i] = pin[i] ^ blocks[i + 16];
	}

	for (size_t i = 0; i < tag_size; ++i)
	{
		pout[i + plaintext_size] = tag[i] ^ blocks[i];
	}

	free(blocks);

	return plaintext_size + tag_size;
}

uint64_t cipher_ccm_decrypt(cipher_ctx *cctx, byte_t tag_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size,
							void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	byte_t *blocks = NULL;

	byte_t expected_tag[16] = {0};
	byte_t actual_tag[16] = {0};
	byte_t t = 0;
	byte_t n = 0;
	byte_t q = 0;

	size_t expected_plaintext_size = ciphertext_size - tag_size;
	size_t blocks_size = ROUND_UP(10 + ad_size, 16) + (2 * ROUND_UP(ciphertext_size, 16)) + 16;
	size_t counters_size = ROUND_UP(expected_plaintext_size, 16) + 16;
	size_t payload_blocks_size = 0;
	size_t plaintext_offset = blocks_size - ROUND_UP(ciphertext_size, 16);

	byte_t *pin = ciphertext;
	byte_t *ptemp = blocks + plaintext_offset;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (ciphertext_size <= tag_size)
	{
		return 0;
	}

	if (plaintext_size < expected_plaintext_size)
	{
		return 0;
	}

	t = tag_size;
	n = nonce_size;
	q = 15 - n;

	// Allowed tag lengths {4, 6, 8, 10, 12, 14, 16}
	if ((t / 2) < 2 || (t / 2) > 8)
	{
		return 0;
	}

	// Allowed nonce lengths {7, 8, 9, 10, 11, 12, 13}
	if (n < 7 || n > 13)
	{
		return 0;
	}

	// Allocate for blocks only.
	blocks = malloc(blocks_size);

	if (blocks == NULL)
	{
		return 0;
	}

	// Generate counters
	memset(blocks, 0, blocks_size);

	generate_counter_blocks(blocks, counters_size, nonce, nonce_size, q);
	encrypt_counters(cctx, blocks, blocks, counters_size);

	for (size_t i = 0; i < tag_size; ++i)
	{
		actual_tag[i] = pin[ciphertext_size - 1 - i] ^ blocks[i];
	}

	// Output plaintext to temporary.
	for (size_t i = 0; i < expected_plaintext_size; ++i)
	{
		ptemp[i] = pin[i] ^ blocks[i + 16];
	}

	// Generate tag
	memset(blocks, 0, blocks_size);

	payload_blocks_size =
		generate_payload_blocks(blocks, nonce, nonce_size, associated_data, ad_size, ptemp, expected_plaintext_size, t, q);
	generate_tag(cctx, blocks, payload_blocks_size, expected_tag, tag_size);

	if (memcmp(actual_tag, expected_tag, tag_size) != 0)
	{
		free(blocks);
		return 0;
	}

	// Copy plaintext from temporary.
	memcpy(plaintext, ptemp, expected_plaintext_size);
	free(blocks);

	return expected_plaintext_size;
}
