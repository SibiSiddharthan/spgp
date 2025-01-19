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

// See NIST SP 800-38C Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality

static uint64_t generate_payload_blocks(byte_t *ptr, byte_t *nonce, size_t nonce_size, byte_t *associated_data, size_t ad_size,
										byte_t *payload, size_t payload_size, byte_t t, byte_t q)
{
	size_t pos = 0;
	byte_t flag = 0;
	size_t payload_size_be = BSWAP_64(payload_size);

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

	memcpy(ptr + pos, PTR_OFFSET(&payload_size_be, 8 - q), q);
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
			memset(ptr + pos, 0, ROUND_UP(pos, 16) - pos);
			pos = ROUND_UP(pos, 16);
		}
	}

	// Payload
	memcpy(ptr + pos, payload, payload_size);
	pos += payload_size;

	// Pad with zeroes
	if (pos % 16 != 0)
	{
		memset(ptr + pos, 0, ROUND_UP(pos, 16) - pos);
		pos = ROUND_UP(pos, 16);
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
		uint64_t i_be = BSWAP_64(i);

		ptr[pos] = flag;
		pos += 1;

		memcpy(ptr + pos, nonce, nonce_size);
		pos += nonce_size;

		memcpy(ptr + pos, PTR_OFFSET(&i_be, 8 - q), q);
		pos += q;
	}
}

static void generate_tag(cipher_ctx *cctx, void *in, size_t in_size, void *tag, size_t tag_size)
{
	size_t count = in_size / 16;
	size_t processed = 0;

	byte_t buffer[16];
	byte_t *pin = in;

	cctx->_encrypt(cctx->_key, pin, buffer);

	for (size_t i = 1; i < count; ++i)
	{
		processed += 16;
		XOR16(buffer, buffer, pin + processed);
		cctx->_encrypt(cctx->_key, buffer, buffer);
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
		cctx->_encrypt(cctx->_key, pin + processed, pout + processed);
		processed += 16;
	}
}

uint64_t cipher_ccm_encrypt(cipher_ctx *cctx, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *plaintext,
							size_t plaintext_size, void *ciphertext, size_t ciphertext_size, void *tag, byte_t tag_size)
{
	byte_t *blocks = NULL;
	byte_t *ptag = tag;

	byte_t computed_tag[16] = {0};
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

	if (ciphertext_size < plaintext_size)
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

	// Generate tag
	memset(blocks, 0, blocks_size);

	payload_blocks_size = generate_payload_blocks(blocks, nonce, nonce_size, associated_data, ad_size, plaintext, plaintext_size, t, q);
	generate_tag(cctx, blocks, payload_blocks_size, computed_tag, tag_size);

	// Generate counters
	memset(blocks, 0, blocks_size);

	generate_counter_blocks(blocks, counters_size, nonce, nonce_size, q);
	encrypt_counters(cctx, blocks, blocks, counters_size);

	// Output ciphertext.
	for (size_t i = 0; i < plaintext_size; ++i)
	{
		pout[i] = pin[i] ^ blocks[i + 16];
	}

	// First block is for the tag.
	for (size_t i = 0; i < tag_size; ++i)
	{
		ptag[i] = computed_tag[i] ^ blocks[i];
	}

	free(blocks);

	return plaintext_size;
}

uint64_t cipher_ccm_decrypt(cipher_ctx *cctx, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *ciphertext,
							size_t ciphertext_size, void *plaintext, size_t plaintext_size, void *tag, byte_t tag_size)
{
	byte_t *blocks = NULL;
	byte_t *ptag = tag;

	byte_t computed_tag[16] = {0};
	byte_t first_block[16] = {0};
	byte_t t = 0;
	byte_t n = 0;
	byte_t q = 0;

	size_t blocks_size = ROUND_UP(10 + ad_size, 16) + ROUND_UP(ciphertext_size, 16) + 16;
	size_t counters_size = ROUND_UP(ciphertext_size, 16) + 16;
	size_t payload_blocks_size = 0;
	size_t total_blocks_size = blocks_size;

	byte_t *pin = ciphertext;
	byte_t *pout = plaintext;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (plaintext_size < ciphertext_size)
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
	blocks = malloc(total_blocks_size);

	if (blocks == NULL)
	{
		return 0;
	}

	// Generate counters
	memset(blocks, 0, blocks_size);

	generate_counter_blocks(blocks, counters_size, nonce, nonce_size, q);
	encrypt_counters(cctx, blocks, blocks, counters_size);

	// Copy the first block
	memcpy(first_block, blocks, 16);

	// Output plaintext to temporary.
	for (size_t i = 0; i < ciphertext_size; ++i)
	{
		pout[i] = pin[i] ^ blocks[i + 16];
	}

	// Generate tag
	memset(blocks, 0, blocks_size);

	payload_blocks_size = generate_payload_blocks(blocks, nonce, nonce_size, associated_data, ad_size, plaintext, ciphertext_size, t, q);
	generate_tag(cctx, blocks, payload_blocks_size, computed_tag, tag_size);

	for (size_t i = 0; i < tag_size; ++i)
	{
		ptag[i] = computed_tag[i] ^ first_block[i];
	}

	free(blocks);

	return ciphertext_size;
}

static uint64_t ccm_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size,
								   void *associated_data, size_t ad_size, void *in, size_t in_size, void *out, size_t out_size, void *tag,
								   byte_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ccm_encrypt(cctx, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag, tag_size);
}

static uint64_t ccm_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *nonce, byte_t nonce_size,
								   void *associated_data, size_t ad_size, void *in, size_t in_size, void *out, size_t out_size, void *tag,
								   byte_t tag_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_ccm_decrypt(cctx, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag, tag_size);
}

uint64_t aes128_ccm_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ccm_encrypt_common(CIPHER_AES128, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes128_ccm_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ccm_decrypt_common(CIPHER_AES128, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_ccm_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ccm_encrypt_common(CIPHER_AES192, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes192_ccm_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ccm_decrypt_common(CIPHER_AES192, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_ccm_encrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ccm_encrypt_common(CIPHER_AES256, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}

uint64_t aes256_ccm_decrypt(void *key, size_t key_size, void *nonce, byte_t nonce_size, void *associated_data, size_t ad_size, void *in,
							size_t in_size, void *out, size_t out_size, void *tag, byte_t tag_size)
{
	return ccm_decrypt_common(CIPHER_AES256, key, key_size, nonce, nonce_size, associated_data, ad_size, in, in_size, out, out_size, tag,
							  tag_size);
}
