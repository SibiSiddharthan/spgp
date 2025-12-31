/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cipher.h>
#include <xor.h>

#include <string.h>

static inline void SHL128_1(byte_t buffer[16], byte_t bit)
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	uint64_t x1 = *t1;
	uint64_t x2 = *t2;

	x1 = BSWAP_64(x1);
	x2 = BSWAP_64(x2);

	x1 = ((x1 << 1) | ((x2 >> 63) & 0x1));
	x2 = ((x2 << 1) | (bit & 0x1));

	*t1 = BSWAP_64(x1);
	*t2 = BSWAP_64(x2);
}

static inline void SHL128_8(byte_t buffer[16], byte_t byte)
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = (*t1 >> 8 | ((*t2 & 0xFF) << 56));
	*t2 = (*t2 >> 8 | ((uint64_t)byte << 56));
}

static inline void SHL128_64(byte_t buffer[16], uint64_t qword)
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = *t2;
	*t2 = qword;
}

static inline byte_t get_bit(byte_t b, uint8_t i)
{
	return (b >> (7 - i)) & 0x1;
}

static inline uint64_t cipher_cfb1_encrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while (processed < size)
	{
		byte_t out_byte = 0;

		for (uint8_t i = 0; i < 8; ++i)
		{
			cctx->_encrypt(cctx->_key, cctx->buffer, temp);
			out_byte |= (get_bit(pin[processed], i) ^ get_bit(temp[0], 0)) << (7 - i);
			SHL128_1(cctx->buffer, get_bit(out_byte, i));
		}

		pout[processed] = out_byte;
		++processed;
	}

	return processed;
}

static inline uint64_t cipher_cfb1_decrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while (processed < size)
	{
		byte_t out_byte = 0;

		for (uint8_t i = 0; i < 8; ++i)
		{
			cctx->_encrypt(cctx->_key, cctx->buffer, temp);
			out_byte |= (get_bit(pin[processed], i) ^ get_bit(temp[0], 0)) << (7 - i);
			SHL128_1(cctx->buffer, get_bit(pin[processed], i));
		}

		pout[processed] = out_byte;
		++processed;
	}

	return processed;
}

static inline uint64_t cipher_cfb8_encrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while (processed < size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);
		pout[processed] = pin[processed] ^ temp[0];
		SHL128_8(cctx->buffer, pout[processed]);

		++processed;
	}

	return processed;
}

static inline uint64_t cipher_cfb8_decrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while (processed < size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);
		pout[processed] = pin[processed] ^ temp[0];
		SHL128_8(cctx->buffer, pin[processed]);

		++processed;
	}

	return processed;
}

static inline uint64_t cipher_cfb64_encrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while ((processed + 8) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);
		XOR8(pout + processed, pin + processed, temp);
		SHL128_64(cctx->buffer, *(uint64_t *)(pout + processed));

		processed += 8;
	}

	return processed;
}

static inline uint64_t cipher_cfb64_decrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while ((processed + 8) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);
		XOR8(pout + processed, pin + processed, temp);
		SHL128_64(cctx->buffer, *(uint64_t *)(pin + processed));

		processed += 8;
	}

	return processed;
}

static inline uint64_t cipher_cfb128_encrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while ((processed + 16) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);
		XOR16(pout + processed, pin + processed, temp);
		memcpy(cctx->buffer, pout + processed, 16);

		processed += 16;
	}

	return processed;
}

static inline uint64_t cipher_cfb128_decrypt_core(cipher_ctx *cctx, void *in, void *out, size_t size)
{
	uint64_t processed = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	while ((processed + 16) <= size)
	{
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);
		XOR16(pout + processed, pin + processed, temp);
		memcpy(cctx->buffer, pin + processed, 16);

		processed += 16;
	}

	return processed;
}

static cipher_ctx *cipher_cfb1_init_common(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

static cipher_ctx *cipher_cfb8_init_common(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

cipher_ctx *cipher_cfb1_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_cfb1_init_common(cctx, iv, iv_size);
}

uint64_t cipher_cfb1_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb1_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb1_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb1_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb1_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb1_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb1_encrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb1_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_cfb1_init_common(cctx, iv, iv_size);
}

uint64_t cipher_cfb1_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb1_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb1_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb1_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb1_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb1_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb1_decrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb8_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_cfb8_init_common(cctx, iv, iv_size);
}

uint64_t cipher_cfb8_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb8_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb8_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb8_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb8_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb8_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb8_encrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb8_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	return cipher_cfb8_init_common(cctx, iv, iv_size);
}

uint64_t cipher_cfb8_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}
	return cipher_cfb8_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb8_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb8_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb8_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb8_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb8_decrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb64_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

uint64_t cipher_cfb64_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb64_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb64_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	if (out_size < in_size)
	{
		return 0;
	}

	// Process upto the last block
	processed += cipher_cfb64_encrypt_core(cctx, in, out, in_size);
	remaining = in_size - processed;

	if (remaining > 0)
	{
		// Final encryption
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);

		for (uint64_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ temp[i];
		}

		processed += remaining;
	}

	// Zero the internal buffer.
	memset(cctx->buffer, 0, cctx->block_size);

	return processed;
}

uint64_t cipher_cfb64_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb64_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb64_encrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb64_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{

	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

uint64_t cipher_cfb64_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb64_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb64_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[32] = {0};

	if (out_size < in_size)
	{
		return 0;
	}

	// Process upto the last block.
	processed += cipher_cfb64_decrypt_core(cctx, in, out, in_size);
	remaining = in_size - processed;

	if (remaining > 0)
	{
		// Final decryption
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);

		for (uint64_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ temp[i];
		}

		processed += remaining;
	}

	// Zero the internal buffer.
	memset(cctx->buffer, 0, cctx->block_size);

	return processed;
}

uint64_t cipher_cfb64_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb64_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb64_decrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb128_encrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	if (cctx->block_size < 16)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

uint64_t cipher_cfb128_encrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb128_encrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb128_encrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	if (out_size < in_size)
	{
		return 0;
	}

	// Process upto the last block
	processed += cipher_cfb128_encrypt_core(cctx, in, out, in_size);
	remaining = in_size - processed;

	if (remaining > 0)
	{
		// Final encryption
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);

		for (uint64_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ temp[i];
		}

		processed += remaining;
	}

	// Zero the internal buffer.
	memset(cctx->buffer, 0, cctx->block_size);

	return processed;
}

uint64_t cipher_cfb128_encrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb128_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb128_encrypt_final(cctx, in, in_size, out, out_size);
}

cipher_ctx *cipher_cfb128_decrypt_init(cipher_ctx *cctx, void *iv, size_t iv_size)
{
	if (cctx->algorithm == CIPHER_CHACHA20)
	{
		return NULL;
	}

	if (iv_size != cctx->block_size)
	{
		return NULL;
	}

	if (cctx->block_size < 16)
	{
		return NULL;
	}

	memcpy(cctx->buffer, iv, iv_size);

	return cctx;
}

uint64_t cipher_cfb128_decrypt_update(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	if (out_size < in_size)
	{
		return 0;
	}

	return cipher_cfb128_decrypt_core(cctx, in, out, in_size);
}

uint64_t cipher_cfb128_decrypt_final(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint64_t processed = 0;
	uint64_t remaining = 0;

	byte_t *pin = (byte_t *)in;
	byte_t *pout = (byte_t *)out;

	byte_t temp[16] = {0};

	if (out_size < in_size)
	{
		return 0;
	}

	// Process upto the last block.
	processed += cipher_cfb128_decrypt_core(cctx, in, out, in_size);
	remaining = in_size - processed;

	if (remaining > 0)
	{
		// Final decryption
		cctx->_encrypt(cctx->_key, cctx->buffer, temp);

		for (uint64_t i = 0; i < remaining; ++i)
		{
			pout[processed + i] = pin[processed + i] ^ temp[i];
		}

		processed += remaining;
	}

	// Zero the internal buffer.
	memset(cctx->buffer, 0, cctx->block_size);

	return processed;
}

uint64_t cipher_cfb128_decrypt(cipher_ctx *cctx, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	cctx = cipher_cfb128_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb128_decrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cfb1_encrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
							 void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cfb1_init_common(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb1_encrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cfb1_decrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
							 void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cfb1_init_common(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb1_decrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cfb8_encrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
							 void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cfb8_init_common(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb8_encrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cfb8_decrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
							 void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cfb8_init_common(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb8_decrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cfb128_encrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
							   void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cfb128_encrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb128_encrypt_final(cctx, in, in_size, out, out_size);
}

static uint64_t cfb128_decrypt(cipher_algorithm algorithm, void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size,
							   void *out, size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	cctx = cipher_cfb128_decrypt_init(cctx, iv, iv_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_cfb128_decrypt_final(cctx, in, in_size, out, out_size);
}

uint64_t aes128_cfb1_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb1_encrypt(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes128_cfb1_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb1_decrypt(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_cfb1_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb1_encrypt(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_cfb1_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb1_decrypt(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_cfb1_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb1_encrypt(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_cfb1_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb1_decrypt(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes128_cfb8_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb8_encrypt(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes128_cfb8_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb8_decrypt(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_cfb8_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb8_encrypt(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_cfb8_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb8_decrypt(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_cfb8_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb8_encrypt(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_cfb8_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb8_decrypt(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes128_cfb128_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb128_encrypt(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}
uint64_t aes128_cfb128_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb128_decrypt(CIPHER_AES128, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_cfb128_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb128_encrypt(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes192_cfb128_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb128_decrypt(CIPHER_AES192, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_cfb128_encrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb128_encrypt(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}

uint64_t aes256_cfb128_decrypt(void *key, size_t key_size, void *iv, size_t iv_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return cfb128_decrypt(CIPHER_AES256, key, key_size, iv, iv_size, in, in_size, out, out_size);
}
