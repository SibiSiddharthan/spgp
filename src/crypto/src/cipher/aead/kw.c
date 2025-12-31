/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cipher.h>

#include <stdlib.h>
#include <string.h>

// See NIST SP 800-38F Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping

static void W(cipher_ctx *cctx, byte_t *material, size_t size, byte_t *result)
{
	size_t n = size / 8;
	size_t s = 6 * (n - 1);

	uint64_t A = 0, *S = NULL, *R = NULL;

	S = (uint64_t *)material;
	A = S[0];
	R = S;

	for (uint64_t t = 1; t <= s; ++t)
	{
		uint64_t plaintext[2], ciphertext[2];

		plaintext[0] = A;
		plaintext[1] = R[1];

		cctx->_encrypt(cctx->_key, plaintext, ciphertext);

		for (uint64_t i = 1; i <= n - 2; ++i)
		{
			R[i] = R[i + 1];
		}

		A = ciphertext[0] ^ BSWAP_64(t);
		R[n - 1] = ciphertext[1];
	}

	memcpy(result, &A, 8);
	memcpy(result + 8, &R[1], size - 8);
}

static void iW(cipher_ctx *cctx, byte_t *material, size_t size, byte_t *result)
{
	size_t n = size / 8;
	size_t s = 6 * (n - 1);

	uint64_t A = 0, *S = NULL, *R = NULL;

	S = (uint64_t *)material;
	A = S[0];
	R = S;

	for (uint64_t t = s; t >= 1; --t)
	{
		uint64_t plaintext[2], ciphertext[2];

		ciphertext[0] = A ^ BSWAP_64(t);
		ciphertext[1] = R[n - 1];

		cctx->_decrypt(cctx->_key, ciphertext, plaintext);

		for (uint64_t i = n - 2; i >= 1; --i)
		{
			R[i + 1] = R[i];
		}

		A = plaintext[0];
		R[1] = plaintext[1];
	}

	memcpy(result, &A, 8);
	memcpy(result + 8, &R[1], size - 8);
}

uint32_t cipher_key_wrap_encrypt(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	byte_t icv1[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
	byte_t *material = NULL;
	size_t material_size = in_size + 8;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (in_size % 8 != 0)
	{
		return 0;
	}

	if (in_size < 16)
	{
		return 0;
	}

	if (out_size < material_size)
	{
		return 0;
	}

	material = malloc(material_size);

	if (material == NULL)
	{
		return 0;
	}

	memcpy(material, icv1, 8);
	memcpy(material + 8, in, in_size);

	W(cctx, material, material_size, out);

	free(material);

	return material_size;
}

uint32_t cipher_key_wrap_decrypt(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	byte_t icv1[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
	byte_t *result = NULL;
	size_t result_size = in_size;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (in_size % 8 != 0)
	{
		return 0;
	}

	if (in_size < 24)
	{
		return 0;
	}

	if (out_size < (in_size - 8))
	{
		return 0;
	}

	result = malloc(result_size);

	if (result == NULL)
	{
		return 0;
	}

	iW(cctx, in, in_size, result);

	if (memcmp(result, icv1, 8) != 0)
	{
		free(result);
		return 0;
	}

	memcpy(out, result + 8, result_size - 8);

	free(result);

	return result_size - 8;
}

uint32_t cipher_key_wrap_pad_encrypt(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	byte_t icv2[4] = {0xA6, 0x59, 0x59, 0xA6};
	byte_t *material = NULL;
	size_t padding_size = ROUND_UP(in_size, 8) - in_size;
	size_t material_size = in_size + 4 + 4 + padding_size;
	size_t pos = 0;

	uint32_t be_size = BSWAP_32((uint32_t)in_size);

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (out_size < material_size)
	{
		return 0;
	}

	material = malloc(material_size);

	if (material == NULL)
	{
		return 0;
	}

	memcpy(material + pos, icv2, 4);
	pos += 4;

	memcpy(material + pos, &be_size, 4);
	pos += 4;

	memcpy(material + pos, in, in_size);
	pos += in_size;

	memset(material + pos, 0, padding_size);

	if (in_size < 8)
	{
		cctx->_encrypt(cctx->_key, material, out);
	}
	else
	{
		W(cctx, material, material_size, out);
	}

	free(material);

	return material_size;
}

uint32_t cipher_key_wrap_pad_decrypt(cipher_ctx *cctx, void *in, size_t in_size, void *out, size_t out_size)
{
	uint32_t status = 0;

	byte_t icv2[4] = {0xA6, 0x59, 0x59, 0xA6};
	byte_t *result = NULL;
	size_t result_size = in_size;
	uint32_t material_size = 0;
	int64_t padding_size = 0;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (in_size % 8 != 0)
	{
		return 0;
	}

	if (in_size < 16)
	{
		return 0;
	}

	if (out_size < (in_size - 8))
	{
		return 0;
	}

	result = malloc(result_size);

	if (result == NULL)
	{
		return 0;
	}

	if (in_size == 16)
	{
		cctx->_decrypt(cctx->_key, in, result);
	}
	else
	{
		iW(cctx, in, in_size, result);
	}

	// Check icv2
	if (memcmp(result, icv2, 4) != 0)
	{
		goto finish;
	}

	material_size = BSWAP_32(*(uint32_t *)&result[4]);
	padding_size = 8 * ((in_size / 8) - 1) - material_size;

	// Check padding
	if (padding_size < 0 || padding_size > 7)
	{
		goto finish;
	}

	for (size_t i = material_size + 8; i < result_size; ++i)
	{
		if (result[i] != 0)
		{
			goto finish;
		}
	}

	memcpy(out, result + 8, material_size);

	status = material_size;

finish:
	free(result);
	return status;
}

static uint32_t key_wrap_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *in, size_t in_size, void *out,
										size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_key_wrap_encrypt(cctx, in, in_size, out, out_size);
}

static uint32_t key_wrap_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *in, size_t in_size, void *out,
										size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_key_wrap_decrypt(cctx, in, in_size, out, out_size);
}

static uint32_t key_wrap_pad_encrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *in, size_t in_size, void *out,
											size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_key_wrap_pad_encrypt(cctx, in, in_size, out, out_size);
}

static uint32_t key_wrap_pad_decrypt_common(cipher_algorithm algorithm, void *key, size_t key_size, void *in, size_t in_size, void *out,
											size_t out_size)
{
	// A big enough buffer for the cipher_ctx.
	cipher_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cipher_init(buffer, 512, 0, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	return cipher_key_wrap_pad_decrypt(cctx, in, in_size, out, out_size);
}

uint32_t aes128_key_wrap_encrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_encrypt_common(CIPHER_AES128, key, key_size, in, in_size, out, out_size);
}

uint32_t aes128_key_wrap_decrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_decrypt_common(CIPHER_AES128, key, key_size, in, in_size, out, out_size);
}

uint32_t aes192_key_wrap_encrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_encrypt_common(CIPHER_AES192, key, key_size, in, in_size, out, out_size);
}

uint32_t aes192_key_wrap_decrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_decrypt_common(CIPHER_AES192, key, key_size, in, in_size, out, out_size);
}

uint32_t aes256_key_wrap_encrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_encrypt_common(CIPHER_AES256, key, key_size, in, in_size, out, out_size);
}

uint32_t aes256_key_wrap_decrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_decrypt_common(CIPHER_AES256, key, key_size, in, in_size, out, out_size);
}

uint32_t aes128_key_wrap_pad_encrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_pad_encrypt_common(CIPHER_AES128, key, key_size, in, in_size, out, out_size);
}

uint32_t aes128_key_wrap_pad_decrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_pad_decrypt_common(CIPHER_AES128, key, key_size, in, in_size, out, out_size);
}

uint32_t aes192_key_wrap_pad_encrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_pad_encrypt_common(CIPHER_AES192, key, key_size, in, in_size, out, out_size);
}

uint32_t aes192_key_wrap_pad_decrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_pad_decrypt_common(CIPHER_AES192, key, key_size, in, in_size, out, out_size);
}

uint32_t aes256_key_wrap_pad_encrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_pad_encrypt_common(CIPHER_AES256, key, key_size, in, in_size, out, out_size);
}

uint32_t aes256_key_wrap_pad_decrypt(void *key, size_t key_size, void *in, size_t in_size, void *out, size_t out_size)
{
	return key_wrap_pad_decrypt_common(CIPHER_AES256, key, key_size, in, in_size, out, out_size);
}
