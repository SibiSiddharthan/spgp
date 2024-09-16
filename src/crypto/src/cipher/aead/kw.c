/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <byteswap.h>

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
		plaintext[1] = R[0];

		cctx->_encrypt(cctx->_ctx, plaintext, ciphertext);

		A = ciphertext[0] ^ t;

		for (uint64_t i = 1; i <= n - 2; ++i)
		{
			R[i] = R[i + 1];
		}

		plaintext[1] = R[0];
		cctx->_encrypt(cctx->_ctx, plaintext, ciphertext);

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

		ciphertext[0] = A ^ t;
		ciphertext[1] = R[n - 1];

		cctx->_decrypt(cctx->_ctx, ciphertext, plaintext);

		A = ciphertext[0] ^ t;
		R[1] = ciphertext[1];

		for (uint64_t i = 1; i < n - 2; ++i)
		{
			R[i + 1] = R[i];
		}
	}

	memcpy(result, &A, 8);
	memcpy(result + 8, R, size - 8);
}

uint32_t cipher_key_wrap_encrypt(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	byte_t icv1[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
	byte_t *material = NULL;
	size_t material_size = plaintext_size + 8;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (plaintext_size % 8 != 0)
	{
		return 0;
	}

	if (plaintext_size < 16)
	{
		return 0;
	}

	if (ciphertext_size < material_size)
	{
		return 0;
	}

	material = malloc(material_size);

	if (material == NULL)
	{
		return 0;
	}

	memcpy(material, icv1, 8);
	memcpy(material + 8, plaintext, plaintext_size);

	W(cctx, material, material_size, ciphertext);

	free(material);

	return material_size;
}

uint32_t cipher_key_wrap_decrypt(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	byte_t icv1[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
	byte_t *result = NULL;
	size_t result_size = ciphertext_size;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (ciphertext_size % 8 != 0)
	{
		return 0;
	}

	if (ciphertext_size < 24)
	{
		return 0;
	}

	if (plaintext_size < ciphertext_size - 8)
	{
		return 0;
	}

	result = malloc(result_size);

	if (result == NULL)
	{
		return 0;
	}

	iW(cctx, ciphertext, ciphertext_size, result);

	if (memcmp(result, icv1, 8) != 0)
	{
		free(result);
		return 0;
	}

	memcpy(plaintext, result + 8, result_size - 8);

	free(result);

	return result_size - 8;
}

uint32_t cipher_key_wrap_pad_encrypt(cipher_ctx *cctx, void *plaintext, size_t plaintext_size, void *ciphertext, size_t ciphertext_size)
{
	byte_t icv2[4] = {0xA6, 0x59, 0x59, 0xA6};
	byte_t *material = NULL;
	size_t padding_size = plaintext_size % 8;
	size_t material_size = plaintext_size + 4 + 4 + padding_size;
	size_t pos = 0;

	uint32_t be_size = BSWAP_32((uint32_t)plaintext_size);

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (ciphertext_size < material_size)
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

	memcpy(material + pos, plaintext, plaintext_size);
	pos += plaintext_size;

	memset(material + pos, 0, padding_size);

	if (plaintext_size < 8)
	{
		cctx->_encrypt(cctx->_ctx, material, ciphertext);
	}
	else
	{
		W(cctx, material, material_size, ciphertext);
	}

	free(material);

	return material_size;
}

uint32_t cipher_key_wrap_pad_decrypt(cipher_ctx *cctx, void *ciphertext, size_t ciphertext_size, void *plaintext, size_t plaintext_size)
{
	uint32_t status = 0;

	byte_t icv2[4] = {0xA6, 0x59, 0x59, 0xA6};
	byte_t *result = NULL;
	size_t result_size = ciphertext_size;
	uint32_t material_size = 0;
	int64_t padding_size = 0;

	if (cctx->block_size != 16)
	{
		return 0;
	}

	if (ciphertext_size < 16)
	{
		return 0;
	}

	if (plaintext_size < ciphertext_size - 8)
	{
		return 0;
	}

	result = malloc(result_size);

	if (result == NULL)
	{
		return 0;
	}

	if (ciphertext_size == 16)
	{
		cctx->_decrypt(cctx->_ctx, ciphertext, result);
	}
	else
	{
		iW(cctx, ciphertext, ciphertext_size, result);
	}

	if (memcmp(result, icv2, 4) != 0)
	{
		goto finish;
	}

	material_size = BSWAP_32(*(uint32_t *)&result[4]);
	padding_size = 8 * ((ciphertext_size / 8) - 1) - material_size;

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

	memcpy(plaintext, result + 8, material_size);

	status = material_size;

finish:
	free(result);
	return status;
}
