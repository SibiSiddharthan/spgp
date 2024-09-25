/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <aes.h>
#include <aria.h>
#include <camellia.h>
#include <des.h>
#include <twofish.h>
#include <chacha20.h>

#include <ptr.h>

static inline size_t get_ctx_size(cipher_algorithm algorithm)
{
	switch (algorithm)
	{
	// AES
	case CIPHER_AES128:
	case CIPHER_AES192:
	case CIPHER_AES256:
		return sizeof(aes_key);
	// ARIA
	case CIPHER_ARIA128:
	case CIPHER_ARIA192:
	case CIPHER_ARIA256:
		return sizeof(aria_key);
	// CAMELLIA
	case CIPHER_CAMELLIA128:
	case CIPHER_CAMELLIA192:
	case CIPHER_CAMELLIA256:
		return sizeof(camellia_key);
	// CHACHA
	case CIPHER_CHACHA20:
		return sizeof(chacha20_key);
	// TDES
	case CIPHER_TDES:
		return sizeof(tdes_key);
	// TWOFISH
	case CIPHER_TWOFISH128:
	case CIPHER_TWOFISH192:
	case CIPHER_TWOFISH256:
		return sizeof(twofish_key);
	default:
		return 0;
	}
}

static void *cipher_key_init(cipher_ctx *cctx, void *key, size_t key_size)
{
	switch (cctx->algorithm)
	{
	// AES
	case CIPHER_AES128:
		return aes_key_init(cctx->_key, sizeof(aes_key), AES128, key, key_size);
	case CIPHER_AES192:
		return aes_key_init(cctx->_key, sizeof(aes_key), AES192, key, key_size);
	case CIPHER_AES256:
		return aes_key_init(cctx->_key, sizeof(aes_key), AES256, key, key_size);

	// ARIA
	case CIPHER_ARIA128:
		return aria_key_init(cctx->_key, sizeof(aria_key), ARIA128, key, key_size);
	case CIPHER_ARIA192:
		return aria_key_init(cctx->_key, sizeof(aria_key), ARIA192, key, key_size);
	case CIPHER_ARIA256:
		return aria_key_init(cctx->_key, sizeof(aria_key), ARIA256, key, key_size);

	// CAMELLIA
	case CIPHER_CAMELLIA128:
		return camellia_key_init(cctx->_key, sizeof(camellia_key), CAMELLIA128, key, key_size);
	case CIPHER_CAMELLIA192:
		return camellia_key_init(cctx->_key, sizeof(camellia_key), CAMELLIA192, key, key_size);
	case CIPHER_CAMELLIA256:
		return camellia_key_init(cctx->_key, sizeof(camellia_key), CAMELLIA256, key, key_size);

	// CHACHA
	// case CIPHER_CHACHA20:
	//	if (key_size != CHACHA20_KEY_SIZE)
	//	{
	//		return NULL;
	//	}
	//	_ctx = chacha20_key_init(_ctx, ctx_size, key, NULL);

	// TDES
	case CIPHER_TDES:
	{
		int32_t status = 0;
		byte_t k1[DES_KEY_SIZE], k2[DES_KEY_SIZE], k3[DES_KEY_SIZE];

		status = tdes_decode_key(key, key_size, k1, k2, k3);

		if (status == -1)
		{
			return NULL;
		}

		return tdes_key_init(cctx->_key, sizeof(tdes_key), k1, k2, k3, false);
	}

	// TWOFISH
	case CIPHER_TWOFISH128:
		return twofish_key_init(cctx->_key, sizeof(twofish_key), TWOFISH128, key, key_size);
	case CIPHER_TWOFISH192:
		return twofish_key_init(cctx->_key, sizeof(twofish_key), TWOFISH192, key, key_size);
	case CIPHER_TWOFISH256:
		return twofish_key_init(cctx->_key, sizeof(twofish_key), TWOFISH256, key, key_size);
	}

	return NULL;
}

size_t cipher_ctx_size(cipher_algorithm algorithm)
{
	return sizeof(cipher_ctx) + get_ctx_size(algorithm);
}

cipher_ctx *cipher_init(void *ptr, size_t size, cipher_algorithm algorithm, void *key, size_t key_size)
{
	cipher_ctx *cctx = (cipher_ctx *)ptr;

	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(cipher_ctx) + ctx_size;

	uint32_t block_size = 16;

	void *_ctx;
	void (*_encrypt)(void *, void *, void *);
	void (*_decrypt)(void *, void *, void *);

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	memset(cctx, 0, sizeof(cipher_ctx));

	_ctx = PTR_OFFSET(cctx, sizeof(cipher_ctx));

	switch (algorithm)
	{
	// AES
	case CIPHER_AES128:
		_encrypt = (void (*)(void *, void *, void *))aes128_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))aes128_decrypt_block;
		break;
	case CIPHER_AES192:
		_encrypt = (void (*)(void *, void *, void *))aes192_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))aes192_decrypt_block;
		break;
	case CIPHER_AES256:
		_ctx = aes_key_init(_ctx, ctx_size, AES256, key, key_size);
		_encrypt = (void (*)(void *, void *, void *))aes256_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))aes256_decrypt_block;
		break;

	// ARIA
	case CIPHER_ARIA128:
		_encrypt = (void (*)(void *, void *, void *))aria128_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))aria128_decrypt_block;
		break;
	case CIPHER_ARIA192:
		_encrypt = (void (*)(void *, void *, void *))aria192_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))aria192_decrypt_block;
		break;
	case CIPHER_ARIA256:
		_encrypt = (void (*)(void *, void *, void *))aria256_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))aria256_decrypt_block;
		break;

	// CAMELLIA
	case CIPHER_CAMELLIA128:
		_encrypt = (void (*)(void *, void *, void *))camellia128_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))camellia128_decrypt_block;
		break;
	case CIPHER_CAMELLIA192:
		_encrypt = (void (*)(void *, void *, void *))camellia192_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))camellia192_decrypt_block;
		break;
	case CIPHER_CAMELLIA256:
		_encrypt = (void (*)(void *, void *, void *))camellia256_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))camellia256_decrypt_block;
		break;

	// CHACHA
	// case CIPHER_CHACHA20:

	// TDES
	case CIPHER_TDES:
		block_size = DES_BLOCK_SIZE;
		_encrypt = (void (*)(void *, void *, void *))tdes_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))tdes_encrypt_block;
		break;

	// TWOFISH
	case CIPHER_TWOFISH128:
	case CIPHER_TWOFISH192:
	case CIPHER_TWOFISH256:
		_encrypt = (void (*)(void *, void *, void *))twofish_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))twofish_decrypt_block;
		break;
	}

	cctx->algorithm = algorithm;
	cctx->block_size = block_size;
	cctx->ctx_size = required_size;

	cctx->_key = _ctx;
	cctx->_encrypt = _encrypt;
	cctx->_decrypt = _decrypt;

	_ctx = cipher_key_init(cctx, key, key_size);

	if (_ctx == NULL)
	{
		return NULL;
	}

	return cctx;
}

cipher_ctx *cipher_new(cipher_algorithm algorithm, void *key, size_t key_size)
{
	cipher_ctx *cctx = NULL;
	cipher_ctx *result = NULL;

	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(cipher_ctx) + ctx_size;

	cctx = (cipher_ctx *)malloc(required_size);

	if (cctx == NULL)
	{
		return NULL;
	}

	result = cipher_init(cctx, required_size, algorithm, key, key_size);

	if (result == NULL)
	{
		free(cctx);
	}

	return cctx;
}

void cipher_delete(cipher_ctx *cctx)
{
	// Set these to invalid values.
	cctx->algorithm = -1;

	memset(cctx->_key, 0, cctx->ctx_size);
	free(cctx);
}

cipher_ctx *cipher_reset(cipher_ctx *cctx, void *key, size_t key_size)
{
	void *ctx = NULL;

	ctx = cipher_key_init(cctx, key, key_size);

	if (ctx == NULL)
	{
		return NULL;
	}

	return cctx;
}
