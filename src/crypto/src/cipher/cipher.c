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

	_ctx = PTR_OFFSET(cctx, sizeof(cipher_ctx));

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	switch (algorithm)
	{
	// AES
	case CIPHER_AES128:
		_ctx = aes_key_init(_ctx, ctx_size, AES128, key, key_size);
		break;
	case CIPHER_AES192:
		_ctx = aes_key_init(_ctx, ctx_size, AES192, key, key_size);
		break;
	case CIPHER_AES256:
		_ctx = aes_key_init(_ctx, ctx_size, AES256, key, key_size);
		break;

	// ARIA
	case CIPHER_ARIA128:
		_ctx = aria_key_init(_ctx, ctx_size, ARIA128, key, key_size);
		break;
	case CIPHER_ARIA192:
		_ctx = aria_key_init(_ctx, ctx_size, ARIA192, key, key_size);
		break;
	case CIPHER_ARIA256:
		_ctx = aria_key_init(_ctx, ctx_size, ARIA256, key, key_size);
		break;

	// CAMELLIA
	case CIPHER_CAMELLIA128:
		_ctx = camellia_key_init(_ctx, ctx_size, CAMELLIA128, key, key_size);
		break;
	case CIPHER_CAMELLIA192:
		_ctx = camellia_key_init(_ctx, ctx_size, CAMELLIA192, key, key_size);
		break;
	case CIPHER_CAMELLIA256:
		_ctx = camellia_key_init(_ctx, ctx_size, CAMELLIA256, key, key_size);
		break;

	// CHACHA
	// case CIPHER_CHACHA20:
	//	if (key_size != CHACHA20_KEY_SIZE)
	//	{
	//		return NULL;
	//	}
	//	_ctx = chacha20_key_init(_ctx, ctx_size, key, NULL);

	// TDES
	// case CIPHER_TDES:
	//	return sizeof(tdes_key);

	// TWOFISH
	case CIPHER_TWOFISH128:
		_ctx = twofish_key_init(_ctx, ctx_size, TWOFISH128, key, key_size);
		break;
	case CIPHER_TWOFISH192:
		_ctx = twofish_key_init(_ctx, ctx_size, TWOFISH192, key, key_size);
		break;
	case CIPHER_TWOFISH256:
		_ctx = twofish_key_init(_ctx, ctx_size, TWOFISH256, key, key_size);
		break;
	}

	if (_ctx == NULL)
	{
		return NULL;
	}

	cctx->algorithm = algorithm;
	cctx->block_size = block_size;
	cctx->ctx_size = ctx_size;

	cctx->_ctx = _ctx;
	cctx->_encrypt = _encrypt;
	cctx->_decrypt = _decrypt;

	return _ctx;
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

	memset(cctx->_ctx, 0, cctx->ctx_size);
	free(cctx);
}
