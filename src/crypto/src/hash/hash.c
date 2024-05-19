/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <hash.h>
#include <md5.h>
#include <ripemd.h>
#include <sha.h>
#include <blake2.h>

static inline size_t get_ctx_size(hash_algorithm algorithm)
{
	switch (algorithm)
	{
	case HASH_MD5:
		return sizeof(md5_ctx);
	case HASH_RIPEMD160:
		return sizeof(ripemd160_ctx);
	case HASH_BLAKE2B:
		return sizeof(blake2b_ctx);
	case HASH_BLAKE2S:
		return sizeof(blake2s_ctx);
	case HASH_SHA1:
		return sizeof(sha1_ctx);
	case HASH_SHA224:
	case HASH_SHA256:
		return sizeof(sha256_ctx);
	case HASH_SHA384:
	case HASH_SHA512:
	case HASH_SHA512_224:
	case HASH_SHA512_256:
		return sizeof(sha512_ctx);
	case HASH_SHA3_224:
	case HASH_SHA3_256:
	case HASH_SHA3_384:
	case HASH_SHA3_512:
		return sizeof(sha3_ctx);
	default:
		return 0;
	}
}

size_t hash_ctx_size(hash_algorithm algorithm)
{
	return sizeof(hash_ctx) + get_ctx_size(algorithm);
}

static hash_ctx *hash_init_checked(void *ptr, hash_algorithm algorithm, size_t ctx_size)
{
	hash_ctx *hctx = NULL;
	size_t hash_size = 0;
	size_t max_input_size = 0xFFFFFFFFFFFFFFFF;

	void *_ctx = NULL;
	void (*_reset)(void *ctx) = NULL;
	void (*_update)(void *ctx, void *data, size_t size) = NULL;
	void (*_final)(void *ctx, byte_t *hash) = NULL;
	void (*_final_size)(void *ctx, byte_t *hash, size_t size) = NULL;

	hctx = (hash_ctx *)ptr;
	memset(hctx, 0, sizeof(hash_ctx) + ctx_size);

	_ctx = (void *)((byte_t *)hctx + sizeof(hash_ctx));

	switch (algorithm)
	{
	case HASH_MD5:
	{
		hash_size = MD5_HASH_SIZE;
		_ctx = md5_init(_ctx, ctx_size);
		_reset = (void (*)(void *))md5_reset;
		_update = (void (*)(void *, void *, size_t))md5_update;
		_final = (void (*)(void *, byte_t *))md5_final;
	}
	break;
	case HASH_RIPEMD160:
	{
		hash_size = RIPEMD160_HASH_SIZE;
		_ctx = ripemd160_init(_ctx, ctx_size);
		_reset = (void (*)(void *))ripemd160_reset;
		_update = (void (*)(void *, void *, size_t))ripemd160_update;
		_final = (void (*)(void *, byte_t *))ripemd160_final;
	}
	break;
	case HASH_BLAKE2B:
	{
		blake2b_param b2bp = BLAKE2_PARAM_INIT(64, 0);
		hash_size = BLAKE2B_MAX_HASH_SIZE;
		_ctx = blake2b_init(_ctx, ctx_size, &b2bp, NULL);
		_update = (void (*)(void *, void *, size_t))blake2b_update;
		_final_size = (void (*)(void *, byte_t *, size_t))blake2b_final;
	}
	break;
	case HASH_BLAKE2S:
	{
		blake2s_param b2sp = BLAKE2_PARAM_INIT(32, 0);
		hash_size = BLAKE2S_MAX_HASH_SIZE;
		_ctx = blake2s_init(_ctx, ctx_size, &b2sp, NULL);
		_update = (void (*)(void *, void *, size_t))blake2s_update;
		_final_size = (void (*)(void *, byte_t *, size_t))blake2s_final;
	}
	break;
	case HASH_SHA1:
	{
		hash_size = SHA1_HASH_SIZE;
		_ctx = sha1_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha1_reset;
		_update = (void (*)(void *, void *, size_t))sha1_update;
		_final = (void (*)(void *, byte_t *))sha1_final;
	}
	break;
	case HASH_SHA224:
	{
		hash_size = SHA224_HASH_SIZE;
		_ctx = sha224_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha224_reset;
		_update = (void (*)(void *, void *, size_t))sha224_update;
		_final = (void (*)(void *, byte_t *))sha224_final;
	}
	break;
	case HASH_SHA256:
	{
		hash_size = SHA256_HASH_SIZE;
		_ctx = sha256_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha256_reset;
		_update = (void (*)(void *, void *, size_t))sha256_update;
		_final = (void (*)(void *, byte_t *))sha256_final;
	}
	break;
	case HASH_SHA384:
	{
		hash_size = SHA384_HASH_SIZE;
		_ctx = sha384_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha384_reset;
		_update = (void (*)(void *, void *, size_t))sha384_update;
		_final = (void (*)(void *, byte_t *))sha384_final;
	}
	break;
	case HASH_SHA512:
	{
		hash_size = SHA512_HASH_SIZE;
		_ctx = sha512_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha512_reset;
		_update = (void (*)(void *, void *, size_t))sha512_update;
		_final = (void (*)(void *, byte_t *))sha512_final;
	}
	break;
	case HASH_SHA512_224:
	{
		hash_size = SHA512_224_HASH_SIZE;
		_ctx = sha512_224_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha512_224_reset;
		_update = (void (*)(void *, void *, size_t))sha512_224_update;
		_final = (void (*)(void *, byte_t *))sha512_224_final;
	}
	break;
	case HASH_SHA512_256:
	{
		hash_size = SHA512_256_HASH_SIZE;
		_ctx = sha512_256_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha512_256_reset;
		_update = (void (*)(void *, void *, size_t))sha512_256_update;
		_final = (void (*)(void *, byte_t *))sha512_256_final;
	}
	break;
	case HASH_SHA3_224:
	{
		hash_size = SHA3_224_HASH_SIZE;
		_ctx = sha3_init(_ctx, ctx_size, SHA3_224);
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	case HASH_SHA3_256:
	{
		hash_size = SHA3_256_HASH_SIZE;
		_ctx = sha3_init(_ctx, ctx_size, SHA3_256);
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	case HASH_SHA3_384:
	{
		hash_size = SHA3_384_HASH_SIZE;
		_ctx = sha3_init(_ctx, ctx_size, SHA3_384);
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	case HASH_SHA3_512:
	{
		hash_size = SHA3_512_HASH_SIZE;
		_ctx = sha3_init(_ctx, ctx_size, SHA3_512);
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	}

	hctx->algorithm = algorithm;
	hctx->ctx_size = ctx_size;
	hctx->hash_size = hash_size;
	hctx->max_input_size = max_input_size;

	hctx->_ctx = _ctx;
	hctx->_reset = _reset;
	hctx->_update = _update;
	hctx->_final = _final;
	hctx->_final_size = _final_size;

	return hctx;
}

hash_ctx *hash_init(void *ptr, size_t size, hash_algorithm algorithm)
{
	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(hash_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	return hash_init_checked(ptr, algorithm, ctx_size);
}

hash_ctx *hash_new(hash_algorithm algorithm)
{
	hash_ctx *hctx = NULL;
	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(hash_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	hctx = (hash_ctx *)malloc(required_size);

	if (hctx == NULL)
	{
		return NULL;
	}

	return hash_init_checked(hctx, algorithm, ctx_size);
}

void hash_delete(hash_ctx *hctx)
{
	// Zero the memory region belonging to ctx.
	memset(hctx->_ctx, 0, hctx->ctx_size);
	free(hctx);
}

void hash_reset(hash_ctx *hctx)
{
	if (hctx->_reset != NULL)
	{
		hctx->_reset(hctx->_ctx);
		return;
	}

	// For Blake2
	if (hctx->algorithm == HASH_BLAKE2B)
	{
		blake2b_param b2bp = BLAKE2_PARAM_INIT(64, 0);
		blake2b_reset(hctx->_ctx, &b2bp, NULL);
		return;
	}
	if (hctx->algorithm == HASH_BLAKE2S)
	{
		blake2s_param b2sp = BLAKE2_PARAM_INIT(32, 0);
		blake2s_reset(hctx->_ctx, &b2sp, NULL);
		return;
	}
}

void hash_update(hash_ctx *hctx, void *data, size_t size)
{
	hctx->_update(hctx->_ctx, data, size);
}

int32_t hash_final(hash_ctx *hctx, byte_t *hash, size_t size)
{
	if (size < hctx->hash_size)
	{
		return -1;
	}

	// Copy to internal buffer first.
	// Check which function to use.
	if (hctx->_final != NULL)
	{
		hctx->_final(hctx->_ctx, hctx->hash);
	}
	else
	{
		hctx->_final_size(hctx->_ctx, hctx->hash, MAX_HASH_SIZE);
	}

	memcpy(hash, hctx->hash, hctx->hash_size);

	return 0;
}
