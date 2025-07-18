/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <hash.h>

#include <stdlib.h>
#include <string.h>

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
		// Invalid hash specifier.
		return 0;
	}
}

size_t hash_ctx_size(hash_algorithm algorithm)
{
	return sizeof(hash_ctx) + get_ctx_size(algorithm);
}

hash_ctx *hash_init(void *ptr, size_t size, hash_algorithm algorithm)
{
	hash_ctx *hctx = (hash_ctx *)ptr;
	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(hash_ctx) + ctx_size;

	size_t hash_size = 0;

	void *_ctx = NULL;
	void (*_reset)(void *ctx) = NULL;
	void (*_update)(void *ctx, void *data, size_t size) = NULL;
	void (*_final)(void *ctx, void *hash) = NULL;
	void (*_final_size)(void *ctx, void *hash, size_t size) = NULL;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	// Zero the memory for hash_ctx only, the memory for the actual hash contexts will be
	// zeroed when they are initialized.
	memset(hctx, 0, sizeof(hash_ctx));

	// The actual hash context will be stored after hash_ctx.
	_ctx = PTR_OFFSET(hctx, sizeof(hash_ctx));

	switch (algorithm)
	{
	case HASH_MD5:
	{
		hash_size = MD5_HASH_SIZE;
		_reset = (void (*)(void *))md5_reset;
		_update = (void (*)(void *, void *, size_t))md5_update;
		_final = (void (*)(void *, void *))md5_final;

		md5_init(_ctx);
	}
	break;
	case HASH_RIPEMD160:
	{
		hash_size = RIPEMD160_HASH_SIZE;
		_reset = (void (*)(void *))ripemd160_reset;
		_update = (void (*)(void *, void *, size_t))ripemd160_update;
		_final = (void (*)(void *, void *))ripemd160_final;

		ripemd160_init(_ctx);
	}
	break;
	case HASH_BLAKE2B:
	{
		blake2b_param b2bp = BLAKE2_PARAM_INIT(64, 0);
		hash_size = BLAKE2B_MAX_HASH_SIZE;
		_update = (void (*)(void *, void *, size_t))blake2b_update;
		_final_size = (void (*)(void *, void *, size_t))blake2b_final;

		blake2b_init(_ctx, &b2bp, NULL);
	}
	break;
	case HASH_BLAKE2S:
	{
		blake2s_param b2sp = BLAKE2_PARAM_INIT(32, 0);
		hash_size = BLAKE2S_MAX_HASH_SIZE;
		_update = (void (*)(void *, void *, size_t))blake2s_update;
		_final_size = (void (*)(void *, void *, size_t))blake2s_final;

		blake2s_init(_ctx, &b2sp, NULL);
	}
	break;
	case HASH_SHA1:
	{
		hash_size = SHA1_HASH_SIZE;
		_reset = (void (*)(void *))sha1_reset;
		_update = (void (*)(void *, void *, size_t))sha1_update;
		_final = (void (*)(void *, void *))sha1_final;

		sha1_init(_ctx);
	}
	break;
	case HASH_SHA224:
	{
		hash_size = SHA224_HASH_SIZE;
		_reset = (void (*)(void *))sha224_reset;
		_update = (void (*)(void *, void *, size_t))sha224_update;
		_final = (void (*)(void *, void *))sha224_final;

		sha224_init(_ctx);
	}
	break;
	case HASH_SHA256:
	{
		hash_size = SHA256_HASH_SIZE;
		_reset = (void (*)(void *))sha256_reset;
		_update = (void (*)(void *, void *, size_t))sha256_update;
		_final = (void (*)(void *, void *))sha256_final;

		sha256_init(_ctx);
	}
	break;
	case HASH_SHA384:
	{
		hash_size = SHA384_HASH_SIZE;
		_reset = (void (*)(void *))sha384_reset;
		_update = (void (*)(void *, void *, size_t))sha384_update;
		_final = (void (*)(void *, void *))sha384_final;

		sha384_init(_ctx);
	}
	break;
	case HASH_SHA512:
	{
		hash_size = SHA512_HASH_SIZE;
		_reset = (void (*)(void *))sha512_reset;
		_update = (void (*)(void *, void *, size_t))sha512_update;
		_final = (void (*)(void *, void *))sha512_final;

		sha512_init(_ctx);
	}
	break;
	case HASH_SHA512_224:
	{
		hash_size = SHA512_224_HASH_SIZE;
		_reset = (void (*)(void *))sha512_224_reset;
		_update = (void (*)(void *, void *, size_t))sha512_224_update;
		_final = (void (*)(void *, void *))sha512_224_final;

		sha512_224_init(_ctx);
	}
	break;
	case HASH_SHA512_256:
	{
		hash_size = SHA512_256_HASH_SIZE;
		_reset = (void (*)(void *))sha512_256_reset;
		_update = (void (*)(void *, void *, size_t))sha512_256_update;
		_final = (void (*)(void *, void *))sha512_256_final;

		sha512_256_init(_ctx);
	}
	break;
	case HASH_SHA3_224:
	{
		hash_size = SHA3_224_HASH_SIZE;
		_reset = (void (*)(void *))sha3_224_reset;
		_update = (void (*)(void *, void *, size_t))sha3_224_update;
		_final = (void (*)(void *, void *))sha3_224_final;

		sha3_224_init(_ctx);
	}
	break;
	case HASH_SHA3_256:
	{
		hash_size = SHA3_256_HASH_SIZE;
		_reset = (void (*)(void *))sha3_256_reset;
		_update = (void (*)(void *, void *, size_t))sha3_256_update;
		_final = (void (*)(void *, void *))sha3_256_final;

		sha3_256_init(_ctx);
	}
	break;
	case HASH_SHA3_384:
	{
		hash_size = SHA3_384_HASH_SIZE;
		_reset = (void (*)(void *))sha3_384_reset;
		_update = (void (*)(void *, void *, size_t))sha3_384_update;
		_final = (void (*)(void *, void *))sha3_384_final;

		sha3_384_init(_ctx);
	}
	break;
	case HASH_SHA3_512:
	{
		hash_size = SHA3_512_HASH_SIZE;
		_reset = (void (*)(void *))sha3_512_reset;
		_update = (void (*)(void *, void *, size_t))sha3_512_update;
		_final = (void (*)(void *, void *))sha3_512_final;

		sha3_512_init(_ctx);
	}
	break;
	}

	hctx->algorithm = algorithm;
	hctx->ctx_size = required_size;
	hctx->hash_size = hash_size;

	hctx->_ctx = _ctx;
	hctx->_reset = _reset;
	hctx->_update = _update;
	hctx->_final = _final;
	hctx->_final_size = _final_size;

	return hctx;
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

	memset(hctx, 0, required_size);

	return hash_init(hctx, required_size, algorithm);
}

void hash_delete(hash_ctx *hctx)
{
	// Zero the total memory region belonging to ctx.
	memset(hctx, 0, hctx->ctx_size);
	free(hctx);
}

hash_ctx *hash_copy(void *ptr, size_t size, hash_ctx *src)
{
	size_t ctx_size = get_ctx_size(src->algorithm);
	size_t required_size = sizeof(hash_ctx) + ctx_size;

	if (size < required_size)
	{
		return NULL;
	}

	memcpy(ptr, src, required_size);

	return ptr;
}

hash_ctx *hash_dup(hash_ctx *hctx)
{
	hash_ctx *copy = NULL;
	size_t ctx_size = get_ctx_size(hctx->algorithm);
	size_t required_size = sizeof(hash_ctx) + ctx_size;

	copy = (hash_ctx *)malloc(required_size);

	if (copy == NULL)
	{
		return NULL;
	}

	memcpy(copy, hctx, required_size);

	return copy;
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

uint32_t hash_final(hash_ctx *hctx, void *hash, size_t size)
{
	// Copy to internal buffer first.
	// Check which function to use.
	if (hctx->_final != NULL)
	{
		hctx->_final(hctx->_ctx, hctx->hash);
	}
	else
	{
		hctx->_final_size(hctx->_ctx, hctx->hash, hctx->hash_size);
	}

	// Truncate hash if necessary.
	if (hash != NULL)
	{
		memcpy(hash, hctx->hash, MIN(hctx->hash_size, size));
	}

	return MIN(hctx->hash_size, size);
}
