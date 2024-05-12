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

hash_ctx *hash_new(hash_algorithm algorithm)
{
	hash_ctx *hctx = NULL;

	size_t hash_size = 0;
	size_t max_input_size = 0xFFFFFFFFFFFFFFFF;
	void *_ctx = NULL;
	void (*_free)(void *ctx) = NULL;
	void (*_reset)(void *ctx) = NULL;
	void (*_update)(void *ctx, void *data, size_t size) = NULL;
	void (*_final)(void *ctx, byte_t *hash) = NULL;
	void (*_final_size)(void *ctx, byte_t *hash, size_t size) = NULL;

	switch (algorithm)
	{
	case HASH_MD5:
	{
		hash_size = 16;
		_ctx = md5_init();
		_free = (void (*)(void *))md5_free;
		_reset = (void (*)(void *))md5_reset;
		_update = (void (*)(void *, void *, size_t))md5_update;
		_final = (void (*)(void *, byte_t *))md5_final;
	}
	break;
	case HASH_RIPEMD160:
	{
		hash_size = 20;
		_ctx = ripemd160_init();
		_free = (void (*)(void *))ripemd160_free;
		_reset = (void (*)(void *))ripemd160_reset;
		_update = (void (*)(void *, void *, size_t))ripemd160_update;
		_final = (void (*)(void *, byte_t *))ripemd160_final;
	}
	break;
	case HASH_BLAKE2B:
	{
		blake2b_param b2bp = {.digest_length = 64, .key_length = 0, .depth = 1, .fanout = 1};
		hash_size = 64;
		_ctx = blake2b_init(&b2bp, NULL);
		_free = (void (*)(void *))blake2b_free;
		_update = (void (*)(void *, void *, size_t))blake2b_update;
		_final_size = (void (*)(void *, byte_t *, size_t))blake2b_final;
	}
	break;
	case HASH_BLAKE2S:
	{
		blake2s_param b2sp = {.digest_length = 32, .key_length = 0, .depth = 1, .fanout = 1};
		hash_size = 32;
		_ctx = blake2s_init(&b2sp, NULL);
		_free = (void (*)(void *))blake2s_free;
		_update = (void (*)(void *, void *, size_t))blake2s_update;
		_final_size = (void (*)(void *, byte_t *, size_t))blake2s_final;
	}
	break;
	case HASH_SHA1:
	{
		hash_size = 20;
		_ctx = sha1_init();
		_free = (void (*)(void *))sha1_free;
		_reset = (void (*)(void *))sha1_reset;
		_update = (void (*)(void *, void *, size_t))sha1_update;
		_final = (void (*)(void *, byte_t *))sha1_final;
	}
	break;
	case HASH_SHA224:
	{
		hash_size = 28;
		_ctx = sha224_init();
		_free = (void (*)(void *))sha224_free;
		_reset = (void (*)(void *))sha224_reset;
		_update = (void (*)(void *, void *, size_t))sha224_update;
		_final = (void (*)(void *, byte_t *))sha224_final;
	}
	break;
	case HASH_SHA256:
	{
		hash_size = 32;
		_ctx = sha256_init();
		_free = (void (*)(void *))sha256_free;
		_reset = (void (*)(void *))sha256_reset;
		_update = (void (*)(void *, void *, size_t))sha256_update;
		_final = (void (*)(void *, byte_t *))sha256_final;
	}
	break;
	case HASH_SHA384:
	{
		hash_size = 48;
		_ctx = sha384_init();
		_free = (void (*)(void *))sha384_free;
		_reset = (void (*)(void *))sha384_reset;
		_update = (void (*)(void *, void *, size_t))sha384_update;
		_final = (void (*)(void *, byte_t *))sha384_final;
	}
	break;
	case HASH_SHA512:
	{
		hash_size = 64;
		_ctx = sha512_init();
		_free = (void (*)(void *))sha512_free;
		_reset = (void (*)(void *))sha512_reset;
		_update = (void (*)(void *, void *, size_t))sha512_update;
		_final = (void (*)(void *, byte_t *))sha512_final;
	}
	break;
	case HASH_SHA512_224:
	{
		hash_size = 28;
		_ctx = sha512_224_init();
		_free = (void (*)(void *))sha512_224_free;
		_reset = (void (*)(void *))sha512_224_reset;
		_update = (void (*)(void *, void *, size_t))sha512_224_update;
		_final = (void (*)(void *, byte_t *))sha512_224_final;
	}
	break;
	case HASH_SHA512_256:
	{
		hash_size = 32;
		_ctx = sha512_256_init();
		_free = (void (*)(void *))sha512_256_free;
		_reset = (void (*)(void *))sha512_256_reset;
		_update = (void (*)(void *, void *, size_t))sha512_256_update;
		_final = (void (*)(void *, byte_t *))sha512_256_final;
	}
	break;
	case HASH_SHA3_224:
	{
		hash_size = 28;
		_ctx = sha3_init(224);
		_free = (void (*)(void *))sha3_free;
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	case HASH_SHA3_256:
	{
		hash_size = 32;
		_ctx = sha3_init(224);
		_free = (void (*)(void *))sha3_free;
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	case HASH_SHA3_384:
	{
		hash_size = 48;
		_ctx = sha3_init(224);
		_free = (void (*)(void *))sha3_free;
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	case HASH_SHA3_512:
	{
		hash_size = 64;
		_ctx = sha3_init(224);
		_free = (void (*)(void *))sha3_free;
		_reset = (void (*)(void *))sha3_reset;
		_update = (void (*)(void *, void *, size_t))sha3_update;
		_final_size = (void (*)(void *, byte_t *, size_t))sha3_final;
	}
	break;
	default:
		return NULL;
	}

	if (_ctx == NULL)
	{
		return NULL;
	}

	hctx = (hash_ctx *)malloc(sizeof(hash_ctx));

	if (hctx == NULL)
	{
		return NULL;
	}

	memset(hctx, 0, sizeof(hash_ctx));

	hctx->algorithm = algorithm;
	hctx->hash_size = hash_size;
	hctx->max_input_size = max_input_size;

	hctx->_ctx = _ctx;
	hctx->_free = _free;
	hctx->_reset = _reset;
	hctx->_update = _update;
	hctx->_final = _final;
	hctx->_final_size = _final_size;

	return hctx;
}

void hash_delete(hash_ctx *hctx)
{
	hctx->_free(hctx->_ctx);
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
		blake2b_param b2bp = {.digest_length = 64, .key_length = 0, .depth = 1, .fanout = 1};
		blake2b_reset(hctx->_ctx, &b2bp, NULL);
		return;
	}
	if (hctx->algorithm == HASH_BLAKE2S)
	{
		blake2s_param b2sp = {.digest_length = 32, .key_length = 0, .depth = 1, .fanout = 1};
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
