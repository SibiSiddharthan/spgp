/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <minmax.h>
#include <mac.h>
#include <hash.h>
#include <sha.h>
#include <md5.h>

static void hmac_determine_key0(hmac_ctx *hctx, byte_t *key, size_t key_size)
{
	if (key_size == hctx->block_size)
	{
		memcpy(hctx->key0, key, key_size);
	}
	else if (key_size > hctx->block_size)
	{
		hctx->_update(hctx->_ctx, key, key_size);
		hctx->_final(hctx->_ctx, hctx->key0);
		hctx->_reset(hctx->_ctx);

		memset(hctx->key0 + hctx->hash_size, 0, hctx->block_size - hctx->hash_size);
	}
	else
	{
		memcpy(hctx->key0, key, key_size);
		memset(hctx->key0 + key_size, 0, hctx->block_size - key_size);
	}
}

static void hmac_pad(hmac_ctx *hctx)
{
	// ipad
	for (size_t i = 0; i < hctx->block_size; ++i)
	{
		hctx->ipad[i] = hctx->key0[i] ^ 0x36;
	}

	// opad
	for (size_t i = 0; i < hctx->block_size; ++i)
	{
		hctx->opad[i] = hctx->key0[i] ^ 0x5C;
	}
}

hmac_ctx *hmac_new(hash_algorithm algorithm, byte_t *key, size_t key_size)
{
	hmac_ctx *hctx = NULL;

	size_t hash_size = 0;
	size_t block_size = 0;

	void *_ctx = NULL;
	void (*_free)(void *ctx) = NULL;
	void (*_reset)(void *ctx) = NULL;
	void (*_update)(void *ctx, void *data, size_t size) = NULL;
	void (*_final)(void *ctx, byte_t *hash) = NULL;

	switch (algorithm)
	{
	case MD5:
	{
		hash_size = MD5_HASH_SIZE;
		block_size = MD5_BLOCK_SIZE;
		_ctx = md5_init();
		_free = (void (*)(void *))md5_free;
		_reset = (void (*)(void *))md5_reset;
		_update = (void (*)(void *, void *, size_t))md5_update;
		_final = (void (*)(void *, byte_t *))md5_final;
	}
	break;
	case SHA1:
	{
		hash_size = SHA1_HASH_SIZE;
		block_size = SHA1_BLOCK_SIZE;
		_ctx = sha1_init();
		_free = (void (*)(void *))sha1_free;
		_reset = (void (*)(void *))sha1_reset;
		_update = (void (*)(void *, void *, size_t))sha1_update;
		_final = (void (*)(void *, byte_t *))sha1_final;
	}
	break;
	case SHA224:
	{
		hash_size = SHA224_HASH_SIZE;
		block_size = SHA256_BLOCK_SIZE;
		_ctx = sha224_init();
		_free = (void (*)(void *))sha224_free;
		_reset = (void (*)(void *))sha224_reset;
		_update = (void (*)(void *, void *, size_t))sha224_update;
		_final = (void (*)(void *, byte_t *))sha224_final;
	}
	break;
	case SHA256:
	{
		hash_size = SHA256_HASH_SIZE;
		block_size = SHA256_BLOCK_SIZE;
		_ctx = sha256_init();
		_free = (void (*)(void *))sha256_free;
		_reset = (void (*)(void *))sha256_reset;
		_update = (void (*)(void *, void *, size_t))sha256_update;
		_final = (void (*)(void *, byte_t *))sha256_final;
	}
	break;
	case SHA384:
	{
		hash_size = SHA384_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha384_init();
		_free = (void (*)(void *))sha384_free;
		_reset = (void (*)(void *))sha384_reset;
		_update = (void (*)(void *, void *, size_t))sha384_update;
		_final = (void (*)(void *, byte_t *))sha384_final;
	}
	break;
	case SHA512:
	{
		hash_size = SHA512_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha512_init();
		_free = (void (*)(void *))sha512_free;
		_reset = (void (*)(void *))sha512_reset;
		_update = (void (*)(void *, void *, size_t))sha512_update;
		_final = (void (*)(void *, byte_t *))sha512_final;
	}
	break;
	case SHA512_224:
	{
		hash_size = SHA512_224_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha512_224_init();
		_free = (void (*)(void *))sha512_224_free;
		_reset = (void (*)(void *))sha512_224_reset;
		_update = (void (*)(void *, void *, size_t))sha512_224_update;
		_final = (void (*)(void *, byte_t *))sha512_224_final;
	}
	break;
	case SHA512_256:
	{
		hash_size = SHA512_256_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha512_256_init();
		_free = (void (*)(void *))sha512_256_free;
		_reset = (void (*)(void *))sha512_256_reset;
		_update = (void (*)(void *, void *, size_t))sha512_256_update;
		_final = (void (*)(void *, byte_t *))sha512_256_final;
	}
	break;
	default:
		return NULL;
	}

	if (_ctx == NULL)
	{
		return NULL;
	}

	hctx = (hmac_ctx *)malloc(sizeof(hmac_ctx));

	if (hctx == NULL)
	{
		return NULL;
	}

	memset(hctx, 0, sizeof(hmac_ctx));

	hctx->algorithm = algorithm;
	hctx->hash_size = hash_size;
	hctx->block_size = block_size;

	hctx->_ctx = _ctx;
	hctx->_free = _free;
	hctx->_reset = _reset;
	hctx->_update = _update;
	hctx->_final = _final;

	hmac_determine_key0(hctx, key, key_size);
	hmac_pad(hctx);

	hctx->_update(hctx->_ctx, hctx->ipad, hctx->block_size);

	return hctx;
}

void hmac_delete(hmac_ctx *hctx)
{
	hctx->_free(hctx->_ctx);
	free(hctx);
}

void hmac_reset(hmac_ctx *hctx, byte_t *key, size_t key_size)
{
	hctx->_reset(hctx->_ctx);

	hmac_determine_key0(hctx, key, key_size);
	hmac_pad(hctx);

	hctx->_update(hctx->_ctx, hctx->ipad, hctx->block_size);
}

void hmac_update(hmac_ctx *hctx, void *data, size_t size)
{
	hctx->_update(hctx->_ctx, data, size);
}

int32_t hmac_final(hmac_ctx *hctx, byte_t *mac, size_t size)
{
	hctx->_final(hctx->_ctx, hctx->ihash);
	hctx->_reset(hctx->_ctx);
	hctx->_update(hctx->_ctx, hctx->opad, hctx->block_size);
	hctx->_update(hctx->_ctx, hctx->ihash, hctx->hash_size);
	hctx->_final(hctx->_ctx, hctx->ihash);

	// Truncate if necessary
	memcpy(mac, hctx->ihash, MIN(hctx->hash_size, size));

	return 0;
}
