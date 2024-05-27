/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <minmax.h>
#include <hmac.h>
#include <sha.h>
#include <md5.h>

// See NIST FIPS 198-1 The Keyed-Hash Message Authentication Code (HMAC)

static inline size_t get_ctx_size(hmac_algorithm algorithm)
{
	// These are the only supported algorithms for HMAC currently.
	switch (algorithm)
	{
	case HMAC_MD5:
		return sizeof(md5_ctx);
	case HMAC_SHA1:
		return sizeof(sha1_ctx);
	case HMAC_SHA224:
	case HMAC_SHA256:
		return sizeof(sha256_ctx);
	case HMAC_SHA384:
	case HMAC_SHA512:
	case HMAC_SHA512_224:
	case HMAC_SHA512_256:
		return sizeof(sha512_ctx);
	default:
		// Invalid hmac specifier.
		return 0;
	}
}

static void hmac_determine_key0(hmac_ctx *hctx, void *key, size_t key_size)
{
	// Determine the initial key based on its size.

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

static void hmac_determine_pad(hmac_ctx *hctx)
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

size_t hmac_ctx_size(hmac_algorithm algorithm)
{
	return sizeof(hmac_ctx) + get_ctx_size(algorithm);
}

hmac_ctx *hmac_init(void *ptr, size_t size, hmac_algorithm algorithm, void *key, size_t key_size)
{
	hmac_ctx *hctx = (hmac_ctx *)ptr;
	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(hmac_ctx) + ctx_size;

	size_t hash_size = 0;
	size_t block_size = 0;

	void *_ctx = NULL;
	void (*_reset)(void *ctx) = NULL;
	void (*_update)(void *ctx, void *data, size_t size) = NULL;
	void (*_final)(void *ctx, void *hash) = NULL;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	// Zero the memory for hmac_ctx only, the memory for the actual hash contexts will be
	// zeroed when they are initialized.
	memset(hctx, 0, sizeof(hmac_ctx));

	// The actual hash context will be stored after hmac_ctx.
	_ctx = (void *)((byte_t *)hctx + sizeof(hmac_ctx));

	switch (algorithm)
	{
	case HMAC_MD5:
	{
		hash_size = MD5_HASH_SIZE;
		block_size = MD5_BLOCK_SIZE;
		_ctx = md5_init(_ctx, ctx_size);
		_reset = (void (*)(void *))md5_reset;
		_update = (void (*)(void *, void *, size_t))md5_update;
		_final = (void (*)(void *, void *))md5_final;
	}
	break;
	case HMAC_SHA1:
	{
		hash_size = SHA1_HASH_SIZE;
		block_size = SHA1_BLOCK_SIZE;
		_ctx = sha1_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha1_reset;
		_update = (void (*)(void *, void *, size_t))sha1_update;
		_final = (void (*)(void *, void *))sha1_final;
	}
	break;
	case HMAC_SHA224:
	{
		hash_size = SHA224_HASH_SIZE;
		block_size = SHA256_BLOCK_SIZE;
		_ctx = sha224_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha224_reset;
		_update = (void (*)(void *, void *, size_t))sha224_update;
		_final = (void (*)(void *, void *))sha224_final;
	}
	break;
	case HMAC_SHA256:
	{
		hash_size = SHA256_HASH_SIZE;
		block_size = SHA256_BLOCK_SIZE;
		_ctx = sha256_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha256_reset;
		_update = (void (*)(void *, void *, size_t))sha256_update;
		_final = (void (*)(void *, void *))sha256_final;
	}
	break;
	case HMAC_SHA384:
	{
		hash_size = SHA384_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha384_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha384_reset;
		_update = (void (*)(void *, void *, size_t))sha384_update;
		_final = (void (*)(void *, void *))sha384_final;
	}
	break;
	case HMAC_SHA512:
	{
		hash_size = SHA512_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha512_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha512_reset;
		_update = (void (*)(void *, void *, size_t))sha512_update;
		_final = (void (*)(void *, void *))sha512_final;
	}
	break;
	case HMAC_SHA512_224:
	{
		hash_size = SHA512_224_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha512_224_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha512_224_reset;
		_update = (void (*)(void *, void *, size_t))sha512_224_update;
		_final = (void (*)(void *, void *))sha512_224_final;
	}
	break;
	case HMAC_SHA512_256:
	{
		hash_size = SHA512_256_HASH_SIZE;
		block_size = SHA512_BLOCK_SIZE;
		_ctx = sha512_256_init(_ctx, ctx_size);
		_reset = (void (*)(void *))sha512_256_reset;
		_update = (void (*)(void *, void *, size_t))sha512_256_update;
		_final = (void (*)(void *, void *))sha512_256_final;
	}
	break;
	}

	hctx->algorithm = algorithm;
	hctx->ctx_size = required_size;
	hctx->hash_size = hash_size;
	hctx->block_size = block_size;

	hctx->_ctx = _ctx;
	hctx->_reset = _reset;
	hctx->_update = _update;
	hctx->_final = _final;

	// Determine the initial key.
	hmac_determine_key0(hctx, key, key_size);

	// Determine ipad and opad.
	hmac_determine_pad(hctx);

	// H(K0 ^ ipad)
	hctx->_update(hctx->_ctx, hctx->ipad, hctx->block_size);

	return hctx;
}

hmac_ctx *hmac_new(hmac_algorithm algorithm, void *key, size_t key_size)
{
	hmac_ctx *hctx = NULL;
	size_t ctx_size = get_ctx_size(algorithm);
	size_t required_size = sizeof(hmac_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	hctx = (hmac_ctx *)malloc(required_size);

	if (hctx == NULL)
	{
		return NULL;
	}

	return hmac_init(hctx, required_size, algorithm, key, key_size);
}

void hmac_delete(hmac_ctx *hctx)
{
	// Zero the total memory region belonging to ctx.
	memset(hctx->_ctx, 0, hctx->ctx_size);
	free(hctx);
}

void hmac_reset(hmac_ctx *hctx, void *key, size_t key_size)
{
	hctx->_reset(hctx->_ctx);

	// If a new key is given, reset key0, ipad, opad.
	// For key reuse we can skip this step.
	if (key != NULL)
	{
		memset(hctx->key0, 0, MAX_BLOCK_SIZE);
		memset(hctx->ipad, 0, MAX_BLOCK_SIZE);
		memset(hctx->opad, 0, MAX_BLOCK_SIZE);

		hmac_determine_key0(hctx, key, key_size);
		hmac_determine_pad(hctx);
	}

	hctx->_update(hctx->_ctx, hctx->ipad, hctx->block_size);
}

void hmac_update(hmac_ctx *hctx, void *data, size_t size)
{
	hctx->_update(hctx->_ctx, data, size);
}

void hmac_final(hmac_ctx *hctx, void *mac, size_t size)
{
	// H ((K0 ^ ipad) || text)
	hctx->_final(hctx->_ctx, hctx->ihash);
	hctx->_reset(hctx->_ctx);

	// H((K0 ^ opad) || H((K0 ^ ipad) || text))
	hctx->_update(hctx->_ctx, hctx->opad, hctx->block_size);
	hctx->_update(hctx->_ctx, hctx->ihash, hctx->hash_size);
	hctx->_final(hctx->_ctx, hctx->ihash);
	hctx->_reset(hctx->_ctx);

	// Truncate if necessary
	memcpy(mac, hctx->ihash, MIN(hctx->hash_size, size));
}

static void hmac_common(hmac_algorithm algorithm, void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	// A big enough buffer for the hash_ctx.
	hmac_ctx *hctx = NULL;
	byte_t buffer[1024];

	hctx = hmac_init(buffer, 1024, algorithm, key, key_size);

	// Compute the mac.
	hmac_update(hctx, data, data_size);
	hmac_final(hctx, mac, mac_size);
}

void hmac_md5(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_MD5, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha1(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA1, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA224, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA256, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha384(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA384, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha512(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA512, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha512_224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA512_224, key, key_size, data, data_size, mac, mac_size);
}

void hmac_sha512_256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HMAC_SHA512_256, key, key_size, data, data_size, mac, mac_size);
}
