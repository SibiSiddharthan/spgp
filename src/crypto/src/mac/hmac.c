/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <hmac.h>

#include <sha.h>
#include <md5.h>
#include <ripemd.h>

#include <stdlib.h>
#include <string.h>

// See NIST FIPS 198-1 The Keyed-Hash Message Authentication Code (HMAC)

static inline size_t get_ctx_size(hash_algorithm algorithm)
{
	// These are the only supported algorithms for HMAC currently.
	switch (algorithm)
	{
	case HASH_MD5:
		return sizeof(md5_ctx);
	case HASH_RIPEMD160:
		return sizeof(ripemd160_ctx);
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

size_t hmac_ctx_size(hash_algorithm algorithm)
{
	return sizeof(hmac_ctx) + get_ctx_size(algorithm);
}

hmac_ctx *hmac_init(void *ptr, size_t size, hash_algorithm algorithm, void *key, size_t key_size)
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
	_ctx = PTR_OFFSET(hctx, sizeof(hmac_ctx));

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
	default:
		// Invalid hmac specifier.
		return NULL;
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

hmac_ctx *hmac_new(hash_algorithm algorithm, void *key, size_t key_size)
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
	memset(hctx, 0, hctx->ctx_size);
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

uint32_t hmac_final(hmac_ctx *hctx, void *mac, size_t size)
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

	return MIN(hctx->hash_size, size);
}

static uint32_t hmac_common(hash_algorithm algorithm, void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	// A big enough buffer for the hmac_ctx.
	hmac_ctx *hctx = NULL;
	byte_t buffer[1536];

	hctx = hmac_init(buffer, 1536, algorithm, key, key_size);

	// Compute the mac.
	hmac_update(hctx, data, data_size);
	return hmac_final(hctx, mac, mac_size);
}

uint32_t hmac_md5(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_MD5, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_ripemd160(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_RIPEMD160, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha1(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA1, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA224, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA256, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha384(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA384, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha512(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA512, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha512_224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA512_224, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha512_256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA512_256, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha3_224(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA3_224, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha3_256(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA3_256, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha3_384(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA3_384, key, key_size, data, data_size, mac, mac_size);
}

uint32_t hmac_sha3_512(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return hmac_common(HASH_SHA3_512, key, key_size, data, data_size, mac, mac_size);
}
