/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <crypt.h>

#include <stdlib.h>
#include <string.h>

#include <cipher.h>
#include <aes.h>
#include <aria.h>
#include <blowfish.h>
#include <camellia.h>
#include <cast5.h>
#include <des.h>
#include <idea.h>
#include <twofish.h>
#include <chacha20.h>

static inline size_t get_key_ctx_size(cipher_algorithm algorithm)
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
	case CIPHER_BLOWFISH64:
	case CIPHER_BLOWFISH128:
		return sizeof(blowfish_key);
	// CAMELLIA
	case CIPHER_CAMELLIA128:
	case CIPHER_CAMELLIA192:
	case CIPHER_CAMELLIA256:
		return sizeof(camellia_key);
	// CAST-5
	case CIPHER_CAST5:
		return sizeof(cast5_key);
	// CHACHA
	case CIPHER_CHACHA20:
		return sizeof(chacha20_key);
	// IDEA
	case CIPHER_IDEA:
		return sizeof(idea_key);
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

static inline size_t aead_ctx_size(cipher_aead_algorithm aead)
{
	switch (aead)
	{
	case CIPHER_AEAD_EAX:
		return sizeof(*((cipher_ctx *)NULL)->eax);
		break;
	case CIPHER_AEAD_GCM:
		return sizeof(*((cipher_ctx *)NULL)->gcm);
		break;
	case CIPHER_AEAD_OCB:
		return sizeof(*((cipher_ctx *)NULL)->ocb);
		break;
	case CIPHER_AEAD_SIV_GCM:
		// TODO determine for optimizations
		return 0;
		break;
	case CIPHER_AEAD_KW:
	case CIPHER_AEAD_CCM:
	case CIPHER_AEAD_SIV_CMAC:
		return 0;
		break;
	default:
		return 0;
	}
}

static inline byte_t cipher_key_size_validate(cipher_algorithm algorithm, byte_t key_size)
{
	byte_t required_size = 0;

	switch (algorithm)
	{
	case CIPHER_BLOWFISH64:
		required_size = 8;
		break;
	case CIPHER_AES128:
	case CIPHER_ARIA128:
	case CIPHER_CAMELLIA128:
	case CIPHER_TWOFISH128:
	case CIPHER_BLOWFISH128:
	case CIPHER_CAST5:
	case CIPHER_IDEA:
		required_size = 16;
		break;
	case CIPHER_AES192:
	case CIPHER_ARIA192:
	case CIPHER_CAMELLIA192:
	case CIPHER_TWOFISH192:
		required_size = 24;
		break;
	case CIPHER_AES256:
	case CIPHER_ARIA256:
	case CIPHER_CAMELLIA256:
	case CIPHER_TWOFISH256:
	case CIPHER_CHACHA20:
		required_size = 32;
		break;
	default:
		break;
	}

	if (algorithm == CIPHER_TDES)
	{
		if (key_size != DES_KEY_SIZE && key_size != (DES_KEY_SIZE * 2) && key_size != (DES_KEY_SIZE * 3))
		{
			return 0;
		}
	}
	else
	{
		if (required_size != key_size)
		{
			return 0;
		}
	}

	return 1;
}

static void *cipher_key_init(cipher_ctx *cctx, void *key, size_t key_size)
{
	if (cipher_key_size_validate(cctx->algorithm, key_size) == 0)
	{
		return NULL;
	}

	switch (cctx->algorithm)
	{
	// AES
	case CIPHER_AES128:
		aes128_key_init(cctx->_key, key);
		break;
	case CIPHER_AES192:
		aes192_key_init(cctx->_key, key);
		break;
	case CIPHER_AES256:
		aes256_key_init(cctx->_key, key);
		break;

	// ARIA
	case CIPHER_ARIA128:
		aria128_key_init(cctx->_key, key);
		break;
	case CIPHER_ARIA192:
		aria192_key_init(cctx->_key, key);
		break;
	case CIPHER_ARIA256:
		aria256_key_init(cctx->_key, key);
		break;

	// BLOWFISH
	case CIPHER_BLOWFISH64:
		blowfish64_key_init(cctx->_key, key);
		break;
	case CIPHER_BLOWFISH128:
		blowfish128_key_init(cctx->_key, key);
		break;

	// CAMELLIA
	case CIPHER_CAMELLIA128:
		camellia128_key_init(cctx->_key, key);
		break;
	case CIPHER_CAMELLIA192:
		camellia192_key_init(cctx->_key, key);
		break;
	case CIPHER_CAMELLIA256:
		camellia256_key_init(cctx->_key, key);
		break;

	// CAST-5
	case CIPHER_CAST5:
		cast5_key_init(cctx->_key, key);
		break;

	// IDEA
	case CIPHER_IDEA:
		idea_key_init(cctx->_key, key);
		break;

	// CHACHA
	// case CIPHER_CHACHA20:
	//	chacha20_key_init(_ctx, ctx_size, key, NULL);
	//	break;

	// TDES
	case CIPHER_TDES:
	{
		byte_t k1[DES_KEY_SIZE], k2[DES_KEY_SIZE], k3[DES_KEY_SIZE];

		tdes_key_decode(key, key_size, k1, k2, k3);
		tdes_key_init(cctx->_key, k1, k2, k3);
	}
	break;

	// TWOFISH
	case CIPHER_TWOFISH128:
		twofish128_key_init(cctx->_key, key);
		break;
	case CIPHER_TWOFISH192:
		twofish192_key_init(cctx->_key, key);
		break;
	case CIPHER_TWOFISH256:
		twofish256_key_init(cctx->_key, key);
		break;
	}

	return cctx->_key;
}

size_t cipher_ctx_size(cipher_algorithm algorithm)
{
	return sizeof(cipher_ctx) + get_key_ctx_size(algorithm);
}

size_t cipher_aead_ctx_size(cipher_algorithm algorithm, cipher_aead_algorithm aead)
{
	return sizeof(cipher_ctx) + get_key_ctx_size(algorithm) + aead_ctx_size(aead);
}

size_t cipher_key_size(cipher_algorithm algorithm)
{
	switch (algorithm)
	{
	case CIPHER_BLOWFISH64:
		return 8;
	case CIPHER_AES128:
	case CIPHER_ARIA128:
	case CIPHER_CAMELLIA128:
	case CIPHER_TWOFISH128:
	case CIPHER_BLOWFISH128:
	case CIPHER_CAST5:
	case CIPHER_IDEA:
		return 16;
	case CIPHER_AES192:
	case CIPHER_ARIA192:
	case CIPHER_CAMELLIA192:
	case CIPHER_TWOFISH192:
		return 24;
	case CIPHER_AES256:
	case CIPHER_ARIA256:
	case CIPHER_CAMELLIA256:
	case CIPHER_TWOFISH256:
	case CIPHER_CHACHA20:
		return 32;
	case CIPHER_TDES:
		return 24;
	default:
		return 0;
	}
}

size_t cipher_block_size(cipher_algorithm algorithm)
{
	// Stream ciphers
	if (algorithm == CIPHER_CHACHA20)
	{
		return 0;
	}

	// 64 bit block ciphers
	if (algorithm == CIPHER_TDES || algorithm == CIPHER_CAST5 || algorithm == CIPHER_IDEA || algorithm == CIPHER_BLOWFISH64 ||
		algorithm == CIPHER_BLOWFISH128)
	{
		return 8;
	}

	// Rest are all 128 bit block ciphers
	return 16;
}

size_t cipher_iv_size(cipher_algorithm algorithm)
{
	if (algorithm == CIPHER_CHACHA20)
	{
		return 12;
	}

	// 64 bit block ciphers
	if (algorithm == CIPHER_TDES || algorithm == CIPHER_CAST5 || algorithm == CIPHER_IDEA || algorithm == CIPHER_BLOWFISH64 ||
		algorithm == CIPHER_BLOWFISH128)
	{
		return 8;
	}

	// Rest are all 128 bit block ciphers
	return 16;
}

cipher_ctx *cipher_init(void *ptr, size_t size, uint16_t flags, cipher_algorithm algorithm, void *key, size_t key_size)
{
	cipher_ctx *cctx = (cipher_ctx *)ptr;

	size_t ctx_size = get_key_ctx_size(algorithm);
	size_t required_size = sizeof(cipher_ctx) + ctx_size;
	size_t total_size = required_size;
	size_t aead_size = 0;

	uint32_t block_size = 16;

	void *_ctx = NULL;
	void (*_encrypt)(void *, void *, void *) = NULL;
	void (*_decrypt)(void *, void *, void *) = NULL;

	if (ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	// Use the extra space for aead construction.
	if (flags & CIPHER_AEAD_INIT)
	{
		if (size > (ROUND_UP(required_size, 16) + 128))
		{
			aead_size = size - ROUND_UP(required_size, 16);
			total_size += aead_size;
		}
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

	// BLOWFISH
	case CIPHER_BLOWFISH64:
	case CIPHER_BLOWFISH128:
		block_size = BLOWFISH_BLOCK_SIZE;
		_encrypt = (void (*)(void *, void *, void *))blowfish_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))blowfish_decrypt_block;
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

	// CAST-5
	case CIPHER_CAST5:
		block_size = CAST5_BLOCK_SIZE;
		_encrypt = (void (*)(void *, void *, void *))cast5_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))cast5_decrypt_block;
		break;

	// IDEA
	case CIPHER_IDEA:
		block_size = IDEA_BLOCK_SIZE;
		_encrypt = (void (*)(void *, void *, void *))idea_encrypt_block;
		_decrypt = (void (*)(void *, void *, void *))idea_decrypt_block;
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
	cctx->ctx_size = total_size;
	cctx->aead_size = aead_size;

	cctx->aead = cctx->aead_size > 0 ? PTR_OFFSET(ptr, ROUND_UP(required_size, 16)) : NULL;

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

	size_t ctx_size = get_key_ctx_size(algorithm);
	size_t required_size = sizeof(cipher_ctx) + ctx_size;

	cctx = (cipher_ctx *)malloc(required_size);

	if (cctx == NULL)
	{
		return NULL;
	}

	result = cipher_init(cctx, required_size, 0, algorithm, key, key_size);

	if (result == NULL)
	{
		free(cctx);
	}

	return cctx;
}

void cipher_delete(cipher_ctx *cctx)
{
	if (cctx->flags & CIPHER_AEAD_INIT)
	{
		free(cctx->aead);
	}

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
