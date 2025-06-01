/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <cmac.h>

#include <aes.h>
#include <aria.h>
#include <camellia.h>
#include <cast5.h>
#include <des.h>
#include <twofish.h>

#include <xor.h>

#include <stdlib.h>
#include <string.h>

// See NIST SP 800-38B Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication

static inline size_t get_key_ctx_size(cipher_algorithm algorithm)
{
	// These are the only supported algorithms for CMAC currently.
	switch (algorithm)
	{
	case CIPHER_AES128:
	case CIPHER_AES192:
	case CIPHER_AES256:
		return sizeof(aes_key);
	case CIPHER_ARIA128:
	case CIPHER_ARIA192:
	case CIPHER_ARIA256:
		return sizeof(aria_key);
	case CIPHER_CAMELLIA128:
	case CIPHER_CAMELLIA192:
	case CIPHER_CAMELLIA256:
		return sizeof(camellia_key);
	case CIPHER_CAST5:
		return sizeof(cast5_key);
	case CIPHER_TDES:
		return sizeof(tdes_key);
	case CIPHER_TWOFISH128:
	case CIPHER_TWOFISH192:
	case CIPHER_TWOFISH256:
		return sizeof(twofish_key);
	default:
		// Invalid CMAC specifier.
		return 0;
	}
}

static inline byte_t cipher_key_size_validate(cipher_algorithm algorithm, byte_t key_size)
{
	byte_t required_size = 0;

	switch (algorithm)
	{
	case CIPHER_AES128:
	case CIPHER_ARIA128:
	case CIPHER_CAMELLIA128:
	case CIPHER_TWOFISH128:
	case CIPHER_CAST5:
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

static void *cmac_key_init(cmac_ctx *cctx, void *key, size_t key_size)
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
	default:
		return NULL;
	}

	return cctx->_key;
}

static inline void SHL128_1(byte_t buffer[16])
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = (BSWAP_64(*t1) << 1 | ((*t2 & 0x80) ? 0x01 : 0));
	*t2 = BSWAP_64(*t2) << 1;

	*t1 = BSWAP_64(*t1);
	*t2 = BSWAP_64(*t2);
}

static void cmac_generate_subkeys_64(cmac_ctx *cctx)
{
	static const byte_t r = 0x1B;

	byte_t l[DES_BLOCK_SIZE] = {0};
	uint64_t *p = (uint64_t *)l;
	uint64_t k1, k2;

	cctx->_encrypt(cctx->_key, l, l);

	// K1
	k1 = BSWAP_64(*p);

	if ((k1 & 0x8000000000000000) == 0)
	{
		k1 <<= 1;
	}
	else
	{
		k1 <<= 1;
		k1 ^= r;
	}

	// K2
	k2 = k1;

	if ((k2 & 0x8000000000000000) == 0)
	{
		k2 <<= 1;
	}
	else
	{
		k2 <<= 1;
		k2 ^= r;
	}

	k1 = BSWAP_64(k1);
	k2 = BSWAP_64(k2);

	memcpy(cctx->subkey1, &k1, 8);
	memcpy(cctx->subkey2, &k2, 8);
}

static void cmac_generate_subkeys_128(cmac_ctx *cctx)
{
	static const byte_t r = 0x87;

	byte_t l[16] = {0};

	cctx->_encrypt(cctx->_key, l, l);

	// K1
	memcpy(cctx->subkey1, l, 16);

	if ((l[0] & 0x80) == 0)
	{
		SHL128_1(cctx->subkey1);
	}
	else
	{
		SHL128_1(cctx->subkey1);
		cctx->subkey1[15] ^= r;
	}

	// K2
	memcpy(cctx->subkey2, cctx->subkey1, 16);

	if ((cctx->subkey2[0] & 0x80) == 0)
	{
		SHL128_1(cctx->subkey2);
	}
	else
	{
		SHL128_1(cctx->subkey2);
		cctx->subkey2[15] ^= r;
	}
}

static void cmac_generate_subkeys(cmac_ctx *cctx)
{
	if (cctx->block_size == 8)
	{
		return cmac_generate_subkeys_64(cctx);
	}

	return cmac_generate_subkeys_128(cctx);
}

static void cmac_process_block64(cmac_ctx *cctx)
{
	XOR8(cctx->state, cctx->state, cctx->buffer);
	cctx->_encrypt(cctx->_key, cctx->state, cctx->state);
}

static void cmac_process_block128(cmac_ctx *cctx)
{
	XOR16(cctx->state, cctx->state, cctx->buffer);
	cctx->_encrypt(cctx->_key, cctx->state, cctx->state);
}

size_t cmac_ctx_size(cipher_algorithm algorithm)
{
	return sizeof(cmac_ctx) + (3 * get_key_ctx_size(algorithm));
}

cmac_ctx *cmac_init(void *ptr, size_t size, cipher_algorithm algorithm, void *key, size_t key_size)
{
	cmac_ctx *cctx = (cmac_ctx *)ptr;
	size_t key_ctx_size = get_key_ctx_size(algorithm);
	size_t required_size = sizeof(cmac_ctx) + key_ctx_size;

	size_t block_size = 16;

	void *_key = NULL;
	void (*_encrypt)(void *key, void *plaintext, void *ciphertext) = NULL;

	if (key_ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	memset(cctx, 0, sizeof(cmac_ctx));

	// The actual hash context will be stored after cmac_ctx.
	_key = PTR_OFFSET(cctx, sizeof(cmac_ctx));

	switch (algorithm)
	{
	case CIPHER_AES128:
		_encrypt = (void (*)(void *, void *, void *))aes128_encrypt_block;
		break;
	case CIPHER_AES192:
		_encrypt = (void (*)(void *, void *, void *))aes192_encrypt_block;
		break;
	case CIPHER_AES256:
		_encrypt = (void (*)(void *, void *, void *))aes256_encrypt_block;
		break;
	case CIPHER_ARIA128:
		_encrypt = (void (*)(void *, void *, void *))aria128_encrypt_block;
		break;
	case CIPHER_ARIA192:
		_encrypt = (void (*)(void *, void *, void *))aria192_encrypt_block;
		break;
	case CIPHER_ARIA256:
		_encrypt = (void (*)(void *, void *, void *))aria256_encrypt_block;
		break;
	case CIPHER_CAMELLIA128:
		_encrypt = (void (*)(void *, void *, void *))camellia128_encrypt_block;
		break;
	case CIPHER_CAMELLIA192:
		_encrypt = (void (*)(void *, void *, void *))camellia192_encrypt_block;
		break;
	case CIPHER_CAMELLIA256:
		_encrypt = (void (*)(void *, void *, void *))camellia256_encrypt_block;
		break;
	case CIPHER_TWOFISH128:
		_encrypt = (void (*)(void *, void *, void *))twofish_encrypt_block;
		break;
	case CIPHER_TWOFISH192:
		_encrypt = (void (*)(void *, void *, void *))twofish_encrypt_block;
		break;
	case CIPHER_TWOFISH256:
		_encrypt = (void (*)(void *, void *, void *))twofish_encrypt_block;
		break;
	case CIPHER_CAST5:
		block_size = CAST5_BLOCK_SIZE;
		_encrypt = (void (*)(void *, void *, void *))cast5_encrypt_block;
	case CIPHER_TDES:
		block_size = DES_BLOCK_SIZE;
		_encrypt = (void (*)(void *, void *, void *))tdes_encrypt_block;
		break;
	default:
		// Invalid CMAC specifier.
		return NULL;
	}

	cctx->algorithm = algorithm;
	cctx->ctx_size = required_size;
	cctx->block_size = block_size;

	cctx->_key = _key;
	cctx->_encrypt = _encrypt;

	if (block_size == 16)
	{
		cctx->_process = cmac_process_block128;
	}
	else
	{
		cctx->_process = cmac_process_block64;
	}

	_key = cmac_key_init(cctx, key, key_size);

	if (_key == NULL)
	{
		return NULL;
	}

	// Determine subkeys.
	cmac_generate_subkeys(cctx);

	return cctx;
}

cmac_ctx *cmac_new(cipher_algorithm algorithm, void *key, size_t key_size)
{
	cmac_ctx *cctx = NULL;
	size_t ctx_size = get_key_ctx_size(algorithm);
	size_t required_size = sizeof(cmac_ctx) + ctx_size;

	if (ctx_size == 0)
	{
		return NULL;
	}

	cctx = (cmac_ctx *)malloc(required_size);

	if (cctx == NULL)
	{
		return NULL;
	}

	return cmac_init(cctx, required_size, algorithm, key, key_size);
}

void cmac_delete(cmac_ctx *cctx)
{
	// Zero the total memory region belonging to ctx.
	memset(cctx, 0, cctx->ctx_size);
	free(cctx);
}

cmac_ctx *cmac_reset(cmac_ctx *cctx, void *key, size_t key_size)
{
	void *ctx = NULL;

	if (key != NULL)
	{
		// If a new key is given, reset the subkeys.
		memset(cctx, 0, offsetof(cmac_ctx, _key));

		ctx = cmac_key_init(cctx, key, key_size);

		if (ctx == NULL)
		{
			return NULL;
		}

		cmac_generate_subkeys(cctx);
	}
	else
	{
		// Reset state and buffer.
		cctx->unprocessed = 0;

		memset(cctx->buffer, 0, 16);
		memset(cctx->state, 0, 16);
	}

	return cctx;
}

void cmac_update(cmac_ctx *cctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t copy = 0;
	byte_t *pdata = (byte_t *)data;

	while (pos < size)
	{
		if (cctx->unprocessed == cctx->block_size)
		{
			cctx->_process(cctx);
			cctx->unprocessed = 0;
		}

		copy = MIN(cctx->block_size - cctx->unprocessed, size - pos);
		memcpy(cctx->buffer + cctx->unprocessed, pdata + pos, copy);

		pos += copy;
		cctx->unprocessed += copy;
	}
}

uint32_t cmac_final(cmac_ctx *cctx, void *mac, size_t size)
{
	if (cctx->unprocessed == cctx->block_size)
	{
		XOR8_N(cctx->buffer, cctx->buffer, cctx->subkey1, cctx->block_size);
		cctx->_process(cctx);
	}
	else
	{
		uint64_t remaining = cctx->block_size - cctx->unprocessed;
		cctx->buffer[cctx->unprocessed] = 0x80;
		--remaining;

		memset(cctx->buffer + (cctx->block_size - remaining), 0, remaining);

		XOR8_N(cctx->buffer, cctx->buffer, cctx->subkey2, cctx->block_size);
		cctx->_process(cctx);
	}

	// Truncate if necessary
	memcpy(mac, cctx->state, MIN(cctx->block_size, size));

	// Reset CMAC
	cmac_reset(cctx, NULL, 0);

	return MIN(cctx->block_size, size);
}

static uint32_t cmac_common(cipher_algorithm algorithm, void *key, size_t key_size, void *data, size_t data_size, void *mac,
							size_t mac_size)
{
	// A big enough buffer for the hmac_ctx.
	cmac_ctx *cctx = NULL;
	byte_t buffer[512];

	cctx = cmac_init(buffer, 512, algorithm, key, key_size);

	if (cctx == NULL)
	{
		return 0;
	}

	// Compute the mac.
	cmac_update(cctx, data, data_size);
	return cmac_final(cctx, mac, mac_size);
}

uint32_t aes128_cmac(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return cmac_common(CIPHER_AES128, key, key_size, data, data_size, mac, mac_size);
}

uint32_t aes192_cmac(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return cmac_common(CIPHER_AES192, key, key_size, data, data_size, mac, mac_size);
}

uint32_t aes256_cmac(void *key, size_t key_size, void *data, size_t data_size, void *mac, size_t mac_size)
{
	return cmac_common(CIPHER_AES256, key, key_size, data, data_size, mac, mac_size);
}
