/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <cmac.h>
#include <aes.h>
#include <aria.h>
#include <camellia.h>
#include <des.h>
#include <twofish.h>

#include <minmax.h>
#include <byteswap.h>

// See NIST SP 800-38B Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication

static inline size_t get_key_ctx_size(cmac_algorithm algorithm)
{
	// These are the only supported algorithms for CMAC currently.
	switch (algorithm)
	{
	case CMAC_AES128:
	case CMAC_AES192:
	case CMAC_AES256:
		return sizeof(aes_key);
	case CMAC_ARIA128:
	case CMAC_ARIA192:
	case CMAC_ARIA256:
		return sizeof(aria_key);
	case CMAC_CAMELLIA128:
	case CMAC_CAMELLIA192:
	case CMAC_CAMELLIA256:
		return sizeof(camellia_key);
	case CMAC_TDES:
		return sizeof(tdes_key);
	case CMAC_TWOFISH128:
	case CMAC_TWOFISH192:
	case CMAC_TWOFISH256:
		return sizeof(twofish_key);
	default:
		// Invalid cmac specifier.
		return 0;
	}
}

static inline void SHL128_1(byte_t buffer[16])
{
	uint64_t *t1 = (uint64_t *)&buffer[0];
	uint64_t *t2 = (uint64_t *)&buffer[8];

	*t1 = (BSWAP_64(*t1) << 1 | (*t2 & 0x1));
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

	cctx->_encrypt_block(cctx->_key, l, l);

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

	cctx->_encrypt_block(cctx->_key, l, l);

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

size_t cmac_ctx_size(cmac_algorithm algorithm)
{
	return sizeof(cmac_ctx) + (3 * get_key_ctx_size(algorithm));
}

cmac_ctx *cmac_init(void *ptr, size_t size, cmac_algorithm algorithm, void *key, size_t key_size)
{
	cmac_ctx *cctx = (cmac_ctx *)ptr;
	size_t key_ctx_size = get_key_ctx_size(algorithm);
	size_t required_size = sizeof(cmac_ctx) + key_ctx_size;

	size_t block_size = 16;

	void *_key = NULL;
	void (*_encrypt_block)(void *key, void *plaintext, void *ciphertext) = NULL;

	if (key_ctx_size == 0)
	{
		return NULL;
	}

	if (size < required_size)
	{
		return NULL;
	}

	if (algorithm == CMAC_TDES)
	{
		block_size = DES_BLOCK_SIZE;
	}

	// Zero the memory for cmac_ctx only, the memory for the actual key contexts will be
	// zeroed when they are initialized.
	memset(cctx, 0, sizeof(cmac_ctx));

	// The actual hash context will be stored after cmac_ctx.
	_key = (void *)((byte_t *)cctx + sizeof(cmac_ctx));

	switch (algorithm)
	{
	case CMAC_AES128:
	{
		_key = aes_key_init(_key, key_ctx_size, AES128, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))aes128_encrypt_block;
	}
	break;
	case CMAC_AES192:
	{
		_key = aes_key_init(_key, key_ctx_size, AES192, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))aes192_encrypt_block;
	}
	break;
	case CMAC_AES256:
	{
		_key = aes_key_init(_key, key_ctx_size, AES256, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))aes256_encrypt_block;
	}
	break;
	case CMAC_ARIA128:
	{
		_key = aria_key_init(_key, key_ctx_size, ARIA128, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))aria128_encrypt_block;
	}
	break;
	case CMAC_ARIA192:
	{
		_key = aria_key_init(_key, key_ctx_size, ARIA192, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))aria192_encrypt_block;
	}
	break;
	case CMAC_ARIA256:
	{
		_key = aria_key_init(_key, key_ctx_size, ARIA256, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))aria256_encrypt_block;
	}
	break;
	case CMAC_CAMELLIA128:
	{
		_key = camellia_key_init(_key, key_ctx_size, CAMELLIA128, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))camellia128_encrypt_block;
	}
	break;
	case CMAC_CAMELLIA192:
	{
		_key = camellia_key_init(_key, key_ctx_size, CAMELLIA192, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))camellia192_encrypt_block;
	}
	break;
	case CMAC_CAMELLIA256:
	{
		_key = camellia_key_init(_key, key_ctx_size, CAMELLIA256, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))camellia256_encrypt_block;
	}
	break;
	case CMAC_TWOFISH128:
	{
		_key = twofish_key_init(_key, key_ctx_size, TWOFISH128, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))twofish_encrypt_block;
	}
	break;
	case CMAC_TWOFISH192:
	{
		_key = twofish_key_init(_key, key_ctx_size, TWOFISH192, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))twofish_encrypt_block;
	}
	break;
	case CMAC_TWOFISH256:
	{
		_key = twofish_key_init(_key, key_ctx_size, TWOFISH256, key, key_size);
		_encrypt_block = (void (*)(void *, void *, void *))twofish_encrypt_block;
	}
	break;
	case CMAC_TDES:
	{
		byte_t k1[8], k2[8], k3[8];

		if (tdes_decode_key(key, key_size, k1, k2, k3) == -1)
		{
			return NULL;
		}

		_key = tdes_key_init(_key, key_ctx_size, k1, k2, k3, false);
		_encrypt_block = (void (*)(void *, void *, void *))tdes_encrypt_block;
	}
	break;
	}

	if (_key == NULL)
	{
		return NULL;
	}

	cctx->algorithm = algorithm;
	cctx->ctx_size = required_size;
	cctx->key_ctx_size = key_ctx_size;
	cctx->block_size = block_size;

	cctx->_key = _key;
	cctx->_encrypt_block = _encrypt_block;

	// Determine subkeys.
	cmac_generate_subkeys(cctx);

	return cctx;
}

cmac_ctx *cmac_new(cmac_algorithm algorithm, void *key, size_t key_size)
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

void cmac_reset(cmac_ctx *cctx, void *key, size_t key_size)
{
	void *result = NULL;

	// If a new key is given, reset the subkeys.
	if (key != NULL)
	{
		memset(cctx->_key, 0, cctx->key_ctx_size);
		memset(cctx->subkey1, 0, 16);
		memset(cctx->subkey2, 0, 16);

		switch (cctx->algorithm)
		{
		case CMAC_AES128:
		{
			result = aes_key_init(cctx->_key, cctx->key_ctx_size, AES128, key, key_size);
		}
		break;
		case CMAC_AES192:
		{
			result = aes_key_init(cctx->_key, cctx->key_ctx_size, AES192, key, key_size);
		}
		break;
		case CMAC_AES256:
		{
			result = aes_key_init(cctx->_key, cctx->key_ctx_size, AES256, key, key_size);
		}
		break;
		case CMAC_ARIA128:
		{
			result = aria_key_init(cctx->_key, cctx->key_ctx_size, ARIA128, key, key_size);
		}
		break;
		case CMAC_ARIA192:
		{
			result = aria_key_init(cctx->_key, cctx->key_ctx_size, ARIA192, key, key_size);
		}
		break;
		case CMAC_ARIA256:
		{
			result = aria_key_init(cctx->_key, cctx->key_ctx_size, ARIA256, key, key_size);
		}
		break;
		case CMAC_CAMELLIA128:
		{
			result = camellia_key_init(cctx->_key, cctx->key_ctx_size, CAMELLIA128, key, key_size);
		}
		break;
		case CMAC_CAMELLIA192:
		{
			result = camellia_key_init(cctx->_key, cctx->key_ctx_size, CAMELLIA192, key, key_size);
		}
		break;
		case CMAC_CAMELLIA256:
		{
			result = camellia_key_init(cctx->_key, cctx->key_ctx_size, CAMELLIA256, key, key_size);
		}
		break;
		case CMAC_TWOFISH128:
		{
			result = twofish_key_init(cctx->_key, cctx->key_ctx_size, TWOFISH128, key, key_size);
		}
		break;
		case CMAC_TWOFISH192:
		{
			result = twofish_key_init(cctx->_key, cctx->key_ctx_size, TWOFISH192, key, key_size);
		}
		break;
		case CMAC_TWOFISH256:
		{
			result = twofish_key_init(cctx->_key, cctx->key_ctx_size, TWOFISH256, key, key_size);
		}
		break;
		case CMAC_TDES:
		{
			byte_t k1[8], k2[8], k3[8];

			if (tdes_decode_key(key, key_size, k1, k2, k3) == -1)
			{
				return;
			}

			cctx->_key = tdes_key_init(cctx->_key, cctx->key_ctx_size, k1, k2, k3, false);
		}
		break;
		}

		if (result == NULL)
		{
			return;
		}

		cmac_generate_subkeys(cctx);
	}
}

static void cmac_process_block(cmac_ctx *cctx)
{
	uint64_t *x = (uint64_t *)cctx->buffer;
	uint64_t *y = (uint64_t *)cctx->state;

	y[0] ^= x[0];
	y[1] ^= x[1];

	cctx->_encrypt_block(cctx->_key, cctx->state, cctx->state);
}

void cmac_update(cmac_ctx *cctx, void *data, size_t size)
{
	uint64_t pos = 0;
	uint64_t copy = 0;
	uint64_t unprocessed = cctx->message_size % cctx->block_size;
	byte_t *pdata = (byte_t *)data;

	// First process the previous data if any.
	if (unprocessed != 0)
	{
		uint64_t spill = cctx->block_size - unprocessed;
		copy = MIN(spill, size);

		memcpy(&cctx->buffer[unprocessed], pdata, copy);

		cctx->message_size += copy;
		pos += copy;
	}

	while (pos < size)
	{
		cmac_process_block(cctx);

		copy = MIN(cctx->block_size, size - pos);

		memcpy(cctx->buffer, pdata + pos, copy);

		cctx->message_size += copy;
		pos += copy;
	}
}

void cmac_generate(cmac_ctx *cctx, void *mac, size_t size)
{
	uint64_t unprocessed = cctx->message_size % cctx->block_size;

	if (unprocessed == 0)
	{
		uint64_t *x = (uint64_t *)cctx->subkey1;
		uint64_t *y = (uint64_t *)cctx->buffer;

		if (cctx->block_size == 16)
		{
			y[0] ^= x[0];
			y[1] ^= x[1];
		}
		else
		{
			y[0] ^= x[0];
		}

		cmac_process_block(cctx);
	}
	else
	{
		uint64_t *x = (uint64_t *)cctx->subkey2;
		uint64_t *y = (uint64_t *)cctx->state;
		uint64_t remaining = cctx->block_size - (cctx->message_size % cctx->block_size);

		cctx->buffer[cctx->message_size % cctx->block_size] = 0x80;
		--remaining;

		memset(cctx->buffer + cctx->block_size + 1, 0, remaining);

		if (cctx->block_size == 16)
		{
			y[0] ^= x[0];
			y[1] ^= x[1];
		}
		else
		{
			y[0] ^= x[0];
		}

		cmac_process_block(cctx);
	}

	// Truncate if necessary
	memcpy(mac, cctx->state, MIN(cctx->block_size, size));
}
