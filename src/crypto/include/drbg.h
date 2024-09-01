/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DRBG_H
#define CRYPTO_DRBG_H

#include <types.h>
#include <cipher.h>
#include <hash.h>
#include <hmac.h>
#include <aes.h>

#define MAX_SEED_SIZE             128
#define MAX_KEY_SIZE              128
#define MAX_PERSONALIZATION_SIZE  (1ull << 32)
#define MAX_ADDITIONAL_INPUT_SIZE (1ull << 32)
#define MAX_DRBG_OUTPUT_SIZE      (1ull << 16)

#define DEFAULT_RESEED_INTERVAL (1u << 16)

typedef struct _hash_drbg
{
	hash_ctx *hctx;
	size_t drbg_size;
	byte_t seed[MAX_SEED_SIZE];
	byte_t constant[MAX_SEED_SIZE];
	uint16_t seed_size;
	uint16_t security_strength;
	uint64_t reseed_interval;
	uint64_t reseed_counter;
} hash_drbg;

typedef struct _hmac_drbg
{
	hmac_ctx *hctx;
	size_t drbg_size;
	byte_t key[MAX_KEY_SIZE];
	byte_t seed[MAX_SEED_SIZE];
	uint16_t output_size;
	uint16_t security_strength;
	uint64_t reseed_interval;
	uint64_t reseed_counter;
} hmac_drbg;

typedef struct _ctr_drbg
{
	size_t drbg_size;
	byte_t key[AES256_KEY_SIZE];
	byte_t block[AES_BLOCK_SIZE];
	uint16_t key_size;
	uint16_t block_size;
	uint16_t seed_size;
	uint16_t security_strength;
	uint64_t reseed_interval;
	uint64_t reseed_counter;

	void *_ctx;
	void *_dfctx;
	size_t _size;
	int32_t _algorithm;
	void (*_init)(void *, size_t, int32_t, void *, size_t);
	void (*_encrypt)(void *, void *, void *);
} ctr_drbg;

typedef enum _drbg_type
{
	HASH_DRBG,
	HMAC_DRBG,
	CTR_DRBG
} drbg_type;

typedef struct _drbg_ctx
{
	drbg_type type;
	size_t drbg_size;

	void *_drbg;
	int32_t (*_reseed)(void *, void *, size_t);
	int32_t (*_generate)(void *, uint32_t, void *, size_t, void *, size_t);
} drbg_ctx;

size_t hash_drbg_size(hash_algorithm algorithm);
hash_drbg *hash_drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), hash_algorithm algorithm,
						  uint32_t reseed_interval, void *nonce, size_t nonce_size, void *personalization, size_t personalization_size);
hash_drbg *hash_drbg_new(uint32_t (*entropy)(void *buffer, size_t size), hash_algorithm algorithm, uint32_t reseed_interval, void *nonce,
						 size_t nonce_size, void *personalization, size_t personalization_size);
void hash_drbg_delete(hash_drbg *hdrbg);
int32_t hash_drbg_reseed(hash_drbg *hdrbg, void *additional_input, size_t input_size);
int32_t hash_drbg_generate(hash_drbg *hdrbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size,
						   void *output, size_t output_size);

size_t hmac_drbg_size(hmac_algorithm algorithm);
hmac_drbg *hmac_drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), hmac_algorithm algorithm,
						  uint32_t reseed_interval, void *nonce, size_t nonce_size, void *personalization, size_t personalization_size);
hmac_drbg *hmac_drbg_new(uint32_t (*entropy)(void *buffer, size_t size), hmac_algorithm algorithm, uint32_t reseed_interval, void *nonce,
						 size_t nonce_size, void *personalization, size_t personalization_size);
void hmac_drbg_delete(hmac_drbg *hdrbg);
int32_t hmac_drbg_reseed(hmac_drbg *hdrbg, void *additional_input, size_t input_size);
int32_t hmac_drbg_generate(hmac_drbg *hdrbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size,
						   void *output, size_t output_size);

size_t ctr_drbg_size(cipher_algorithm algorithm);
ctr_drbg *ctr_drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), cipher_algorithm algorithm,
						uint32_t reseed_interval, void *nonce, size_t nonce_size, void *personalization, size_t personalization_size);
ctr_drbg *ctr_drbg_new(uint32_t (*entropy)(void *buffer, size_t size), cipher_algorithm algorithm, uint32_t reseed_interval, void *nonce,
					   size_t nonce_size, void *personalization, size_t personalization_size);
void ctr_drbg_delete(ctr_drbg *cdrbg);
int32_t ctr_drbg_reseed(ctr_drbg *cdrbg, void *additional_input, size_t input_size);
int32_t ctr_drbg_generate(ctr_drbg *cdrbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size, void *output,
						  size_t output_size);

size_t drbg_ctx_size(drbg_type type, uint32_t algorithm);
drbg_ctx *drbg_init(void *ptr, size_t size, uint32_t (*entropy)(void *buffer, size_t size), drbg_type type, uint32_t algorithm,
					uint32_t reseed_interval, void *nonce, size_t nonce_size, void *personalization, size_t personalization_size);
drbg_ctx *drbg_new(uint32_t (*entropy)(void *buffer, size_t size), drbg_type type, uint32_t algorithm, uint32_t reseed_interval,
				   void *nonce, size_t nonce_size, void *personalization, size_t personalization_size);
void drbg_delete(drbg_ctx *drbg);
int32_t drbg_reseed(drbg_ctx *drbg, void *additional_input, size_t input_size);
int32_t drbg_generate(drbg_ctx *drbg, uint32_t prediction_resistance_request, void *additional_input, size_t input_size, void *output,
					  size_t output_size);

drbg_ctx *get_default_drbg(void);

#endif
