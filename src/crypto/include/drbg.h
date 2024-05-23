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
	void *x;
} ctr_drbg;

typedef struct _drbg
{
	void *context;
	byte_t seed[MAX_SEED_SIZE];
	uint16_t seed_size;
	uint16_t security_strength;
	uint32_t reseed_interval;
	uint32_t reseed_counter;
} drbg;

typedef enum _drbg_type
{
	HASH_DRBG,
	HMAC_DRBG,
	CTR_DRBG
} drbg_type;

drbg *drbg_init(drbg_type type, byte_t *personalization, size_t size);
void drbg_free(drbg *drbg);
void drbg_reseed(drbg *drbg);
void drbg_generate(drbg *drbg, void *buffer, size_t size);

hash_drbg *hash_drbg_init(void *ptr, size_t size, hash_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization,
						  size_t personalization_size);
hash_drbg *hash_drbg_new(hash_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization, size_t personalization_size);
void hash_drbg_delete(hash_drbg *hdrbg);
int32_t hash_drbg_reseed(hash_drbg *hdrbg, byte_t *additional_input, size_t input_size);
int32_t hash_drbg_generate(hash_drbg *hdrbg, byte_t *additional_input, size_t input_size, void *output, size_t output_size);

hmac_drbg *hmac_drbg_init(void *ptr, size_t size, hmac_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization,
						  size_t personalization_size);
hmac_drbg *hmac_drbg_new(hmac_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization, size_t personalization_size);
void hmac_drbg_delete(hmac_drbg *hdrbg);
int32_t hmac_drbg_reseed(hmac_drbg *hdrbg, byte_t *additional_input, size_t input_size);
int32_t hmac_drbg_generate(hmac_drbg *hdrbg, byte_t *additional_input, size_t input_size, void *output, size_t output_size);

ctr_drbg *ctr_drbg_init(void);
void ctr_drbg_free(ctr_drbg *drbg);
void ctr_drbg_reseed(ctr_drbg *drbg);
void ctr_drbg_generate(ctr_drbg *drbg, void *buffer, size_t size);

#endif
