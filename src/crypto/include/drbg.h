/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DRBG_H
#define CRYPTO_DRBG_H

#include <types.h>
#include <hash.h>

#define MAX_SEED_SIZE             128
#define MAX_PERSONALIZATION_SIZE  1024
#define MAX_ADDITIONAL_INPUT_SIZE 1024

#define DEFAULT_RESEED_INTERVAL (1u << 16)

typedef struct _hash_drbg
{
	hash_ctx *hctx;
	byte_t seed[MAX_SEED_SIZE];
	byte_t constant[MAX_SEED_SIZE];
	uint16_t seed_size;
	uint16_t security_strength;
	uint32_t reseed_interval;
	uint32_t reseed_counter;
} hash_drbg;

typedef struct _hmac_drbg
{
	void *x;
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

hash_drbg *hash_drbg_init(hash_algorithm algorithm, uint32_t reseed_interval, byte_t *personalization, size_t personalization_size);
void hash_drbg_free(hash_drbg *hdrbg);
int32_t hash_drbg_reseed(hash_drbg *hdrbg, byte_t *additional_input, size_t input_size);
void hash_drbg_generate(hash_drbg *hdrbg, void *buffer, size_t size);

hmac_drbg *hmac_drbg_init(void);
void hmac_drbg_free(hmac_drbg *drbg);
void hmac_drbg_reseed(hmac_drbg *drbg);
void hmac_drbg_generate(hmac_drbg *drbg, void *buffer, size_t size);

ctr_drbg *ctr_drbg_init(void);
void ctr_drbg_free(ctr_drbg *drbg);
void ctr_drbg_reseed(ctr_drbg *drbg);
void ctr_drbg_generate(ctr_drbg *drbg, void *buffer, size_t size);

#endif