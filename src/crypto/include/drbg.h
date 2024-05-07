/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_DRBG_H
#define CRYPTO_DRBG_H

typedef struct _hash_drbg
{
	void *x;
} hash_drbg;

typedef struct _hmac_drbg
{
	void *x;
} hmac_drbg;

typedef struct _ctr_drbg
{
	void *x;
} ctr_drbg;

hash_drbg *hash_drbg_init(void);
void hash_drbg_free(hash_drbg *drbg);
void hash_drbg_reseed(hash_drbg *drbg);
void hash_drbg_generate(hash_drbg *drbg, void *buffer, size_t size);

hmac_drbg *hmac_drbg_init(void);
void hmac_drbg_free(hmac_drbg *drbg);
void hmac_drbg_reseed(hmac_drbg *drbg);
void hmac_drbg_generate(hmac_drbg *drbg, void *buffer, size_t size);

ctr_drbg *ctr_drbg_init(void);
void ctr_drbg_free(ctr_drbg *drbg);
void ctr_drbg_reseed(ctr_drbg *drbg);
void ctr_drbg_generate(ctr_drbg *drbg, void *buffer, size_t size);

#endif
