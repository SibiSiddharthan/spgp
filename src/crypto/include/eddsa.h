/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_ed25519_H
#define CRYPTO_ed25519_H

#include <bignum.h>
#include <ec.h>
#include <sha.h>
#include <shake.h>

#define ED25519_KEY_OCTETS  32
#define ED25519_SIGN_OCTETS 64

#define ED448_KEY_OCTETS  114
#define ED448_SIGN_OCTETS 114

typedef struct _ed25519_key
{
	byte_t private_key[ED25519_KEY_OCTETS];
	byte_t public_key[ED25519_KEY_OCTETS];
} ed25519_key;

typedef struct _ed448_key
{
	byte_t private_key[ED448_KEY_OCTETS];
	byte_t public_key[ED448_KEY_OCTETS];
} ed448_key;

typedef struct _ed25519_ctx
{
	ec_group *group;
	ed25519_key *key;
	sha512_ctx *hctx;

	byte_t prehash[ED25519_SIGN_OCTETS];

} ed25519_ctx;

typedef struct _ed448_ctx
{
	ec_group *group;
	ed448_key *key;
	shake256_ctx *hctx;

	void *context;
	size_t context_size;
	byte_t prehash[ED448_SIGN_OCTETS];
} ed448_ctx;

typedef struct _ed25519_signature
{
	byte_t sign[ED25519_SIGN_OCTETS];
} ed25519_signature;

typedef struct _ed448_signature
{
	byte_t sign[ED448_SIGN_OCTETS];
} ed448_signature;

ed25519_ctx *ed25519_sign_new(ed25519_key *key);
void ed25519_sign_delete(ed25519_ctx *ectx);
void ed25519_sign_reset(ed25519_ctx *ectx, ed25519_key *key);
void ed25519_sign_update(ed25519_ctx *ectx, void *message, size_t size);
ed25519_signature *ed25519_sign_final(ed25519_ctx *ectx, void *signature, size_t size);
ed25519_signature *ed25519_sign(ed25519_key *key, void *message, size_t message_size, void *signature, size_t signature_size);

ed25519_ctx *ed25519_verify_new(ed25519_key *key);
void ed25519_verify_delete(ed25519_ctx *ectx);
void ed25519_verify_reset(ed25519_ctx *ectx, ed25519_key *key);
void ed25519_verify_update(ed25519_ctx *ectx, void *message, size_t size);
uint32_t ed25519_verify_final(ed25519_ctx *ectx, ed25519_signature *edsign);
uint32_t ed25519_verify(ed25519_key *key, void *message, size_t size, ed25519_signature *edsign);

ed25519_ctx *ed25519ph_sign_new(ed25519_key *key);
void ed25519ph_sign_delete(ed25519_ctx *ectx);
void ed25519ph_sign_reset(ed25519_ctx *ectx, ed25519_key *key);
void ed25519ph_sign_update(ed25519_ctx *ectx, void *message, size_t size);
ed25519_signature *ed25519_sign_final(ed25519_ctx *ectx, void *signature, size_t size);
ed25519_signature *ed25519_sign(ed25519_key *key, void *message, size_t message_size, void *signature, size_t signature_size);

ed25519_ctx *ed25519ph_verify_new(ed25519_key *key);
void ed25519ph_verify_delete(ed25519_ctx *ectx);
void ed25519ph_verify_reset(ed25519_ctx *ectx, ed25519_key *key);
void ed25519ph_verify_update(ed25519_ctx *ectx, void *message, size_t size);
uint32_t ed25519ph_verify_final(ed25519_ctx *ectx, ed25519_signature *edsign);
uint32_t ed25519ph_verify(ed25519_key *key, void *message, size_t size, ed25519_signature *edsign);

ed448_ctx *ed448_sign_new(ed448_key *key, void *context, size_t context_size);
void ed448_sign_delete(ed448_ctx *ectx);
void ed448_sign_reset(ed448_ctx *ectx, ed448_key *key);
void ed448_sign_update(ed448_ctx *ectx, void *message, size_t size);
ed448_signature *ed448_sign_final(ed448_ctx *ectx, void *signature, size_t size);
ed448_signature *ed448_sign(ed448_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
							size_t signature_size);

ed448_ctx *ed448_verify_new(ed448_key *key, void *context, size_t context_size);
void ed448_verify_delete(ed448_ctx *ectx);
void ed448_verify_reset(ed448_ctx *ectx, ed448_key *key);
void ed448_verify_update(ed448_ctx *ectx, void *message, size_t size);
uint32_t ed448_verify_final(ed448_ctx *ectx, ed448_signature *edsign);
uint32_t ed448_verify(ed448_key *key, void *context, size_t context_size, void *message, size_t size, ed448_signature *edsign);

ed448_ctx *ed448ph_sign_new(ed448_key *key, void *context, size_t context_size);
void ed448ph_sign_delete(ed448_ctx *ectx);
void ed448ph_sign_reset(ed448_ctx *ectx, ed448_key *key);
void ed448ph_sign_update(ed448_ctx *ectx, void *message, size_t size);
ed448_signature *ed448_sign_final(ed448_ctx *ectx, void *signature, size_t size);
ed448_signature *ed448_sign(ed448_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
							size_t signature_size);

ed448_ctx *ed448ph_verify_new(ed448_key *key, void *context, size_t context_size);
void ed448ph_verify_delete(ed448_ctx *ectx);
void ed448ph_verify_reset(ed448_ctx *ectx, ed448_key *key);
void ed448ph_verify_update(ed448_ctx *ectx, void *message, size_t size);
uint32_t ed448ph_verify_final(ed448_ctx *ectx, ed448_signature *edsign);
uint32_t ed448ph_verify(ed448_key *key, void *context, size_t context_size, void *message, size_t size, ed448_signature *edsign);

#endif
