/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

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

#define ED448_KEY_OCTETS  57
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

typedef struct _ed25519_signature
{
	byte_t sign[ED25519_SIGN_OCTETS];
} ed25519_signature;

typedef struct _ed448_signature
{
	byte_t sign[ED448_SIGN_OCTETS];
} ed448_signature;

ed25519_key *ed25519_key_generate(ed25519_key *key, byte_t private_key[ED25519_KEY_OCTETS]);
ed448_key *ed448_key_generate(ed448_key *key, byte_t private_key[ED448_KEY_OCTETS]);

ed25519_signature *ed25519_sign(ed25519_key *key, void *message, size_t message_size, void *signature, size_t signature_size);
uint32_t ed25519_verify(ed25519_key *key, ed25519_signature *edsign, void *message, size_t size);

ed448_signature *ed448_sign(ed448_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
							size_t signature_size);
uint32_t ed448_verify(ed448_key *key, ed448_signature *edsign, void *context, size_t context_size, void *message, size_t message_size);

ed25519_signature *ed25519ph_sign(ed25519_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
								  size_t signature_size);
uint32_t ed25519ph_verify(ed25519_key *key, ed25519_signature *edsign, void *context, size_t context_size, void *message, size_t size);

ed448_signature *ed448ph_sign(ed448_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
							  size_t signature_size);
uint32_t ed448ph_verify(ed448_key *key, ed448_signature *edsign, void *context, size_t context_size, void *message, size_t message_size);

#endif
