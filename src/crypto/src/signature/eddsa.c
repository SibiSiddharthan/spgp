/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <eddsa.h>
#include <ec.h>
#include <bignum.h>
#include <bignum-internal.h>

#include <drbg.h>

#include <sha.h>
#include <shake.h>

#include <stdlib.h>
#include <string.h>

static void ed25519_encode_scalar(byte_t scalar[ED25519_KEY_OCTETS])
{
	// Clear the lowest 3 bits of the first octet
	scalar[0] &= 0xF8;

	// Clear the highest bit of the last octet
	scalar[ED25519_KEY_OCTETS - 1] &= 0x7F;

	// Set the second highest bit of the last octet
	scalar[ED25519_KEY_OCTETS - 1] |= 0x40;
}

static void ed448_encode_scalar(byte_t scalar[ED448_KEY_OCTETS])
{
	// Clear the lowest 2 bits of the first octet
	scalar[0] &= 0xFC;

	// Clear the last octet
	scalar[ED448_KEY_OCTETS - 1] = 0;

	// Set the highest bit of the second last octet
	scalar[ED448_KEY_OCTETS - 2] |= 0x80;
}

static void dom2_sha512_update(sha512_ctx *hctx, byte_t octet, void *context, byte_t context_size)
{
	sha512_update(hctx, "SigEd25519 no Ed25519 collisions", 32);
	sha512_update(hctx, &octet, 1);
	sha512_update(hctx, &context_size, 1);
	sha512_update(hctx, context, context_size);
}

static void dom4_shake256_update(shake256_ctx *hctx, byte_t octet, void *context, byte_t context_size)
{
	shake256_update(hctx, "SigEd448", 8);
	shake256_update(hctx, &octet, 1);
	shake256_update(hctx, &context_size, 1);
	shake256_update(hctx, context, context_size);
}

ed25519_key *ed25519_key_generate(ed25519_key *key, byte_t private_key[ED25519_KEY_OCTETS])
{
	ec_group *group = NULL;
	ec_point *a = NULL;
	bignum_t *s = NULL;

	uint32_t result = 0;

	byte_t hash[SHA512_HASH_SIZE] = {0};
	byte_t zero[ED25519_KEY_OCTETS] = {0};

	if (memcmp(zero, private_key, ED25519_KEY_OCTETS) == 0)
	{
		result = drbg_generate(get_default_drbg(), 0, NULL, 0, key->private_key, ED25519_KEY_OCTETS);

		if (result != ED25519_KEY_OCTETS)
		{
			return NULL;
		}
	}
	else
	{
		memcpy(key->private_key, private_key, ED25519_KEY_OCTETS);
	}

	// Hash the 32 byte private key
	sha512_hash(key->private_key, ED25519_KEY_OCTETS, hash);
	ed25519_encode_scalar(hash);

	s = bignum_set_bytes_le(NULL, hash, ED25519_KEY_OCTETS);

	if (s == NULL)
	{
		return NULL;
	}

	group = ec_group_new(EC_ED25519);

	if (group == NULL)
	{
		return NULL;
	}

	a = ec_point_multiply(group, NULL, group->g, s);

	if (a == NULL)
	{
		ec_group_delete(group);
		return NULL;
	}

	ec_point_encode(group, a, key->public_key, ED25519_KEY_OCTETS, 0);

	ec_point_delete(a);
	ec_group_delete(group);

	return key;
}

ed448_key *ed448_key_generate(ed448_key *key, byte_t private_key[ED448_KEY_OCTETS])
{
	ec_group *group = NULL;
	ec_point *a = NULL;
	bignum_t *s = NULL;

	uint32_t result = 0;

	byte_t hash[ED448_SIGN_OCTETS] = {0};
	byte_t zero[ED448_KEY_OCTETS] = {0};

	if (memcmp(zero, private_key, ED448_KEY_OCTETS) == 0)
	{
		result = drbg_generate(get_default_drbg(), 0, NULL, 0, key->private_key, ED448_KEY_OCTETS);

		if (result != ED448_KEY_OCTETS)
		{
			return NULL;
		}
	}
	else
	{
		memcpy(key->private_key, private_key, ED448_KEY_OCTETS);
	}

	// Hash the 32 byte private key
	shake256_xof(key->private_key, ED448_KEY_OCTETS, hash, ED448_SIGN_OCTETS);
	ed448_encode_scalar(hash);

	s = bignum_set_bytes_le(NULL, hash, ED448_KEY_OCTETS);

	if (s == NULL)
	{
		return NULL;
	}

	group = ec_group_new(EC_ED448);

	if (group == NULL)
	{
		return NULL;
	}

	a = ec_point_multiply(group, NULL, group->g, s);

	if (a == NULL)
	{
		ec_group_delete(group);
		return NULL;
	}

	ec_point_encode(group, a, key->public_key, ED448_KEY_OCTETS, 0);

	bignum_delete(s);
	ec_point_delete(a);
	ec_group_delete(group);

	return key;
}

uint32_t ed25519_key_validate(ed25519_key *key)
{
	uint32_t status = 0;

	ec_group *group = NULL;
	ec_point *point = NULL;

	group = ec_group_new(EC_ED25519);

	if (group == NULL)
	{
		return 0;
	}

	point = ec_point_new(group);

	if (point == NULL)
	{
		ec_group_delete(group);
		return 0;
	}

	// Check if point decoding works
	point = ec_point_decode(group, point, key->public_key, ED25519_KEY_OCTETS);

	if (point != NULL)
	{
		status = 1;
	}

	ec_point_delete(point);
	ec_group_delete(group);

	return status;
}

uint32_t ed448_key_validate(ed448_key *key)
{
	uint32_t status = 0;

	ec_group *group = NULL;
	ec_point *point = NULL;

	group = ec_group_new(EC_ED448);

	if (group == NULL)
	{
		return 0;
	}

	point = ec_point_new(group);

	if (point == NULL)
	{
		ec_group_delete(group);
		return 0;
	}

	// Check if point decoding works
	point = ec_point_decode(group, point, key->public_key, ED448_KEY_OCTETS);

	if (point != NULL)
	{
		status = 1;
	}

	ec_point_delete(point);
	ec_group_delete(group);

	return status;
}

static ed25519_signature *ed25519_sign_internal(ec_group *group, ed25519_key *key, ed25519_signature *edsign, void *message, size_t size)
{
	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 2 * bignum_size(group->bits) + 3 * bignum_size(SHA512_HASH_SIZE * 8);

	bignum_t *k = NULL;
	bignum_t *s = NULL;
	bignum_t *d = NULL;

	bignum_t *x = NULL;
	bignum_t *y = NULL;

	ec_point r;

	sha512_ctx hctx;

	byte_t prehash[SHA512_HASH_SIZE];
	byte_t hash[SHA512_HASH_SIZE];

	sha512_init(&hctx, sizeof(sha512_ctx));

	bignum_ctx_start(bctx, ctx_size);

	x = bignum_ctx_allocate_bignum(bctx, group->bits);
	y = bignum_ctx_allocate_bignum(bctx, group->bits);
	k = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);
	s = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);
	d = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);

	// Compute the prehash
	sha512_update(&hctx, key->private_key, ED25519_KEY_OCTETS);
	sha512_final(&hctx, prehash);
	sha512_reset(&hctx);

	// Hash the message
	sha512_update(&hctx, PTR_OFFSET(prehash, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);
	sha512_update(&hctx, message, size);
	sha512_final(&hctx, hash);
	sha512_reset(&hctx);

	ed25519_encode_scalar(prehash);

	k = bignum_set_bytes_le(k, hash, SHA512_HASH_SIZE);
	s = bignum_set_bytes_le(s, prehash, ED25519_KEY_OCTETS);

	k = bignum_mod(bctx, k, k, group->n);

	// R = [k]G.
	r.x = x;
	r.y = y;

	ec_point_multiply(group, &r, group->g, k);
	ec_point_encode(group, &r, edsign, ED25519_KEY_OCTETS, 0);

	sha512_update(&hctx, edsign, ED25519_KEY_OCTETS);
	sha512_update(&hctx, key->public_key, ED25519_KEY_OCTETS);
	sha512_update(&hctx, message, size);
	sha512_final(&hctx, hash);

	d = bignum_set_bytes_le(d, hash, SHA512_HASH_SIZE);

	// s = (r + ds) mod n.
	s = bignum_modmul(bctx, s, s, d, group->n);
	s = bignum_modadd(bctx, s, s, k, group->n);

	bignum_get_bytes_le(s, PTR_OFFSET(edsign, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);

	bignum_ctx_end(bctx);

	return edsign;
}

ed25519_signature *ed25519_sign(ed25519_key *key, void *message, size_t message_size, void *signature, size_t signature_size)
{
	ec_group *group = NULL;
	ed25519_signature *edsign = signature;

	// Allocate the signature
	if (edsign == NULL)
	{
		edsign = malloc(ED25519_SIGN_OCTETS);
	}
	else
	{
		if (signature_size < ED25519_SIGN_OCTETS)
		{
			return NULL;
		}
	}

	if (edsign == NULL)
	{
		return NULL;
	}

	// Allocate the group
	group = ec_group_new(EC_ED25519);

	if (group == NULL)
	{
		if (signature == NULL)
		{
			free(edsign);
		}

		return NULL;
	}

	edsign = ed25519_sign_internal(group, key, edsign, message, message_size);

	ec_group_delete(group);

	return edsign;
}

static uint32_t ed25519_verify_internal(ec_group *group, ed25519_key *key, ed25519_signature *edsign, void *message, size_t size)
{
	uint32_t status = 0;

	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 10 * bignum_size(group->bits);

	bignum_t *t = NULL;
	bignum_t *u = NULL;

	ec_point *r = NULL, *q = NULL;
	ec_point *lhs = NULL, *rhs = NULL;

	sha512_ctx hctx;

	byte_t hash[SHA512_HASH_SIZE];

	bignum_ctx_start(bctx, ctx_size);

	r = ec_point_new(group);
	q = ec_point_new(group);

	t = bignum_ctx_allocate_bignum(bctx, ED25519_SIGN_OCTETS * 8);
	u = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);

	t = bignum_set_bytes_le(t, PTR_OFFSET(edsign, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);

	if (bignum_cmp(t, group->n) >= 0)
	{
		goto end;
	}

	r = ec_point_decode(group, r, edsign, ED25519_KEY_OCTETS);

	if (r == NULL)
	{
		goto end;
	}

	q = ec_point_decode(group, q, key->public_key, ED25519_KEY_OCTETS);

	if (q == NULL)
	{
		goto end;
	}

	sha512_init(&hctx, sizeof(sha512_ctx));

	sha512_update(&hctx, edsign, ED25519_KEY_OCTETS);
	sha512_update(&hctx, key->public_key, ED25519_KEY_OCTETS);
	sha512_update(&hctx, message, size);
	sha512_final(&hctx, hash);

	u = bignum_set_bytes_le(u, hash, SHA512_HASH_SIZE);

	lhs = ec_point_multiply(group, lhs, group->g, t);

	rhs = ec_point_multiply(group, rhs, q, u);
	rhs = ec_point_add(group, rhs, rhs, r);

	if (bignum_cmp(rhs->y, lhs->y) == 0)
	{
		status = 1;
	}

end:
	ec_point_delete(r);
	ec_point_delete(q);
	bignum_ctx_end(bctx);

	return status;
}

uint32_t ed25519_verify(ed25519_key *key, ed25519_signature *edsign, void *message, size_t message_size)
{
	uint32_t status = 0;
	ec_group *group = NULL;

	// Allocate the group
	group = ec_group_new(EC_ED25519);

	if (group == NULL)
	{
		return 0;
	}

	status = ed25519_verify_internal(group, key, edsign, message, message_size);

	ec_group_delete(group);

	return status;
}

static ed448_signature *ed448_sign_internal(ec_group *group, ed448_key *key, ed448_signature *edsign, void *context, size_t context_size,
											void *message, size_t message_size)
{
	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 2 * bignum_size(group->bits) + 3 * bignum_size(ED448_SIGN_OCTETS * 8);

	bignum_t *k = NULL;
	bignum_t *s = NULL;
	bignum_t *d = NULL;

	bignum_t *x = NULL;
	bignum_t *y = NULL;

	ec_point r;

	shake256_ctx hctx;

	byte_t prehash[ED448_SIGN_OCTETS];
	byte_t hash[ED448_SIGN_OCTETS];

	shake256_init(&hctx, sizeof(shake256_ctx), 912);

	bignum_ctx_start(bctx, ctx_size);

	x = bignum_ctx_allocate_bignum(bctx, group->bits);
	y = bignum_ctx_allocate_bignum(bctx, group->bits);
	k = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);
	s = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);
	d = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);

	// Compute the prehash
	shake256_update(&hctx, key->private_key, ED448_KEY_OCTETS);
	shake256_final(&hctx, prehash, ED448_SIGN_OCTETS);

	// Hash the message
	shake256_reset(&hctx, 912);
	dom4_shake256_update(&hctx, 0, context, context_size);
	shake256_update(&hctx, PTR_OFFSET(prehash, ED448_KEY_OCTETS), ED448_KEY_OCTETS);
	shake256_update(&hctx, message, message_size);
	shake256_final(&hctx, hash, ED448_SIGN_OCTETS);

	ed448_encode_scalar(prehash);

	k = bignum_set_bytes_le(k, hash, ED448_SIGN_OCTETS);
	s = bignum_set_bytes_le(s, prehash, ED448_KEY_OCTETS);

	k = bignum_mod(bctx, k, k, group->n);

	// R = [k]G.
	r.x = x;
	r.y = y;

	ec_point_multiply(group, &r, group->g, k);
	ec_point_encode(group, &r, edsign, ED448_KEY_OCTETS, 0);

	shake256_reset(&hctx, 912);
	dom4_shake256_update(&hctx, 0, context, context_size);
	shake256_update(&hctx, edsign, ED448_KEY_OCTETS);
	shake256_update(&hctx, key->public_key, ED448_KEY_OCTETS);
	shake256_update(&hctx, message, message_size);
	shake256_final(&hctx, hash, ED448_SIGN_OCTETS);

	d = bignum_set_bytes_le(d, hash, ED448_SIGN_OCTETS);

	// s = (r + ds) mod n.
	s = bignum_modmul(bctx, s, s, d, group->n);
	s = bignum_modadd(bctx, s, s, k, group->n);

	bignum_get_bytes_le(s, PTR_OFFSET(edsign, ED448_KEY_OCTETS), ED448_KEY_OCTETS);

	bignum_ctx_end(bctx);

	return edsign;
}

ed448_signature *ed448_sign(ed448_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
							size_t signature_size)
{
	ec_group *group = NULL;
	ed448_signature *edsign = signature;

	// Check context size
	if (context_size > 255)
	{
		return NULL;
	}

	// Allocate the signature
	if (edsign == NULL)
	{
		edsign = malloc(ED448_SIGN_OCTETS);
	}
	else
	{
		if (signature_size < ED448_SIGN_OCTETS)
		{
			return NULL;
		}
	}

	if (edsign == NULL)
	{
		return NULL;
	}

	// Allocate the group
	group = ec_group_new(EC_ED448);

	if (group == NULL)
	{
		if (signature == NULL)
		{
			free(edsign);
		}

		return NULL;
	}

	edsign = ed448_sign_internal(group, key, edsign, context, context_size, message, message_size);

	ec_group_delete(group);

	return edsign;
}

static uint32_t ed448_verify_internal(ec_group *group, ed448_key *key, ed448_signature *edsign, void *context, size_t context_size,
									  void *message, size_t size)
{
	uint32_t status = 0;

	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 10 * bignum_size(group->bits);

	bignum_t *t = NULL;
	bignum_t *u = NULL;

	ec_point *r = NULL, *q = NULL;
	ec_point *lhs = NULL, *rhs = NULL;

	shake256_ctx hctx;

	byte_t hash[ED448_SIGN_OCTETS];

	bignum_ctx_start(bctx, ctx_size);

	r = ec_point_new(group);
	q = ec_point_new(group);

	t = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);
	u = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);

	t = bignum_set_bytes_le(t, PTR_OFFSET(edsign, ED448_KEY_OCTETS), ED448_KEY_OCTETS);

	if (bignum_cmp(t, group->n) >= 0)
	{
		goto end;
	}

	r = ec_point_decode(group, r, edsign, ED448_KEY_OCTETS);

	if (r == NULL)
	{
		goto end;
	}

	q = ec_point_decode(group, q, key->public_key, ED448_KEY_OCTETS);

	if (q == NULL)
	{
		goto end;
	}

	shake256_init(&hctx, sizeof(shake256_ctx), 912);

	shake256_reset(&hctx, 912);
	dom4_shake256_update(&hctx, 0, context, context_size);
	shake256_update(&hctx, edsign, ED448_KEY_OCTETS);
	shake256_update(&hctx, key->public_key, ED448_KEY_OCTETS);
	shake256_update(&hctx, message, size);
	shake256_final(&hctx, hash, ED448_SIGN_OCTETS);

	u = bignum_set_bytes_le(u, hash, ED448_SIGN_OCTETS);

	lhs = ec_point_multiply(group, lhs, group->g, t);

	rhs = ec_point_multiply(group, rhs, q, u);
	rhs = ec_point_add(group, rhs, rhs, r);

	if (bignum_cmp(rhs->y, lhs->y) == 0)
	{
		status = 1;
	}

end:
	ec_point_delete(r);
	ec_point_delete(q);
	bignum_ctx_end(bctx);

	return status;
}

uint32_t ed448_verify(ed448_key *key, ed448_signature *edsign, void *context, size_t context_size, void *message, size_t message_size)
{
	uint32_t status = 0;
	ec_group *group = NULL;

	// Allocate the group
	group = ec_group_new(EC_ED448);

	if (group == NULL)
	{
		return 0;
	}

	status = ed448_verify_internal(group, key, edsign, context, context_size, message, message_size);

	ec_group_delete(group);

	return status;
}

static ed25519_signature *ed25519ph_sign_internal(ec_group *group, ed25519_key *key, ed25519_signature *edsign, void *context,
												  size_t context_size, void *message, size_t message_size)
{
	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 2 * bignum_size(group->bits) + 3 * bignum_size(SHA512_HASH_SIZE * 8);

	bignum_t *k = NULL;
	bignum_t *s = NULL;
	bignum_t *d = NULL;

	bignum_t *x = NULL;
	bignum_t *y = NULL;

	ec_point r;

	sha512_ctx hctx;

	byte_t prehash[SHA512_HASH_SIZE];
	byte_t mhash[SHA512_HASH_SIZE];
	byte_t hash[SHA512_HASH_SIZE];

	bignum_ctx_start(bctx, ctx_size);

	x = bignum_ctx_allocate_bignum(bctx, group->bits);
	y = bignum_ctx_allocate_bignum(bctx, group->bits);
	k = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);
	s = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);
	d = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);

	sha512_init(&hctx, sizeof(sha512_ctx));

	// Hash the message
	sha512_update(&hctx, message, message_size);
	sha512_final(&hctx, mhash);

	// Compute the prehash
	sha512_reset(&hctx);
	sha512_update(&hctx, key->private_key, ED25519_KEY_OCTETS);
	sha512_final(&hctx, prehash);

	// Compute the final hash
	sha512_reset(&hctx);
	dom2_sha512_update(&hctx, 1, context, context_size);
	sha512_update(&hctx, PTR_OFFSET(prehash, SHA512_HASH_SIZE / 2), SHA512_HASH_SIZE / 2);
	sha512_update(&hctx, mhash, SHA512_HASH_SIZE);
	sha512_final(&hctx, hash);

	ed25519_encode_scalar(prehash);

	k = bignum_set_bytes_le(k, hash, SHA512_HASH_SIZE);
	s = bignum_set_bytes_le(s, prehash, ED25519_KEY_OCTETS);

	k = bignum_mod(bctx, k, k, group->n);

	// R = [k]G.
	r.x = x;
	r.y = y;

	ec_point_multiply(group, &r, group->g, k);
	ec_point_encode(group, &r, edsign, ED25519_KEY_OCTETS, 0);

	sha512_reset(&hctx);
	dom2_sha512_update(&hctx, 1, context, context_size);
	sha512_update(&hctx, edsign, ED25519_KEY_OCTETS);
	sha512_update(&hctx, key->public_key, ED25519_KEY_OCTETS);
	sha512_update(&hctx, mhash, SHA512_HASH_SIZE);
	sha512_final(&hctx, hash);

	d = bignum_set_bytes_le(d, hash, SHA512_HASH_SIZE);

	// s = (r + ds) mod n.
	s = bignum_modmul(bctx, s, s, d, group->n);
	s = bignum_modadd(bctx, s, s, k, group->n);

	bignum_get_bytes_le(s, PTR_OFFSET(edsign, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);

	bignum_ctx_end(bctx);

	return edsign;
}

ed25519_signature *ed25519ph_sign(ed25519_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
								  size_t signature_size)
{
	ec_group *group = NULL;
	ed25519_signature *edsign = signature;

	// Allocate the signature
	if (edsign == NULL)
	{
		edsign = malloc(ED25519_SIGN_OCTETS);
	}
	else
	{
		if (signature_size < ED25519_SIGN_OCTETS)
		{
			return NULL;
		}
	}

	if (edsign == NULL)
	{
		return NULL;
	}

	// Allocate the group
	group = ec_group_new(EC_ED25519);

	if (group == NULL)
	{
		if (signature == NULL)
		{
			free(edsign);
		}

		return NULL;
	}

	edsign = ed25519ph_sign_internal(group, key, edsign, context, context_size, message, message_size);

	ec_group_delete(group);

	return edsign;
}

static uint32_t ed25519ph_verify_internal(ec_group *group, ed25519_key *key, ed25519_signature *edsign, void *context, size_t context_size,
										  void *message, size_t message_size)
{
	uint32_t status = 0;

	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 10 * bignum_size(group->bits);

	bignum_t *t = NULL;
	bignum_t *u = NULL;

	ec_point *r = NULL, *q = NULL;
	ec_point *lhs = NULL, *rhs = NULL;

	sha512_ctx hctx;

	byte_t hash[SHA512_HASH_SIZE];

	bignum_ctx_start(bctx, ctx_size);

	r = ec_point_new(group);
	q = ec_point_new(group);

	t = bignum_ctx_allocate_bignum(bctx, ED25519_SIGN_OCTETS * 8);
	u = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);

	t = bignum_set_bytes_le(t, PTR_OFFSET(edsign, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);

	if (bignum_cmp(t, group->n) >= 0)
	{
		goto end;
	}

	r = ec_point_decode(group, r, edsign, ED25519_KEY_OCTETS);

	if (r == NULL)
	{
		goto end;
	}

	q = ec_point_decode(group, q, key->public_key, ED25519_KEY_OCTETS);

	if (q == NULL)
	{
		goto end;
	}

	sha512_init(&hctx, sizeof(sha512_ctx));

	sha512_update(&hctx, message, message_size);
	sha512_final(&hctx, hash);

	sha512_reset(&hctx);
	dom2_sha512_update(&hctx, 1, context, context_size);
	sha512_update(&hctx, edsign, ED25519_KEY_OCTETS);
	sha512_update(&hctx, key->public_key, ED25519_KEY_OCTETS);
	sha512_update(&hctx, hash, SHA512_HASH_SIZE);
	sha512_final(&hctx, hash);

	u = bignum_set_bytes_le(u, hash, SHA512_HASH_SIZE);

	lhs = ec_point_multiply(group, lhs, group->g, t);

	rhs = ec_point_multiply(group, rhs, q, u);
	rhs = ec_point_add(group, rhs, rhs, r);

	if (bignum_cmp(rhs->y, lhs->y) == 0)
	{
		status = 1;
	}

end:
	ec_point_delete(r);
	ec_point_delete(q);
	bignum_ctx_end(bctx);

	return status;
}

uint32_t ed25519ph_verify(ed25519_key *key, ed25519_signature *edsign, void *context, size_t context_size, void *message,
						  size_t message_size)
{
	uint32_t status = 0;
	ec_group *group = NULL;

	// Allocate the group
	group = ec_group_new(EC_ED25519);

	if (group == NULL)
	{
		return 0;
	}

	status = ed25519ph_verify_internal(group, key, edsign, context, context_size, message, message_size);

	ec_group_delete(group);

	return status;
}

static ed448_signature *ed448ph_sign_internal(ec_group *group, ed448_key *key, ed448_signature *edsign, void *context, size_t context_size,
											  void *message, size_t message_size)
{
	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 2 * bignum_size(group->bits) + 3 * bignum_size(ED448_SIGN_OCTETS * 8);

	bignum_t *k = NULL;
	bignum_t *s = NULL;
	bignum_t *d = NULL;

	bignum_t *x = NULL;
	bignum_t *y = NULL;

	ec_point r;

	shake256_ctx hctx;

	byte_t prehash[ED448_SIGN_OCTETS];
	byte_t hash[ED448_SIGN_OCTETS];
	byte_t mhash[64];

	bignum_ctx_start(bctx, ctx_size);

	x = bignum_ctx_allocate_bignum(bctx, group->bits);
	y = bignum_ctx_allocate_bignum(bctx, group->bits);
	k = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);
	s = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);
	d = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);

	// Hash the message
	shake256_init(&hctx, sizeof(shake256_ctx), 512);
	shake256_update(&hctx, message, message_size);
	shake256_final(&hctx, mhash, 64);

	// Compute the prehash
	shake256_reset(&hctx, 912);
	shake256_update(&hctx, key->private_key, ED448_KEY_OCTETS);
	shake256_final(&hctx, prehash, ED448_SIGN_OCTETS);

	// Compute the final hash
	shake256_reset(&hctx, 912);
	dom4_shake256_update(&hctx, 1, context, context_size);
	shake256_update(&hctx, PTR_OFFSET(prehash, ED448_KEY_OCTETS), ED448_KEY_OCTETS);
	shake256_update(&hctx, mhash, 64);
	shake256_final(&hctx, hash, ED448_SIGN_OCTETS);

	ed448_encode_scalar(prehash);

	k = bignum_set_bytes_le(k, hash, ED448_SIGN_OCTETS);
	s = bignum_set_bytes_le(s, prehash, ED448_KEY_OCTETS);

	k = bignum_mod(bctx, k, k, group->n);

	// R = [k]G.
	r.x = x;
	r.y = y;

	ec_point_multiply(group, &r, group->g, k);
	ec_point_encode(group, &r, edsign, ED448_KEY_OCTETS, 0);

	shake256_reset(&hctx, 912);
	dom4_shake256_update(&hctx, 1, context, context_size);
	shake256_update(&hctx, edsign, ED448_KEY_OCTETS);
	shake256_update(&hctx, key->public_key, ED448_KEY_OCTETS);
	shake256_update(&hctx, mhash, 64);
	shake256_final(&hctx, hash, ED448_SIGN_OCTETS);

	d = bignum_set_bytes_le(d, hash, ED448_SIGN_OCTETS);

	// s = (r + ds) mod n.
	s = bignum_modmul(bctx, s, s, d, group->n);
	s = bignum_modadd(bctx, s, s, k, group->n);

	bignum_get_bytes_le(s, PTR_OFFSET(edsign, ED448_KEY_OCTETS), ED448_KEY_OCTETS);

	bignum_ctx_end(bctx);

	return edsign;
}

ed448_signature *ed448ph_sign(ed448_key *key, void *context, size_t context_size, void *message, size_t message_size, void *signature,
							  size_t signature_size)
{
	ec_group *group = NULL;
	ed448_signature *edsign = signature;

	// Check context size
	if (context_size > 255)
	{
		return NULL;
	}

	// Allocate the signature
	if (edsign == NULL)
	{
		edsign = malloc(ED448_SIGN_OCTETS);
	}
	else
	{
		if (signature_size < ED448_SIGN_OCTETS)
		{
			return NULL;
		}
	}

	if (edsign == NULL)
	{
		return NULL;
	}

	// Allocate the group
	group = ec_group_new(EC_ED448);

	if (group == NULL)
	{
		if (signature == NULL)
		{
			free(edsign);
		}

		return NULL;
	}

	edsign = ed448ph_sign_internal(group, key, edsign, context, context_size, message, message_size);

	ec_group_delete(group);

	return edsign;
}

static uint32_t ed448ph_verify_internal(ec_group *group, ed448_key *key, ed448_signature *edsign, void *context, size_t context_size,
										void *message, size_t message_size)
{
	uint32_t status = 0;

	bignum_ctx *bctx = group->bctx;
	size_t ctx_size = 10 * bignum_size(group->bits);

	bignum_t *t = NULL;
	bignum_t *u = NULL;

	ec_point *r = NULL, *q = NULL;
	ec_point *lhs = NULL, *rhs = NULL;

	shake256_ctx hctx;

	byte_t hash[ED448_SIGN_OCTETS];

	bignum_ctx_start(bctx, ctx_size);

	r = ec_point_new(group);
	q = ec_point_new(group);

	t = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);
	u = bignum_ctx_allocate_bignum(bctx, ED448_SIGN_OCTETS * 8);

	t = bignum_set_bytes_le(t, PTR_OFFSET(edsign, ED448_KEY_OCTETS), ED448_KEY_OCTETS);

	if (bignum_cmp(t, group->n) >= 0)
	{
		goto end;
	}

	r = ec_point_decode(group, r, edsign, ED448_KEY_OCTETS);

	if (r == NULL)
	{
		goto end;
	}

	q = ec_point_decode(group, q, key->public_key, ED448_KEY_OCTETS);

	if (q == NULL)
	{
		goto end;
	}

	shake256_init(&hctx, sizeof(shake256_ctx), 512);
	shake256_update(&hctx, message, message_size);
	shake256_final(&hctx, hash, 64);

	shake256_reset(&hctx, 912);
	dom4_shake256_update(&hctx, 1, context, context_size);
	shake256_update(&hctx, edsign, ED448_KEY_OCTETS);
	shake256_update(&hctx, key->public_key, ED448_KEY_OCTETS);
	shake256_update(&hctx, hash, 64);
	shake256_final(&hctx, hash, ED448_SIGN_OCTETS);

	u = bignum_set_bytes_le(u, hash, ED448_SIGN_OCTETS);

	lhs = ec_point_multiply(group, lhs, group->g, t);

	rhs = ec_point_multiply(group, rhs, q, u);
	rhs = ec_point_add(group, rhs, rhs, r);

	if (bignum_cmp(rhs->y, lhs->y) == 0)
	{
		status = 1;
	}

end:
	ec_point_delete(r);
	ec_point_delete(q);
	bignum_ctx_end(bctx);

	return status;
}

uint32_t ed448ph_verify(ed448_key *key, ed448_signature *edsign, void *context, size_t context_size, void *message, size_t message_size)
{
	uint32_t status = 0;
	ec_group *group = NULL;

	// Allocate the group
	group = ec_group_new(EC_ED448);

	if (group == NULL)
	{
		return 0;
	}

	status = ed448ph_verify_internal(group, key, edsign, context, context_size, message, message_size);

	ec_group_delete(group);

	return status;
}
