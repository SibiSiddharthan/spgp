/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <ec.h>
#include <eddsa.h>
#include <bignum-internal.h>

#include <sha.h>
#include <shake.h>

#include <minmax.h>
#include <ptr.h>

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
	void *result = NULL;

	sha512_ctx hctx;

	byte_t prehash[SHA512_HASH_SIZE];
	byte_t hash[SHA512_HASH_SIZE];

	sha512_init(&hctx, sizeof(sha512_ctx));

	bignum_ctx_start(bctx, ctx_size);

	x = bignum_ctx_allocate_bignum(bctx, group->bits);
	y = bignum_ctx_allocate_bignum(bctx, group->bits);
	k = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);
	s = bignum_ctx_allocate_bignum(bctx, SHA512_HASH_SIZE * 8);

	// Compute the prehash
	sha512_update(&hctx, key->private_key, ED25519_KEY_OCTETS);
	sha512_final(&hctx, prehash);
	sha512_reset(&hctx);

	// Hash the message
	sha512_update(&hctx, PTR_OFFSET(prehash, ED25519_KEY_OCTETS), ED25519_KEY_OCTETS);
	sha512_update(&hctx, message, size);
	sha512_final(&hctx, hash);
	sha512_reset(&hctx);

	k = bignum_set_bytes_le(k, hash, SHA512_HASH_SIZE);
	s = bignum_set_bytes_le(k, prehash, SHA512_HASH_SIZE);

	// R = [k]G.
	r.x = x;
	r.y = y;

	ec_point_multiply(&group, &r, group->g, k);
	ec_point_encode(&group, &r, edsign, ED25519_KEY_OCTETS, 0);

	sha512_update(&hctx, edsign, ED25519_KEY_OCTETS);
	sha512_update(&hctx, key->public_key, ED25519_KEY_OCTETS);
	sha512_update(&hctx, message, size);
	sha512_final(&hctx, hash);

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
	bignum_t *v = NULL;

	ec_point *r = NULL, *q = NULL;
	ec_point *lhs = NULL, *rhs = NULL;
	void *result = NULL;

	sha512_ctx hctx;

	byte_t hash[SHA512_HASH_SIZE];

	bignum_ctx_start(bctx, ctx_size);

	t = bignum_ctx_allocate_bignum(bctx, group->bits);
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

	sha512_update(&hctx, edsign, 32);
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
		return NULL;
	}

	status = ed25519_verify_internal(group, key, edsign, message, message_size);

	ec_group_delete(group);

	return status;
}
