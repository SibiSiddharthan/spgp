/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_KAS_H
#define CRYPTO_KAS_H

#include <dh.h>
#include <ec.h>

uint32_t ff_dh(dh_key *self_key, bignum_t *public_key, void *shared_secret, uint32_t size);
uint32_t ec_dh(ec_key *self_key, ec_point *public_key, void *shared_secret, uint32_t size);

uint32_t ff_mqv(dh_key *self_static_key, bignum_t *self_ephemeral_private_key, bignum_t *self_ephemeral_public_key,
				bignum_t *static_pulbic_key, bignum_t *ephermal_public_key, void *shared_secret, uint32_t size);
uint32_t ec_mqv(ec_key *self_static_key, bignum_t *self_ephemeral_private_key, ec_point *self_ephemeral_public_key,
				ec_point *static_pulbic_key, ec_point *ephermal_public_key, void *shared_secret, uint32_t size);

#endif
