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

uint32_t ff_mqv(dh_key *self_static_key, dh_key *self_ephemral_key, bignum_t *public_static_key, bignum_t *public_ephermal_key,
				void *shared_secret, uint32_t size);
uint32_t ec_mqv(ec_key *self_static_key, ec_key *self_ephemral_key, ec_point *public_static_key, ec_point *public_ephermal_key,
				void *shared_secret, uint32_t size);

#endif
