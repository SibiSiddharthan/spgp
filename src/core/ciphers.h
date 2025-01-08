/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_CIPHERS_H
#define SPGP_CIPHERS_H

#include <spgp.h>
#include <algorithms.h>

#include <cipher.h>

#define PGP_AEAD_TAG_SIZE 16

byte_t pgp_symmetric_cipher_algorithm_validate(pgp_symmetric_key_algorithms algorithm);
byte_t pgp_asymmetric_cipher_algorithm_validate(pgp_public_key_algorithms algorithm);
byte_t pgp_signature_algorithm_validate(pgp_public_key_algorithms algorithm);
byte_t pgp_aead_algorithm_validate(pgp_aead_algorithms algorithm);

byte_t pgp_symmetric_cipher_key_size(pgp_symmetric_key_algorithms algorithm);
byte_t pgp_symmetric_cipher_iv_size(pgp_symmetric_key_algorithms algorithm);

size_t pgp_aead_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
						size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
						void *out, size_t out_size, void *tag, size_t tag_size);

size_t pgp_aead_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
						size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
						void *out, size_t out_size, void *tag, size_t tag_size);

#endif
