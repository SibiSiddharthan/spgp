/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_CRYPTO_H
#define SPGP_CRYPTO_H

#include <spgp.h>
#include <algorithms.h>

#include <key.h>
#include <session.h>

#define PGP_AEAD_TAG_SIZE 16

byte_t pgp_symmetric_cipher_algorithm_validate(pgp_symmetric_key_algorithms algorithm);
byte_t pgp_public_cipher_algorithm_validate(pgp_public_key_algorithms algorithm);
byte_t pgp_asymmetric_cipher_algorithm_validate(pgp_public_key_algorithms algorithm);
byte_t pgp_signature_algorithm_validate(pgp_public_key_algorithms algorithm);
byte_t pgp_aead_algorithm_validate(pgp_aead_algorithms algorithm);
byte_t pgp_hash_algorithm_validate(pgp_hash_algorithms algorithm);

byte_t pgp_symmetric_cipher_key_size(pgp_symmetric_key_algorithms algorithm);
byte_t pgp_symmetric_cipher_block_size(pgp_symmetric_key_algorithms algorithm);
byte_t pgp_aead_iv_size(pgp_aead_algorithms algorithm);
byte_t pgp_hash_salt_size(pgp_hash_algorithms algorithm);

size_t pgp_cfb_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, void *key, size_t key_size, void *iv, byte_t iv_size,
					   void *in, size_t in_size, void *out, size_t out_size);
size_t pgp_cfb_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, void *key, size_t key_size, void *iv, byte_t iv_size,
					   void *in, size_t in_size, void *out, size_t out_size);

size_t pgp_aead_encrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
						size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
						void *out, size_t out_size, void *tag, size_t tag_size);

size_t pgp_aead_decrypt(pgp_symmetric_key_algorithms symmetric_key_algorithm_id, pgp_aead_algorithms aead_algorithm_id, void *key,
						size_t key_size, void *iv, byte_t iv_size, void *associated_data, size_t ad_size, void *in, size_t in_size,
						void *out, size_t out_size, void *tag, size_t tag_size);

uint32_t pgp_rand(void *buffer, uint32_t size);

pgp_rsa_kex *pgp_rsa_kex_encrypt(pgp_public_rsa_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
								 byte_t session_key_size);
uint32_t pgp_rsa_kex_decrypt(pgp_public_rsa_key *public_key, pgp_private_rsa_key *private_key, pgp_rsa_kex *kex,
							 byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_elgamal_kex *pgp_elgamal_kex_encrypt(pgp_public_elgamal_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
										 byte_t session_key_size);
uint32_t pgp_elgamal_kex_decrypt(pgp_public_elgamal_key *public_key, pgp_private_elgamal_key *private_key, pgp_elgamal_kex *kex,
								 byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_ecdh_kex *pgp_ecdh_kex_encrypt(pgp_public_ecdh_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
								   byte_t session_key_size);
uint32_t pgp_ecdh_kex_decrypt(pgp_public_ecdh_key *public_key, pgp_private_ecdh_key *private_key, pgp_ecdh_kex *kex,
							  byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_x25519_kex *pgp_x25519_kex_encrypt(pgp_public_x25519_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
									 byte_t session_key_size);
uint32_t pgp_x25519_kex_decrypt(pgp_public_x25519_key *public_key, pgp_private_x25519_key *private_key, pgp_x25519_kex *kex,
							  byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_x448_kex *pgp_x448_kex_encrypt(pgp_public_x448_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
								   byte_t session_key_size);
uint32_t pgp_x448_kex_decrypt(pgp_public_x448_key *public_key, pgp_private_x448_key *private_key, pgp_x448_kex *kex,
							  byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

#endif
