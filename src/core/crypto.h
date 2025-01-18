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
#include <signature.h>

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

uint32_t pgp_rsa_generate_key(pgp_rsa_public_key **public_key, pgp_rsa_private_key **private_key);
uint32_t pgp_dsa_generate_key(pgp_dsa_public_key **public_key, pgp_dsa_private_key **private_key);

uint32_t pgp_ecdsa_generate_key(pgp_ecdsa_public_key **public_key, pgp_ecdsa_private_key **private_key);
uint32_t pgp_ecdh_generate_key(pgp_ecdh_public_key **public_key, pgp_ecdh_private_key **private_key);

uint32_t pgp_x25519_generate_key(pgp_x25519_public_key *public_key, pgp_x25519_private_key *private_key);
uint32_t pgp_x448_generate_key(pgp_x448_public_key *public_key, pgp_x448_private_key *private_key);

uint32_t pgp_ed25519_generate_key(pgp_ed25519_public_key *public_key, pgp_ed25519_private_key *private_key);
uint32_t pgp_ed448_generate_key(pgp_ed448_public_key *public_key, pgp_ed448_private_key *private_key);

pgp_ecdh_public_key *pgp_ecdh_generate_ephermal_key(byte_t curve_id);
uint32_t pgp_x25519_generate_ephemeral_key(pgp_x25519_public_key *public_key);
uint32_t pgp_x448_generate_ephemeral_key(pgp_x448_public_key *public_key);

pgp_rsa_kex *pgp_rsa_kex_encrypt(pgp_rsa_public_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
								 byte_t session_key_size);
uint32_t pgp_rsa_kex_decrypt(pgp_rsa_kex *kex, pgp_rsa_public_key *public_key, pgp_rsa_private_key *private_key,
							 byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_elgamal_kex *pgp_elgamal_kex_encrypt(pgp_elgamal_public_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
										 byte_t session_key_size);
uint32_t pgp_elgamal_kex_decrypt(pgp_elgamal_kex *kex, pgp_elgamal_public_key *public_key, pgp_elgamal_private_key *private_key,
								 byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_ecdh_kex *pgp_ecdh_kex_encrypt(pgp_ecdh_public_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
								   byte_t session_key_size);
uint32_t pgp_ecdh_kex_decrypt(pgp_ecdh_kex *kex, pgp_ecdh_public_key *public_key, pgp_ecdh_private_key *private_key,
							  byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_x25519_kex *pgp_x25519_kex_encrypt(pgp_x25519_public_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
									   byte_t session_key_size);
uint32_t pgp_x25519_kex_decrypt(pgp_x25519_kex *kex, pgp_x25519_public_key *public_key, pgp_x25519_private_key *private_key,
								byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_x448_kex *pgp_x448_kex_encrypt(pgp_x448_public_key *public_key, byte_t symmetric_key_algorithm_id, void *session_key,
								   byte_t session_key_size);
uint32_t pgp_x448_kex_decrypt(pgp_x448_kex *kex, pgp_x448_public_key *public_key, pgp_x448_private_key *private_key,
							  byte_t *symmetric_key_algorithm_id, void *session_key, uint32_t session_key_size);

pgp_rsa_signature *pgp_rsa_sign(pgp_rsa_public_key *public_key, pgp_rsa_private_key *private_key, byte_t hash_algorithm_id, void *hash,
								uint32_t hash_size);
uint32_t pgp_rsa_verify(pgp_rsa_signature *signature, pgp_rsa_public_key *public_key, void *hash, uint32_t hash_size);

pgp_dsa_signature *pgp_dsa_sign(pgp_dsa_public_key *public_key, pgp_dsa_private_key *private_key, void *hash, uint32_t hash_size);
uint32_t pgp_dsa_verify(pgp_dsa_signature *signature, pgp_dsa_public_key *public_key, void *hash, uint32_t hash_size);

pgp_dsa_signature *pgp_ecdsa_sign(pgp_ecdsa_public_key *public_key, pgp_ecdsa_private_key *private_key, void *hash, uint32_t hash_size);
uint32_t pgp_ecdsa_verify(pgp_ecdsa_signature *signature, pgp_ecdsa_public_key *public_key, void *hash, uint32_t hash_size);

pgp_ed25519_signature *pgp_ed25519_sign(pgp_ed25519_public_key *public_key, pgp_ed25519_private_key *private_key, void *hash,
										uint32_t hash_size);
uint32_t pgp_ed25519_verify(pgp_ed25519_signature *signature, pgp_ed25519_public_key *public_key, void *hash, uint32_t hash_size);

pgp_ed448_signature *pgp_ed448_sign(pgp_ed448_public_key *public_key, pgp_ed448_private_key *private_key, void *hash, uint32_t hash_size);
uint32_t pgp_ed448_verify(pgp_ed448_signature *signature, pgp_ed448_public_key *public_key, void *hash, uint32_t hash_size);

#endif
