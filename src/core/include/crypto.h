/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_CRYPTO_H
#define SPGP_CRYPTO_H

#include <pgp.h>
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
byte_t pgp_hash_size(pgp_hash_algorithms algorithm);
byte_t pgp_hash_salt_size(pgp_hash_algorithms algorithm);
byte_t pgp_elliptic_curve(byte_t *oid, byte_t size);

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

pgp_error_t pgp_rsa_kex_encrypt(pgp_rsa_kex **kex, pgp_rsa_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
								byte_t session_key_size);
pgp_error_t pgp_rsa_kex_decrypt(pgp_rsa_kex *kex, pgp_rsa_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
								byte_t *session_key_size);

pgp_error_t pgp_elgamal_kex_encrypt(pgp_elgamal_kex **kex, pgp_elgamal_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
									byte_t session_key_size);
pgp_error_t pgp_elgamal_kex_decrypt(pgp_elgamal_kex *kex, pgp_elgamal_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
									byte_t *session_key_size);

pgp_error_t pgp_ecdh_kex_encrypt(pgp_ecdh_kex **kex, pgp_ecdh_key *pgp_key, byte_t symmetric_key_algorithm_id, byte_t *fingerprint,
								 byte_t fingerprint_size, void *session_key, byte_t session_key_size);
pgp_error_t pgp_ecdh_kex_decrypt(pgp_ecdh_kex *kex, pgp_ecdh_key *pgp_key, byte_t *symmetric_key_algorithm_id, byte_t *fingerprint,
								 byte_t fingerprint_size, void *session_key, byte_t *session_key_size);

pgp_error_t pgp_x25519_kex_encrypt(pgp_x25519_kex **kex, pgp_x25519_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
								   byte_t session_key_size);
pgp_error_t pgp_x25519_kex_decrypt(pgp_x25519_kex *kex, pgp_x25519_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
								   byte_t *session_key_size);

pgp_error_t pgp_x448_kex_encrypt(pgp_x448_kex **kex, pgp_x448_key *pgp_key, byte_t symmetric_key_algorithm_id, void *session_key,
								 byte_t session_key_size);
pgp_error_t pgp_x448_kex_decrypt(pgp_x448_kex *kex, pgp_x448_key *pgp_key, byte_t *symmetric_key_algorithm_id, void *session_key,
								 byte_t *session_key_size);

pgp_error_t pgp_rsa_sign(pgp_rsa_signature **signature, pgp_rsa_key *pgp_key, byte_t hash_algorithm_id, void *hash, uint32_t hash_size);
pgp_error_t pgp_rsa_verify(pgp_rsa_signature *signature, pgp_rsa_key *pgp_key, byte_t hash_algorithm_id, void *hash, uint32_t hash_size);

pgp_error_t pgp_dsa_sign(pgp_dsa_signature **signature, pgp_dsa_key *pgp_key, void *hash, uint32_t hash_size);
pgp_error_t pgp_dsa_verify(pgp_dsa_signature *signature, pgp_dsa_key *pgp_key, void *hash, uint32_t hash_size);

pgp_error_t pgp_ecdsa_sign(pgp_ecdsa_signature **signature, pgp_ecdsa_key *pgp_key, void *hash, uint32_t hash_size);
pgp_error_t pgp_ecdsa_verify(pgp_ecdsa_signature *signature, pgp_ecdsa_key *pgp_key, void *hash, uint32_t hash_size);

pgp_error_t pgp_eddsa_sign(pgp_eddsa_signature **signature, pgp_eddsa_key *pgp_key, void *hash, uint32_t hash_size);
pgp_error_t pgp_eddsa_verify(pgp_eddsa_signature *signature, pgp_eddsa_key *pgp_key, void *hash, uint32_t hash_size);

pgp_error_t pgp_ed25519_sign(pgp_ed25519_signature **signature, pgp_ed25519_key *pgp_key, void *hash, uint32_t hash_size);
pgp_error_t pgp_ed25519_verify(pgp_ed25519_signature *signature, pgp_ed25519_key *pgp_key, void *hash, uint32_t hash_size);

pgp_error_t pgp_ed448_sign(pgp_ed448_signature **signature, pgp_ed448_key *pgp_key, void *hash, uint32_t hash_size);
pgp_error_t pgp_ed448_verify(pgp_ed448_signature *signature, pgp_ed448_key *pgp_key, void *hash, uint32_t hash_size);

// KDFs
uint32_t pgp_argon2(void *password, uint32_t password_size, void *salt, uint32_t salt_size, uint32_t parallel, uint32_t memory,
					uint32_t iterations, void *secret, uint32_t secret_size, void *data, uint32_t data_size, void *key, uint32_t key_size);

uint32_t pgp_hkdf(pgp_hash_algorithms algorithm, void *key, uint32_t key_size, void *salt, size_t salt_size, void *info, size_t info_size,
				  void *derived_key, uint32_t derived_key_size);

#endif
