/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_H
#define SPGP_H

#include <types.h>
#include <buffer.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <load.h>

// Configuration
#define SPGP_DEFAULT_HOME ".spgp"
#define SPGP_CONFIG       "spgp.conf"
#define SPGP_KEYRING      "keyring"

// Directories
#define SPGP_KEYS  "keys"
#define SPGP_CERTS "certs"

// Filename extensions
#define SPGP_KEY_EXT  ".key"
#define SPGP_CERT_EXT ".cert"

typedef enum _spgp_key_id
{
	SPGP_UNKNOWN = 0,

	// RSA
	SPGP_RSA2048,
	SPGP_RSA3072,
	SPGP_RSA4096,

	// DSA
	SPGP_DSA1024,
	SPGP_DSA2048,
	SPGP_DSA3072,

	// Elgamal
	SPGP_ELGAMAL1024,
	SPGP_ELGAMAL2048,
	SPGP_ELGAMAL3072,
	SPGP_ELGAMAL4096,

	// ECC
	SPGP_EC_NISTP256,
	SPGP_EC_NISTP384,
	SPGP_EC_NISTP521,
	SPGP_EC_BRAINPOOL256R1,
	SPGP_EC_BRAINPOOL384R1,
	SPGP_EC_BRAINPOOL512R1,
	SPGP_EC_CURVE25519,
	SPGP_EC_CURVE448,
	SPGP_EC_ED25519,
	SPGP_EC_ED448,

	// Legacy
	SPGP_EC_CURVE25519_LEGACY,
	SPGP_EC_ED25519_LEGACY,

} spgp_key_id;

uint32_t spgp_initialize_home(const char *home);

uint32_t spgp_generate_key(spgp_key_id id, const char *uid, uint16_t uid_size);
uint32_t spgp_delete_key(const char *key_id, uint16_t key_id_size, uint32_t options);

uint32_t spgp_export_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size);
uint32_t spgp_import_key(void *buffer, size_t buffer_size);

uint32_t spgp_search_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size, uint32_t options);
uint32_t spgp_list_keys(uint32_t options);

#endif
