/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_S2K_H
#define SPGP_S2K_H

#include <pgp.h>

// Refer RFC 9580 - OpenPGP, Section 3.7 String-to-Key (S2K) Specifier

#define EXPBIAS     6
#define IT_COUNT(c) ((16 + ((c) & 15)) << ((c >> 4) + EXPBIAS))

typedef enum _pgp_s2k_type
{
	PGP_S2K_SIMPLE = 0,
	PGP_S2K_SALTED = 1,
	PGP_S2K_ITERATED = 3,
	PGP_S2K_ARGON2 = 4
} pgp_s2k_type;

typedef struct _pgp_s2k
{
	byte_t id;
	union {
		struct
		{
			// id = 0;
			byte_t hash_id;
		} simple;

		struct
		{
			// id = 1;
			byte_t hash_id;
			byte_t salt[8];
		} salted;

		struct
		{
			// id = 3;
			byte_t hash_id;
			byte_t salt[8];
			byte_t count;
		} iterated;

		struct
		{
			// id = 4;
			byte_t salt[16];
			byte_t t; // Iterations
			byte_t p; // Parallelism
			byte_t m; // Memory
		} argon2;
	};
} pgp_s2k;

static inline uint32_t pgp_s2k_size(pgp_s2k *s2k)
{
	switch (s2k->id)
	{
	case PGP_S2K_SIMPLE:
		return 2;
	case PGP_S2K_SALTED:
		return 10;
	case PGP_S2K_ITERATED:
		return 11;
	case PGP_S2K_ARGON2:
		return 20;
	}

	// Unreachable
	return 0;
}

pgp_s2k *pgp_s2k_read(pgp_s2k *s2k, void *data, size_t size);
uint32_t pgp_s2k_write(pgp_s2k *s2k, void *ptr);

pgp_s2k *pgp_s2k_simple_init(pgp_s2k *s2k, byte_t hash_id);
pgp_s2k *pgp_s2k_salted_init(pgp_s2k *s2k, byte_t hash_id, byte_t salt[8]);
pgp_s2k *pgp_s2k_iterated_init(pgp_s2k *s2k, byte_t hash_id, byte_t salt[8], byte_t count);
pgp_s2k *pgp_s2k_argon2_init(pgp_s2k *s2k, byte_t salt[16], byte_t t, byte_t p, byte_t m);

uint32_t pgp_s2k_hash(pgp_s2k *s2k, void *password, uint32_t password_size, void *key, uint32_t key_size);

#endif
