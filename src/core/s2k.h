/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_S2K_H
#define SPGP_S2K_H

#include <spgp.h>

// Refer RFC 9580 - OpenPGP, Section 3.7 String-to-Key (S2K) Specifier

#define EXPBIAS     6
#define IT_COUNT(c) ((16 + ((c) & 15)) << ((c >> 4) + EXPBIAS))

typedef enum _pgp_s2k_type
{
	pgp_simple_s2k = 0,
	pgp_salted_s2k = 1,
	pgp_iterated_s2k = 3,
	pgp_argon2 = 4
} pgp_s2k_type;

typedef struct _pgp_s2k
{
	byte_t id;
	union {
		struct
		{
			// id = 0;
			byte_t hash_id;
		} simple_s2k;

		struct
		{
			// id = 1;
			byte_t hash_id;
			byte_t salt[8];
		} salted_s2k;

		struct
		{
			// id = 3;
			byte_t hash_id;
			byte_t salt[8];
			byte_t count;
		} iterated_s2k;

		struct
		{
			// id = 4;
			byte_t salt[16];
			byte_t t;
			byte_t p;
			byte_t m;
		} argon2;
	};
} pgp_s2k;

#endif
