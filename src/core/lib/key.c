/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <s2k.h>
#include <mpi.h>
#include <signature.h>
#include <crypto.h>

#include <stdlib.h>
#include <string.h>

#ifndef MD5_HASH_SIZE
#	define MD5_HASH_SIZE 16
#endif

#ifndef SHA1_HASH_SIZE
#	define SHA1_HASH_SIZE 20
#endif

static uint32_t get_public_key_material_octets(pgp_public_key_algorithms public_key_algorithm_id, void *key_data)
{
	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = key_data;

		return mpi_octets(key->n->bits) + mpi_octets(key->e->bits);
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = key_data;

		return mpi_octets(key->p->bits) + mpi_octets(key->g->bits) + mpi_octets(key->y->bits);
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = key_data;

		return mpi_octets(key->p->bits) + mpi_octets(key->q->bits) + mpi_octets(key->g->bits) + mpi_octets(key->y->bits);
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = key_data;

		return 5 + key->oid_size + mpi_octets(key->point->bits);
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = key_data;

		return 1 + key->oid_size + mpi_octets(key->point->bits);
	}
	case PGP_X25519:
	{
		return 32;
	}
	case PGP_X448:
	{
		return 56;
	}
	case PGP_ED25519:
	{
		return 32;
	}
	case PGP_ED448:
	{
		return 57;
	}
	default:
		return 0;
	}
}

static uint32_t get_private_key_material_octets(pgp_public_key_algorithms public_key_algorithm_id, void *key_data)
{
	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = key_data;

		return mpi_octets(key->d->bits) + mpi_octets(key->p->bits) + mpi_octets(key->q->bits) + mpi_octets(key->u->bits);
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = key_data;

		return mpi_octets(key->x->bits);
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = key_data;

		return mpi_octets(key->x->bits);
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = key_data;

		return mpi_octets(key->x->bits);
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = key_data;

		return mpi_octets(key->x->bits);
	}
	case PGP_X25519:
	{
		return 32;
	}
	case PGP_X448:
	{
		return 56;
	}
	case PGP_ED25519:
	{
		return 32;
	}
	case PGP_ED448:
	{
		return 57;
	}
	default:
		return 0;
	}
}

static uint16_t mpi_checksum(mpi_t *mpi)
{
	uint16_t checksum = 0;
	uint16_t bytes = 0;

	checksum += mpi->bits >> 8;
	checksum += mpi->bits & 0xFF;
	bytes = CEIL_DIV(mpi->bits, 8);

	for (uint16_t i = 0; i < bytes; ++i)
	{
		checksum += mpi->bytes[i];
	}

	return checksum;
}

static uint16_t pgp_private_key_material_checksum(pgp_key_packet *packet)
{
	uint16_t checksum = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = packet->key;

		checksum += mpi_checksum(key->d);
		checksum += mpi_checksum(key->p);
		checksum += mpi_checksum(key->q);
		checksum += mpi_checksum(key->u);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key;

		checksum += mpi_checksum(key->x);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;

		checksum += mpi_checksum(key->x);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key;

		checksum += mpi_checksum(key->x);
	}
	break;
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = packet->key;

		checksum += mpi_checksum(key->x);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key;

		for (uint16_t i = 0; i < 32; ++i)
		{
			checksum += key->private_key[i];
		}
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key;

		for (uint16_t i = 0; i < 56; ++i)
		{
			checksum += key->private_key[i];
		}
	}
	break;
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key;

		for (uint16_t i = 0; i < 32; ++i)
		{
			checksum += key->private_key[i];
		}
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key;

		for (uint16_t i = 0; i < 57; ++i)
		{
			checksum += key->private_key[i];
		}
	}
	break;
	default:
		return 0;
	}

	return BSWAP_16(checksum);
}

static pgp_error_t pgp_public_key_material_read(pgp_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	if (size == 0)
	{
		return PGP_EMPTY_PUBLIC_KEY;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		// MPI of n,e
		pgp_rsa_key *key = NULL;
		uint16_t offset = 0;
		uint16_t mpi_n_bits = 0;
		uint16_t mpi_e_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_RSA_PUBLIC_KEY;
		}

		mpi_n_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_n_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_RSA_PUBLIC_KEY;
		}

		mpi_e_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_e_bits);

		if (size < offset)
		{
			return PGP_MALFORMED_RSA_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_rsa_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_rsa_key));

		key->n = mpi_new(mpi_n_bits);
		key->e = mpi_new(mpi_e_bits);

		if (key->n == NULL || key->e == NULL)
		{
			pgp_rsa_key_delete(key);
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->n, in + pos, size - pos);
		pos += mpi_read(key->e, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		// MPI of p,g,y
		pgp_elgamal_key *key = NULL;
		uint16_t offset = 0;
		uint16_t mpi_p_bits = 0;
		uint16_t mpi_g_bits = 0;
		uint16_t mpi_y_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_ELGAMAL_PUBLIC_KEY;
		}

		mpi_p_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_p_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_ELGAMAL_PUBLIC_KEY;
		}

		mpi_g_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_g_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_ELGAMAL_PUBLIC_KEY;
		}

		mpi_y_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_y_bits);

		if (size < offset)
		{
			return PGP_MALFORMED_ELGAMAL_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_elgamal_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_elgamal_key));

		key->p = mpi_new(mpi_p_bits);
		key->g = mpi_new(mpi_g_bits);
		key->y = mpi_new(mpi_y_bits);

		if (key->p == NULL || key->g == NULL || key->y == NULL)
		{
			pgp_elgamal_key_delete(key);
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_DSA:
	{
		// MPI of p,q,g,y
		pgp_dsa_key *key = NULL;
		uint16_t offset = 0;
		uint16_t mpi_p_bits = 0;
		uint16_t mpi_q_bits = 0;
		uint16_t mpi_g_bits = 0;
		uint16_t mpi_y_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_DSA_PUBLIC_KEY;
		}

		mpi_p_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_p_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_DSA_PUBLIC_KEY;
		}

		mpi_q_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_q_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_DSA_PUBLIC_KEY;
		}

		mpi_g_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_g_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_DSA_PUBLIC_KEY;
		}

		mpi_y_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_y_bits);

		if (size < offset)
		{
			return PGP_MALFORMED_DSA_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_dsa_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_dsa_key));

		key->p = mpi_new(mpi_p_bits);
		key->q = mpi_new(mpi_q_bits);
		key->g = mpi_new(mpi_g_bits);
		key->y = mpi_new(mpi_y_bits);

		if (key->p == NULL || key->q == NULL || key->g == NULL || key->y == NULL)
		{
			pgp_dsa_key_delete(key);
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = NULL;
		uint16_t offset = in[0] + 1;
		uint16_t mpi_point_bits = 0;

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_ECDH_PUBLIC_KEY;
		}

		mpi_point_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_point_bits);

		if (size < (offset + 4)) // 4 octets for KDF
		{
			return PGP_MALFORMED_ECDH_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_ecdh_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_ecdh_key));

		// 1-octet oid size
		LOAD_8(&key->oid_size, in + pos);
		pos += 1;

		// N octets of oid
		memcpy(key->oid, in + pos, key->oid_size);
		pos += key->oid_size;

		// Decode the OID
		key->curve = pgp_elliptic_curve(key->oid, key->oid_size);

		// EC point
		key->point = mpi_new(mpi_point_bits);

		if (key->point == NULL)
		{
			pgp_ecdh_key_delete(key);
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->point, in + pos, size - pos);

		// KDF
		LOAD_8(&key->kdf.size, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.extensions, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.hash_algorithm_id, in + pos);
		pos += 1;

		LOAD_8(&key->kdf.symmetric_key_algorithm_id, in + pos);
		pos += 1;

		packet->public_key_data_octets = pos;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = NULL;
		uint16_t offset = in[0] + 1;
		uint16_t mpi_point_bits = 0;
		pgp_error_t error =
			(packet->public_key_algorithm_id == PGP_ECDSA) ? PGP_MALFORMED_ECDSA_PUBLIC_KEY : PGP_MALFORMED_EDDSA_PUBLIC_KEY;

		if (size < (offset + 2))
		{
			return error;
		}

		mpi_point_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_point_bits);

		if (size < offset)
		{
			return error;
		}

		key = malloc(sizeof(pgp_ecdsa_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_ecdsa_key));

		// 1-octet oid size
		LOAD_8(&key->oid_size, in + pos);
		pos += 1;

		// N octets of oid
		memcpy(key->oid, in + pos, key->oid_size);
		pos += key->oid_size;

		// Decode the OID
		key->curve = pgp_elliptic_curve(key->oid, key->oid_size);

		// EC point
		key->point = mpi_new(mpi_point_bits);

		if (key->point == NULL)
		{
			pgp_ecdsa_key_delete(key);
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->point, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_X25519:
	{
		// 32 octets
		pgp_x25519_key *key = NULL;

		if (size < 32)
		{
			return PGP_MALFORMED_X25519_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_x25519_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_x25519_key));
		memcpy(key->public_key, in, 32);

		packet->public_key_data_octets = 32;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_X448:
	{
		// 56 octets
		pgp_x448_key *key = NULL;

		if (size < 56)
		{
			return PGP_MALFORMED_X448_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_x448_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_x448_key));
		memcpy(key->public_key, in, 56);

		packet->public_key_data_octets = 56;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_ED25519:
	{
		// 32 octets
		pgp_ed25519_key *key = NULL;

		if (size < 32)
		{
			return PGP_MALFORMED_ED25519_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_ed25519_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_ed25519_key));
		memcpy(key->public_key, in, 32);

		packet->public_key_data_octets = 32;
		packet->key = key;

		return PGP_SUCCESS;
	}
	case PGP_ED448:
	{
		// 57 octets
		pgp_ed448_key *key = NULL;

		if (size < 57)
		{
			return PGP_MALFORMED_ED448_PUBLIC_KEY;
		}

		key = malloc(sizeof(pgp_ed448_key));

		if (key == NULL)
		{
			return PGP_NO_MEMORY;
		}

		memset(key, 0, sizeof(pgp_ed448_key));
		memcpy(key->public_key, in, 57);

		packet->public_key_data_octets = 57;
		packet->key = key;

		return PGP_SUCCESS;
	}
	default:
		packet->public_key_data_octets = size;
		return PGP_SUCCESS;
	}
}

static uint32_t pgp_public_key_material_write(pgp_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = packet->key;

		pos += mpi_write(key->n, out + pos, size - pos);
		pos += mpi_write(key->e, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;

		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->g, out + pos, size - pos);
		pos += mpi_write(key->y, out + pos, size - pos);

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key;

		// 1-octet oid size
		LOAD_8(out + pos, &key->oid_size);
		pos += 1;

		// N octets of oid
		memcpy(out + pos, key->oid, key->oid_size);
		pos += key->oid_size;

		// EC point
		pos += mpi_write(key->point, out + pos, size - pos);

		// KDF
		LOAD_8(out + pos, &key->kdf.size);
		pos += 1;

		LOAD_8(out + pos, &key->kdf.extensions);
		pos += 1;

		LOAD_8(out + pos, &key->kdf.hash_algorithm_id);
		pos += 1;

		LOAD_8(out + pos, &key->kdf.symmetric_key_algorithm_id);
		pos += 1;

		return pos;
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = packet->key;

		// 1-octet oid size
		LOAD_8(out + pos, &key->oid_size);
		pos += 1;

		// N octets of oid
		memcpy(out + pos, key->oid, key->oid_size);
		pos += key->oid_size;

		// EC point
		pos += mpi_write(key->point, out + pos, size - pos);

		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key;

		// 32 octets
		memcpy(out, key->public_key, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key;

		// 56 octets
		memcpy(out, key->public_key, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key;

		// 32 octets
		memcpy(out, key->public_key, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key;

		// 57 octets
		memcpy(out, key->public_key, 57);
		return 57;
	}
	default:
		return 0;
	}
}

// This should only be called after `pgp_public_key_material_read` which will allocate the key.
static pgp_error_t pgp_private_key_material_read(pgp_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	if (packet->key == NULL)
	{
		return PGP_INTERNAL_BUG;
	}

	if (size == 0)
	{
		return PGP_EMPTY_SECRET_KEY;
	}

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = packet->key;
		uint16_t offset = 0;
		uint16_t mpi_d_bits = 0;
		uint16_t mpi_p_bits = 0;
		uint16_t mpi_q_bits = 0;
		uint16_t mpi_u_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_RSA_SECRET_KEY;
		}

		mpi_d_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_d_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_RSA_SECRET_KEY;
		}

		mpi_p_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_p_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_RSA_SECRET_KEY;
		}

		mpi_q_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_q_bits);

		if (size < (offset + 2))
		{
			return PGP_MALFORMED_RSA_SECRET_KEY;
		}

		mpi_u_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_u_bits);

		if (size < offset)
		{
			return PGP_MALFORMED_RSA_SECRET_KEY;
		}

		key->d = mpi_new(mpi_d_bits);
		key->p = mpi_new(mpi_p_bits);
		key->q = mpi_new(mpi_q_bits);
		key->u = mpi_new(mpi_u_bits);

		if (key->d == NULL || key->p == NULL || key->q == NULL || key->u == NULL)
		{
			// Only delete the secret parts
			mpi_delete(key->d);
			mpi_delete(key->p);
			mpi_delete(key->q);
			mpi_delete(key->d);

			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->d, in + pos, size - pos);
		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->u, in + pos, size - pos);

		packet->private_key_data_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key;
		uint16_t mpi_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_ELGAMAL_SECRET_KEY;
		}

		mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return PGP_MALFORMED_ELGAMAL_SECRET_KEY;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;
		uint16_t mpi_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_DSA_SECRET_KEY;
		}

		mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return PGP_MALFORMED_DSA_SECRET_KEY;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key;
		uint16_t mpi_bits = 0;

		if (size < 2)
		{
			return PGP_MALFORMED_ECDH_SECRET_KEY;
		}

		mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return PGP_MALFORMED_ECDH_SECRET_KEY;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = packet->key;
		uint16_t mpi_bits = 0;
		pgp_error_t error =
			(packet->public_key_algorithm_id == PGP_ECDSA) ? PGP_MALFORMED_ECDSA_SECRET_KEY : PGP_MALFORMED_EDDSA_SECRET_KEY;

		if (size < 2)
		{
			return error;
		}

		mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return error;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return PGP_NO_MEMORY;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return PGP_SUCCESS;
	}
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key;

		if (size < 32)
		{
			return PGP_MALFORMED_X25519_SECRET_KEY;
		}

		// 32 octets
		memcpy(key->private_key, in, 32);
		packet->private_key_data_octets = 32;

		return PGP_SUCCESS;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key;

		if (size < 56)
		{
			return PGP_MALFORMED_X448_SECRET_KEY;
		}

		// 56 octets
		memcpy(key->private_key, in, 56);
		packet->private_key_data_octets = 56;

		return PGP_SUCCESS;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key;

		if (size < 32)
		{
			return PGP_MALFORMED_ED25519_SECRET_KEY;
		}

		// 32 octets
		memcpy(key->private_key, in, 32);
		packet->private_key_data_octets = 32;

		return PGP_SUCCESS;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key;

		if (size < 57)
		{
			return PGP_MALFORMED_ED448_SECRET_KEY;
		}

		// 57 octets
		memcpy(key->private_key, in, 57);
		packet->private_key_data_octets = 57;

		return PGP_SUCCESS;
	}
	default:
		packet->private_key_data_octets = size;
		return PGP_SUCCESS;
	}
}

static uint32_t pgp_private_key_material_write(pgp_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *out = ptr;
	uint32_t pos = 0;

	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = packet->key;

		pos += mpi_write(key->d, out + pos, size - pos);
		pos += mpi_write(key->p, out + pos, size - pos);
		pos += mpi_write(key->q, out + pos, size - pos);
		pos += mpi_write(key->u, out + pos, size - pos);

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = packet->key;

		pos += mpi_write(key->x, out, size);
		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key;

		// 32 octets
		memcpy(out, key->private_key, 32);
		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key;

		// 56 octets
		memcpy(out, key->private_key, 56);
		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key;

		// 32 octets
		memcpy(out, key->private_key, 32);
		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key;

		// 57 octets
		memcpy(out, key->private_key, 57);
		return 57;
	}
	default:
		return 0;
	}
}

static uint32_t pgp_key_packet_get_s2k_size(pgp_key_packet *packet)
{
	switch (packet->s2k_usage)
	{
	case 0: // Plaintext
		return 0;
	case 253: // AEAD
		// A 1-octet symmetric key algorithm.
		// A 1-octet AEAD algorithm.
		// A 1-octet count of S2K specifier
		// A S2K specifier
		// IV
		return 1 + 1 + 1 + packet->iv_size + pgp_s2k_octets(&packet->s2k);
	case 254: // CFB
	case 255: // Malleable CFB
		// A 1-octet symmetric key algorithm.
		// A 1-octet count of S2K specifier
		// A S2K specifier
		// IV
		return 1 + 1 + packet->iv_size + pgp_s2k_octets(&packet->s2k);
		break;
	default:
		return 0;
	}
}

static void pgp_key_packet_encode_header(pgp_key_packet *packet, pgp_packet_type type)
{
	pgp_packet_header_format format = packet->version >= PGP_KEY_V4 ? PGP_HEADER : PGP_LEGACY_HEADER;
	uint32_t body_size = 0;

	if (type == PGP_KEYDEF)
	{
		// A 1-octet key version number.
		// A 1-octet key type.
		// A 1-octet key capabilities.
		// A 1-octet key flags.
		// A 1-octet public key algorithm.
		// A 4-octet number denoting the time when the key was created.
		// A 4-octet number denoting the time when the key was revoked.
		// A 4-octet number denoting the time when the key will expire.
		// A 4-octet scalar count for the public key material
		// One or more MPIs comprising the public key.

		// If secret key the below fields as well
		// A 1-octet of S2K usage
		// A 1-octet scalar count of s2k fields if above field is non zero
		// s2k fields
		// A 4-octet scalar count of key data (inclusive of tag)
		// (Plaintext or encrypted) Private key data.

		body_size = 1 + 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + packet->public_key_data_octets;

		if (packet->type == PGP_KEY_TYPE_SECRET)
		{
			body_size += 1 + 4;
			body_size += (packet->encrypted != NULL ? packet->encrypted_octets : packet->private_key_data_octets);
			body_size += (packet->s2k_usage != 0) ? (1 + pgp_key_packet_get_s2k_size(packet)) : 0;
		}

		packet->header = pgp_packet_header_encode(format, type, 0, body_size);
	}

	if (type == PGP_PUBKEY || type == PGP_PUBSUBKEY)
	{
		// A 1-octet version number.
		// A 4-octet number denoting the time when the key was created.
		// (For V3) A 2-octet number denoting expiry in days.
		// A 1-octet public key algorithm.
		// (For V6) A 4-octet scalar count for the public key material
		// One or more MPIs comprising the key.

		body_size = 1 + 4 + 1 + packet->public_key_data_octets;
		body_size += (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3) ? 2 : 0;
		body_size += (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5) ? 4 : 0;

		packet->header = pgp_packet_header_encode(format, type, 0, body_size);
	}

	if (type == PGP_SECKEY || type == PGP_SECSUBKEY)
	{
		// A 1-octet version number.
		// A 4-octet number denoting the time when the key was created.
		// (For V3) A 2-octet number denoting expiry in days.
		// A 1-octet public key algorithm.
		// (For V5, V6) A 4-octet scalar count for the public key material
		// One or more MPIs comprising the public key.
		// A 1-octet of S2K usage
		// (For V5, V6) A 1-octet scalar count of s2k fields if above field is non zero
		// s2k fields
		// (For V5) A 4-octet scalar count of key data (inclusive of tag)
		// (Plaintext or encrypted) Private key data.
		// (For V3, V4, V5) A 2-octet checksum of private key if not encrypted

		body_size = 1 + 4 + 1 + 1 + packet->public_key_data_octets;
		body_size += (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3) ? 2 : 0;
		body_size += (packet->encrypted != NULL ? packet->encrypted_octets : packet->private_key_data_octets);

		// Checksum
		if (packet->s2k_usage == 0)
		{
			if (packet->version != PGP_KEY_V6)
			{
				body_size += 2;
			}
		}

		// Key octets
		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			body_size += 4;

			if (packet->version == PGP_KEY_V5)
			{
				body_size += 4;
			}
		}

		body_size += (packet->s2k_usage != 0) ? (1 + pgp_key_packet_get_s2k_size(packet)) : 0;

		packet->header = pgp_packet_header_encode(format, type, 0, body_size);
	}
}

static pgp_error_t pgp_public_key_packet_read_body(pgp_key_packet *packet, buffer_t *buffer)
{
	pgp_error_t error = 0;
	uint32_t public_key_data_octets = 0;

	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_PUBLIC_KEY_PACKET);

	if (packet->version != PGP_KEY_V2 && packet->version != PGP_KEY_V3 && packet->version != PGP_KEY_V4 && packet->version != PGP_KEY_V5 &&
		packet->version != PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	// 4-octet number denoting the time when the key was created.
	CHECK_READ(read32_be(buffer, &packet->key_creation_time), PGP_MALFORMED_PUBLIC_KEY_PACKET);

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		CHECK_READ(read16_be(buffer, &packet->key_expiry_days), PGP_MALFORMED_PUBLIC_KEY_PACKET);
	}

	// 1-octet public key algorithm.
	CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_PUBLIC_KEY_PACKET);

	// Public key material
	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		// 4-octet scalar count for the public key material
		CHECK_READ(read32_be(buffer, &public_key_data_octets), PGP_MALFORMED_PUBLIC_KEY_PACKET);
	}
	else
	{
		public_key_data_octets = buffer->size - buffer->pos;
	}

	error = pgp_public_key_material_read(packet, buffer->data + buffer->pos, public_key_data_octets);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	// Check whether the given count is correct
	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		if (packet->public_key_data_octets != public_key_data_octets)
		{
			return PGP_MALFORMED_PUBLIC_KEY_COUNT;
		}
	}

	buffer->pos += packet->public_key_data_octets;

	return PGP_SUCCESS;
}

pgp_error_t pgp_public_key_packet_read_with_header(pgp_key_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_key_packet *key = NULL;

	key = malloc(sizeof(pgp_key_packet));

	if (packet == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(key, 0, sizeof(pgp_key_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	key->header = *header;

	// Read the body
	error = pgp_public_key_packet_read_body(key, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_key_packet_delete(key);
		return error;
	}

	*packet = key;

	return error;
}

pgp_error_t pgp_public_key_packet_read(pgp_key_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_PUBKEY && pgp_packet_type_from_tag(header.tag) != PGP_PUBSUBKEY)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_public_key_packet_read_with_header(packet, &header, data);
}

size_t pgp_public_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 4-octet number denoting the time when the key was created
	LOAD_32BE(out + pos, &packet->key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		LOAD_16BE(out + pos, &packet->key_expiry_days);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		// 4-octet scalar count for the public key material
		LOAD_32BE(out + pos, &packet->public_key_data_octets);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, out + pos, size - pos);

	return pos;
}

static pgp_error_t pgp_secret_key_material_encrypt_legacy_cfb_v3(pgp_key_packet *packet, byte_t hash[MD5_HASH_SIZE])
{
	// Only RSA keys
	pgp_error_t status = 0;

	pgp_rsa_key *key = packet->key;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t size = mpi_octets(key->d->bits) + mpi_octets(key->p->bits) + mpi_octets(key->q->bits) + mpi_octets(key->u->bits) + 2;

	uint32_t pos = 0;
	uint16_t bits_be = 0;

	packet->encrypted = malloc(size);

	if (packet->encrypted == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(packet->encrypted, 0, size);

	// d
	bits_be = BSWAP_16(key->d->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->d->bytes,
							 CEIL_DIV(key->d->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->d->bits, 8));
	pos += CEIL_DIV(key->d->bits, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// p
	bits_be = BSWAP_16(key->p->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->p->bytes,
							 CEIL_DIV(key->p->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->p->bits, 8));
	pos += CEIL_DIV(key->p->bits, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// q
	bits_be = BSWAP_16(key->q->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->q->bytes,
							 CEIL_DIV(key->q->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->q->bits, 8));
	pos += CEIL_DIV(key->q->bits, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// u
	bits_be = BSWAP_16(key->u->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->u->bytes,
							 CEIL_DIV(key->u->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->u->bits, 8));
	pos += CEIL_DIV(key->u->bits, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Store the checksum at the end
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &packet->key_checksum);

	packet->encrypted_octets = pos;

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_decrypt_legacy_cfb_v3(pgp_key_packet *packet, byte_t hash[MD5_HASH_SIZE])
{
	// Only RSA keys
	pgp_error_t status = 0;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	uint32_t pos = 0;
	uint16_t bits_be = 0;
	uint16_t bits_le = 0;

	byte_t *buffer = 0;

	buffer = malloc(packet->encrypted_octets);

	if (buffer == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, packet->encrypted_octets);

	// d
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
							 PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));
	pos += CEIL_DIV(bits_le, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// p
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
							 PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));
	pos += CEIL_DIV(bits_le, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// q
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
							 PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));
	pos += CEIL_DIV(bits_le, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// u
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
							 PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));
	pos += CEIL_DIV(bits_le, 8);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Load the checksum from the end
	LOAD_16(&packet->key_checksum, PTR_OFFSET(packet->encrypted, pos));
	pos += 2;

	// Read in the key from the buffer
	status = pgp_private_key_material_read(packet, buffer, pos - 2);
	free(buffer);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Verify the checksum
	if (pgp_private_key_material_checksum(packet) != packet->key_checksum)
	{
		return PGP_KEY_CHECKSUM_MISMATCH;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_encrypt_legacy_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;

	byte_t hash[MD5_HASH_SIZE] = {0};
	byte_t *buffer = NULL;

	uint32_t count = 0;

	// Hash the passphrase
	status = pgp_hash(PGP_MD5, passphrase, passphrase_size, hash, MD5_HASH_SIZE);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		return pgp_secret_key_material_encrypt_legacy_cfb_v3(packet, hash);
	}

	count = get_private_key_material_octets(packet->public_key_algorithm_id, packet->key);

	buffer = malloc(ROUND_UP(count + 2, 16));
	packet->encrypted = malloc(ROUND_UP(count + 2, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		free(packet->encrypted);

		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(count + 2, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + 2, 16));

	// Write the octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Store the checksum at the end
	LOAD_16(PTR_OFFSET(buffer, count), &packet->key_checksum);

	// Encrypt using CFB
	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, MD5_HASH_SIZE, packet->iv, packet->iv_size, buffer, count + 2,
							 packet->encrypted, count + 2);
	packet->encrypted_octets = count + 2;
	free(buffer);

	if (status != PGP_SUCCESS)
	{
		free(packet->encrypted);
		return status;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_decrypt_legacy_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	byte_t hash[MD5_HASH_SIZE] = {0};
	byte_t *buffer = NULL;

	// Hash the passphrase
	status = pgp_hash(PGP_MD5, passphrase, passphrase_size, hash, MD5_HASH_SIZE);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (key_size != MD5_HASH_SIZE)
	{
		return PGP_INVALID_CIPHER_ALGORITHM_FOR_LEGACY_CFB;
	}

	if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		return pgp_secret_key_material_decrypt_legacy_cfb_v3(packet, hash);
	}

	buffer = malloc(ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL)
	{
		free(buffer);
		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(packet->encrypted_octets, 16));

	// Decrypt using CFB
	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, MD5_HASH_SIZE, packet->iv, packet->iv_size, packet->encrypted,
							 packet->encrypted_octets, buffer, packet->encrypted_octets);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Load the checksum at the end
	LOAD_16(&packet->key_checksum, PTR_OFFSET(buffer, packet->encrypted_octets - 2));

	// Read the key from the buffer
	status = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - 2);
	free(buffer);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (pgp_private_key_material_checksum(packet) != packet->key_checksum)
	{
		return PGP_KEY_CHECKSUM_MISMATCH;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_encrypt_malleable_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;

	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t count = 0;

	byte_t key[32] = {0};
	byte_t *buffer = NULL;

	count = get_private_key_material_octets(packet->public_key_algorithm_id, packet->key);
	buffer = malloc(ROUND_UP(count + 2, 16));
	packet->encrypted = malloc(ROUND_UP(count + 2, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		free(packet->encrypted);

		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(count + 2, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + 2, 16));

	// Hash the passphrase
	status = pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		free(packet->encrypted);

		return status;
	}

	// Write the octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Store the checksum at the end
	LOAD_16(PTR_OFFSET(buffer, count), &packet->key_checksum);

	// Encrypt using CFB
	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, buffer, count + 2,
							 packet->encrypted, count + 2);
	packet->encrypted_octets = count + 2;

	free(buffer);

	if (status != PGP_SUCCESS)
	{
		free(packet->encrypted);
		return status;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_decrypt_malleable_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	byte_t key[32] = {0};
	byte_t *buffer = NULL;

	buffer = malloc(ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL)
	{
		free(buffer);
		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(packet->encrypted_octets, 16));

	// Hash the passphrase
	status = pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Decrypt using CFB
	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, packet->encrypted,
							 packet->encrypted_octets, buffer, packet->encrypted_octets);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Load the checksum at the end
	LOAD_16(&packet->key_checksum, PTR_OFFSET(buffer, packet->encrypted_octets - 2));

	// Read the key from the buffer
	status = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - 2);
	free(buffer);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	if (pgp_private_key_material_checksum(packet) != packet->key_checksum)
	{
		return PGP_KEY_CHECKSUM_MISMATCH;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_encrypt_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;

	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t count = 0;

	byte_t key[32] = {0};
	byte_t *buffer = NULL;

	count = get_private_key_material_octets(packet->public_key_algorithm_id, packet->key);
	buffer = malloc(ROUND_UP(count + SHA1_HASH_SIZE, 16));
	packet->encrypted = malloc(ROUND_UP(count + SHA1_HASH_SIZE, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		free(packet->encrypted);

		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(count + SHA1_HASH_SIZE, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + SHA1_HASH_SIZE, 16));

	// Hash the passphrase
	status = pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		free(packet->encrypted);

		return status;
	}

	// Write the octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Calculate the hash and store it the end
	status = pgp_hash(PGP_SHA1, buffer, count, PTR_OFFSET(buffer, count), SHA1_HASH_SIZE);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		free(packet->encrypted);

		return status;
	}

	// Encrypt using CFB
	status = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, buffer, count + SHA1_HASH_SIZE,
							 packet->encrypted, count + SHA1_HASH_SIZE);
	packet->encrypted_octets = count + SHA1_HASH_SIZE;

	free(buffer);

	if (status != PGP_SUCCESS)
	{
		free(packet->encrypted);
		return status;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_decrypt_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	byte_t key[32] = {0};
	byte_t hash[SHA1_HASH_SIZE] = {0};
	byte_t *buffer = NULL;

	buffer = malloc(ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL)
	{
		free(buffer);
		return 0;
	}

	memset(buffer, 0, ROUND_UP(packet->encrypted_octets, 16));

	// Hash the passphrase
	status = pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Decrypt using CFB
	status = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, packet->encrypted,
							 packet->encrypted_octets, buffer, packet->encrypted_octets);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Hash the material
	status = pgp_hash(PGP_SHA1, buffer, packet->encrypted_octets - SHA1_HASH_SIZE, hash, SHA1_HASH_SIZE);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Check the hash
	if (memcmp(hash, PTR_OFFSET(buffer, packet->encrypted_octets - SHA1_HASH_SIZE), SHA1_HASH_SIZE) != 0)
	{
		free(buffer);
		return PGP_MDC_TAG_MISMATCH;
	}

	// Read the key from the buffer
	status = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - SHA1_HASH_SIZE);
	free(buffer);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Calculate checksum
	packet->key_checksum = pgp_private_key_material_checksum(packet);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_encrypt_aead(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;

	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t aad_size = packet->public_key_data_octets + 16; // Upper bound
	uint32_t aad_count = 0;
	uint32_t count = 0;

	size_t pos = 0;

	byte_t ikey[32] = {0};
	byte_t dkey[32] = {0};
	byte_t info[4] = {0};

	byte_t *key = NULL;
	byte_t *buffer = NULL;

	count = get_private_key_material_octets(packet->public_key_algorithm_id, packet->key);
	buffer = malloc(ROUND_UP(count + aad_size, 16));
	packet->encrypted = malloc(ROUND_UP(count + PGP_AEAD_TAG_SIZE, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		free(packet->encrypted);

		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(count + aad_size, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + PGP_AEAD_TAG_SIZE, 16));

	// Hash the passphrase
	status = pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, ikey, key_size);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		free(packet->encrypted);

		return status;
	}

	// Generate the key
	if (packet->version == PGP_KEY_V6)
	{
		info[0] = packet->header.tag;
		info[1] = packet->version;
		info[2] = packet->symmetric_key_algorithm_id;
		info[3] = packet->aead_algorithm_id;

		pgp_hkdf(PGP_SHA2_256, dkey, key_size, NULL, 0, info, 4, dkey, key_size);
		key = dkey;
	}
	else
	{
		key = ikey;
	}

	// Write the private octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Prepare the associated data
	pos = count;

	LOAD_8(buffer + pos, &packet->header.tag);
	pos += 1;

	if (packet->version == PGP_KEY_V5)
	{
		LOAD_8(buffer + pos, &packet->symmetric_key_algorithm_id);
		pos += 1;

		LOAD_8(buffer + pos, &packet->aead_algorithm_id);
		pos += 1;
	}

	LOAD_8(buffer + pos, &packet->version);
	pos += 1;

	LOAD_32BE(buffer + pos, &packet->key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		LOAD_32BE(buffer + pos, &packet->public_key_data_octets);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, PTR_OFFSET(buffer, pos), packet->public_key_data_octets);
	aad_count = pos - count;

	// Encrypt using AEAD (Store the tag at the end)
	status = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, key_size, packet->iv, packet->iv_size,
							  PTR_OFFSET(buffer, count), aad_count, buffer, count, packet->encrypted, count + PGP_AEAD_TAG_SIZE);
	packet->encrypted_octets = count + PGP_AEAD_TAG_SIZE;

	free(buffer);

	if (status != PGP_SUCCESS)
	{
		free(packet->encrypted);
		return status;
	}

	return PGP_SUCCESS;
}

static pgp_error_t pgp_secret_key_material_decrypt_aead(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;

	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t aad_size = packet->public_key_data_octets + 16; // Upper bound
	uint32_t aad_count = 0;

	size_t pos = 0;

	byte_t ikey[32] = {0};
	byte_t dkey[32] = {0};
	byte_t info[4] = {0};

	byte_t *key = NULL;
	byte_t *buffer = NULL;

	buffer = malloc(ROUND_UP(aad_size, 16) + ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		return PGP_NO_MEMORY;
	}

	memset(buffer, 0, ROUND_UP(aad_size, 16) + ROUND_UP(packet->encrypted_octets, 16));

	// Hash the passphrase
	status = pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, ikey, key_size);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Generate the key
	if (packet->version == PGP_KEY_V6)
	{
		info[0] = packet->header.tag;
		info[1] = packet->version;
		info[2] = packet->symmetric_key_algorithm_id;
		info[3] = packet->aead_algorithm_id;

		pgp_hkdf(PGP_SHA2_256, dkey, key_size, NULL, 0, info, 4, dkey, key_size);
		key = dkey;
	}
	else
	{
		key = ikey;
	}

	// Prepare the associated data
	pos = 0;

	LOAD_8(buffer + pos, &packet->header.tag);
	pos += 1;

	if (packet->version == PGP_KEY_V5)
	{
		LOAD_8(buffer + pos, &packet->symmetric_key_algorithm_id);
		pos += 1;

		LOAD_8(buffer + pos, &packet->aead_algorithm_id);
		pos += 1;
	}

	LOAD_8(buffer + pos, &packet->version);
	pos += 1;

	LOAD_32BE(buffer + pos, &packet->key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		LOAD_32BE(buffer + pos, &packet->public_key_data_octets);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, PTR_OFFSET(buffer, pos), packet->public_key_data_octets);
	aad_count = pos;

	pos = ROUND_UP(pos, 16);

	// Decrypt using AEAD
	status =
		pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, key_size, packet->iv, packet->iv_size, buffer,
						 aad_count, packet->encrypted, packet->encrypted_octets, PTR_OFFSET(buffer, pos), packet->encrypted_octets);

	if (status != PGP_SUCCESS)
	{
		free(buffer);
		return status;
	}

	// Read the key from the buffer
	status = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - PGP_AEAD_TAG_SIZE);
	free(buffer);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Calculate checksum
	packet->key_checksum = pgp_private_key_material_checksum(packet);

	return PGP_SUCCESS;
}

static uint32_t pgp_secret_key_material_encrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	if (packet->s2k_usage >= PGP_IDEA && packet->s2k_usage <= PGP_CAMELLIA_256)
	{
		return pgp_secret_key_material_encrypt_legacy_cfb(packet, passphrase, passphrase_size);
	}

	if (packet->s2k_usage == 253)
	{
		return pgp_secret_key_material_encrypt_aead(packet, passphrase, passphrase_size);
	}

	if (packet->s2k_usage == 254)
	{
		return pgp_secret_key_material_encrypt_cfb(packet, passphrase, passphrase_size);
	}

	if (packet->s2k_usage == 255)
	{
		return pgp_secret_key_material_encrypt_malleable_cfb(packet, passphrase, passphrase_size);
	}

	return 0;
}

static uint32_t pgp_secret_key_material_decrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	if (packet->s2k_usage >= PGP_IDEA && packet->s2k_usage <= PGP_CAMELLIA_256)
	{
		return pgp_secret_key_material_decrypt_legacy_cfb(packet, passphrase, passphrase_size);
	}

	if (packet->s2k_usage == 253)
	{
		return pgp_secret_key_material_decrypt_aead(packet, passphrase, passphrase_size);
	}

	if (packet->s2k_usage == 254)
	{
		return pgp_secret_key_material_decrypt_cfb(packet, passphrase, passphrase_size);
	}

	if (packet->s2k_usage == 255)
	{
		return pgp_secret_key_material_decrypt_malleable_cfb(packet, passphrase, passphrase_size);
	}

	return 0;
}

static pgp_error_t pgp_secret_key_packet_read_body(pgp_key_packet *packet, buffer_t *buffer)
{
	pgp_error_t error = 0;
	uint32_t public_key_data_octets = 0;

	// 1 octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_SECRET_KEY_PACKET);

	if (packet->version != PGP_KEY_V2 && packet->version != PGP_KEY_V3 && packet->version != PGP_KEY_V4 && packet->version != PGP_KEY_V5 &&
		packet->version != PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	// 4-octet number denoting the time when the key was created.
	CHECK_READ(read32_be(buffer, &packet->key_creation_time), PGP_MALFORMED_SECRET_KEY_PACKET);

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		CHECK_READ(read16_be(buffer, &packet->key_expiry_days), PGP_MALFORMED_SECRET_KEY_PACKET);
	}

	// 1-octet public key algorithm.
	CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_SECRET_KEY_PACKET);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		// 4-octet scalar count for the public key material
		CHECK_READ(read32_be(buffer, &public_key_data_octets), PGP_MALFORMED_SECRET_KEY_PACKET);
	}
	else
	{
		public_key_data_octets = buffer->size - buffer->pos;
	}

	error = pgp_public_key_material_read(packet, buffer->data + buffer->pos, public_key_data_octets);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	// Check whether the given count is correct
	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		if (packet->public_key_data_octets != public_key_data_octets)
		{
			return PGP_MALFORMED_PUBLIC_KEY_COUNT;
		}
	}

	buffer->pos += packet->public_key_data_octets;

	// 1 octet of S2K usage
	CHECK_READ(read8(buffer, &packet->s2k_usage), PGP_MALFORMED_SECRET_KEY_PACKET);

	if (packet->s2k_usage != 0)
	{
		byte_t s2k_size = 0;
		byte_t conditional_field_size = 0;

		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			// 1-octet scalar count of S2K fields
			CHECK_READ(read8(buffer, &conditional_field_size), PGP_MALFORMED_SECRET_KEY_PACKET);
		}

		// 1 octet symmetric key algorithm
		CHECK_READ(read8(buffer, &packet->symmetric_key_algorithm_id), PGP_MALFORMED_SECRET_KEY_PACKET);

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			CHECK_READ(read8(buffer, &packet->aead_algorithm_id), PGP_MALFORMED_SECRET_KEY_PACKET);
		}

		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			// 1-octet count of S2K specifier
			CHECK_READ(read8(buffer, &s2k_size), PGP_MALFORMED_SECRET_KEY_PACKET);
		}

		// S2K specifier
		if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
		{
			uint32_t result = 0;

			result = pgp_s2k_read(&packet->s2k, buffer->data + buffer->pos, s2k_size != 0 ? s2k_size : (buffer->size - buffer->pos));

			if (result == 0)
			{
				return PGP_UNKNOWN_S2K_SPECIFIER;
			}

			if (s2k_size != 0)
			{
				if (result != s2k_size)
				{
					return PGP_MALFORMED_S2K_SIZE;
				}
			}

			buffer->pos += result;
		}

		// IV
		if (packet->s2k_usage == 253)
		{
			packet->iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);
		}
		else if (packet->s2k_usage == 254 || packet->s2k_usage == 255 ||
				 (packet->s2k_usage >= PGP_IDEA && packet->s2k_usage <= PGP_CAMELLIA_256))
		{
			packet->iv_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);
		}

		CHECK_READ(readn(buffer, packet->iv, packet->iv_size), PGP_MALFORMED_SECRET_KEY_PACKET);

		// Encrypted secret key
		if (packet->version == PGP_KEY_V5)
		{
			CHECK_READ(read32_be(buffer, &packet->encrypted_octets), PGP_MALFORMED_SECRET_KEY_PACKET);
		}
		else
		{
			packet->encrypted_octets = buffer->size - buffer->pos;
		}

		packet->encrypted = malloc(packet->encrypted_octets);

		if (packet->encrypted == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->encrypted, packet->encrypted_octets), PGP_MALFORMED_SECRET_KEY_PACKET);
	}
	else
	{
		uint32_t private_key_data_octets = 0;

		if (packet->version == PGP_KEY_V5)
		{
			CHECK_READ(read32_be(buffer, &private_key_data_octets), PGP_MALFORMED_SECRET_KEY_PACKET);
		}
		else
		{
			private_key_data_octets = buffer->size - buffer->pos;
		}

		// Plaintext private key
		error = pgp_private_key_material_read(packet, buffer->data + buffer->pos, private_key_data_octets);

		if (error != PGP_SUCCESS)
		{
			return error;
		}

		if (packet->version == PGP_KEY_V5)
		{
			if (packet->private_key_data_octets != private_key_data_octets)
			{
				return PGP_MALFORMED_SECRET_KEY_COUNT;
			}
		}

		buffer->pos += packet->private_key_data_octets;

		if (packet->version != PGP_KEY_V6)
		{
			// 2-octet checksum
			CHECK_READ(read16(buffer, &packet->key_checksum), PGP_MALFORMED_SECRET_KEY_PACKET);
		}
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_secret_key_packet_read_with_header(pgp_key_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_key_packet *key = NULL;

	key = malloc(sizeof(pgp_key_packet));

	if (packet == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(key, 0, sizeof(pgp_key_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	key->header = *header;

	// Read the body
	error = pgp_secret_key_packet_read_body(key, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_key_packet_delete(key);
		return error;
	}

	*packet = key;

	return error;
}

pgp_error_t pgp_secret_key_packet_read(pgp_key_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_SECKEY && pgp_packet_type_from_tag(header.tag) != PGP_SECSUBKEY)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_secret_key_packet_read_with_header(packet, &header, data);
}

size_t pgp_secret_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	byte_t s2k_size = 0;
	byte_t conditional_field_size = 0;

	s2k_size = (packet->s2k_usage != 0) ? pgp_s2k_octets(&packet->s2k) : 0;
	conditional_field_size = pgp_key_packet_get_s2k_size(packet);

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 4-octet number denoting the time when the key was created
	LOAD_32BE(out + pos, &packet->key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		LOAD_16BE(out + pos, &packet->key_expiry_days);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_KEY_V5 || packet->version == PGP_KEY_V6)
	{
		// 4-octet scalar count for the public key material
		LOAD_32BE(out + pos, &packet->public_key_data_octets);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, out + pos, size - pos);

	// 1 octet of S2K usage
	LOAD_8(out + pos, &packet->s2k_usage);
	pos += 1;

	if (conditional_field_size != 0)
	{
		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			// 1-octet scalar count of S2K fields
			LOAD_8(out + pos, &conditional_field_size);
			pos += 1;
		}

		// 1 octet symmetric key algorithm
		LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
		pos += 1;

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			LOAD_8(out + pos, &packet->aead_algorithm_id);
			pos += 1;
		}

		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			// 1-octet count of S2K specifier
			LOAD_8(out + pos, &s2k_size);
			pos += 1;
		}

		// S2K specifier
		pos += pgp_s2k_write(&packet->s2k, out + pos);

		// IV
		memcpy(out + pos, packet->iv, packet->iv_size);
		pos += 16;

		// Secret key octet count
		if (packet->version == PGP_KEY_V5)
		{
			LOAD_32BE(out + pos, &packet->encrypted_octets);
			pos += 4;
		}

		// Encrypted private key
		memcpy(out + pos, packet->encrypted, packet->encrypted_octets);
		pos += packet->encrypted_octets;
	}
	else
	{
		// Secret key octet count
		if (packet->version == PGP_KEY_V5)
		{
			LOAD_32(out + pos, &packet->private_key_data_octets);
			pos += 4;
		}

		// Plaintext private key
		pos += pgp_private_key_material_write(packet, out + pos, size - pos);

		if (packet->version != PGP_KEY_V6)
		{
			// 2-octet checksum
			LOAD_16(out + pos, &packet->key_checksum);
			pos += 2;
		}
	}

	return pos;
}

pgp_error_t pgp_key_generate(pgp_key_packet **packet, byte_t version, byte_t public_key_algorithm_id, byte_t capabilities, byte_t flags,
							 uint32_t key_creation_time, uint32_t key_expiry_seconds, pgp_key_parameters *parameters)
{
	pgp_error_t status = 0;

	pgp_key_packet *pgpkey = NULL;
	void *key = NULL;

	byte_t legacy_oid = 0;

	if (version < PGP_KEY_V2 || version > PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	if (pgp_public_cipher_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_PUBLIC_ALGORITHM;
	}

	if (capabilities & (PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN | PGP_KEY_FLAG_AUTHENTICATION))
	{
		if (public_key_algorithm_id == PGP_RSA_ENCRYPT_ONLY || public_key_algorithm_id == PGP_ECDH ||
			public_key_algorithm_id == PGP_ELGAMAL_ENCRYPT_ONLY || public_key_algorithm_id == PGP_X25519 ||
			public_key_algorithm_id == PGP_X448)
		{
			return PGP_UNKNOWN_SIGNATURE_ALGORITHM;
		}
	}

	if (capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
	{
		if (public_key_algorithm_id == PGP_RSA_SIGN_ONLY || public_key_algorithm_id == PGP_DSA || public_key_algorithm_id == PGP_ECDSA ||
			public_key_algorithm_id == PGP_EDDSA || public_key_algorithm_id == PGP_ED25519 || public_key_algorithm_id == PGP_ED448)
		{
			return PGP_UNKNOWN_KEY_EXCHANGE_ALGORITHM;
		}
	}

	if (version == PGP_KEY_V4)
	{
		if ((public_key_algorithm_id == PGP_EDDSA && parameters->curve == PGP_EC_ED25519) ||
			(public_key_algorithm_id == PGP_ECDH && parameters->curve == PGP_EC_CURVE25519))
		{
			legacy_oid = 1;
		}
	}

	pgpkey = malloc(sizeof(pgp_key_packet));

	if (pgpkey == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(pgpkey, 0, sizeof(pgp_key_packet));

	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
		status = pgp_rsa_generate_key((pgp_rsa_key **)&key, parameters->bits);
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		status = pgp_elgamal_generate_key((pgp_elgamal_key **)&key, parameters->bits);
		break;
	case PGP_DSA:
		status = pgp_dsa_generate_key((pgp_dsa_key **)&key, parameters->bits);
		break;
	case PGP_ECDH:
		status = pgp_ecdh_generate_key((pgp_ecdh_key **)&key, parameters->curve, parameters->hash_algorithm, parameters->cipher_algorithm,
									   legacy_oid);
		break;
	case PGP_ECDSA:
		status = pgp_ecdsa_generate_key((pgp_ecdsa_key **)&key, parameters->curve);
		break;
	case PGP_EDDSA:
		status = pgp_eddsa_generate_key((pgp_eddsa_key **)&key, parameters->curve, legacy_oid);
		break;
	case PGP_X25519:
		status = pgp_x25519_generate_key((pgp_x25519_key **)&key);
		break;
	case PGP_X448:
		status = pgp_x448_generate_key((pgp_x448_key **)&key);
		break;
	case PGP_ED25519:
		status = pgp_ed25519_generate_key((pgp_ed25519_key **)&key);
		break;
	case PGP_ED448:
		status = pgp_ed448_generate_key((pgp_ed448_key **)&key);
		break;

	default:
		// Unreachable
		return PGP_INTERNAL_BUG;
	}

	if (status != PGP_SUCCESS)
	{
		free(pgpkey);
		return status;
	}

	pgpkey->version = version;
	pgpkey->key_creation_time = key_creation_time;
	pgpkey->key_expiry_seconds = key_expiry_seconds;
	pgpkey->capabilities = capabilities & PGP_KEY_CAPABILITIES_MASK;
	pgpkey->flags = flags & PGP_KEY_FLAGS_MASK;

	pgpkey->key = key;
	pgpkey->public_key_data_octets = get_public_key_material_octets(public_key_algorithm_id, key);
	pgpkey->private_key_data_octets = get_private_key_material_octets(public_key_algorithm_id, key);

	pgpkey->key_checksum = pgp_private_key_material_checksum(pgpkey);
	pgp_key_packet_encode_header(pgpkey, PGP_KEYDEF);

	*packet = pgpkey;

	return PGP_SUCCESS;
}

pgp_error_t pgp_key_packet_new(pgp_key_packet **packet, byte_t version, byte_t public_key_algorithm_id, uint32_t key_creation_time,
							   uint32_t key_expiry_seconds, byte_t capabilities, byte_t flags, void *key)
{
	pgp_key_packet *pgpkey = NULL;

	if (version < PGP_KEY_V2 || version > PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	if (key == NULL)
	{
		return PGP_INVALID_PARAMETER;
	}

	if (pgp_public_cipher_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return PGP_UNKNOWN_PUBLIC_ALGORITHM;
	}

	if (capabilities & (PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN | PGP_KEY_FLAG_AUTHENTICATION))
	{
		if (public_key_algorithm_id == PGP_RSA_ENCRYPT_ONLY || public_key_algorithm_id == PGP_ECDH ||
			public_key_algorithm_id == PGP_ELGAMAL_ENCRYPT_ONLY || public_key_algorithm_id == PGP_X25519 ||
			public_key_algorithm_id == PGP_X448)
		{
			return PGP_UNKNOWN_SIGNATURE_ALGORITHM;
		}
	}

	if (capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
	{
		if (public_key_algorithm_id == PGP_RSA_SIGN_ONLY || public_key_algorithm_id == PGP_DSA || public_key_algorithm_id == PGP_ECDSA ||
			public_key_algorithm_id == PGP_EDDSA || public_key_algorithm_id == PGP_ED25519 || public_key_algorithm_id == PGP_ED448)
		{
			return PGP_UNKNOWN_KEY_EXCHANGE_ALGORITHM;
		}
	}

	pgpkey = malloc(sizeof(pgp_key_packet));

	if (pgpkey == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(pgpkey, 0, sizeof(pgp_key_packet));

	pgpkey->version = version;
	pgpkey->key_creation_time = key_creation_time;
	pgpkey->key_expiry_seconds = key_expiry_seconds;
	pgpkey->capabilities = capabilities & PGP_KEY_CAPABILITIES_MASK;
	pgpkey->flags = flags & PGP_KEY_FLAGS_MASK;

	pgpkey->key = key;
	pgpkey->public_key_data_octets = get_public_key_material_octets(public_key_algorithm_id, key);
	pgpkey->private_key_data_octets = get_private_key_material_octets(public_key_algorithm_id, key);

	pgpkey->key_checksum = pgp_private_key_material_checksum(pgpkey);
	pgp_key_packet_encode_header(pgpkey, PGP_KEYDEF);

	*packet = pgpkey;

	return PGP_SUCCESS;
}

void pgp_key_packet_delete(pgp_key_packet *packet)
{
	if (packet == NULL)
	{
		return;
	}

	free(packet->encrypted);

	// Free the key
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
		pgp_rsa_key_delete(packet->key);
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
		break;
	case PGP_DSA:
		pgp_dsa_key_delete(packet->key);
		break;
	case PGP_ECDH:
		pgp_ecdh_key_delete(packet->key);
		break;
	case PGP_ECDSA:
	case PGP_EDDSA:
		pgp_ecdsa_key_delete(packet->key);
		break;
	case PGP_X25519:
	case PGP_X448:
	case PGP_ED25519:
	case PGP_ED448:
		free(packet->key);
		break;
	default:
		break;
	}

	free(packet);
}

pgp_error_t pgp_key_packet_transform(pgp_key_packet *packet, pgp_packet_type type)
{
	pgp_packet_type packet_type = pgp_packet_type_from_tag(packet->header.tag);

	// We cannot convert a public key to a secret key
	if (packet_type == PGP_PUBKEY || packet_type == PGP_PUBSUBKEY)
	{
		if (type == PGP_SECKEY || type == PGP_SECSUBKEY)
		{
			return PGP_INVALID_KEY_TRANSFORMATION;
		}
	}

	if (packet_type == PGP_KEYDEF)
	{
		if (packet->type == PGP_KEY_TYPE_PUBLIC)
		{
			if (type == PGP_SECKEY || type == PGP_SECSUBKEY)
			{
				return PGP_INVALID_KEY_TRANSFORMATION;
			}
		}
	}

	if (type == PGP_KEYDEF)
	{
		if (packet_type == PGP_PUBKEY || packet_type == PGP_PUBSUBKEY)
		{
			packet->type = PGP_KEY_TYPE_PUBLIC;
		}

		if (packet_type == PGP_SECKEY || packet_type == PGP_SECSUBKEY)
		{
			packet->type = PGP_KEY_TYPE_SECRET;
		}
	}

	pgp_key_packet_encode_header(packet, type);

	return PGP_SUCCESS;
}

static void pgp_key_packet_fill(pgp_key_packet *key, pgp_stream_t *stream)
{
	pgp_subpacket_header *header = NULL;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		switch (header->tag & PGP_SUBPACKET_TAG_MASK)
		{
		// Set expiration time
		case PGP_KEY_EXPIRATION_TIME_SUBPACKET:
		{
			pgp_key_expiration_time_subpacket *subpacket = stream->packets[i];

			if (key->key_expiry_seconds == 0)
			{
				key->key_expiry_seconds = subpacket->duration;
			}
		}
		break;
		// Set capabilities
		case PGP_KEY_FLAGS_SUBPACKET:
		{
			pgp_key_flags_subpacket *flags_subpacket = stream->packets[i];
			byte_t count = flags_subpacket->header.body_size;

			if (key->capabilities == 0 && key->flags == 0)
			{
				switch (count)
				{
				case 2:
					key->flags |= flags_subpacket->flags[1] & (PGP_KEY_FLAG_RESTRICTED_ENCRYPT | PGP_KEY_FLAG_TIMESTAMP);
				case 1:
					key->capabilities |= flags_subpacket->flags[0] & (PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN | PGP_KEY_FLAG_ENCRYPT_COM |
																	  PGP_KEY_FLAG_ENCRYPT_STORAGE | PGP_KEY_FLAG_AUTHENTICATION);
					key->flags |= flags_subpacket->flags[0] & (PGP_KEY_FLAG_PRIVATE_SPLIT | PGP_KEY_FLAG_PRIVATE_SHARED);
				}
			}
		}
		break;
		}
	}
}

pgp_error_t pgp_key_packet_make_definition(pgp_key_packet *key, pgp_signature_packet *sign)
{
	// Process hashed subpackets then process the unhashed subpackets.
	pgp_key_packet_fill(key, sign->hashed_subpackets);
	pgp_key_packet_fill(key, sign->unhashed_subpackets);

	// Set revocation time
	if (sign->type == PGP_KEY_REVOCATION_SIGNATURE || sign->type == PGP_SUBKEY_REVOCATION_SIGNATURE)
	{
		// Only check the hashed subpackets
		for (uint32_t i = 0; i < sign->hashed_subpackets->count; ++i)
		{
			pgp_subpacket_header *header = sign->hashed_subpackets->packets[i];

			if ((header->tag & PGP_SUBPACKET_TAG_MASK) == PGP_SIGNATURE_CREATION_TIME_SUBPACKET)
			{
				pgp_signature_creation_time_subpacket *subpacket = sign->hashed_subpackets->packets[i];
				key->key_revocation_time = subpacket->timestamp;
			}
		}
	}

	// Transform it to key definition packet.
	return pgp_key_packet_transform(key, PGP_KEYDEF);
}

pgp_error_t pgp_key_packet_encrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size, byte_t s2k_usage, pgp_s2k *s2k,
								   void *iv, byte_t iv_size, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id)
{
	pgp_error_t result = 0;
	byte_t tag = pgp_packet_type_from_tag(packet->header.tag);

	if (tag != PGP_KEYDEF && tag != PGP_SECKEY && tag != PGP_SECSUBKEY)
	{
		return PGP_INVALID_PARAMETER;
	}

	if (s2k_usage == 0)
	{
		// Nothing to encrypt
		return PGP_SUCCESS;
	}

	if (s2k_usage != 0)
	{
		if (passphrase == NULL || passphrase_size == 0)
		{
			return PGP_EMPTY_PASSPHRASE;
		}

		if (iv == NULL || iv_size == 0)
		{
			return PGP_EMPTY_IV;
		}

		if (s2k == NULL)
		{
			return PGP_EMPTY_S2K;
		}
	}

	if (s2k_usage >= PGP_IDEA && s2k_usage <= PGP_CAMELLIA_256) // Legacy CFB
	{
		if (pgp_symmetric_cipher_block_size(s2k_usage) != iv_size)
		{
			return PGP_INVALID_CFB_IV_SIZE;
		}

		packet->symmetric_key_algorithm_id = s2k_usage;
	}
	else if (s2k_usage >= 253 && s2k_usage <= 255)
	{
		if (pgp_symmetric_cipher_algorithm_validate(symmetric_key_algorithm_id) == 0)
		{
			return PGP_UNKNOWN_CIPHER_ALGORITHM;
		}

		if (s2k_usage == 253) // AEAD
		{

			if (symmetric_key_algorithm_id == PGP_PLAINTEXT || symmetric_key_algorithm_id == PGP_BLOWFISH ||
				symmetric_key_algorithm_id == PGP_TDES || symmetric_key_algorithm_id == PGP_IDEA)
			{
				return PGP_INVALID_AEAD_CIPHER_PAIR;
			}

			if (pgp_aead_algorithm_validate(aead_algorithm_id) == 0)
			{
				return PGP_UNKNOWN_AEAD_ALGORITHM;
			}

			if (pgp_aead_iv_size(aead_algorithm_id) != iv_size)
			{
				return PGP_INVALID_AEAD_IV_SIZE;
			}

			packet->aead_algorithm_id = aead_algorithm_id;
		}
		else // CFB
		{
			if (pgp_symmetric_cipher_block_size(symmetric_key_algorithm_id) != iv_size)
			{
				return PGP_INVALID_CFB_IV_SIZE;
			}
		}

		packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;

		// Copy the IV
		packet->iv_size = iv_size;
		memcpy(packet->iv, iv, iv_size);
	}
	else
	{
		return PGP_UNKNOWN_S2K_USAGE;
	}

	// Copy the s2k
	packet->s2k_usage = s2k_usage;
	packet->s2k = *s2k;

	// Will update encrypted octets
	result = pgp_secret_key_material_encrypt(packet, passphrase, passphrase_size);

	if (result != PGP_SUCCESS)
	{
		return result;
	}

	pgp_key_packet_encode_header(packet, PGP_KEYDEF);

	return PGP_SUCCESS;
}

static pgp_error_t pgp_key_packet_decrypt_internal(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t tag = pgp_packet_type_from_tag(packet->header.tag);

	if (tag != PGP_KEYDEF && tag != PGP_SECKEY && tag != PGP_SECSUBKEY)
	{
		return PGP_INVALID_PARAMETER;
	}

	if (tag == PGP_KEYDEF && packet->type != PGP_KEY_TYPE_SECRET)
	{
		return PGP_INVALID_PARAMETER;
	}

	if (packet->s2k_usage == 0)
	{
		// Nothing to decrypt
		return PGP_SUCCESS;
	}

	if (packet->s2k_usage != 0)
	{
		if (passphrase == NULL || passphrase_size == 0)
		{
			return PGP_EMPTY_PASSPHRASE;
		}
	}

	// Validations
	// TODO: Move this to a separate validation function
	if (packet->s2k_usage >= PGP_IDEA && packet->s2k_usage <= PGP_CAMELLIA_256) // Legacy CFB
	{
		if (pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id) != packet->iv_size)
		{
			return PGP_INVALID_CFB_IV_SIZE;
		}
	}
	else if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
	{
		if (pgp_symmetric_cipher_algorithm_validate(packet->symmetric_key_algorithm_id) == 0)
		{
			return PGP_UNKNOWN_CIPHER_ALGORITHM;
		}

		if (packet->s2k_usage == 253) // AEAD
		{
			if (packet->symmetric_key_algorithm_id == PGP_PLAINTEXT || packet->symmetric_key_algorithm_id == PGP_BLOWFISH ||
				packet->symmetric_key_algorithm_id == PGP_TDES || packet->symmetric_key_algorithm_id == PGP_IDEA)
			{
				return PGP_INVALID_AEAD_CIPHER_PAIR;
			}

			if (pgp_aead_algorithm_validate(packet->aead_algorithm_id) == 0)
			{
				return PGP_UNKNOWN_AEAD_ALGORITHM;
			}

			if (pgp_aead_iv_size(packet->aead_algorithm_id) != packet->iv_size)
			{
				return PGP_INVALID_AEAD_IV_SIZE;
			}
		}
		else // CFB
		{
			if (pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id) != packet->iv_size)
			{
				return PGP_INVALID_CFB_IV_SIZE;
			}
		}
	}
	else
	{
		return PGP_UNKNOWN_S2K_USAGE;
	}

	// Checksum will be updated
	// Private octet count will be updated
	return pgp_secret_key_material_decrypt(packet, passphrase, passphrase_size);
}

pgp_error_t pgp_key_packet_decrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	pgp_error_t status = 0;

	status = pgp_key_packet_decrypt_internal(packet, passphrase, passphrase_size);

	if (status != PGP_SUCCESS)
	{
		return status;
	}

	// Free the encrypted portion
	free(packet->encrypted);
	packet->encrypted = NULL;
	packet->encrypted_octets = 0;

	packet->s2k_usage = 0;

	pgp_key_packet_encode_header(packet, PGP_KEYDEF);

	return PGP_SUCCESS;
}

pgp_error_t pgp_key_packet_decrypt_check(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	// Only check whether the key can be decrypted with the given passphrase
	return pgp_key_packet_decrypt_internal(packet, passphrase, passphrase_size);
}

static pgp_error_t pgp_key_packet_read_body(pgp_key_packet *packet, buffer_t *buffer)
{
	pgp_error_t error = 0;
	uint32_t public_key_data_octets = 0;

	// 1-octet version
	CHECK_READ(read8(buffer, &packet->version), PGP_MALFORMED_KEYDEF_PACKET);

	if (packet->version != PGP_KEY_V2 && packet->version != PGP_KEY_V3 && packet->version != PGP_KEY_V4 && packet->version != PGP_KEY_V5 &&
		packet->version != PGP_KEY_V6)
	{
		return PGP_UNKNOWN_KEY_VERSION;
	}

	// 1 octet key type
	CHECK_READ(read8(buffer, &packet->type), PGP_MALFORMED_KEYDEF_PACKET);

	if (packet->type != PGP_KEY_TYPE_PUBLIC && packet->type != PGP_KEY_TYPE_SECRET)
	{
		return PGP_INVALID_KEY_TYPE;
	}

	// 1-octet key capabilities
	CHECK_READ(read8(buffer, &packet->capabilities), PGP_MALFORMED_KEYDEF_PACKET);

	// 1-octet key flags
	CHECK_READ(read8(buffer, &packet->flags), PGP_MALFORMED_KEYDEF_PACKET);

	// 4-octet number denoting the time when the key was created.
	CHECK_READ(read32_be(buffer, &packet->key_creation_time), PGP_MALFORMED_KEYDEF_PACKET);

	// 4-octet number denoting the time when the key was revoked.
	CHECK_READ(read32_be(buffer, &packet->key_revocation_time), PGP_MALFORMED_KEYDEF_PACKET);

	// 4-octet number denoting the time when the key will expire.
	CHECK_READ(read32_be(buffer, &packet->key_expiry_seconds), PGP_MALFORMED_KEYDEF_PACKET);

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		packet->key_expiry_days = packet->key_expiry_seconds / 86400;
	}

	// 1-octet public key algorithm.
	CHECK_READ(read8(buffer, &packet->public_key_algorithm_id), PGP_MALFORMED_KEYDEF_PACKET);

	// 4-octet scalar count for the public key material
	CHECK_READ(read32_be(buffer, &public_key_data_octets), PGP_MALFORMED_KEYDEF_PACKET);

	error = pgp_public_key_material_read(packet, buffer->data + buffer->pos, public_key_data_octets);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	// Check whether the given count is correct
	if (packet->public_key_data_octets != public_key_data_octets)
	{
		return PGP_MALFORMED_PUBLIC_KEY_COUNT;
	}

	buffer->pos += packet->public_key_data_octets;

	if (packet->type == PGP_KEY_TYPE_PUBLIC)
	{
		return PGP_SUCCESS;
	}

	// 1 octet of S2K usage
	CHECK_READ(read8(buffer, &packet->s2k_usage), PGP_MALFORMED_KEYDEF_PACKET);

	if (packet->s2k_usage != 0)
	{
		byte_t s2k_size = 0;
		byte_t conditional_field_size = 0;

		// 1-octet scalar count of S2K fields
		CHECK_READ(read8(buffer, &conditional_field_size), PGP_MALFORMED_KEYDEF_PACKET);

		// 1 octet symmetric key algorithm
		CHECK_READ(read8(buffer, &packet->symmetric_key_algorithm_id), PGP_MALFORMED_KEYDEF_PACKET);

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			CHECK_READ(read8(buffer, &packet->aead_algorithm_id), PGP_MALFORMED_KEYDEF_PACKET);
		}

		// 1-octet count of S2K specifier
		CHECK_READ(read8(buffer, &s2k_size), PGP_MALFORMED_KEYDEF_PACKET);

		// S2K specifier
		if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
		{
			uint32_t result = 0;

			result = pgp_s2k_read(&packet->s2k, buffer->data + buffer->pos, s2k_size);

			if (result == 0)
			{
				return PGP_UNKNOWN_S2K_SPECIFIER;
			}

			if (s2k_size != 0)
			{
				if (result != s2k_size)
				{
					return PGP_MALFORMED_S2K_SIZE;
				}
			}

			buffer->pos += result;
		}

		// IV
		if (packet->s2k_usage == 253)
		{
			packet->iv_size = pgp_aead_iv_size(packet->aead_algorithm_id);
		}
		else if (packet->s2k_usage == 254 || packet->s2k_usage == 255 ||
				 (packet->s2k_usage >= PGP_IDEA && packet->s2k_usage <= PGP_CAMELLIA_256))
		{
			packet->iv_size = pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id);
		}

		CHECK_READ(readn(buffer, packet->iv, packet->iv_size), PGP_MALFORMED_KEYDEF_PACKET);

		// Secret key octet count
		CHECK_READ(read32_be(buffer, &packet->encrypted_octets), PGP_MALFORMED_KEYDEF_PACKET);

		// Encrypted private key
		packet->encrypted = malloc(packet->encrypted_octets);

		if (packet->encrypted == NULL)
		{
			return PGP_NO_MEMORY;
		}

		CHECK_READ(readn(buffer, packet->encrypted, packet->encrypted_octets), PGP_MALFORMED_KEYDEF_PACKET);
	}
	else
	{
		uint32_t private_key_data_octets = 0;

		if (packet->version == PGP_KEY_V5)
		{
			// Secret key octet count
			CHECK_READ(read32_be(buffer, &private_key_data_octets), PGP_MALFORMED_KEYDEF_PACKET);
		}

		// Plaintext private key
		error = pgp_private_key_material_read(packet, buffer->data + buffer->pos, private_key_data_octets);

		if (error != PGP_SUCCESS)
		{
			return error;
		}

		if (packet->version == PGP_KEY_V5)
		{
			if (packet->private_key_data_octets != private_key_data_octets)
			{
				return PGP_MALFORMED_SECRET_KEY_COUNT;
			}
		}

		buffer->pos += packet->private_key_data_octets;
	}

	return PGP_SUCCESS;
}

pgp_error_t pgp_key_packet_read_with_header(pgp_key_packet **packet, pgp_packet_header *header, void *data)
{
	pgp_error_t error = 0;
	buffer_t buffer = {0};
	pgp_key_packet *key = NULL;

	key = malloc(sizeof(pgp_key_packet));

	if (packet == NULL)
	{
		return PGP_NO_MEMORY;
	}

	memset(key, 0, sizeof(pgp_key_packet));

	buffer.data = data;
	buffer.pos = header->header_size;
	buffer.size = buffer.capacity = PGP_PACKET_OCTETS(*header);

	// Copy the header
	key->header = *header;

	// Read the body
	error = pgp_key_packet_read_body(key, &buffer);

	if (error != PGP_SUCCESS)
	{
		pgp_key_packet_delete(key);
		return error;
	}

	*packet = key;

	return error;
}

pgp_error_t pgp_key_packet_read(pgp_key_packet **packet, void *data, size_t size)
{
	pgp_error_t error = 0;
	pgp_packet_header header = {0};

	error = pgp_packet_header_read(&header, data, size);

	if (error != PGP_SUCCESS)
	{
		return error;
	}

	if (pgp_packet_type_from_tag(header.tag) != PGP_KEYDEF)
	{
		return PGP_INCORRECT_FUNCTION;
	}

	if (size < PGP_PACKET_OCTETS(header))
	{
		return PGP_INSUFFICIENT_DATA;
	}

	if (header.body_size == 0)
	{
		return PGP_EMPTY_PACKET;
	}

	return pgp_key_packet_read_with_header(packet, &header, data);
}

size_t pgp_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t pos = 0;

	byte_t s2k_size = 0;
	byte_t conditional_field_size = 0;

	if (size < PGP_PACKET_OCTETS(packet->header))
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1-octet key version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 1-octet key type
	LOAD_8(out + pos, &packet->type);
	pos += 1;

	// 1-octet key capabilities
	LOAD_8(out + pos, &packet->capabilities);
	pos += 1;

	// 1-octet key flags
	LOAD_8(out + pos, &packet->flags);
	pos += 1;

	// 4-octet number denoting the time when the key was created.
	LOAD_32BE(out + pos, &packet->key_creation_time);
	pos += 4;

	// 4-octet number denoting the time when the key was revoked.
	LOAD_32BE(out + pos, &packet->key_revocation_time);
	pos += 4;

	// 4-octet number denoting the time when the key will expire.
	uint32_t key_expiry_seconds = 0;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V2)
	{
		key_expiry_seconds = ((uint32_t)packet->key_expiry_days) * 86400;
	}
	else
	{
		key_expiry_seconds = packet->key_expiry_seconds;
	}

	LOAD_32BE(out + pos, &key_expiry_seconds);
	pos += 4;

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	// 4-octet scalar count for the public key material
	LOAD_32BE(out + pos, &packet->public_key_data_octets);
	pos += 4;

	// Public key material
	pos += pgp_public_key_material_write(packet, out + pos, size - pos);

	if (packet->type == PGP_KEY_TYPE_PUBLIC)
	{
		return pos;
	}

	s2k_size = (packet->s2k_usage != 0) ? pgp_s2k_octets(&packet->s2k) : 0;
	conditional_field_size = pgp_key_packet_get_s2k_size(packet);

	// 1 octet of S2K usage
	LOAD_8(out + pos, &packet->s2k_usage);
	pos += 1;

	if (conditional_field_size != 0)
	{
		// 1-octet scalar count of S2K fields
		LOAD_8(out + pos, &conditional_field_size);
		pos += 1;

		// 1 octet symmetric key algorithm
		LOAD_8(out + pos, &packet->symmetric_key_algorithm_id);
		pos += 1;

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			LOAD_8(out + pos, &packet->aead_algorithm_id);
			pos += 1;
		}

		// 1-octet count of S2K specifier
		LOAD_8(out + pos, &s2k_size);
		pos += 1;

		// S2K specifier
		pos += pgp_s2k_write(&packet->s2k, out + pos);

		// IV
		memcpy(out + pos, packet->iv, packet->iv_size);
		pos += 16;

		// Secret key octet count
		LOAD_32BE(out + pos, &packet->encrypted_octets);
		pos += 4;

		// Encrypted private key
		memcpy(out + pos, packet->encrypted, packet->encrypted_octets);
		pos += packet->encrypted_octets;
	}
	else
	{
		// Secret key octet count
		LOAD_32(out + pos, &packet->private_key_data_octets);
		pos += 4;

		// Plaintext private key
		pos += pgp_private_key_material_write(packet, out + pos, size - pos);
	}

	return pos;
}

static void pgp_hash_key_material(pgp_hash_t *hctx, pgp_key_packet *key)
{
	switch (key->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *pkey = key->key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// n
		bits_be = BSWAP_16(pkey->n->bits);
		bytes = CEIL_DIV(pkey->n->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->n->bytes, bytes);

		// e
		bits_be = BSWAP_16(pkey->e->bits);
		bytes = CEIL_DIV(pkey->e->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->e->bytes, bytes);
	}
	break;
	case PGP_KYBER:
		// TODO
		break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *pkey = key->key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->p->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->y->bytes, bytes);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *pkey = key->key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->p->bytes, bytes);

		// q
		bits_be = BSWAP_16(pkey->q->bits);
		bytes = CEIL_DIV(pkey->q->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->q->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->y->bytes, bytes);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *pkey = key->key;

		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// OID
		pgp_hash_update(hctx, &pkey->oid_size, 1);
		pgp_hash_update(hctx, pkey->oid, pkey->oid_size);

		// EC point
		bits_be = BSWAP_16(pkey->point->bits);
		bytes = CEIL_DIV(pkey->point->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->point->bytes, bytes);

		// KDF
		pgp_hash_update(hctx, &pkey->kdf.size, 1);
		pgp_hash_update(hctx, &pkey->kdf.extensions, 1);
		pgp_hash_update(hctx, &pkey->kdf.hash_algorithm_id, 1);
		pgp_hash_update(hctx, &pkey->kdf.symmetric_key_algorithm_id, 1);
	}
	break;
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *pkey = key->key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// OID
		pgp_hash_update(hctx, &pkey->oid_size, 1);
		pgp_hash_update(hctx, pkey->oid, pkey->oid_size);

		// EC point
		bits_be = BSWAP_16(pkey->point->bits);
		bytes = CEIL_DIV(pkey->point->bits, 8);
		pgp_hash_update(hctx, &bits_be, 2);
		pgp_hash_update(hctx, pkey->point->bytes, bytes);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *pkey = key->key;
		pgp_hash_update(hctx, pkey->public_key, 32);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *pkey = key->key;
		pgp_hash_update(hctx, pkey->public_key, 56);
	}
	break;
	case PGP_ED25519:
	{

		pgp_ed25519_key *pkey = key->key;
		pgp_hash_update(hctx, pkey->public_key, 32);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *pkey = key->key;
		pgp_hash_update(hctx, pkey->public_key, 57);
	}
	break;
	}
}

static void pgp_key_v3_hash(pgp_hash_t *hctx, pgp_key_packet *key)
{
	// V3 keys only support RSA
	pgp_rsa_key *pkey = key->key;
	uint32_t bytes = 0;

	// n
	bytes = CEIL_DIV(pkey->n->bits, 8);
	pgp_hash_update(hctx, pkey->n->bytes, bytes);

	// e
	bytes = CEIL_DIV(pkey->e->bits, 8);
	pgp_hash_update(hctx, pkey->e->bytes, bytes);
}

static void pgp_key_v4_hash(pgp_hash_t *hctx, pgp_key_packet *key)
{
	byte_t buffer[16] = {0};
	byte_t pos = 0;

	byte_t constant = 0x99;
	uint16_t octet_count_be = BSWAP_16((uint16_t)(key->public_key_data_octets + 6));
	uint32_t creation_time_be = BSWAP_32(key->key_creation_time);

	// 1 octet 0x99
	LOAD_8(buffer + pos, &constant);
	pos += 1;

	// 2 octet count
	LOAD_16(buffer + pos, &octet_count_be);
	pos += 2;

	// 1 octet version
	LOAD_8(buffer + pos, &key->version);
	pos += 1;

	// 4 octet creation time
	LOAD_32(buffer + pos, &creation_time_be);
	pos += 4;

	// 1 octet algorithm
	LOAD_8(buffer + pos, &key->public_key_algorithm_id);
	pos += 1;

	pgp_hash_update(hctx, buffer, pos);
	pgp_hash_key_material(hctx, key);
}

static void pgp_key_v5_hash(pgp_hash_t *hctx, pgp_key_packet *key)
{
	byte_t buffer[16] = {0};
	byte_t pos = 0;

	byte_t constant = 0x9A;
	uint32_t octet_count_be = BSWAP_32(key->public_key_data_octets + 10);
	uint32_t material_count_be = BSWAP_32(key->public_key_data_octets);
	uint32_t creation_time_be = BSWAP_32(key->key_creation_time);

	// 1 octet 0x9A
	LOAD_8(buffer + pos, &constant);
	pos += 1;

	// 4 octet count
	LOAD_32(buffer + pos, &octet_count_be);
	pos += 4;

	// 1 octet version
	LOAD_8(buffer + pos, &key->version);
	pos += 1;

	// 4 octet creation time
	LOAD_32(buffer + pos, &creation_time_be);
	pos += 4;

	// 1 octet algorithm
	LOAD_8(buffer + pos, &key->public_key_algorithm_id);
	pos += 1;

	// 4 octet count public key
	LOAD_32(buffer + pos, &material_count_be);
	pos += 4;

	pgp_hash_update(hctx, buffer, pos);
	pgp_hash_key_material(hctx, key);
}

static void pgp_key_v6_hash(pgp_hash_t *hctx, pgp_key_packet *key)
{
	byte_t buffer[16] = {0};
	byte_t pos = 0;

	byte_t constant = 0x9B;
	uint32_t octet_count_be = BSWAP_32(key->public_key_data_octets + 10);
	uint32_t material_count_be = BSWAP_32(key->public_key_data_octets);
	uint32_t creation_time_be = BSWAP_32(key->key_creation_time);

	// 1 octet 0x9B
	LOAD_8(buffer + pos, &constant);
	pos += 1;

	// 4 octet count
	LOAD_32(buffer + pos, &octet_count_be);
	pos += 4;

	// 1 octet version
	LOAD_8(buffer + pos, &key->version);
	pos += 1;

	// 4 octet creation time
	LOAD_32(buffer + pos, &creation_time_be);
	pos += 4;

	// 1 octet algorithm
	LOAD_8(buffer + pos, &key->public_key_algorithm_id);
	pos += 1;

	// 4 octet count public key
	LOAD_32(buffer + pos, &material_count_be);
	pos += 4;

	pgp_hash_update(hctx, buffer, pos);
	pgp_hash_key_material(hctx, key);
}

void pgp_key_hash(void *ctx, pgp_key_packet *key)
{
	switch (key->version)
	{
	case PGP_KEY_V2:
	case PGP_KEY_V3:
		return pgp_key_v3_hash(ctx, key);
	case PGP_KEY_V4:
		return pgp_key_v4_hash(ctx, key);
	case PGP_KEY_V5:
		return pgp_key_v5_hash(ctx, key);
	case PGP_KEY_V6:
		return pgp_key_v6_hash(ctx, key);
	default:
		return;
	}
}

pgp_error_t pgp_key_fingerprint(pgp_key_packet *key, void *fingerprint, byte_t *size)
{
	pgp_error_t status = 0;
	pgp_hash_t *hctx = NULL;

	// Copy from cache
	if (key->fingerprint_size != 0)
	{
	cache_read:
		if (*size < key->fingerprint_size)
		{
			return PGP_BUFFER_TOO_SMALL;
		}

		memcpy(fingerprint, key->fingerprint, key->fingerprint_size);
		*size = key->fingerprint_size;

		return PGP_SUCCESS;
	}

	switch (key->version)
	{
	case PGP_KEY_V2:
	case PGP_KEY_V3:
	{
		status = pgp_hash_new(&hctx, PGP_MD5);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		pgp_key_v3_hash(hctx, key);
		pgp_hash_final(hctx, key->fingerprint, PGP_KEY_V3_FINGERPRINT_SIZE);
		pgp_hash_delete(hctx);
		key->fingerprint_size = PGP_KEY_V3_FINGERPRINT_SIZE;

		goto cache_read;
	}
	case PGP_KEY_V4:
	{
		status = pgp_hash_new(&hctx, PGP_SHA1);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		pgp_key_v4_hash(hctx, key);
		pgp_hash_final(hctx, key->fingerprint, PGP_KEY_V4_FINGERPRINT_SIZE);
		pgp_hash_delete(hctx);
		key->fingerprint_size = PGP_KEY_V4_FINGERPRINT_SIZE;

		goto cache_read;
	}
	case PGP_KEY_V5:
	{
		status = pgp_hash_new(&hctx, PGP_SHA2_256);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		pgp_key_v5_hash(hctx, key);
		pgp_hash_final(hctx, key->fingerprint, PGP_KEY_V5_FINGERPRINT_SIZE);
		pgp_hash_delete(hctx);
		key->fingerprint_size = PGP_KEY_V5_FINGERPRINT_SIZE;

		goto cache_read;
	}
	case PGP_KEY_V6:
	{
		status = pgp_hash_new(&hctx, PGP_SHA2_256);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		pgp_key_v6_hash(hctx, key);
		pgp_hash_final(hctx, key->fingerprint, PGP_KEY_V6_FINGERPRINT_SIZE);
		pgp_hash_delete(hctx);
		key->fingerprint_size = PGP_KEY_V6_FINGERPRINT_SIZE;

		goto cache_read;
	}
	default:
		return PGP_UNKNOWN_KEY_VERSION;
	}

	// Unreachable
	return PGP_INTERNAL_BUG;
}

pgp_error_t pgp_key_id(pgp_key_packet *key, byte_t id[PGP_KEY_ID_SIZE])
{
	pgp_error_t status = 0;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	if (key->version > 3)
	{
		status = pgp_key_fingerprint(key, fingerprint, &fingerprint_size);

		if (status != PGP_SUCCESS)
		{
			return status;
		}

		if (key->version == PGP_KEY_V4 || key->version == PGP_KEY_V6)
		{
			// Low 64 bits of fingerprint
			LOAD_64(id, PTR_OFFSET(fingerprint, fingerprint_size - 8));
			return 8;
		}

		if (key->version == PGP_KEY_V5)
		{
			// High 64 bits of fingerprint
			LOAD_64(id, PTR_OFFSET(fingerprint, 8));
			return 8;
		}
	}
	else
	{
		// Low 64 bits of public modulus
		pgp_rsa_key *rsa_key = key->key;
		uint16_t bytes = CEIL_DIV(rsa_key->n->bits, 8);

		LOAD_64(id, &rsa_key->n->bytes[bytes - 8]);
		return 8;
	}

	// Unreachable
	return 0;
}

uint32_t pgp_key_id_from_fingerprint(pgp_key_version version, byte_t id[PGP_KEY_ID_SIZE], void *fingerprint, uint32_t size)
{
	if (version == PGP_KEY_V4 || version == PGP_KEY_V6)
	{
		// Low 64 bits of fingerprint
		LOAD_64(id, PTR_OFFSET(fingerprint, size - 8));
		return 8;
	}

	if (version == PGP_KEY_V5)
	{
		// High 64 bits of fingerprint
		LOAD_64(id, PTR_OFFSET(fingerprint, 8));
		return 8;
	}

	return 0;
}

uint32_t pgp_key_compare(pgp_key_packet *key, byte_t *input, byte_t input_size)
{
	pgp_error_t status = 0;

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	status = pgp_key_fingerprint(key, &fingerprint, &fingerprint_size);

	if (status != PGP_SUCCESS)
	{
		// Assume comparison fails
		return 1;
	}

	if (fingerprint_size == input_size)
	{
		return memcmp(fingerprint, input, fingerprint_size);
	}
	else
	{
		// Check key ID
		if (input_size == PGP_KEY_ID_SIZE)
		{
			if (key->version == PGP_KEY_V5)
			{
				return memcmp(fingerprint, input, PGP_KEY_ID_SIZE);
			}
			else
			{
				return memcmp(PTR_OFFSET(fingerprint, fingerprint_size - PGP_KEY_ID_SIZE), input, PGP_KEY_ID_SIZE);
			}
		}
	}

	return 1;
}

byte_t pgp_key_fingerprint_size(byte_t version)
{
	switch (version)
	{
	case PGP_KEY_V2:
	case PGP_KEY_V3:
		return 16;
	case PGP_KEY_V4:
		return 20;
	case PGP_KEY_V5:
	case PGP_KEY_V6:
		return 32;
	default:
		return 0;
	}
}

pgp_rsa_key *pgp_rsa_key_new()
{
	pgp_rsa_key *key = malloc(sizeof(pgp_rsa_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(pgp_rsa_key));

	return key;
}

void pgp_rsa_key_delete(pgp_rsa_key *key)
{
	if (key == NULL)
	{
		return;
	}

	mpi_delete(key->n);
	mpi_delete(key->e);
	mpi_delete(key->d);
	mpi_delete(key->p);
	mpi_delete(key->q);
	mpi_delete(key->u);

	free(key);
}

pgp_elgamal_key *pgp_elgamal_key_new()
{
	pgp_elgamal_key *key = malloc(sizeof(pgp_elgamal_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(pgp_elgamal_key));

	return key;
}

void pgp_elgamal_key_delete(pgp_elgamal_key *key)
{
	if (key == NULL)
	{
		return;
	}

	mpi_delete(key->p);
	mpi_delete(key->g);
	mpi_delete(key->x);
	mpi_delete(key->y);

	free(key);
}

pgp_dsa_key *pgp_dsa_key_new()
{
	pgp_dsa_key *key = malloc(sizeof(pgp_dsa_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(pgp_dsa_key));

	return key;
}

void pgp_dsa_key_delete(pgp_dsa_key *key)
{
	if (key == NULL)
	{
		return;
	}

	mpi_delete(key->p);
	mpi_delete(key->q);
	mpi_delete(key->g);
	mpi_delete(key->x);
	mpi_delete(key->y);

	free(key);
}

pgp_ecdsa_key *pgp_ecdsa_key_new()
{
	pgp_ecdsa_key *key = malloc(sizeof(pgp_ecdsa_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(pgp_ecdsa_key));

	return key;
}

void pgp_ecdsa_key_delete(pgp_ecdsa_key *key)
{
	if (key == NULL)
	{
		return;
	}

	mpi_delete(key->point);
	mpi_delete(key->x);
	memset(key, 0, sizeof(pgp_ecdsa_key));

	free(key);
}

pgp_ecdh_key *pgp_ecdh_key_new()
{
	pgp_ecdh_key *key = malloc(sizeof(pgp_ecdh_key));

	if (key == NULL)
	{
		return NULL;
	}

	memset(key, 0, sizeof(pgp_ecdh_key));

	return key;
}

void pgp_ecdh_key_delete(pgp_ecdh_key *key)
{
	if (key == NULL)
	{
		return;
	}

	mpi_delete(key->point);
	mpi_delete(key->x);
	memset(key, 0, sizeof(pgp_ecdh_key));

	free(key);
}
