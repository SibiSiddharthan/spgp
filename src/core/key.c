/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <algorithms.h>
#include <packet.h>
#include <key.h>
#include <s2k.h>
#include <mpi.h>
#include <crypto.h>

#include <hash.h>
#include <sha.h>
#include <md5.h>

#include <stdlib.h>
#include <string.h>

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

static uint32_t get_public_key_material_size(pgp_public_key_algorithms public_key_algorithm_id, void *key_data)
{
	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = key_data;

		return sizeof(pgp_rsa_key) + mpi_size(key->n->bits) + mpi_size(key->e->bits);
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = key_data;

		return sizeof(pgp_elgamal_key) + mpi_size(key->p->bits) + mpi_size(key->g->bits) + mpi_size(key->y->bits);
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = key_data;

		return sizeof(pgp_dsa_key) + mpi_size(key->p->bits) + mpi_size(key->q->bits) + mpi_size(key->g->bits) + mpi_size(key->y->bits);
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = key_data;

		return sizeof(pgp_ecdh_key) + mpi_size(key->point->bits);
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = key_data;

		return sizeof(pgp_ecdsa_key) + mpi_size(key->point->bits);
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

static uint32_t get_private_key_material_size(pgp_public_key_algorithms public_key_algorithm_id, void *key_data)
{
	switch (public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *key = key_data;

		return sizeof(pgp_rsa_key) + mpi_size(key->d->bits) + mpi_size(key->p->bits) + mpi_size(key->q->bits) + mpi_size(key->u->bits);
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = key_data;

		return sizeof(pgp_elgamal_key) + mpi_size(key->x->bits);
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = key_data;

		return sizeof(pgp_dsa_key) + mpi_size(key->x->bits);
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = key_data;

		return sizeof(pgp_ecdh_key) + mpi_size(key->x->bits);
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = key_data;

		return sizeof(pgp_ecdsa_key) + mpi_size(key->x->bits);
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

static uint32_t pgp_public_key_material_read(pgp_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

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

		mpi_n_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_n_bits);
		mpi_e_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];

		if (size < (mpi_octets(mpi_n_bits) + mpi_octets(mpi_e_bits)))
		{
			return 0;
		}

		key = malloc(sizeof(pgp_rsa_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_rsa_key));

		key->n = mpi_new(mpi_n_bits);
		key->e = mpi_new(mpi_e_bits);

		if (key->n == NULL || key->e == NULL)
		{
			mpi_delete(key->n);
			mpi_delete(key->e);

			free(key);

			return 0;
		}

		pos += mpi_read(key->n, in + pos, size - pos);
		pos += mpi_read(key->e, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		// MPI of p,g,y
		pgp_elgamal_key *key = NULL;
		uint16_t offset = 0;
		uint16_t mpi_p_bits = 0;
		uint16_t mpi_g_bits = 0;
		uint16_t mpi_y_bits = 0;

		mpi_p_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_p_bits);
		mpi_g_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_g_bits);
		mpi_y_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];

		if (size < (mpi_octets(mpi_p_bits) + mpi_octets(mpi_g_bits) + mpi_octets(mpi_y_bits)))
		{
			return 0;
		}

		key = malloc(sizeof(pgp_elgamal_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_elgamal_key));

		key->p = mpi_new(mpi_p_bits);
		key->g = mpi_new(mpi_g_bits);
		key->y = mpi_new(mpi_y_bits);

		if (key->p == NULL || key->g == NULL || key->y == NULL)
		{
			mpi_delete(key->p);
			mpi_delete(key->g);
			mpi_delete(key->y);

			free(key);

			return 0;
		}

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return pos;
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

		mpi_p_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_p_bits);
		mpi_q_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_q_bits);
		mpi_g_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_g_bits);
		mpi_y_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];

		if (size < (mpi_octets(mpi_p_bits) + mpi_octets(mpi_q_bits) + mpi_octets(mpi_g_bits) + mpi_octets(mpi_y_bits)))
		{
			return 0;
		}

		key = malloc(sizeof(pgp_dsa_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_dsa_key));

		key->p = mpi_new(mpi_p_bits);
		key->q = mpi_new(mpi_q_bits);
		key->g = mpi_new(mpi_g_bits);
		key->y = mpi_new(mpi_y_bits);

		if (key->p == NULL || key->q == NULL || key->g == NULL || key->y == NULL)
		{
			mpi_delete(key->p);
			mpi_delete(key->q);
			mpi_delete(key->g);
			mpi_delete(key->y);

			free(key);

			return 0;
		}

		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->g, in + pos, size - pos);
		pos += mpi_read(key->y, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = NULL;
		uint16_t offset = in[0] + 1;
		uint16_t mpi_point_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];

		if (size < (offset + mpi_octets(mpi_point_bits)))
		{
			return 0;
		}

		key = malloc(sizeof(pgp_ecdh_key));

		if (key == NULL)
		{
			return 0;
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
			free(key);
			return 0;
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

		return pos;
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = NULL;
		uint16_t offset = in[0] + 1;
		uint16_t mpi_point_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];

		if (size < (offset + mpi_octets(mpi_point_bits)))
		{
			return 0;
		}

		key = malloc(sizeof(pgp_ecdsa_key));

		if (key == NULL)
		{
			return 0;
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
			free(key);
			return 0;
		}

		pos += mpi_read(key->point, in + pos, size - pos);

		packet->public_key_data_octets = pos;
		packet->key = key;

		return pos;
	}
	case PGP_X25519:
	{
		// 32 octets
		pgp_x25519_key *key = NULL;

		if (size < 32)
		{
			return 0;
		}

		key = malloc(sizeof(pgp_x25519_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_x25519_key));
		memcpy(key->public_key, in, 32);

		packet->public_key_data_octets = 32;
		packet->key = key;

		return pos;
	}
	case PGP_X448:
	{
		// 56 octets
		pgp_x448_key *key = NULL;

		if (size < 56)
		{
			return 0;
		}

		key = malloc(sizeof(pgp_x448_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_x448_key));
		memcpy(key->public_key, in, 56);

		packet->public_key_data_octets = 56;
		packet->key = key;

		return pos;
	}
	case PGP_ED25519:
	{
		// 32 octets
		pgp_ed25519_key *key = NULL;

		if (size < 32)
		{
			return 0;
		}

		key = malloc(sizeof(pgp_ed25519_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_ed25519_key));
		memcpy(key->public_key, in, 32);

		packet->public_key_data_octets = 32;
		packet->key = key;

		return pos;
	}
	case PGP_ED448:
	{
		// 57 octets
		pgp_ed448_key *key = NULL;

		if (size < 57)
		{
			return 0;
		}

		key = malloc(sizeof(pgp_ed448_key));

		if (key == NULL)
		{
			return 0;
		}

		memset(key, 0, sizeof(pgp_ed448_key));
		memcpy(key->public_key, in, 57);

		packet->public_key_data_octets = 57;
		packet->key = key;

		return pos;
	}
	default:
		packet->public_key_data_octets = 0;
		return 0;
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
static uint32_t pgp_private_key_material_read(pgp_key_packet *packet, void *ptr, uint32_t size)
{
	byte_t *in = ptr;
	uint32_t pos = 0;

	if (packet->key == NULL)
	{
		return 0;
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

		mpi_d_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_d_bits);
		mpi_p_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_p_bits);
		mpi_q_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_q_bits);
		mpi_u_bits = ((uint16_t)in[offset] << 8) + in[offset + 1];
		offset += mpi_octets(mpi_u_bits);

		if (size < offset)
		{
			return 0;
		}

		key->d = mpi_new(mpi_d_bits);
		key->p = mpi_new(mpi_p_bits);
		key->q = mpi_new(mpi_q_bits);
		key->u = mpi_new(mpi_u_bits);

		if (key->d == NULL || key->p == NULL || key->q == NULL || key->u == NULL)
		{
			mpi_delete(key->d);
			mpi_delete(key->p);
			mpi_delete(key->q);
			mpi_delete(key->d);

			return 0;
		}

		pos += mpi_read(key->d, in + pos, size - pos);
		pos += mpi_read(key->p, in + pos, size - pos);
		pos += mpi_read(key->q, in + pos, size - pos);
		pos += mpi_read(key->u, in + pos, size - pos);

		packet->private_key_data_octets = pos;

		return pos;
	}
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *key = packet->key;
		uint16_t mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return 0;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return 0;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return pos;
	}
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;
		uint16_t mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return 0;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return 0;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return pos;
	}
	case PGP_ECDH:
	{
		pgp_ecdh_key *key = packet->key;
		uint16_t mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return 0;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return 0;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return pos;
	}
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *key = packet->key;
		uint16_t mpi_bits = ((uint16_t)in[0] << 8) + in[1];

		if (size < mpi_octets(mpi_bits))
		{
			return 0;
		}

		key->x = mpi_new(mpi_bits);

		if (key->x == NULL)
		{
			return 0;
		}

		pos += mpi_read(key->x, in, size);
		packet->private_key_data_octets = pos;

		return pos;
	}
	case PGP_X25519:
	{
		pgp_x25519_key *key = packet->key;

		// 32 octets
		memcpy(key->private_key, in, 32);
		packet->private_key_data_octets = 32;

		return 32;
	}
	case PGP_X448:
	{
		pgp_x448_key *key = packet->key;

		// 56 octets
		memcpy(key->private_key, in, 56);
		packet->private_key_data_octets = 56;

		return 56;
	}
	case PGP_ED25519:
	{
		pgp_ed25519_key *key = packet->key;

		// 32 octets
		memcpy(key->private_key, in, 32);
		packet->private_key_data_octets = 32;

		return 32;
	}
	case PGP_ED448:
	{
		pgp_ed448_key *key = packet->key;

		// 57 octets
		memcpy(key->private_key, in, 57);
		packet->private_key_data_octets = 57;

		return 57;
	}
	default:
		return 0;
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

pgp_key_packet *pgp_public_key_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_key_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_PUBKEY && pgp_packet_get_type(header.tag) != PGP_PUBSUBKEY)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_key_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_key_packet));

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	// 4-octet number denoting the time that the key was created.
	uint32_t key_creation_time_be;

	LOAD_32(&key_creation_time_be, in + pos);
	packet->key_creation_time = BSWAP_32(key_creation_time_be);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days_be;

		LOAD_16(&key_expiry_days_be, in + pos);
		packet->key_expiry_days = BSWAP_16(key_expiry_days_be);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(&packet->public_key_algorithm_id, in + pos);
	pos += 1;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		// 4-octet scalar count for the public key material
		uint32_t key_data_octets_be;

		LOAD_32(&key_data_octets_be, in + pos);
		packet->public_key_data_octets = BSWAP_32(key_data_octets_be);
		pos += 4;
	}
	else
	{
		packet->public_key_data_octets = packet->header.body_size - (pos - packet->header.header_size);
	}

	pos += pgp_public_key_material_read(packet, in + pos, packet->public_key_data_octets);

	return packet;
}

size_t pgp_public_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	// A 1-octet version number 3 or 4.
	// A 4-octet number denoting the time that the key was created.
	// (For V3) A 2-octet number denoting expiry in days.
	// A 1-octet public key algorithm.
	// (For V6) A 4-octet scalar count for the public key material
	// One or more MPIs comprising the key.

	required_size = 1 + 4 + 1 + packet->public_key_data_octets;
	required_size += (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3) ? 2 : 0;
	required_size += (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5) ? 4 : 0;
	required_size += packet->header.header_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 4-octet number denoting the time that the key was created
	uint32_t key_creation_time = BSWAP_32(packet->key_creation_time);

	LOAD_32(out + pos, &key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days = BSWAP_16(packet->key_expiry_days);

		LOAD_16(out + pos, &key_expiry_days);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		// 4-octet scalar count for the public key material
		uint32_t key_data_octets_be = BSWAP_32(packet->public_key_data_octets);

		LOAD_32(out + pos, &key_data_octets_be);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, out + pos, size - pos);

	return pos;
}

static uint32_t pgp_secret_key_material_encrypt_legacy_cfb_v3(pgp_key_packet *packet, byte_t hash[MD5_HASH_SIZE])
{
	// Only RSA keys
	pgp_rsa_key *key = packet->key;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t size = mpi_octets(key->d->bits) + mpi_octets(key->p->bits) + mpi_octets(key->q->bits) + mpi_octets(key->u->bits) + 2;

	uint32_t pos = 0;
	uint16_t bits_be = 0;

	if (key_size > MD5_HASH_SIZE)
	{
		return 0;
	}

	packet->encrypted = malloc(size);

	if (packet->encrypted == NULL)
	{
		return 0;
	}

	memset(packet->encrypted, 0, size);

	// d
	bits_be = BSWAP_16(key->d->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	pos += pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->d->bytes,
						   CEIL_DIV(key->d->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->d->bits, 8));

	// p
	bits_be = BSWAP_16(key->p->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	pos += pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->p->bytes,
						   CEIL_DIV(key->p->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->p->bits, 8));

	// q
	bits_be = BSWAP_16(key->q->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	pos += pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->q->bytes,
						   CEIL_DIV(key->q->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->q->bits, 8));

	// u
	bits_be = BSWAP_16(key->u->bits);
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &bits_be);
	pos += 2;

	pos += pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size, key->u->bytes,
						   CEIL_DIV(key->u->bits, 8), PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(key->u->bits, 8));

	// Store the checksum at the end
	LOAD_16(PTR_OFFSET(packet->encrypted, pos), &packet->key_checksum);

	packet->encrypted_octets = pos;

	return pos;
}

static uint32_t pgp_secret_key_material_decrypt_legacy_cfb_v3(pgp_key_packet *packet, byte_t hash[MD5_HASH_SIZE])
{
	// Only RSA keys
	uint32_t result = 0;
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);

	uint32_t pos = 0;
	uint16_t bits_be = 0;
	uint16_t bits_le = 0;

	byte_t *buffer = 0;

	if (key_size > MD5_HASH_SIZE)
	{
		return 0;
	}

	buffer = malloc(packet->encrypted_octets);

	if (buffer == NULL)
	{
		return 0;
	}

	memset(buffer, 0, packet->encrypted_octets);

	// d
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	pos += pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
						   PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));

	// p
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	pos += pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
						   PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));

	// q
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	pos += pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
						   PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));

	// u
	LOAD_16(&bits_be, PTR_OFFSET(packet->encrypted, pos));
	LOAD_16(PTR_OFFSET(buffer, pos), &bits_be);
	bits_le = BSWAP_16(bits_be);
	pos += 2;

	pos += pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, key_size, packet->iv, packet->iv_size,
						   PTR_OFFSET(packet->encrypted, pos), CEIL_DIV(bits_le, 8), PTR_OFFSET(buffer, pos), CEIL_DIV(bits_le, 8));

	// Load the checksum from the end
	LOAD_16(&packet->key_checksum, PTR_OFFSET(packet->encrypted, pos));
	pos += 2;

	// Read in the key from the buffer
	result = pgp_private_key_material_read(packet, buffer, pos - 2);
	free(buffer);

	if (result == 0)
	{
		return 0;
	}

	// Verify the checksum
	if (pgp_private_key_material_checksum(packet) != packet->key_checksum)
	{
		free(buffer);
		return 0;
	}

	free(buffer);

	return result;
}

static uint32_t pgp_secret_key_material_encrypt_legacy_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t hash[MD5_HASH_SIZE] = {0};
	byte_t *buffer = NULL;

	uint32_t count = 0;
	size_t result = 0;

	// Hash the passphrase
	md5_hash(passphrase, passphrase_size, hash);

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

		return 0;
	}

	memset(buffer, 0, ROUND_UP(count + 2, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + 2, 16));

	// Write the octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Store the checksum at the end
	LOAD_16(PTR_OFFSET(buffer, count), &packet->key_checksum);

	// Encrypt using CFB
	result = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, hash, MD5_HASH_SIZE, packet->iv, packet->iv_size, buffer, count + 2,
							 packet->encrypted, count + 2);
	packet->encrypted_octets = result;

	free(buffer);

	if (result == 0)
	{
		free(packet->encrypted);
		return 0;
	}

	return result;
}

static uint32_t pgp_secret_key_material_decrypt_legacy_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t hash[MD5_HASH_SIZE] = {0};
	byte_t *buffer = NULL;

	size_t result = 0;

	// Hash the passphrase
	md5_hash(passphrase, passphrase_size, hash);

	if (packet->version == PGP_KEY_V3 || packet->version == PGP_KEY_V2)
	{
		return pgp_secret_key_material_decrypt_legacy_cfb_v3(packet, hash);
	}

	buffer = malloc(ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL)
	{
		free(buffer);
		return 0;
	}

	memset(buffer, 0, ROUND_UP(packet->encrypted_octets, 16));

	// Decrypt using CFB
	result = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, hash, MD5_HASH_SIZE, packet->iv, packet->iv_size, packet->encrypted,
							 packet->encrypted_octets, buffer, packet->encrypted_octets);

	if (result == 0)
	{
		free(buffer);
		return 0;
	}

	// Load the checksum at the end
	LOAD_16(&packet->key_checksum, PTR_OFFSET(buffer, packet->encrypted_octets - 2));

	// Read the key from the buffer
	result = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - 2);
	free(buffer);

	if (result == 0)
	{
		return 0;
	}

	if (pgp_private_key_material_checksum(packet) != packet->key_checksum)
	{
		return 0;
	}

	return result;
}

static uint32_t pgp_secret_key_material_encrypt_malleable_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t count = 0;
	size_t result = 0;

	byte_t key[32] = {0};
	byte_t *buffer = NULL;

	count = get_private_key_material_octets(packet->public_key_algorithm_id, packet->key);
	buffer = malloc(ROUND_UP(count + 2, 16));
	packet->encrypted = malloc(ROUND_UP(count + 2, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		free(packet->encrypted);

		return 0;
	}

	memset(buffer, 0, ROUND_UP(count + 2, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + 2, 16));

	// Hash the passphrase
	pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	// Write the octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Store the checksum at the end
	LOAD_16(PTR_OFFSET(buffer, count), &packet->key_checksum);

	// Encrypt using CFB
	result = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, buffer, count + 2,
							 packet->encrypted, count + 2);
	packet->encrypted_octets = result;

	free(buffer);

	if (result == 0)
	{
		free(packet->encrypted);
		return 0;
	}

	return result;
}

static uint32_t pgp_secret_key_material_decrypt_malleable_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	size_t result = 0;

	byte_t key[32] = {0};
	byte_t *buffer = NULL;

	buffer = malloc(ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL)
	{
		free(buffer);
		return 0;
	}

	memset(buffer, 0, ROUND_UP(packet->encrypted_octets, 16));

	// Hash the passphrase
	pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	// Decrypt using CFB
	result = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, packet->encrypted,
							 packet->encrypted_octets, buffer, packet->encrypted_octets);

	if (result == 0)
	{
		free(buffer);
		return 0;
	}

	// Load the checksum at the end
	LOAD_16(&packet->key_checksum, PTR_OFFSET(buffer, packet->encrypted_octets - 2));

	// Read the key from the buffer
	result = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - 2);
	free(buffer);

	if (result == 0)
	{
		return 0;
	}

	if (pgp_private_key_material_checksum(packet) != packet->key_checksum)
	{
		return 0;
	}

	return result;
}

static uint32_t pgp_secret_key_material_encrypt_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t count = 0;
	size_t result = 0;

	byte_t key[32] = {0};
	byte_t *buffer = NULL;

	count = get_private_key_material_octets(packet->public_key_algorithm_id, packet->key);
	buffer = malloc(ROUND_UP(count + SHA1_HASH_SIZE, 16));
	packet->encrypted = malloc(ROUND_UP(count + SHA1_HASH_SIZE, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		free(packet->encrypted);

		return 0;
	}

	memset(buffer, 0, ROUND_UP(count + SHA1_HASH_SIZE, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + SHA1_HASH_SIZE, 16));

	// Hash the passphrase
	pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	// Write the octets to the buffer
	pgp_private_key_material_write(packet, buffer, count);

	// Calculate the hash and store it the end
	sha1_hash(buffer, count, PTR_OFFSET(buffer, count));

	// Encrypt using CFB
	result = pgp_cfb_encrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, buffer, count + SHA1_HASH_SIZE,
							 packet->encrypted, count + SHA1_HASH_SIZE);
	packet->encrypted_octets = result;

	free(buffer);

	if (result == 0)
	{
		free(packet->encrypted);
		return 0;
	}

	return result;
}

static uint32_t pgp_secret_key_material_decrypt_cfb(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	size_t result = 0;

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
	pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, key, key_size);

	// Decrypt using CFB
	result = pgp_cfb_decrypt(packet->symmetric_key_algorithm_id, key, key_size, packet->iv, packet->iv_size, packet->encrypted,
							 packet->encrypted_octets, buffer, packet->encrypted_octets);

	if (result == 0)
	{
		free(buffer);
		return 0;
	}

	// Hash the material
	sha1_hash(buffer, packet->encrypted_octets - SHA1_HASH_SIZE, hash);

	// Check the hash
	if (memcmp(hash, PTR_OFFSET(buffer, packet->encrypted_octets - SHA1_HASH_SIZE), SHA1_HASH_SIZE) != 0)
	{
		free(buffer);
		return 0;
	}

	// Read the key from the buffer
	result = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - SHA1_HASH_SIZE);
	free(buffer);

	if (result == 0)
	{
		return 0;
	}

	// Calculate checksum
	packet->key_checksum = pgp_private_key_material_checksum(packet);

	return result;
}

static uint32_t pgp_secret_key_material_encrypt_aead(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t aad_size = packet->public_key_data_octets + 16; // Upper bound
	uint32_t aad_count = 0;
	uint32_t count = 0;

	size_t pos = 0;
	size_t result = 0;

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

		return 0;
	}

	memset(buffer, 0, ROUND_UP(count + aad_size, 16));
	memset(packet->encrypted, 0, ROUND_UP(count + PGP_AEAD_TAG_SIZE, 16));

	// Hash the passphrase
	pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, ikey, key_size);

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

	uint32_t creation_time_be = BSWAP_32(packet->key_creation_time);
	LOAD_32(buffer + pos, &creation_time_be);
	pos += 4;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		uint32_t public_key_octets_be = BSWAP_32(packet->public_key_data_octets);
		LOAD_32(buffer + pos, &public_key_octets_be);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, PTR_OFFSET(buffer, pos), packet->public_key_data_octets);
	aad_count = pos - count;

	// Encrypt using AEAD (Store the tag at the end)
	result = pgp_aead_encrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, key_size, packet->iv, packet->iv_size,
							  PTR_OFFSET(buffer, count), aad_count, buffer, count, packet->encrypted, count,
							  PTR_OFFSET(packet->encrypted, count), PGP_AEAD_TAG_SIZE);

	packet->encrypted_octets = result + PGP_AEAD_TAG_SIZE;

	free(buffer);

	if (result == 0)
	{
		free(packet->encrypted);
		return 0;
	}

	return result + PGP_AEAD_TAG_SIZE;
}

static uint32_t pgp_secret_key_material_decrypt_aead(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	byte_t key_size = pgp_symmetric_cipher_key_size(packet->symmetric_key_algorithm_id);
	uint32_t aad_size = packet->public_key_data_octets + 16; // Upper bound
	uint32_t aad_count = 0;

	size_t pos = 0;
	size_t result = 0;

	byte_t ikey[32] = {0};
	byte_t dkey[32] = {0};
	byte_t info[4] = {0};

	byte_t expected_tag[PGP_AEAD_TAG_SIZE] = {0};
	byte_t actual_tag[PGP_AEAD_TAG_SIZE] = {0};

	byte_t *key = NULL;
	byte_t *buffer = NULL;

	buffer = malloc(ROUND_UP(aad_size, 16) + ROUND_UP(packet->encrypted_octets, 16));

	if (buffer == NULL || packet->encrypted == NULL)
	{
		free(buffer);
		return 0;
	}

	memset(buffer, 0, ROUND_UP(aad_size, 16) + ROUND_UP(packet->encrypted_octets, 16));

	// Hash the passphrase
	pgp_s2k_hash(&packet->s2k, passphrase, passphrase_size, ikey, key_size);

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

	uint32_t creation_time_be = BSWAP_32(packet->key_creation_time);
	LOAD_32(buffer + pos, &creation_time_be);
	pos += 4;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		uint32_t public_key_octets_be = BSWAP_32(packet->public_key_data_octets);
		LOAD_32(buffer + pos, &public_key_octets_be);
		pos += 4;
	}

	pos += pgp_public_key_material_write(packet, PTR_OFFSET(buffer, pos), packet->public_key_data_octets);
	aad_count = pos;

	pos = ROUND_UP(pos, 16);

	// Decrypt using AEAD
	memcpy(actual_tag, PTR_OFFSET(packet->encrypted, packet->encrypted_octets - PGP_AEAD_TAG_SIZE), PGP_AEAD_TAG_SIZE);

	result = pgp_aead_decrypt(packet->symmetric_key_algorithm_id, packet->aead_algorithm_id, key, key_size, packet->iv, packet->iv_size,
							  buffer, aad_count, packet->encrypted, packet->encrypted_octets - PGP_AEAD_TAG_SIZE, PTR_OFFSET(buffer, pos),
							  packet->encrypted_octets - PGP_AEAD_TAG_SIZE, expected_tag, PGP_AEAD_TAG_SIZE);

	if (result == 0)
	{
		free(buffer);
		return 0;
	}

	if (memcmp(actual_tag, expected_tag, PGP_AEAD_TAG_SIZE) != 0)
	{
		free(buffer);
		return 0;
	}

	// Read the key from the buffer
	result = pgp_private_key_material_read(packet, buffer, packet->encrypted_octets - PGP_AEAD_TAG_SIZE);
	free(buffer);

	if (result == 0)
	{
		return 0;
	}

	// Calculate checksum
	packet->key_checksum = pgp_private_key_material_checksum(packet);

	return result;
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

pgp_key_packet *pgp_secret_key_packet_read(void *data, size_t size)
{
	byte_t *in = data;

	pgp_key_packet *packet = NULL;
	pgp_packet_header header = {0};

	size_t pos = 0;

	header = pgp_packet_header_read(data, size);
	pos = header.header_size;

	if (pgp_packet_get_type(header.tag) != PGP_SECKEY && pgp_packet_get_type(header.tag) != PGP_SECSUBKEY)
	{
		return NULL;
	}

	if (size < (header.header_size + header.body_size))
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_key_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_key_packet));

	// Copy the header
	packet->header = header;

	// 1 octet version
	LOAD_8(&packet->version, in + pos);
	pos += 1;

	// 4-octet number denoting the time that the key was created.
	uint32_t key_creation_time_be;

	LOAD_32(&key_creation_time_be, in + pos);
	packet->key_creation_time = BSWAP_32(key_creation_time_be);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days_be;

		LOAD_16(&key_expiry_days_be, in + pos);
		packet->key_expiry_days = BSWAP_16(key_expiry_days_be);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(&packet->public_key_algorithm_id, in + pos);
	pos += 1;

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		// 4-octet scalar count for the public key material
		uint32_t public_key_data_octets_be;

		LOAD_32(&public_key_data_octets_be, in + pos);
		packet->public_key_data_octets = BSWAP_32(public_key_data_octets_be);
		pos += 4;
	}

	pos += pgp_public_key_material_read(packet, in + pos, packet->header.body_size - pos);

	// 1 octet of S2K usage
	LOAD_8(&packet->s2k_usage, in + pos);
	pos += 1;

	if (packet->s2k_usage != 0)
	{
		void *result;

		byte_t s2k_size = 0;
		byte_t conditional_field_size = 0;

		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			// 1-octet scalar count of S2K fields
			LOAD_8(&conditional_field_size, in + pos);
			pos += 1;
		}

		// 1 octet symmetric key algorithm
		LOAD_8(&packet->symmetric_key_algorithm_id, in + pos);
		pos += 1;

		if (packet->s2k_usage == 253)
		{
			// 1 octet AEAD algorithm
			LOAD_8(&packet->aead_algorithm_id, in + pos);
			pos += 1;
		}

		if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
		{
			// 1-octet count of S2K specifier
			LOAD_8(&s2k_size, in + pos);
			pos += 1;
		}

		// S2K specifier
		if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
		{
			result = pgp_s2k_read(&packet->s2k, in + pos, s2k_size != 0 ? s2k_size : (packet->header.body_size - pos));

			if (result == NULL)
			{
				return NULL;
			}

			pos += pgp_s2k_size(&packet->s2k);
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

		memcpy(packet->iv, in + pos, packet->iv_size);
		pos += packet->iv_size;

		if (packet->version == PGP_KEY_V5)
		{
			LOAD_32(&packet->encrypted_octets, in + pos);
			pos += 4;
		}

		// Encrypted private key
		packet->encrypted_octets = packet->header.body_size - (pos - packet->header.header_size);
		packet->encrypted = malloc(packet->encrypted_octets);

		if (packet->encrypted == NULL)
		{
			return NULL;
		}

		memcpy(packet->encrypted, in + pos, packet->encrypted_octets);
		pos += packet->encrypted_octets;
	}
	else
	{
		if (packet->version == PGP_KEY_V5)
		{
			LOAD_32(&packet->private_key_data_octets, in + pos);
			pos += 4;
		}

		// Plaintext private key
		pos += pgp_private_key_material_read(packet, in + pos, packet->header.body_size - (pos - packet->header.header_size));

		if (packet->version != PGP_KEY_V6)
		{
			// 2-octet checksum
			LOAD_16(&packet->key_checksum, in + pos);
			pos += 2;
		}
	}

	return packet;
}

size_t pgp_secret_key_packet_write(pgp_key_packet *packet, void *ptr, size_t size)
{
	byte_t *out = ptr;
	size_t required_size = 0;
	size_t pos = 0;

	byte_t s2k_size = 0;
	byte_t conditional_field_size = 0;

	// A 1-octet version number 3 or 4.
	// A 4-octet number denoting the time that the key was created.
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

	s2k_size = (packet->s2k_usage != 0) ? pgp_s2k_size(&packet->s2k) : 0;

	required_size = 1 + 4 + 1 + 1 + packet->public_key_data_octets;
	required_size += (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3) ? 2 : 0;
	required_size += (packet->encrypted_octets != 0 ? packet->encrypted_octets : packet->private_key_data_octets);

	// Checksum
	if (packet->s2k_usage == 0)
	{
		if (packet->version != PGP_KEY_V6)
		{
			required_size += 2;
		}
	}

	// Key octets
	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		required_size += 4;

		if (packet->version == PGP_KEY_V5)
		{
			required_size += 4;
		}
	}

	required_size += packet->header.header_size;

	switch (packet->s2k_usage)
	{
	case 0: // Plaintext
		conditional_field_size = 0;
		break;
	case 253: // AEAD
		// A 1-octet symmetric key algorithm.
		// A 1-octet AEAD algorithm.
		// (For V6) A 1-octet count of S2K specifier
		// A S2K specifier
		// IV
		conditional_field_size = 1 + 1 + packet->iv_size + s2k_size;
		conditional_field_size += (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5) ? 1 : 0;
		break;
	case 254: // CFB
	case 255: // Malleable CFB
		// A 1-octet symmetric key algorithm.
		// (For V6) A 1-octet count of S2K specifier
		// A S2K specifier
		// IV
		s2k_size = pgp_s2k_size(&packet->s2k);
		conditional_field_size = 1 + packet->iv_size + s2k_size;
		conditional_field_size += (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5) ? 1 : 0;
	default:
		return 0;
	}

	required_size += conditional_field_size;

	if (size < required_size)
	{
		return 0;
	}

	// Header
	pos += pgp_packet_header_write(&packet->header, out + pos);

	// 1 octet version
	LOAD_8(out + pos, &packet->version);
	pos += 1;

	// 4-octet number denoting the time that the key was created
	uint32_t key_creation_time = BSWAP_32(packet->key_creation_time);

	LOAD_32(out + pos, &key_creation_time);
	pos += 4;

	if (packet->version == PGP_KEY_V2 || packet->version == PGP_KEY_V3)
	{
		// 2-octet number denoting expiry in days.
		uint16_t key_expiry_days = BSWAP_16(packet->key_expiry_days);

		LOAD_16(out + pos, &key_expiry_days);
		pos += 2;
	}

	// 1-octet public key algorithm.
	LOAD_8(out + pos, &packet->public_key_algorithm_id);
	pos += 1;

	if (packet->version == PGP_KEY_V6)
	{
		// 4-octet scalar count for the public key material
		uint32_t public_key_data_octets_be = BSWAP_32(packet->public_key_data_octets);

		LOAD_32(out + pos, &public_key_data_octets_be);
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
			LOAD_32(out + pos, &packet->encrypted_octets);
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

pgp_key_packet *pgp_key_packet_new(byte_t version, byte_t subkey, uint32_t key_creation_time, uint16_t key_expiry_days,
								   byte_t public_key_algorithm_id, void *key)
{
	pgp_key_packet *packet = NULL;
	pgp_packet_type packet_type = (subkey == 0) ? PGP_SECKEY : PGP_SECSUBKEY;
	uint32_t body_size = 1 + 1 + 4; // Public

	if (version == PGP_KEY_V6 || version == PGP_KEY_V5)
	{
		body_size += 4;
	}

	// Don't generate V3 keys
	if (version < PGP_KEY_V4 || version > PGP_KEY_V6)
	{
		return NULL;
	}

	if (pgp_public_cipher_algorithm_validate(public_key_algorithm_id) == 0)
	{
		return NULL;
	}

	packet = malloc(sizeof(pgp_key_packet));

	if (packet == NULL)
	{
		return NULL;
	}

	memset(packet, 0, sizeof(pgp_key_packet));

	packet->version = version;
	packet->key_creation_time = key_creation_time;
	packet->key_expiry_days = key_expiry_days;

	packet->key = key;
	packet->public_key_data_octets = get_public_key_material_octets(public_key_algorithm_id, key);
	packet->private_key_data_octets = get_private_key_material_octets(public_key_algorithm_id, key);

	packet->key_checksum = pgp_private_key_material_checksum(packet);

	// Assume unencrypted key, header will be updated on call to encrypt/decrypt
	body_size += 1; // s2k_usage

	if (version == PGP_KEY_V6)
	{
		body_size += 1;
	}

	if (version == PGP_KEY_V5)
	{
		body_size += 3;
	}

	body_size += packet->public_key_data_octets + packet->private_key_data_octets;
	packet->header = pgp_encode_packet_header(PGP_HEADER, packet_type, body_size);

	return packet;
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

pgp_key_packet *pgp_key_packet_encrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size, byte_t s2k_usage, pgp_s2k *s2k,
									   void *iv, byte_t iv_size, byte_t symmetric_key_algorithm_id, byte_t aead_algorithm_id)
{
	uint32_t result = 0;
	uint32_t body_size = 1 + 1 + 4; // Public
	byte_t tag = pgp_packet_get_type(packet->header.tag);

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		body_size += 4;
	}

	if (tag != PGP_SECKEY && tag != PGP_SECSUBKEY)
	{
		return NULL;
	}

	if (s2k_usage == 0)
	{
		// Nothing to encrypt
		return packet;
	}

	if (s2k_usage != 0)
	{
		if (passphrase == NULL || passphrase_size == 0)
		{
			return NULL;
		}

		if (iv == NULL || iv_size == 0)
		{
			return NULL;
		}

		if (s2k == NULL)
		{
			return NULL;
		}
	}

	if (s2k_usage >= PGP_IDEA && s2k_usage <= PGP_CAMELLIA_256) // Legacy CFB
	{
		if (pgp_symmetric_cipher_block_size(s2k_usage) != iv_size)
		{
			return NULL;
		}

		packet->symmetric_key_algorithm_id = s2k_usage;
	}
	else if (s2k_usage >= 253 && s2k_usage <= 255)
	{
		if (pgp_symmetric_cipher_algorithm_validate(symmetric_key_algorithm_id) == 0)
		{
			return NULL;
		}

		if (s2k_usage == 253) // AEAD
		{
			if (pgp_aead_algorithm_validate(aead_algorithm_id) == 0)
			{
				return NULL;
			}

			if (pgp_aead_iv_size(aead_algorithm_id) != iv_size)
			{
				return NULL;
			}

			packet->aead_algorithm_id = aead_algorithm_id;
		}
		else // CFB
		{
			if (pgp_symmetric_cipher_block_size(symmetric_key_algorithm_id) != iv_size)
			{
				return NULL;
			}
		}

		packet->symmetric_key_algorithm_id = symmetric_key_algorithm_id;

		// Copy the IV
		packet->iv_size = iv_size;
		memcpy(packet->iv, iv, iv_size);
	}
	else
	{
		return NULL;
	}

	// Copy the s2k
	packet->s2k_usage = s2k_usage;
	packet->s2k = *s2k;

	// Will update encrypted octets
	result = pgp_secret_key_material_encrypt(packet, passphrase, passphrase_size);

	if (result == 0)
	{
		return NULL;
	}

	body_size += 2; // s2k_usage, cipher algo
	body_size += pgp_s2k_size(&packet->s2k);
	body_size += iv_size;

	if (s2k_usage == 253)
	{
		body_size += 1;
	}

	if (packet->version == PGP_KEY_V6 || packet->version == PGP_KEY_V5)
	{
		body_size += 2; // Count octets
	}

	body_size += packet->public_key_data_octets + packet->encrypted_octets;
	packet->header = pgp_encode_packet_header(PGP_HEADER, tag, body_size);

	return packet;
}

pgp_key_packet *pgp_key_packet_decrypt(pgp_key_packet *packet, void *passphrase, size_t passphrase_size)
{
	uint32_t result = 0;
	uint32_t body_size = 0;
	byte_t tag = pgp_packet_get_type(packet->header.tag);

	if (tag != PGP_SECKEY && tag != PGP_SECSUBKEY)
	{
		return NULL;
	}

	if (packet->s2k_usage == 0)
	{
		// Nothing to decrypt
		return packet;
	}

	if (packet->s2k_usage != 0)
	{
		if (passphrase == NULL || passphrase_size == 0)
		{
			return NULL;
		}
	}

	// Validations
	// TODO: Move this to a separate validation function
	if (packet->s2k_usage >= PGP_IDEA && packet->s2k_usage <= PGP_CAMELLIA_256) // Legacy CFB
	{
		if (pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id) != packet->iv_size)
		{
			return NULL;
		}
	}
	else if (packet->s2k_usage >= 253 && packet->s2k_usage <= 255)
	{
		if (pgp_symmetric_cipher_algorithm_validate(packet->symmetric_key_algorithm_id) == 0)
		{
			return NULL;
		}

		if (packet->s2k_usage == 253) // AEAD
		{
			if (pgp_aead_algorithm_validate(packet->aead_algorithm_id) == 0)
			{
				return NULL;
			}

			if (pgp_aead_iv_size(packet->aead_algorithm_id) != packet->iv_size)
			{
				return NULL;
			}
		}
		else // CFB
		{
			if (pgp_symmetric_cipher_block_size(packet->symmetric_key_algorithm_id) != packet->iv_size)
			{
				return NULL;
			}
		}
	}
	else
	{
		return NULL;
	}

	// Checksum will be updated
	// Private octet count will be updated
	result = pgp_secret_key_material_decrypt(packet, passphrase, passphrase_size);

	if (result == 0)
	{
		return NULL;
	}

	// Free the encrypted portion
	free(packet->encrypted);
	packet->encrypted_octets = 0;

	packet->s2k_usage = 0;

	// Update the header
	body_size = 1 + 1 + 4 + 4;

	if (packet->version == PGP_KEY_V6)
	{
		body_size += 2;
	}

	if (packet->version == PGP_KEY_V5)
	{
		body_size += 4;
	}

	body_size += packet->public_key_data_octets + packet->private_key_data_octets;
	packet->header = pgp_encode_packet_header(PGP_HEADER, tag, body_size);

	return packet;
}

static hash_ctx *pgp_hash_key_material(hash_ctx *hctx, pgp_public_key_algorithms algorithm, void *key)
{
	switch (algorithm)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_ENCRYPT_ONLY:
	case PGP_RSA_SIGN_ONLY:
	{
		pgp_rsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// n
		bits_be = BSWAP_16(pkey->n->bits);
		bytes = CEIL_DIV(pkey->n->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->n->bytes, bytes);

		// e
		bits_be = BSWAP_16(pkey->e->bits);
		bytes = CEIL_DIV(pkey->e->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->e->bytes, bytes);
	}
	break;
	case PGP_ELGAMAL_ENCRYPT_ONLY:
	{
		pgp_elgamal_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->p->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->y->bytes, bytes);
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// p
		bits_be = BSWAP_16(pkey->p->bits);
		bytes = CEIL_DIV(pkey->p->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->p->bytes, bytes);

		// q
		bits_be = BSWAP_16(pkey->q->bits);
		bytes = CEIL_DIV(pkey->q->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->q->bytes, bytes);

		// g
		bits_be = BSWAP_16(pkey->g->bits);
		bytes = CEIL_DIV(pkey->g->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->g->bytes, bytes);

		// y
		bits_be = BSWAP_16(pkey->y->bits);
		bytes = CEIL_DIV(pkey->y->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->y->bytes, bytes);
	}
	break;
	case PGP_ECDH:
	{
		pgp_ecdh_key *pkey = key;

		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// OID
		hash_update(hctx, &pkey->oid_size, 1);
		hash_update(hctx, pkey->oid, pkey->oid_size);

		// EC point
		bits_be = BSWAP_16(pkey->point->bits);
		bytes = CEIL_DIV(pkey->point->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->point->bytes, bytes);

		// KDF
		hash_update(hctx, &pkey->kdf.size, 1);
		hash_update(hctx, &pkey->kdf.extensions, 1);
		hash_update(hctx, &pkey->kdf.hash_algorithm_id, 1);
		hash_update(hctx, &pkey->kdf.symmetric_key_algorithm_id, 1);
	}
	break;
	case PGP_ECDSA:
	case PGP_EDDSA:
	{
		pgp_ecdsa_key *pkey = key;
		uint16_t bits_be = 0;
		uint32_t bytes = 0;

		// OID
		hash_update(hctx, &pkey->oid_size, 1);
		hash_update(hctx, pkey->oid, pkey->oid_size);

		// EC point
		bits_be = BSWAP_16(pkey->point->bits);
		bytes = CEIL_DIV(pkey->point->bits, 8);
		hash_update(hctx, &bits_be, 2);
		hash_update(hctx, pkey->point->bytes, bytes);
	}
	break;
	case PGP_X25519:
	{
		pgp_x25519_key *pkey = key;
		hash_update(hctx, pkey->public_key, 32);
	}
	break;
	case PGP_X448:
	{
		pgp_x448_key *pkey = key;
		hash_update(hctx, pkey->public_key, 56);
	}
	break;
	case PGP_ED25519:
	{

		pgp_ed25519_key *pkey = key;
		hash_update(hctx, pkey->public_key, 32);
	}
	break;
	case PGP_ED448:
	{
		pgp_ed448_key *pkey = key;
		hash_update(hctx, pkey->public_key, 57);
	}
	break;
	default:
		return NULL;
	}

	return hctx;
}

static uint32_t pgp_key_fingerprint_v3(void *key, byte_t fingerprint_v3[PGP_KEY_V3_FINGERPRINT_SIZE])
{
	// MD5 of mpi without length octets
	hash_ctx *hctx = NULL;
	byte_t buffer[512] = {0};

	hash_init(buffer, 512, HASH_MD5);

	// V3 keys only support RSA
	pgp_rsa_key *pkey = key;
	uint32_t bytes = 0;

	// n
	bytes = CEIL_DIV(pkey->n->bits, 8);
	hash_update(hctx, pkey->n->bytes, bytes);

	// e
	bytes = CEIL_DIV(pkey->e->bits, 8);
	hash_update(hctx, pkey->e->bytes, bytes);

	hash_final(hctx, fingerprint_v3, PGP_KEY_V3_FINGERPRINT_SIZE);

	return PGP_KEY_V3_FINGERPRINT_SIZE;
}

static uint32_t pgp_key_fingerprint_v4(pgp_public_key_algorithms algorithm, uint32_t creation_time, uint16_t octet_count, void *key,
									   byte_t fingerprint_v4[PGP_KEY_V4_FINGERPRINT_SIZE])
{
	hash_ctx *hctx = NULL;
	byte_t buffer[512] = {0};

	byte_t constant = 0x99;
	byte_t version = 4;
	uint16_t octet_count_be = BSWAP_16(octet_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	hash_init(buffer, 512, HASH_SHA1);

	hash_update(hctx, &constant, 1);
	hash_update(hctx, &octet_count_be, 2);
	hash_update(hctx, &version, 1);
	hash_update(hctx, &creation_time_be, 4);
	hash_update(hctx, &algorithm, 1);

	hctx = pgp_hash_key_material(hctx, algorithm, key);

	if (hctx == NULL)
	{
		return 0;
	}

	hash_final(hctx, fingerprint_v4, PGP_KEY_V4_FINGERPRINT_SIZE);

	return PGP_KEY_V4_FINGERPRINT_SIZE;
}

static uint32_t pgp_key_fingerprint_v5(pgp_public_key_algorithms algorithm, uint32_t creation_time, uint32_t octet_count,
									   uint32_t material_count, void *key, byte_t fingerprint_v5[PGP_KEY_V6_FINGERPRINT_SIZE])
{
	hash_ctx *hctx = NULL;
	byte_t buffer[512] = {0};

	byte_t constant = 0x9A;
	byte_t version = 5;
	uint32_t octet_count_be = BSWAP_32(octet_count);
	uint32_t material_count_be = BSWAP_32(material_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	hash_init(buffer, 512, HASH_SHA256);

	hash_update(hctx, &constant, 1);
	hash_update(hctx, &octet_count_be, 4);
	hash_update(hctx, &version, 1);
	hash_update(hctx, &creation_time_be, 4);
	hash_update(hctx, &algorithm, 1);
	hash_update(hctx, &material_count_be, 4);

	hctx = pgp_hash_key_material(hctx, algorithm, key);

	if (hctx == NULL)
	{
		return 0;
	}

	hash_final(hctx, fingerprint_v5, PGP_KEY_V5_FINGERPRINT_SIZE);

	return PGP_KEY_V5_FINGERPRINT_SIZE;
}

static uint32_t pgp_key_fingerprint_v6(pgp_public_key_algorithms algorithm, uint32_t creation_time, uint32_t octet_count,
									   uint32_t material_count, void *key, byte_t fingerprint_v6[PGP_KEY_V6_FINGERPRINT_SIZE])
{
	hash_ctx *hctx = NULL;
	byte_t buffer[512] = {0};

	byte_t constant = 0x9B;
	byte_t version = 6;
	uint32_t octet_count_be = BSWAP_32(octet_count);
	uint32_t material_count_be = BSWAP_32(material_count);
	uint32_t creation_time_be = BSWAP_32(creation_time);

	hash_init(buffer, 512, HASH_SHA256);

	hash_update(hctx, &constant, 1);
	hash_update(hctx, &octet_count_be, 4);
	hash_update(hctx, &version, 1);
	hash_update(hctx, &creation_time_be, 4);
	hash_update(hctx, &algorithm, 1);
	hash_update(hctx, &material_count_be, 4);

	hctx = pgp_hash_key_material(hctx, algorithm, key);

	if (hctx == NULL)
	{
		return 0;
	}

	hash_final(hctx, fingerprint_v6, PGP_KEY_V6_FINGERPRINT_SIZE);

	return PGP_KEY_V6_FINGERPRINT_SIZE;
}

uint32_t pgp_key_fingerprint(void *key, void *fingerprint, uint32_t size)
{
	pgp_packet_header *header = key;
	byte_t tag = pgp_packet_get_type(header->tag);

	if (tag == PGP_PUBKEY || tag == PGP_PUBSUBKEY || tag == PGP_SECKEY || tag == PGP_SECSUBKEY)
	{
		pgp_key_packet *packet = key;

		switch (packet->version)
		{
		case PGP_KEY_V2:
		case PGP_KEY_V3:
		{
			if (size < PGP_KEY_V3_FINGERPRINT_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v3(packet->key, fingerprint);
		}
		case PGP_KEY_V4:
		{
			if (size < PGP_KEY_V4_FINGERPRINT_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v4(packet->public_key_algorithm_id, packet->key_creation_time,
										  (uint16_t)packet->public_key_data_octets + 6, packet->key, fingerprint);
		}
		case PGP_KEY_V5:
		{
			if (size < PGP_KEY_V5_FINGERPRINT_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v5(packet->public_key_algorithm_id, packet->key_creation_time, packet->public_key_data_octets + 9,
										  packet->public_key_data_octets, packet->key, fingerprint);
		}
		case PGP_KEY_V6:
		{
			if (size < PGP_KEY_V6_FINGERPRINT_SIZE)
			{
				return 0;
			}

			return pgp_key_fingerprint_v6(packet->public_key_algorithm_id, packet->key_creation_time, packet->public_key_data_octets + 9,
										  packet->public_key_data_octets, packet->key, fingerprint);
		}
		default:
			return 0;
		}
	}
	else
	{
		return 0;
	}

	return 0;
}

uint32_t pgp_key_id(void *key, byte_t id[8])
{
	pgp_packet_header *header = key;
	byte_t tag = pgp_packet_get_type(header->tag);

	uint32_t result = 0;
	byte_t fingerprint[32] = {0};

	// For V3 RSA
	if (tag == PGP_PUBKEY || tag == PGP_PUBSUBKEY || tag == PGP_SECKEY || tag == PGP_SECSUBKEY)
	{
		pgp_key_packet *packet = key;

		if (packet->version == PGP_KEY_V3)
		{
			// Low 64 bits of public modulus
			pgp_rsa_key *rsa_key = packet->key;
			uint16_t bytes = CEIL_DIV(rsa_key->n->bits, 8);

			LOAD_64(id, &rsa_key->n->bytes[bytes - 8]);
		}
	}
	else
	{
		return 0;
	}

	// Last 64 bits of the fingerprint
	result = pgp_key_fingerprint(key, fingerprint, 32);

	if (result == 0)
	{
		return 0;
	}

	LOAD_64(id, PTR_OFFSET(fingerprint, result - 8));

	return 8;
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
