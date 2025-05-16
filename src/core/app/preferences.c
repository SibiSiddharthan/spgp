/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <crypto.h>

pgp_hash_algorithms preferred_hash_algorithm_for_signature(pgp_key_packet *packet)
{
	switch (packet->public_key_algorithm_id)
	{
	case PGP_RSA_ENCRYPT_OR_SIGN:
	case PGP_RSA_SIGN_ONLY:
	{
		return PGP_SHA2_256;
	}
	break;
	case PGP_DSA:
	{
		pgp_dsa_key *key = packet->key;

		if (ROUND_UP(key->p->bits, 1024) == 1024)
		{
			return PGP_SHA1;
		}

		if (ROUND_UP(key->p->bits, 1024) == 2048)
		{
			return PGP_SHA2_224;
		}

		if (ROUND_UP(key->p->bits, 1024) == 3072)
		{
			return PGP_SHA2_256;
		}
	}
	break;
	case PGP_ECDSA:
	{
		pgp_ecdsa_key *key = packet->key;

		switch (key->curve)
		{
		case PGP_EC_NIST_P256:
			return PGP_SHA2_256;
		case PGP_EC_NIST_P384:
			return PGP_SHA2_384;
		case PGP_EC_NIST_P521:
			return PGP_SHA2_512;
		case PGP_EC_BRAINPOOL_256R1:
			return PGP_SHA2_256;
		case PGP_EC_BRAINPOOL_384R1:
			return PGP_SHA2_384;
		case PGP_EC_BRAINPOOL_512R1:
			return PGP_SHA2_512;
		}
	}
	break;
	case PGP_EDDSA:
	{
		pgp_eddsa_key *key = packet->key;

		if (key->curve == PGP_EC_ED25519)
		{
			return PGP_SHA2_256;
		}

		if (key->curve == PGP_EC_ED25519)
		{
			return PGP_SHA2_512;
		}
	}
	break;
	case PGP_ED25519:
	{
		return PGP_SHA2_256;
	}
	break;
	case PGP_ED448:
	{
		return PGP_SHA2_512;
	}
	break;
	default:
		return PGP_SHA2_512;
	}

	return PGP_SHA2_256;
}

pgp_compression_algorithms preferred_compression_algorithm(pgp_user_info **users, uint32_t count)
{
	pgp_compression_algorithms algorithm = PGP_UNCOMPRESSED;
	byte_t preferences[4] = {0};

	for (uint32_t i = 0; i < count; ++i)
	{
		for (byte_t j = 0; j < users[i]->compression_algorithm_preferences_octets; ++j)
		{
			preferences[users[i]->compression_algorithm_preferences[j]] += 1;
		}
	}

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (preferences[i] == count)
		{
			algorithm = preferences[i];
			break;
		}
	}

	return algorithm;
}

pgp_symmetric_key_algorithms preferred_cipher_algorithm(pgp_user_info **users, uint32_t count)
{
	pgp_symmetric_key_algorithms algorithm = 0;
	byte_t preferences[16] = {0};

	for (uint32_t i = 0; i < count; ++i)
	{
		for (byte_t j = 0; j < users[i]->cipher_algorithm_preferences_octets; ++j)
		{
			preferences[users[i]->cipher_algorithm_preferences[j]] += 1;
		}
	}

	for (uint32_t i = 0; i < 16; ++i)
	{
		if (preferences[i] == count)
		{
			if (algorithm == 0)
			{
				algorithm = preferences[i];
			}
			else
			{
				// Choose the stronger encryption algorithm
				if (pgp_symmetric_cipher_key_size(preferences[i]) > pgp_symmetric_cipher_key_size(algorithm))
				{
					algorithm = preferences[i];
				}
			}
		}
	}

	if (algorithm == 0)
	{
		// Default Algorithm
		algorithm = PGP_AES_128;
	}

	return algorithm;
}
