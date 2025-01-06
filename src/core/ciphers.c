/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <ciphers.h>

static cipher_algorithm pgp_algorithm_to_cipher_algorithm(pgp_symmetric_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_PLAINTEXT:
	case PGP_IDEA:
	case PGP_CAST5_128:
	case PGP_BLOWFISH:
		return 0; // Unimplemented
	case PGP_TDES:
		return CIPHER_TDES;
	case PGP_AES_128:
		return CIPHER_AES128;
	case PGP_AES_192:
		return CIPHER_AES192;
	case PGP_AES_256:
		return CIPHER_AES256;
	case PGP_TWOFISH:
		return CIPHER_TWOFISH256;
	case PGP_CAMELLIA_128:
		return CIPHER_CAMELLIA128;
	case PGP_CAMELLIA_192:
		return CIPHER_CAMELLIA192;
	case PGP_CAMELLIA_256:
		return CIPHER_CAMELLIA256;
	default:
		return 0;
	}
}

byte_t pgp_symmetric_cipher_valid(pgp_symmetric_key_algorithms algorithm)
{
	switch (algorithm)
	{
	case PGP_PLAINTEXT:
	case PGP_IDEA:
	case PGP_TDES:
	case PGP_CAST5_128:
	case PGP_BLOWFISH:
	case PGP_AES_128:
	case PGP_AES_192:
	case PGP_AES_256:
	case PGP_TWOFISH:
	case PGP_CAMELLIA_128:
	case PGP_CAMELLIA_192:
	case PGP_CAMELLIA_256:
		return 1;
	}

	return 0;
}

byte_t pgp_symmetric_cipher_key_size(pgp_symmetric_key_algorithms algorithm)
{
	return (byte_t)cipher_key_size(pgp_algorithm_to_cipher_algorithm(algorithm));
}

byte_t pgp_symmetric_cipher_iv_size(pgp_symmetric_key_algorithms algorithm)
{
	return (byte_t)cipher_iv_size(pgp_algorithm_to_cipher_algorithm(algorithm));
}