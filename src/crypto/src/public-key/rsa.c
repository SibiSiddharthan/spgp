/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>
#include <rsa.h>

bignum_t *rsa_public_encrypt(rsa_key *key, bignum_t *plain)
{
	if (key->bits < plain->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->e == NULL)
	{
		return NULL;
	}

	return bignum_modexp(plain, key->e, key->n);
}

bignum_t *rsa_public_decrypt(rsa_key *key, bignum_t *cipher)
{
	if (key->bits < cipher->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->e == NULL)
	{
		return NULL;
	}

	return bignum_modexp(cipher, key->e, key->n);
}

bignum_t *rsa_private_encrypt(rsa_key *key, bignum_t *plain)
{
	if (key->bits < plain->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->d == NULL)
	{
		return NULL;
	}

	return bignum_modexp(plain, key->d, key->n);
}

bignum_t *rsa_private_decrypt(rsa_key *key, bignum_t *cipher)
{
	if (key->bits < cipher->bits)
	{
		return NULL;
	}

	if (key->n == NULL || key->d == NULL)
	{
		return NULL;
	}

	return bignum_modexp(cipher, key->d, key->n);
}
