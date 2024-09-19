/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_CIPHER_ALGORITHM_H
#define CRYPTO_CIPHER_ALGORITHM_H

typedef enum _cipher_algorithm
{
	// AES
	CIPHER_AES128,
	CIPHER_AES192,
	CIPHER_AES256,
	// ARIA
	CIPHER_ARIA128,
	CIPHER_ARIA192,
	CIPHER_ARIA256,
	// CAMELLIA
	CIPHER_CAMELLIA128,
	CIPHER_CAMELLIA192,
	CIPHER_CAMELLIA256,
	// CHACHA
	CIPHER_CHACHA20,
	// TDES
	CIPHER_TDES,
	// TWOFISH
	CIPHER_TWOFISH128,
	CIPHER_TWOFISH192,
	CIPHER_TWOFISH256,
} cipher_algorithm;

#endif
