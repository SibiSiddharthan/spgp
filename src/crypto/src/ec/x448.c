/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>

#define X_SCALAR_SIZE 56

void x448_decode_scalar(byte_t k[56])
{
	// Set the 2 least significant bits of first byte to 0
	k[0] &= 252;

	// Set the most significant bit of the last byte to 1
	k[55] |= 128;
}
