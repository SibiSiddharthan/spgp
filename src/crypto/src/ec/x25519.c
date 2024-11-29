/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>

#define X25519_SCALAR_SIZE 32

void x25519_decode_scalar(byte_t k[32])
{
	// Set the 3 least significant bits of first byte to 0
	k[0] &= 248;

	// Set the most significant bit of the last byte to 0
	k[31] &= 127;

	// Set the second most significant bit of the last byte to 1
	k[31] |= 64;
}
