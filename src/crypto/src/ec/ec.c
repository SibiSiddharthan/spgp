/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum-internal.h>
#include <bignum.h>
#include <ec.h>

#include <round.h>

size_t ec_group_size(uint32_t bits);

uint32_t ec_group_bits(curve_id id)
{
	switch (id)
	{
	case EC_CUSTOM:
		return 0;

	// NIST
	// Prime curves
	case EC_NIST_P192:
		return 192;
	case EC_NIST_P224:
		return 224;
	case EC_NIST_P256:
		return 256;
	case EC_NIST_P384:
		return 384;
	case EC_NIST_P521:
		return 521;

	// SECG
	case EC_SECP_160K1:
		return 160;
	case EC_SECP_160R1:
		return 160;
	case EC_SECP_160R2:
		return 160;
	case EC_SECP_192K1:
		return 192;
	case EC_SECP_224K1:
		return 224;
	case EC_SECP_256K1:
		return 256;

	// Brainpool
	case EC_BRAINPOOL_160R1:
		return 160;
	case EC_BRAINPOOL_160T1:
		return 160;
	case EC_BRAINPOOL_192R1:
		return 192;
	case EC_BRAINPOOL_192T1:
		return 192;
	case EC_BRAINPOOL_224R1:
		return 224;
	case EC_BRAINPOOL_224T1:
		return 224;
	case EC_BRAINPOOL_256R1:
		return 256;
	case EC_BRAINPOOL_256T1:
		return 256;
	case EC_BRAINPOOL_320R1:
		return 320;
	case EC_BRAINPOOL_320T1:
		return 320;
	case EC_BRAINPOOL_384R1:
		return 384;
	case EC_BRAINPOOL_384T1:
		return 384;
	case EC_BRAINPOOL_512R1:
		return 512;
	case EC_BRAINPOOL_512T1:
		return 512;

	// Special
	case EC_X25519:
		return 255;
	case EC_X448:
		return 448;

	// Twisted Edwards
	case EC_ED25519:
		return 255;
	case EC_ED448:
		return 448;

	default:
		return 0;
	}
}
