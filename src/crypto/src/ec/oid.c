/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <ec.h>
#include <string.h>

uint32_t ec_curve_oid_size(curve_id id)
{
	switch (id)
	{
	case EC_CUSTOM:
		return 0;

	// NIST
	// Prime curves
	case EC_NIST_P192:
	case EC_NIST_P256:
		return 8;
	case EC_NIST_P224:
	case EC_NIST_P384:
	case EC_NIST_P521:
		return 5;

	// Binary curves
	case EC_NIST_K163:
	case EC_NIST_B163:
	case EC_NIST_K233:
	case EC_NIST_B233:
	case EC_NIST_K283:
	case EC_NIST_B283:
	case EC_NIST_K409:
	case EC_NIST_B409:
	case EC_NIST_K571:
	case EC_NIST_B571:
		return 5;

	// SEC
	// Prime curves
	case EC_SECP_192R1:
	case EC_SECP_256R1:
		return 8;
	case EC_SECP_160K1:
	case EC_SECP_160R1:
	case EC_SECP_160R2:
	case EC_SECP_192K1:
	case EC_SECP_224K1:
	case EC_SECP_224R1:
	case EC_SECP_256K1:
	case EC_SECP_384R1:
	case EC_SECP_521R1:
		return 5;

	// Binary curves
	case EC_SECT_163K1:
	case EC_SECT_163R1:
	case EC_SECT_163R2:
	case EC_SECT_193R1:
	case EC_SECT_193R2:
	case EC_SECT_233K1:
	case EC_SECT_233R1:
	case EC_SECT_239K1:
	case EC_SECT_283K1:
	case EC_SECT_283R1:
	case EC_SECT_409K1:
	case EC_SECT_409R1:
	case EC_SECT_571K1:
	case EC_SECT_571R1:
		return 5;

	// Brainpool
	case EC_BRAINPOOL_160R1:
	case EC_BRAINPOOL_160T1:
	case EC_BRAINPOOL_192R1:
	case EC_BRAINPOOL_192T1:
	case EC_BRAINPOOL_224R1:
	case EC_BRAINPOOL_224T1:
	case EC_BRAINPOOL_256R1:
	case EC_BRAINPOOL_256T1:
	case EC_BRAINPOOL_320R1:
	case EC_BRAINPOOL_320T1:
	case EC_BRAINPOOL_384R1:
	case EC_BRAINPOOL_384T1:
	case EC_BRAINPOOL_512R1:
	case EC_BRAINPOOL_512T1:
		return 9;

	default:
		return 0;
	}
}

uint32_t ec_curve_oid(curve_id id, void *buffer, uint32_t size)
{
	uint32_t required_size = 0;

	required_size = ec_curve_oid_size(id);

	if (size < required_size)
	{
		return 0;
	}

	if (required_size == 0)
	{
		return 0;
	}

	switch (id)
	{
	case EC_CUSTOM:
		return 0;

	// NIST
	// Prime curves
	case EC_NIST_P192:
		memcpy(buffer, "\x2A\x86\x48\xCE\x3D\x03\x01\x01", 8);
		return 8;
	case EC_NIST_P224:
		memcpy(buffer, "\x2B\x81\x04\x00\x21", 5);
		return 5;
	case EC_NIST_P256:
		memcpy(buffer, "\x2A\x86\x48\xCE\x3D\x03\x01\x07", 8);
		return 8;
	case EC_NIST_P384:
		memcpy(buffer, "\x2B\x81\x04\x00\x22", 5);
		return 5;
	case EC_NIST_P521:
		memcpy(buffer, "\x2B\x81\x04\x00\x23", 5);
		return 5;

	// Binary curves
	case EC_NIST_K163:
		memcpy(buffer, "\x2B\x81\x04\x00\x01", 5);
		return 5;
	case EC_NIST_B163:
		memcpy(buffer, "\x2B\x81\x04\x00\x0F", 5);
		return 5;
	case EC_NIST_K233:
		memcpy(buffer, "\x2B\x81\x04\x00\x1A", 5);
		return 5;
	case EC_NIST_B233:
		memcpy(buffer, "\x2B\x81\x04\x00\x1B", 5);
		return 5;
	case EC_NIST_K283:
		memcpy(buffer, "\x2B\x81\x04\x00\x10", 5);
		return 5;
	case EC_NIST_B283:
		memcpy(buffer, "\x2B\x81\x04\x00\x11", 5);
		return 5;
	case EC_NIST_K409:
		memcpy(buffer, "\x2B\x81\x04\x00\x24", 5);
		return 5;
	case EC_NIST_B409:
		memcpy(buffer, "\x2B\x81\x04\x00\x25", 5);
		return 5;
	case EC_NIST_K571:
		memcpy(buffer, "\x2B\x81\x04\x00\x26", 5);
		return 5;
	case EC_NIST_B571:
		memcpy(buffer, "\x2B\x81\x04\x00\x27", 5);
		return 5;

	// SEC
	// Prime curves
	case EC_SECP_160K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x09", 5);
		return 5;
	case EC_SECP_160R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x08", 5);
		return 5;
	case EC_SECP_160R2:
		memcpy(buffer, "\x2B\x81\x04\x00\x1E", 5);
		return 5;
	case EC_SECP_192K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x1F", 5);
		return 5;
	case EC_SECP_192R1:
		memcpy(buffer, "\x2A\x86\x48\xCE\x3D\x03\x01\x01", 8);
		return 8;
	case EC_SECP_224K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x20", 5);
		return 5;
	case EC_SECP_224R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x21", 5);
		return 5;
	case EC_SECP_256K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x0A", 5);
		return 5;
	case EC_SECP_256R1:
		memcpy(buffer, "\x2A\x86\x48\xCE\x3D\x03\x01\x07", 8);
		return 8;
	case EC_SECP_384R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x22", 5);
		return 5;
	case EC_SECP_521R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x23", 5);
		return 5;

	// Binary curves
	case EC_SECT_163K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x01", 5);
		return 5;
	case EC_SECT_163R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x02", 5);
		return 5;
	case EC_SECT_163R2:
		memcpy(buffer, "\x2B\x81\x04\x00\x0F", 5);
		return 5;
	case EC_SECT_193R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x18", 5);
		return 5;
	case EC_SECT_193R2:
		memcpy(buffer, "\x2B\x81\x04\x00\x19", 5);
		return 5;
	case EC_SECT_233K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x1A", 5);
		return 5;
	case EC_SECT_233R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x1B", 5);
		return 5;
	case EC_SECT_239K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x03", 5);
		return 5;
	case EC_SECT_283K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x10", 5);
		return 5;
	case EC_SECT_283R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x11", 5);
		return 5;
	case EC_SECT_409K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x24", 5);
		return 5;
	case EC_SECT_409R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x25", 5);
		return 5;
	case EC_SECT_571K1:
		memcpy(buffer, "\x2B\x81\x04\x00\x26", 5);
		return 5;
	case EC_SECT_571R1:
		memcpy(buffer, "\x2B\x81\x04\x00\x27", 5);
		return 5;

	// Brainpool
	case EC_BRAINPOOL_160R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x01", 9);
		return 9;
	case EC_BRAINPOOL_160T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x02", 9);
		return 9;
	case EC_BRAINPOOL_192R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x03", 9);
		return 9;
	case EC_BRAINPOOL_192T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x04", 9);
		return 9;
	case EC_BRAINPOOL_224R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x05", 9);
		return 9;
	case EC_BRAINPOOL_224T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x06", 9);
		return 9;
	case EC_BRAINPOOL_256R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x07", 9);
		return 9;
	case EC_BRAINPOOL_256T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x08", 9);
		return 9;
	case EC_BRAINPOOL_320R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x09", 9);
		return 9;
	case EC_BRAINPOOL_320T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0A", 9);
		return 9;
	case EC_BRAINPOOL_384R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0B", 9);
		return 9;
	case EC_BRAINPOOL_384T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0C", 9);
		return 9;
	case EC_BRAINPOOL_512R1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0D", 9);
		return 9;
	case EC_BRAINPOOL_512T1:
		memcpy(buffer, "\x2B\x24\x03\x03\x02\x08\x01\x01\x0E", 9);
		return 9;

	default:
		return 0;
	}
}
