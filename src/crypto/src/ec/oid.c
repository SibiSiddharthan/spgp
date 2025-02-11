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

uint32_t ec_curve_encode_oid(curve_id id, void *buffer, uint32_t size)
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

curve_id ec_curve_decode_oid(void *oid, uint32_t size)
{
	byte_t *in = oid;

	// Check if we have enough size for the prefix
	if (size < 2)
	{
		// Invalid OID.
		return 0;
	}

	// Standard curves
	if (in[0] == 0x2B)
	{
		// NIST and SEC
		if (in[1] == 0x81)
		{
			if (size != 5)
			{
				return 0;
			}

			if (in[2] != 0x04 && in[3] != 0x00)
			{
				return 0;
			}

			switch (in[4])
			{
			case 0x01:
				return EC_NIST_K163;
			case 0x02:
				return EC_SECT_163R1;
			case 0x03:
				return EC_SECT_239K1;
			case 0x08:
				return EC_SECP_160R1;
			case 0x09:
				return EC_SECP_160K1;
			case 0x0A:
				return EC_SECP_256K1;
			case 0x0F:
				return EC_NIST_B163;
			case 0x10:
				return EC_NIST_K283;
			case 0x11:
				return EC_NIST_B283;
			case 0x18:
				return EC_SECT_193R1;
			case 0x19:
				return EC_SECT_193R2;
			case 0x1A:
				return EC_NIST_K233;
			case 0x1B:
				return EC_NIST_B233;
			case 0x1E:
				return EC_SECP_160R2;
			case 0x1F:
				return EC_SECP_192K1;
			case 0x20:
				return EC_SECP_224K1;
			case 0x21:
				return EC_NIST_P224;
			case 0x22:
				return EC_NIST_P384;
			case 0x23:
				return EC_NIST_P521;
			case 0x24:
				return EC_NIST_K409;
			case 0x25:
				return EC_NIST_B409;
			case 0x26:
				return EC_NIST_K571;
			case 0x27:
				return EC_NIST_B571;
			default:
				return 0;
			}
		}
		// Brainpool
		else if (in[1] == 0x24)
		{
			if (size != 9)
			{
				return 0;
			}

			if (in[2] != 0x03 && in[3] != 0x03 && in[4] != 0x02 && in[5] != 0x08 && in[6] != 0x01 && in[7] != 0x01)
			{
				return 0;
			}

			switch (in[8])
			{
			case 0x01:
				return EC_BRAINPOOL_160R1;
			case 0x02:
				return EC_BRAINPOOL_160T1;
			case 0x03:
				return EC_BRAINPOOL_192R1;
			case 0x04:
				return EC_BRAINPOOL_192T1;
			case 0x05:
				return EC_BRAINPOOL_224R1;
			case 0x06:
				return EC_BRAINPOOL_224T1;
			case 0x07:
				return EC_BRAINPOOL_256R1;
			case 0x08:
				return EC_BRAINPOOL_256T1;
			case 0x09:
				return EC_BRAINPOOL_320R1;
			case 0x0A:
				return EC_BRAINPOOL_320T1;
			case 0x0B:
				return EC_BRAINPOOL_384R1;
			case 0x0C:
				return EC_BRAINPOOL_384T1;
			case 0x0D:
				return EC_BRAINPOOL_512R1;
			case 0x0E:
				return EC_BRAINPOOL_512T1;
			default:
				return 0;
			}
		}
		else
		{
			// Not a standard curve
			return 0;
		}
	}
	// Outliers NIST-P192, NIST-P256
	else if (in[0] == 0x2A)
	{
		if (size != 8)
		{
			return 0;
		}

		if (in[1] != 0x86 && in[2] != 0x48 && in[3] != 0xCE && in[4] != 0x3D && in[5] != 0x03 && in[6] != 0x01)
		{
			return 0;
		}

		switch (in[7])
		{
		case 0x01:
			return EC_NIST_P192;
		case 0x07:
			return EC_NIST_P256;
		default:
			return 0;
		}
	}
	else
	{
		// Not a standard curve
		return 0;
	}

	return 0;
}
