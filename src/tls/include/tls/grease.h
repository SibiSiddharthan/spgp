/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_GREASE_H
#define TLS_GREASE_H

#include <tls/types.h>

// RFC 8701: Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility
#define TLS_MAKE_GREASE_CIPHER_ID(A) ((((uint16_t)(A)) << 8) + ((uint16_t)(A)))

static const uint16_t tls_grease_ciphers[16] = {
	TLS_MAKE_GREASE_CIPHER_ID(0x0A), TLS_MAKE_GREASE_CIPHER_ID(0x1A), TLS_MAKE_GREASE_CIPHER_ID(0x2A), TLS_MAKE_GREASE_CIPHER_ID(0x3A),
	TLS_MAKE_GREASE_CIPHER_ID(0x4A), TLS_MAKE_GREASE_CIPHER_ID(0x5A), TLS_MAKE_GREASE_CIPHER_ID(0x6A), TLS_MAKE_GREASE_CIPHER_ID(0x7A),
	TLS_MAKE_GREASE_CIPHER_ID(0x8A), TLS_MAKE_GREASE_CIPHER_ID(0x9A), TLS_MAKE_GREASE_CIPHER_ID(0xAA), TLS_MAKE_GREASE_CIPHER_ID(0xBA),
	TLS_MAKE_GREASE_CIPHER_ID(0xCA), TLS_MAKE_GREASE_CIPHER_ID(0xDA), TLS_MAKE_GREASE_CIPHER_ID(0xEA), TLS_MAKE_GREASE_CIPHER_ID(0xFA),
};

static const uint16_t tls_grease_signatures[16] = {
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
};

static inline uint16_t tls_check_grease_value(uint16_t value)
{
	uint8_t o1 = 0, o2 = 0;

	o1 = (value >> 8) & 0xFF;
	o2 = (value >> 0) & 0xFF;

	if (o1 == o2)
	{
		if ((o1 & 0x0F) == 0x0A)
		{
			return 1;
		}
	}

	return 0;
}

#endif
