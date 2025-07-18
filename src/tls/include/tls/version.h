/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef TLS_VERSION_H
#define TLS_VERSION_H

#define TLS_VERSION_1_0 0x0301 // TLS 1.0
#define TLS_VERSION_1_1 0x0302 // TLS 1.1
#define TLS_VERSION_1_2 0x0303 // TLS 1.2
#define TLS_VERSION_1_3 0x0304 // TLS 1.3

#define TLS_VERSION_DEFAULT TLS_VERSION_1_2

typedef struct _tls_protocol_version
{
	uint8_t major;
	uint8_t minor;
} tls_protocol_version;

#define TLS_VERSION_RAW(V) ((((uint16_t)((V).major)) << 8) + ((uint16_t)((V).minor)))

#endif
