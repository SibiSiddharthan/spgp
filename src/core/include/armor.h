/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ARMOR_H
#define SPGP_ARMOR_H

#include <pgp.h>

#define PGP_ARMOR_NO_CRC 0x1

typedef enum _pgp_armor_type
{
	PGP_ARMOR_MESSAGE = 1,
	PGP_ARMOR_PUBLIC_KEY,
	PGP_ARMOR_PRIVATE_KEY,
	PGP_ARMOR_SIGNATURE,
	PGP_ARMOR_CLEARTEXT
} pgp_armor_type;

typedef enum _pgp_armor_header
{
	PGP_ARMOR_VERSION = 1,
	PGP_ARMOR_COMMENT,
	PGP_ARMOR_HASH,
	PGP_ARMOR_CHARSET,
	PGP_ARMOR_MESSAGE_ID,
} pgp_armor_header;

typedef enum _armor_status
{
	ARMOR_SUCCESS = 0,
	ARMOR_INVALID_HEADER = -1,
	ARMOR_INVALID_TYPE_FOR_CLEARTEXT = -2,
	ARMOR_INCOMPATIBLE_TYPE_AND_HEADER = -3,
	ARMOR_INSUFFICIENT_OUTPUT_BUFFER = -4,
	ARMOR_INSUFFICIENT_SYSTEM_MEMORY = -5,
	ARMOR_MALFORMED_DATA = -6,
	ARMOR_BAD_CRC = -7,
	ARMOR_HEADER_MISMATCH = -8,
	ARMOR_BASE64_LINE_TOO_BIG = -9,
} armor_status;

typedef struct _pgp_armor_ctx
{
	// Type
	pgp_armor_type type;
	uint32_t flags;

	// Headers
	buffer_t version;
	buffer_t hash;
	buffer_t charset;
	buffer_t comment;
	buffer_t message_id;

	buffer_t cleartext;
	buffer_t data;

	// CRC-24
	uint32_t crc;

} pgp_armor_ctx;

pgp_armor_ctx *pgp_armor_new(pgp_armor_type type, uint32_t flags);
void pgp_armor_delete(pgp_armor_ctx *ctx);

armor_status armor_set_header(pgp_armor_ctx *ctx, pgp_armor_header header, void *data, size_t size);
armor_status armor_set_cleartext(pgp_armor_ctx *ctx, void *data, size_t size);
armor_status armor_set_data(pgp_armor_ctx *ctx, void *data, size_t size);

armor_status pgp_armor_read(pgp_armor_ctx *ctx, void *ptr, size_t size, size_t *result);
armor_status pgp_armor_write(pgp_armor_ctx *ctx, void *ptr, size_t size, size_t *result);

#endif
