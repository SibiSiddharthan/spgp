/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ARMOR_H
#define SPGP_ARMOR_H

#include <spgp.h>

#define PGP_ARMOR_NO_CRC 0x1

typedef enum _pgp_armor_type
{
	PGP_ARMOR_MESSAGE = 0,
	PGP_ARMOR_PUBLIC_KEY = 1,
	PGP_ARMOR_PRIVATE_KEY = 2,
	PGP_ARMOR_SIGNATURE = 3,
	PGP_ARMOR_CLEARTEXT = 4
} pgp_armor_type;

typedef enum _pgp_armor_header
{
	PGP_ARMOR_VERSION = 0,
	PGP_ARMOR_COMMENT = 1,
	PGP_ARMOR_HASH = 2,
	PGP_ARMOR_CHARSET = 3
} pgp_armor_header;

typedef enum _armor_status
{
	ARMOR_SUCCESS = 0,
	ARMOR_INVALID_HEADER = -1,
	ARMOR_INVALID_TYPE_FOR_CLEARTEXT = -2,
	ARMOR_INCOMPATIBLE_TYPE_AND_HEADER = -3,
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

	buffer_t cleartext;
	buffer_t data;

	// CRC-24
	uint32_t crc;

} pgp_armor_ctx;

pgp_armor_ctx *pgp_armor_init(void *ptr, size_t size, pgp_armor_type type, uint32_t flags);
pgp_armor_ctx *pgp_armor_new(pgp_armor_type type, uint32_t flags);
void pgp_armor_delete(pgp_armor_ctx *ctx);

armor_status armor_set_header(pgp_armor_ctx *ctx, pgp_armor_header header, void *data, size_t size);
armor_status armor_set_cleartext(pgp_armor_ctx *ctx, void *data, size_t size);
armor_status armor_set_data(pgp_armor_ctx *ctx, void *data, size_t size);
int32_t armor_write(pgp_armor_ctx *ctx, void *ptr, size_t size);

#endif
