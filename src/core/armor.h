/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ARMOR_H
#define SPGP_ARMOR_H

#include <spgp.h>

typedef enum _armor_type
{
	ARMOR_MESSAGE = 0,
	ARMOR_PUBLIC_KEY = 1,
	ARMOR_PRIVATE_KEY = 2,
	ARMOR_SIGNATURE = 3,
	ARMOR_MULTIPART = 4,
	ARMOR_CLEARTEXT = 5
} armor_type;

typedef enum _armor_header
{
	ARMOR_VERSION = 0,
	ARMOR_COMMENT = 1,
	ARMOR_HASH = 2,
	ARMOR_CHARSET = 3
} armor_header;

typedef enum _armor_flags
{
	ARMOR_NO_CRC = 0x1,
} armor_flags;

typedef enum _armor_status
{
	ARMOR_SUCCESS = 0,
	ARMOR_INVALID_HEADER = -1,
	ARMOR_INVALID_TYPE_FOR_CLEARTEXT = -2,
	ARMOR_INCOMPATIBLE_TYPE_AND_HEADER = -3,
	ARMOR_HEADER_TOO_BIG = -4
} armor_status;

typedef struct _armor_ctx
{
	// Type
	armor_type type;
	uint32_t flags;

	// Headers
	byte_t version[15];
	uint8_t version_size;

	byte_t hash[15];
	uint8_t hash_size;

	byte_t charset[15];
	uint8_t charset_size;

	byte_t comment[31];
	uint8_t comment_size;

	buffer_t cleartext;
	buffer_t data;

	// CRC-24
	uint32_t crc;

} armor_ctx;

armor_ctx *create_armor_encode_ctx(armor_type type, armor_flags flags);
void destroy_armor_ctx(armor_ctx *ctx);

armor_status armor_add_header(armor_ctx *ctx, armor_header header, byte_t *value, size_t size);
armor_status armor_encode_cleartext(armor_ctx *ctx, void *data, size_t size);
armor_status armor_encode_data(armor_ctx *ctx, void *data, size_t size);
buffer_t *armor_encode_finish(armor_ctx *ctx);

armor_ctx *create_armor_decode_ctx(armor_type type, int flags);

#endif
