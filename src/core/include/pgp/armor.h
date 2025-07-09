/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_ARMOR_H
#define SPGP_ARMOR_H

#include <pgp/pgp.h>

#define PGP_ARMOR_BEGIN_MESSAGE "BEGIN PGP MESSAGE"
#define PGP_ARMOR_END_MESSAGE   "END PGP MESSAGE"

#define PGP_ARMOR_BEGIN_PUBLIC_KEY "BEGIN PGP PUBLIC KEY BLOCK"
#define PGP_ARMOR_END_PUBLIC_KEY   "END PGP PUBLIC KEY BLOCK"

#define PGP_ARMOR_BEGIN_PRIVATE_KEY "BEGIN PGP PRIVATE KEY BLOCK"
#define PGP_ARMOR_END_PRIVATE_KEY   "END PGP PRIVATE KEY BLOCK"

#define PGP_ARMOR_BEGIN_SIGNATURE "BEGIN PGP SIGNATURE"
#define PGP_ARMOR_END_SIGNATURE   "END PGP SIGNATURE"

#define PGP_ARMOR_CLEARTEXT "-----BEGIN PGP SIGNED MESSAGE-----"

#define PGP_ARMOR_HEADER_VERSION    "Version"
#define PGP_ARMOR_HEADER_HASH       "Hash"
#define PGP_ARMOR_HEADER_CHARSET    "Charset"
#define PGP_ARMOR_HEADER_COMMENT    "Comment"
#define PGP_ARMOR_HEADER_MESSAGE_ID "MessageID"

#define ARMOR_MAX_MARKER_SIZE 64

typedef enum _armor_status
{
	ARMOR_SUCCESS = 0,
	ARMOR_UNKOWN_MARKER,
	ARMOR_MARKER_MISMATCH,
	ARMOR_MALFORMED_DATA,
	ARMOR_CRC_MISMATCH,
	ARMOR_BUFFER_TOO_SMALL,
	ARMOR_NO_MEMORY,
	ARMOR_INPUT_TOO_BIG,
	ARMOR_LINE_TOO_BIG,
	ARMOR_MARKER_TOO_BIG
} armor_status;

#define ARMOR_CHECKSUM_CRC24         0x01
#define ARMOR_EMPTY_LINE             0x02
#define ARMOR_CRLF_ENDING            0x04
#define ARMOR_SCAN_HEADERS           0x08
#define ARMOR_IGNORE_UNKNOWN_MARKERS 0x10

typedef struct _armor_marker
{
	void *header_line;
	void *trailer_line;
	uint16_t header_line_size;
	uint16_t trailer_line_size;

} armor_marker;

typedef struct _armor_options
{
	armor_marker *marker;

	byte_t *headers;
	uint16_t headers_size;

	uint16_t flags;

	byte_t unknown_header[ARMOR_MAX_MARKER_SIZE];
	uint16_t unknown_header_size;

} armor_options;

armor_status armor_read(armor_options *options, armor_marker *markers, uint16_t count, void *input, uint32_t *input_size, void *output,
						uint32_t *output_size);
armor_status armor_write(armor_options *options, void *input, uint32_t input_size, void *output, uint32_t *output_size);

#endif
