/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_BASE64_H
#define SPGP_BASE64_H

#include <spgp.h>

#define BASE64_ENCODE_SIZE(x) ((ROUND_UP(x, 3) / 3) * 4)
#define BASE64_DECODE_SIZE(x) (((x) / 4) * 3)

typedef enum _base64_status
{
	BASE64_SUCCESS = 0,
	BASE64_STREAM_END = 1,
	BASE64_INSUFFICIENT_BUFFER = -1,
	BASE64_ILLEGAL_STREAM = -2
} base64_status;

typedef enum _base64_op
{
	BASE64_CONTINUE = 0,
	BASE64_FINISH = 1
} base64_op;

int32_t base64_encode(buffer_range_t *output, buffer_range_t *input, base64_op op);
int32_t base64_decode(buffer_range_t *output, buffer_range_t *input);

#endif
