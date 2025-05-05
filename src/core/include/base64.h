/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_BASE64_H
#define SPGP_BASE64_H

#include <pgp.h>

#define BASE64_ENCODE_SIZE(x) (CEIL_DIV((x), 3) * 4)
#define BASE64_DECODE_SIZE(x) (((x) / 4) * 3)

size_t base64_encode(void *input, size_t input_size, void *output, size_t output_size);
size_t base64_decode(void *input, size_t input_size, void *output, size_t output_size);

#endif
