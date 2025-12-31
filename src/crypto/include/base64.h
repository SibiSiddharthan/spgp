/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H

#include <crypt.h>

#define BASE64_ENCODE_SIZE(x) (CEIL_DIV((x), 3) * 4)
#define BASE64_DECODE_SIZE(x) (((x) / 4) * 3)

size_t base64_encode(void *input, size_t input_size, void *output, size_t output_size);
size_t base64_decode(void *input, size_t input_size, void *output, size_t output_size);

#endif
