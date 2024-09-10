/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_PTR_H
#define CRYPTO_PTR_H

#include <stdint.h>

#define PTR_OFFSET(p, o) ((void *)(((uint8_t *)(p)) + (o)))

#endif
