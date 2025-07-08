/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_PTR_H
#define COMMON_PTR_H

#include <stdint.h>

#define PTR_OFFSET(p, o) ((void *)(((uint8_t *)(p)) + (o)))
#define PTR_DIFF(a, b)   (uintptr_t)((uintptr_t)(a) - (uintptr_t)(b))

#endif
