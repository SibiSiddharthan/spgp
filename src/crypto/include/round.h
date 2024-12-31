/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_ROUND_H
#define CRYPTO_ROUND_H

#define ROUND_UP(x, y)   ((((x) + ((y) - 1)) / (y)) * (y))
#define ROUND_DOWN(x, y) (((x) / (y)) * (y))

#define CEIL_DIV(x, y)  (((x) + (y) - 1) / (y))
#define FLOOR_DIV(x, y) ((x) / (y))
#define ROUND_DIV(x, y) (((x) + (y) / 2) / (y))

#endif
