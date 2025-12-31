/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_ROTATE_H
#define COMMON_ROTATE_H

// Given an unsigned N-bit argument X and a shift count S rotate (left/right) the bytes and return.

#define ROTL_16(x, s) (((x) << (s)) | ((x) >> (16 - (s))))
#define ROTL_32(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#define ROTL_64(x, s) (((x) << (s)) | ((x) >> (64 - (s))))

#define ROTR_16(x, s) (((x) >> (s)) | ((x) << (16 - (s))))
#define ROTR_32(x, s) (((x) >> (s)) | ((x) << (32 - (s))))
#define ROTR_64(x, s) (((x) >> (s)) | ((x) << (64 - (s))))

#endif
