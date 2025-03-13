/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_WIN32_TYPES_H
#define OS_WIN32_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

typedef long status_t;
typedef void *handle_t;

typedef uint64_t ino_t;
typedef uint64_t off_t;

typedef uint32_t nlink_t;
typedef uint32_t mode_t;
typedef uint32_t dev_t;

typedef uint32_t uid_t;
typedef uint32_t gid_t;

typedef struct timespec timespec_t;

#endif
