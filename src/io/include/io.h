/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef IO_H
#define IO_H

#include <stddef.h>
#include <stdint.h>

#if defined _WIN32
#	include "win32/io.h"
#elif defined __linux__
#	include "linux/io.h"
#elif defined __APPLE__
#	include "darwin/io.h"
#endif

status_t os_open(handle_t *handle, handle_t root, const char *path, uint16_t length, uint32_t flags, uint32_t mode);
status_t os_close(handle_t handle);

status_t os_read(handle_t handle, void *buffer, size_t size, size_t *result);
status_t os_write(handle_t handle, void *buffer, size_t size, size_t *result);

#endif
