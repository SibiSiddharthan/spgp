/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_H
#define OS_H

#include <stddef.h>
#include <stdint.h>

#if defined _WIN32
#	include "win32/os.h"
#elif defined __linux__
#	include "linux/os.h"
#elif defined __APPLE__
#	include "darwin/os.h"
#endif

typedef uint8_t byte_t;

status_t os_open(handle_t *handle, handle_t root, const char *path, uint16_t length, uint32_t access, uint32_t flags, uint32_t mode);
status_t os_close(handle_t handle);

status_t os_read(handle_t handle, void *buffer, size_t size, size_t *result);
status_t os_write(handle_t handle, void *buffer, size_t size, size_t *result);

status_t os_stat(handle_t root, const char *path, uint16_t length, uint32_t flags, void *buffer, uint16_t size);

status_t os_mkdir(handle_t root, const char *path, uint16_t length, uint32_t mode);
status_t os_remove(handle_t root, const char *path, uint16_t length);

status_t os_lock(handle_t handle, size_t offset, size_t length, byte_t nonblocking, byte_t exclusive);
status_t os_unlock(handle_t handle, size_t offset, size_t length);

status_t os_isatty(handle_t handle, uint32_t *result);
status_t os_path(handle_t root, const char *path, uint16_t length, char *buffer, uint16_t size, uint16_t *result);

#endif
