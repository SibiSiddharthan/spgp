/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef IO_H
#define IO_H

#include <stddef.h>
#include <stdint.h>

#include <os.h>

typedef struct _dir_t
{
	status_t status;
	handle_t handle;

	void *buffer;
	size_t size;
	size_t pos;
	size_t received;
} dir_t;

typedef struct _file_t
{
	status_t status;
	handle_t handle;

	void *buffer;
	size_t size;
	size_t start;
	size_t end;
	size_t pos;
	size_t offset;
} file_t;

status_t dir_open(dir_t *directory, handle_t root, const char *path, uint16_t length);
status_t dir_close(dir_t *directory);

void *dir_entry(dir_t *directory, uint32_t options, void *buffer, uint32_t size);

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

status_t file_open(file_t *file, handle_t root, const char *path, uint16_t length, uint32_t access, uint32_t allocation);
status_t file_close(file_t *file);

size_t file_read(file_t *file, void *buffer, size_t size);
size_t file_write(file_t *file, void *buffer, size_t size);

size_t file_seek(file_t *file, int64_t offset, byte_t whence);
size_t file_tell(file_t *file);

status_t file_flush(file_t *file);

#endif
