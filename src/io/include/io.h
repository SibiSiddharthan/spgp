/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef IO_H
#define IO_H

#include <os.h>

#define STDIN_HANDLE  (_os_stdin_handle())
#define STDOUT_HANDLE (_os_stdout_handle())
#define STDERR_HANDLE (_os_stderr_handle())

typedef struct _dir_t
{
	status_t status;
	handle_t handle;

	void *buffer;
	size_t size;
	size_t pos;
	size_t received;
} dir_t;

typedef struct _dir_entry_t
{
	ino_t entry_id;
	uint8_t entry_type;
	uint8_t entry_name_size;
	byte_t entry_name[256];
} dir_entry_t;

typedef struct _dir_entry_extended_t
{
	ino_t entry_id;
	byte_t entry_type;

	timespec_t entry_access_time;
	timespec_t entry_modification_time;
	timespec_t entry_change_time;
	timespec_t entry_created_time;

	size_t entry_end_of_file;
	size_t entry_allocation_size;

	byte_t entry_name_size;
	byte_t entry_name[256];
} dir_entry_extended_t;

typedef enum _dir_entry_class
{
	DIR_ENTRY_STANDARD = 1,
	DIR_ENTRY_EXTENDED
} dir_entry_class;

#define ENTRY_TYPE_UNKNOWN   0  // Unknown
#define ENTRY_TYPE_FIFO      1  // pipe
#define ENTRY_TYPE_CHARACTER 2  // character device
#define ENTRY_TYPE_DIRECTORY 4  // directory
#define ENTRY_TYPE_BLOCK     6  // block
#define ENTRY_TYPE_REGULAR   8  // regular file
#define ENTRY_TYPE_LINK      10 // symbolic link
#define ENTRY_TYPE_SOCKET    12 // socket

#define ENTRY_FLAG_SKIP_DOT 0x1 // Skip '.' and '..' entries

status_t dir_open(dir_t *directory, handle_t root, const char *path, uint16_t length);
status_t dir_close(dir_t *directory);

void *dir_entry(dir_t *directory, dir_entry_class entry_class, uint32_t flags, void *buffer, uint32_t size);

typedef struct _file_t
{
	status_t status;
	handle_t handle;

	void *buffer;
	size_t size;
	size_t remaining;

	size_t offset;
	size_t pos;
} file_t;

#define FILE_READ   0x1
#define FILE_WRITE  0x2
#define FILE_APPEND 0x4

status_t file_open(file_t *file, handle_t root, const char *path, uint16_t length, uint32_t flags, uint32_t allocation);
status_t file_close(file_t *file);

size_t file_read(file_t *file, void *buffer, size_t size);
size_t file_write(file_t *file, void *buffer, size_t size);

size_t file_seek(file_t *file, int64_t offset, byte_t whence);
size_t file_tell(file_t *file);

status_t file_flush(file_t *file);

#endif
