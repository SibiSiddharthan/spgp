/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_POSIX_H
#define OS_POSIX_H

#include <sys/types.h>
#include <time.h>

typedef long status_t;
typedef int errno_t;
typedef unsigned int handle_t;

typedef struct timespec timespec_t;

// Current directory handle
#define _os_cwd_handle() (-100) // AT_FDCWD

// Standard handles
#define _os_stdin_handle()  (0) // STDIN_FILENO
#define _os_stdout_handle() (1) // STDOUT_FILENO
#define _os_stderr_handle() (2) // STDERR FILENO

#define HANDLE_CWD              (_os_cwd_handle())
#define HANDLE_EMPTY_PATH       0x1000 // AT_EMPTY_PATH
#define HANDLE_SYMLINK_FOLLOW   0x0400 // AT_SYMLINK_FOLLOW
#define HANDLE_SYMLINK_NOFOLLOW 0x0100 // AT_SYMLINK_NOFOLLOW

// Status mapping
status_t _os_status(errno_t error);

// Seek constants
#define SEEK_BEGIN   0
#define SEEK_CURRENT 1
#define SEEK_END     2

// Access
#define FILE_ACCESS_READ   0x001
#define FILE_ACCESS_WRITE  0x002
#define FILE_ACCESS_APPEND 0x400 // O_APPEND

// Flags
#define FILE_FLAG_CREATE    0x0040 // O_CREAT
#define FILE_FLAG_EXCLUSIVE 0x0080 // O_EXCL
#define FILE_FLAG_NOCTTY    0x0100 // O_NOCTTY
#define FILE_FLAG_TRUNCATE  0x0200 // O_TRUC
#define FILE_FLAG_LARGEFILE 0x8000 // O_LARGEFILE

#define FILE_FLAG_SYNC      0x1000  // O_DSYNC
#define FILE_FLAG_DIRECT    0x4000  // O_DIRECT
#define FILE_FLAG_DIRECTORY 0x10000 // O_DIRECTORY
#define FILE_FLAG_NOFOLLOW  0x20000 // O_NOFOLLOW

#define FILE_FLAG_NO_INHERIT 0x80000 // O_CLOEXEC
#define FILE_FLAG_NONBLOCK   0x00800 // O_NONBLOCK

// Unsupported
#define FILE_FLAG_READONLY      0x0
#define FILE_FLAG_HIDDEN        0x0
#define FILE_FLAG_SYSTEM        0x0
#define FILE_FLAG_NON_DIRECTORY 0x0

// User permissions
#define PERM_USER_READ    0400
#define PERM_USER_WRITE   0200
#define PERM_USER_EXECUTE 0100

// Group permissions
#define PERM_GROUP_READ    0040
#define PERM_GROUP_WRITE   0020
#define PERM_GROUP_EXECUTE 0010

// Other permissions
#define PERM_OTHER_READ    0004
#define PERM_OTHER_WRITE   0002
#define PERM_OTHER_EXECUTE 0001

// File types
#define STAT_FILE_TYPE_MASK 0xF000 // File type mask
#define STAT_FILE_TYPE_FIFO 0x1000 // Pipe or FIFO (FIFO is unsupported)
#define STAT_FILE_TYPE_CHAR 0x2000 // Character special
#define STAT_FILE_TYPE_DIR  0x4000 // Directory
#define STAT_FILE_TYPE_BLCK 0x6000 // Block special
#define STAT_FILE_TYPE_REG  0x8000 // Regular
#define STAT_FILE_TYPE_LINK 0xA000 // Symbolic Link
#define STAT_FILE_TYPE_SOCK 0xC000 // Socket

#define STAT_IS_TYPE(mode, type) (((mode) & STAT_FILE_TYPE_MASK) == (type))

#define STAT_IS_FIFO(mode) STAT_IS_TYPE((mode), STAT_FILE_TYPE_FIFO)
#define STAT_IS_CHAR(mode) STAT_IS_TYPE((mode), STAT_FILE_TYPE_CHAR)
#define STAT_IS_DIR(mode)  STAT_IS_TYPE((mode), STAT_FILE_TYPE_DIR)
#define STAT_IS_BLCK(mode) STAT_IS_TYPE((mode), STAT_FILE_TYPE_BLCK)
#define STAT_IS_REG(mode)  STAT_IS_TYPE((mode), STAT_FILE_TYPE_REG)
#define STAT_IS_LINK(mode) STAT_IS_TYPE((mode), STAT_FILE_TYPE_LINK)
#define STAT_IS_SOCK(mode) STAT_IS_TYPE((mode), STAT_FILE_TYPE_SOCK)

#define STAT_UID_ON_EXEC 0x800 // Set user ID on execution
#define STAT_GID_ON_EXEC 0x400 // Set group ID on execution
#define STAT_STICKY_BIT  0x200 // Sticky bit (Obsolete)

// File attributes (Unsupported)
#define STAT_ATTRIBUTE_COMPRESSED 0x0004
#define STAT_ATTRIBUTE_READONLY   0x0010
#define STAT_ATTRIBUTE_APPEND     0x0020
#define STAT_ATTRIBUTE_NODUMP     0x0040
#define STAT_ATTRIBUTE_ENCRYPTED  0x0800
#define STAT_ATTRIBUTE_AUTOMOUNT  0x1000
#define STAT_ATTRIBUTE_MASK       0x1874

// Unsupported
#define STAT_ATTRIBUTE_HIDDEN   0x0
#define STAT_ATTRIBUTE_SYSTEM   0x0
#define STAT_ATTRIBUTE_ARCHIVE  0x0
#define STAT_ATTRIBUTE_SPARSE   0x0
#define STAT_ATTRIBUTE_REPARSE  0x0
#define STAT_ATTRIBUTE_OFFLINE  0x0
#define STAT_ATTRIBUTE_NOUNLINK 0x0000

typedef struct _stat_t
{
	dev_t st_dev;           // ID of device containing file
	dev_t st_rdev;          // device ID (if file is character or block special)
	ino_t st_ino;           // file serial number
	mode_t st_mode;         // mode of file
	uint32_t st_attributes; // file attributes
	nlink_t st_nlink;       // number of links to the file
	uid_t st_uid;           // user ID of file
	gid_t st_gid;           // group ID of file
	size_t st_size;         // file size in bytes (if file is a regular file)
	timespec_t st_atim;     // time of last access
	timespec_t st_mtim;     // time of last data modification
	timespec_t st_ctim;     // time of last status change
	timespec_t st_birthtim; // time of birth
} stat_t;

#define STAT_NO_ACLS 0x0

#endif
