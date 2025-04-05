/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_WIN32_H
#define OS_WIN32_H

#include <win32/types.h>

// Current directory handle
handle_t _os_cwd_handle();

// Standard handles
handle_t _os_stdin_handle();
handle_t _os_stdout_handle();
handle_t _os_stderr_handle();

// NT Paths
status_t _os_ntpath(void **result, handle_t root, const char *path, uint16_t length);

#define HANDLE_CWD              (_os_cwd_handle())
#define HANDLE_EMPTY_PATH       0x0
#define HANDLE_SYMLINK_FOLLOW   0x1
#define HANDLE_SYMLINK_NOFOLLOW 0x2

// Status mapping
status_t _os_status(status_t nt_status);

// Security descriptor
void *_os_security_descriptor(mode_t mode, uint32_t directory);
void _os_access(handle_t handle, void *st);

// Seek constants
#define SEEK_SET 1
#define SEEK_CUR 2
#define SEEK_END 3

// Native NT access
#define __FILE_ACCESS_READ_DATA   0x0001ul
#define __FILE_ACCESS_WRITE_DATA  0x0002ul
#define __FILE_ACCESS_APPEND_DATA 0x0004ul

#define __FILE_ACCESS_READ_EA          0x0008ul
#define __FILE_ACCESS_WRITE_EA         0x0010ul
#define __FILE_ACCESS_READ_ATTRIBUTES  0x0080ul
#define __FILE_ACCESS_WRITE_ATTRIBUTES 0x0100ul

#define __FILE_ACCESS_EXECUTE      0x0020ul
#define __FILE_ACCESS_DELETE_CHILD 0x0040ul

#define __FILE_ACCESS_READ_CONTROL 0x00020000ul
#define __FILE_ACCESS_DELETE       0x00010000ul
#define __FILE_ACCESS_WRITE_DAC    0x00040000ul
#define __FILE_ACCESS_WRITE_OWNER  0x00080000ul
#define __FILE_ACCESS_SYNCHRONIZE  0x00100000ul

// Native NT FLAGS
#define __FILE_DIRECTORY_FILE            0x00000001
#define __FILE_WRITE_THROUGH             0x00000002
#define __FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define __FILE_SYNCHRONOUS_IO_NONALERT   0x00000020
#define __FILE_NON_DIRECTORY_FILE        0x00000040
#define __FILE_DELETE_ON_CLOSE           0x00001000
#define __FILE_OPEN_REPARSE_POINT        0x00200000

// Native NT Attributes
#define __FILE_ATTRIBUTE_READONLY   0x0001
#define __FILE_ATTRIBUTE_HIDDEN     0x0002
#define __FILE_ATTRIBUTE_SYSTEM     0x0004
#define __FILE_ATTRIBUTE_ARCHIVE    0x0020
#define __FILE_ATTRIBUTE_SPARSE     0x0200
#define __FILE_ATTRIBUTE_REPARSE    0x0400
#define __FILE_ATTRIBUTE_COMPRESSED 0x0800
#define __FILE_ATTRIBUTE_OFFLINE    0x1000
#define __FILE_ATTRIBUTE_ENCRYPTED  0x4000

// Access constants

// clang-format off
#define FILE_ACCESS_READ         (__FILE_ACCESS_READ_CONTROL       |\
                                  __FILE_ACCESS_SYNCHRONIZE        |\
                                  __FILE_ACCESS_READ_DATA          |\
                                  __FILE_ACCESS_READ_EA            |\
                                  __FILE_ACCESS_READ_ATTRIBUTES)


#define FILE_ACCESS_WRITE        (__FILE_ACCESS_READ_CONTROL       |\
                                  __FILE_ACCESS_SYNCHRONIZE        |\
                                  __FILE_ACCESS_WRITE_DATA         |\
                                  __FILE_ACCESS_WRITE_EA           |\
                                  __FILE_ACCESS_READ_ATTRIBUTES    |\
                                  __FILE_ACCESS_WRITE_ATTRIBUTES)

#define FILE_ACCESS_APPEND __FILE_ACCESS_APPEND_DATA

#define FILE_ACCESS_EXECUTE      (__FILE_ACCESS_READ_CONTROL       |\
                                  __FILE_ACCESS_SYNCHRONIZE        |\
                                  __FILE_ACCESS_EXECUTE            |\
                                  __FILE_ACCESS_READ_ATTRIBUTES)

// clang-format on

#define FILE_ACCESS_PATH (__FILE_ACCESS_READ_CONTROL | __FILE_ACCESS_SYNCHRONIZE)

// Flags
#define FILE_FLAG_CREATE    0x00100000ul
#define FILE_FLAG_EXCLUSIVE 0x00200000ul
#define FILE_FLAG_TRUNCATE  0x00400000ul

#define FILE_FLAG_READONLY __FILE_ATTRIBUTE_READONLY
#define FILE_FLAG_HIDDEN   __FILE_ATTRIBUTE_HIDDEN
#define FILE_FLAG_SYSTEM   __FILE_ATTRIBUTE_SYSTEM

#define FILE_FLAG_DIRECTORY     (__FILE_DIRECTORY_FILE << 4)
#define FILE_FLAG_SYNC          (__FILE_WRITE_THROUGH << 4)
#define FILE_FLAG_DIRECT        (__FILE_NO_INTERMEDIATE_BUFFERING << 4)
#define FILE_FLAG_NON_DIRECTORY (__FILE_NON_DIRECTORY_FILE << 4)
#define FILE_FLAG_NOFOLLOW      (__FILE_OPEN_REPARSE_POINT << 4)

#define FILE_FLAG_NO_INHERIT 0x010000000ul
#define FILE_FLAG_NONBLOCK   0x020000000ul

// Unsupported
#define FILE_FLAG_LARGEFILE 0
#define FILE_FLAG_NOCTTY    0

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

// Unsupported
#define STAT_UID_ON_EXEC 0x0 // Set user ID on execution
#define STAT_GID_ON_EXEC 0x0 // Set group ID on execution
#define STAT_STICKY_BIT  0x0 // Sticky bit (Obsolete)

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

// File attributes
#define STAT_ATTRIBUTE_READONLY   __FILE_ATTRIBUTE_READONLY
#define STAT_ATTRIBUTE_HIDDEN     __FILE_ATTRIBUTE_HIDDEN
#define STAT_ATTRIBUTE_SYSTEM     __FILE_ATTRIBUTE_SYSTEM
#define STAT_ATTRIBUTE_ARCHIVE    __FILE_ATTRIBUTE_ARCHIVE
#define STAT_ATTRIBUTE_SPARSE     __FILE_ATTRIBUTE_SPARSE
#define STAT_ATTRIBUTE_REPARSE    __FILE_ATTRIBUTE_REPARSE
#define STAT_ATTRIBUTE_COMPRESSED __FILE_ATTRIBUTE_COMPRESSED
#define STAT_ATTRIBUTE_OFFLINE    __FILE_ATTRIBUTE_OFFLINE
#define STAT_ATTRIBUTE_ENCRYPTED  __FILE_ATTRIBUTE_ENCRYPTED
#define STAT_ATTRIBUTE_MASK       0x5e27

// Unsupported
#define STAT_ATTRIBUTE_AUTOMOUNT 0x0000
#define STAT_ATTRIBUTE_APPEND    0x0000
#define STAT_ATTRIBUTE_NODUMP    0x0000
#define STAT_ATTRIBUTE_NOUNLINK  0x0000

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
	size_t st_size;          // file size in bytes (if file is a regular file)
	timespec_t st_atim;     // time of last access
	timespec_t st_mtim;     // time of last data modification
	timespec_t st_ctim;     // time of last status change
	timespec_t st_birthtim; // time of birth
} stat_t;

#define STAT_NO_ACLS 0x10

#endif
