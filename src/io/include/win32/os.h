/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_WIN32_H
#define OS_WIN32_H

#include <stdint.h>

typedef long status_t;
typedef void *handle_t;

typedef uint64_t ino_t;

// Current directory handle
handle_t _os_cwd_handle();
#define HANDLE_CWD (_os_cwd_handle())

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

#define FILE_FLAG_READONLY 0x000000001ul
#define FILE_FLAG_HIDDEN   0x000000002ul
#define FILE_FLAG_SYSTEM   0x000000004ul

#define FILE_FLAG_DIRECTORY     0x000000010ul
#define FILE_FLAG_SYNC          0x000000020ul
#define FILE_FLAG_DIRECT        0x000000080ul
#define FILE_FLAG_NON_DIRECTORY 0x000000400ul
#define FILE_FLAG_NOFOLLOW      0x002000000ul

#define FILE_FLAG_APPEND __FILE_ACCESS_APPEND_DATA

#define FILE_FLAG_NO_INHERIT 0x010000000ul
#define FILE_FLAG_NONBLOCK   0x020000000ul

// Unsupported
#define FILE_FLAG_LARGEFILE 0
#define FILE_FLAG_NOCTTY    0

#endif
