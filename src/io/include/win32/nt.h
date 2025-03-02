/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef IO_WIN32_NT_H
#define IO_WIN32_NT_H

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winnt.h>

#ifndef NTSYSCALLAPI
#	define NTSYSCALLAPI __declspec(dllimport)
#endif

#ifndef NTAPI
#	define NTAPI __stdcall
#endif

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;

/*
 UTF-8 strings. If they are NULL terminated, Length does not include trailing NULL.
*/
typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING UTF8_STRING;
typedef PSTRING PUTF8_STRING;

#define ANSI_NULL ((CHAR)0)

/*
 UTF-16 strings. If they are NULL terminated, Length does not include trailing NULL.
*/
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0)

#define OBJ_INHERIT                       0x00000002L
#define OBJ_PERMANENT                     0x00000010L
#define OBJ_EXCLUSIVE                     0x00000020L
#define OBJ_CASE_INSENSITIVE              0x00000040L
#define OBJ_OPENIF                        0x00000080L
#define OBJ_OPENLINK                      0x00000100L
#define OBJ_KERNEL_HANDLE                 0x00000200L
#define OBJ_FORCE_ACCESS_CHECK            0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x00000800L
#define OBJ_DONT_REPARSE                  0x00001000L
#define OBJ_VALID_ATTRIBUTES              0x00001FF2L

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;       // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService; // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(POBJECT, NAME, ATTRIBUTES, ROOT, SECURITY) \
	{                                                                         \
		(POBJECT)->Length = sizeof(OBJECT_ATTRIBUTES);                        \
		(POBJECT)->RootDirectory = ROOT;                                      \
		(POBJECT)->Attributes = ATTRIBUTES;                                   \
		(POBJECT)->ObjectName = NAME;                                         \
		(POBJECT)->SecurityDescriptor = SECURITY;                             \
		(POBJECT)->SecurityQualityOfService = NULL;                           \
	}

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(_In_ PVOID ApcContext, _In_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG Reserved);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose(_In_ _Post_ptr_invalid_ HANDLE Handle);

#endif
