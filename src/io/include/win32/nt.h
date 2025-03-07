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

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,            // 2
	FileBothDirectoryInformation,            // 3
	FileBasicInformation,                    // 4
	FileStandardInformation,                 // 5
	FileInternalInformation,                 // 6
	FileEaInformation,                       // 7
	FileAccessInformation,                   // 8
	FileNameInformation,                     // 9
	FileRenameInformation,                   // 10
	FileLinkInformation,                     // 11
	FileNamesInformation,                    // 12
	FileDispositionInformation,              // 13
	FilePositionInformation,                 // 14
	FileFullEaInformation,                   // 15
	FileModeInformation,                     // 16
	FileAlignmentInformation,                // 17
	FileAllInformation,                      // 18
	FileAllocationInformation,               // 19
	FileEndOfFileInformation,                // 20
	FileAlternateNameInformation,            // 21
	FileStreamInformation,                   // 22
	FilePipeInformation,                     // 23
	FilePipeLocalInformation,                // 24
	FilePipeRemoteInformation,               // 25
	FileMailslotQueryInformation,            // 26
	FileMailslotSetInformation,              // 27
	FileCompressionInformation,              // 28
	FileObjectIdInformation,                 // 29
	FileCompletionInformation,               // 30
	FileMoveClusterInformation,              // 31
	FileQuotaInformation,                    // 32
	FileReparsePointInformation,             // 33
	FileNetworkOpenInformation,              // 34
	FileAttributeTagInformation,             // 35
	FileTrackingInformation,                 // 36
	FileIdBothDirectoryInformation,          // 37
	FileIdFullDirectoryInformation,          // 38
	FileValidDataLengthInformation,          // 39
	FileShortNameInformation,                // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileNormalizedNameInformation,           // 48
	FileNetworkPhysicalNameInformation,      // 49
	FileIdGlobalTxDirectoryInformation,      // 50
	FileIsRemoteDeviceInformation,           // 51
	FileUnusedInformation,                   // 52
	FileNumaNodeInformation,                 // 53
	FileStandardLinkInformation,             // 54
	FileRemoteProtocolInformation,           // 55

	//
	//  These are special versions of these operations (defined earlier)
	//  which can be used by kernel mode drivers only to bypass security
	//  access checks for Rename and HardLink operations.  These operations
	//  are only recognized by the IOManager, a file system should never
	//  receive these.
	//

	FileRenameInformationBypassAccessCheck, // 56
	FileLinkInformationBypassAccessCheck,   // 57

	//
	// End of special information classes reserved for IOManager.
	//

	FileVolumeNameInformation,                    // 58
	FileIdInformation,                            // 59
	FileIdExtdDirectoryInformation,               // 60
	FileReplaceCompletionInformation,             // 61
	FileHardLinkFullIdInformation,                // 62
	FileIdExtdBothDirectoryInformation,           // 63
	FileDispositionInformationEx,                 // 64
	FileRenameInformationEx,                      // 65
	FileRenameInformationExBypassAccessCheck,     // 66
	FileDesiredStorageClassInformation,           // 67
	FileStatInformation,                          // 68
	FileMemoryPartitionInformation,               // 69
	FileStatLxInformation,                        // 70
	FileCaseSensitiveInformation,                 // 71
	FileLinkInformationEx,                        // 72
	FileLinkInformationExBypassAccessCheck,       // 73
	FileStorageReserveIdInformation,              // 74
	FileCaseSensitiveInformationForceAccessCheck, // 75

	FileMaximumInformation = 76
} FILE_INFORMATION_CLASS,
	*PFILE_INFORMATION_CLASS;

//
// Define the create disposition values
//

#define FILE_SUPERSEDE           0x00000000
#define FILE_OPEN                0x00000001
#define FILE_CREATE              0x00000002
#define FILE_OPEN_IF             0x00000003
#define FILE_OVERWRITE           0x00000004
#define FILE_OVERWRITE_IF        0x00000005
#define FILE_MAXIMUM_DISPOSITION 0x00000005

//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE            0x00000001
#define FILE_WRITE_THROUGH             0x00000002
#define FILE_SEQUENTIAL_ONLY           0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT    0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE      0x00000040
#define FILE_CREATE_TREE_CONNECTION  0x00000080

#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE      0x00000200
#define FILE_OPEN_REMOTE_INSTANCE 0x00000400
#define FILE_RANDOM_ACCESS        0x00000800

#define FILE_DELETE_ON_CLOSE        0x00001000
#define FILE_OPEN_BY_FILE_ID        0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION         0x00008000

#if (NTDDI_VERSION >= NTDDI_WIN7)
#	define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#	define FILE_DISALLOW_EXCLUSIVE    0x00020000
#endif /* NTDDI_VERSION >= NTDDI_WIN7 */
#if (NTDDI_VERSION >= NTDDI_WIN8)
#	define FILE_SESSION_AWARE 0x00040000
#endif /* NTDDI_VERSION >= NTDDI_WIN8 */

#define FILE_RESERVE_OPFILTER          0x00100000
#define FILE_OPEN_REPARSE_POINT        0x00200000
#define FILE_OPEN_NO_RECALL            0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS5)

//
// Create options that go with FILE_CREATE_TREE_CONNECTION.
//

#	define TREE_CONNECT_NO_CLIENT_BUFFERING 0x00000008 // matches with FILE_NO_INTERMEDIATE_BUFFERING
#	define TREE_CONNECT_WRITE_THROUGH       0x00000002 // matches with FILE_WRITE_THROUGH
#	define TREE_CONNECT_USE_COMPRESSION     0x00008000 // matches with FILE_NO_COMPRESSION

#endif // _WIN32_WINNT_WIN10_RS5

//
//  The FILE_VALID_OPTION_FLAGS mask cannot be expanded to include the
//  highest 8 bits of the DWORD because those are used to represent the
//  create disposition in the IO Request Packet when sending information
//  to the file system
//
#define FILE_VALID_OPTION_FLAGS          0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS     0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS 0x00000032
#define FILE_VALID_SET_FLAGS             0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED     0x00000000
#define FILE_OPENED         0x00000001
#define FILE_CREATED        0x00000002
#define FILE_OVERWRITTEN    0x00000003
#define FILE_EXISTS         0x00000004
#define FILE_DOES_NOT_EXIST 0x00000005

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)
//
// Define the QueryFlags values for NtQueryDirectoryFileEx.
//

#	define FILE_QUERY_RESTART_SCAN                0x00000001
#	define FILE_QUERY_RETURN_SINGLE_ENTRY         0x00000002
#	define FILE_QUERY_INDEX_SPECIFIED             0x00000004
#	define FILE_QUERY_RETURN_ON_DISK_ENTRIES_ONLY 0x00000008
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
#	define FILE_QUERY_NO_CURSOR_UPDATE 0x00000010
#endif

//
// Define special ByteOffset parameters for read and write operations
//

#define FILE_WRITE_TO_END_OF_FILE      0xffffffff
#define FILE_USE_FILE_POINTER_POSITION 0xfffffffe

//
// Define alignment requirement values
//

#define FILE_BYTE_ALIGNMENT     0x00000000
#define FILE_WORD_ALIGNMENT     0x00000001
#define FILE_LONG_ALIGNMENT     0x00000003
#define FILE_QUAD_ALIGNMENT     0x00000007
#define FILE_OCTA_ALIGNMENT     0x0000000f
#define FILE_32_BYTE_ALIGNMENT  0x0000001f
#define FILE_64_BYTE_ALIGNMENT  0x0000003f
#define FILE_128_BYTE_ALIGNMENT 0x0000007f
#define FILE_256_BYTE_ALIGNMENT 0x000000ff
#define FILE_512_BYTE_ALIGNMENT 0x000001ff

NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose(_In_ _Post_ptr_invalid_ HANDLE Handle);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateFile(_Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes,
			 _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
			 _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions, _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
			 _In_ ULONG EaLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadFile(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
		   _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID Buffer, _In_ ULONG Length,
		   _In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteFile(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
			_Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length,
			_In_opt_ PLARGE_INTEGER ByteOffset, _In_opt_ PULONG Key);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation,
					   _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_reads_bytes_(Length) PVOID FileInformation,
					 _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);

NTSYSAPI
VOID NTAPI RtlInitUTF8String(_Out_ PUTF8_STRING DestinationString, _In_opt_z_ PCSTR SourceString);

NTSYSAPI
VOID NTAPI RtlInitUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ PCWSTR SourceString);

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToUTF8String(_Out_ PUTF8_STRING DestinationString, _In_ PCUNICODE_STRING SourceString,
							 _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
VOID NTAPI RtlFreeUTF8String(_Inout_ _At_(utf8String->Buffer, _Frees_ptr_opt_) PUTF8_STRING utf8String);

NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8StringToUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_ PUTF8_STRING SourceString,
							 _In_ BOOLEAN AllocateDestinationString);

NTSYSAPI
VOID NTAPI RtlFreeUnicodeString(_Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_) PUNICODE_STRING UnicodeString);

//================ FileDispositionInformationEx ===============================

typedef struct _FILE_DISPOSITION_INFORMATION
{
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
#	define FILE_DISPOSITION_DO_NOT_DELETE             0x00000000
#	define FILE_DISPOSITION_DELETE                    0x00000001
#	define FILE_DISPOSITION_POSIX_SEMANTICS           0x00000002
#	define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK 0x00000004
#	define FILE_DISPOSITION_ON_CLOSE                  0x00000008
#	if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS5)
#		define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010
#	endif

typedef struct _FILE_DISPOSITION_INFORMATION_EX
{
	ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;
#endif

#endif
