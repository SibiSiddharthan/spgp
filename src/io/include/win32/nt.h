/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef OS_WIN32_NT_H
#define OS_WIN32_NT_H

#define WIN32_LEAN_AND_MEAN
#define UMDF_USING_NTSTATUS

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

#include <ntstatus.h>

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;

typedef ULONG LOGICAL, *PLOGICAL;

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

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,         // q: OBJECT_BASIC_INFORMATION
	ObjectNameInformation,          // q: OBJECT_NAME_INFORMATION
	ObjectTypeInformation,          // q: OBJECT_TYPE_INFORMATION
	ObjectTypesInformation,         // q: OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation,    // qs: OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation,       // s: void // change object session // (requires SeTcbPrivilege)
	ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

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

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,        // 2
	FileFsSizeInformation,         // 3
	FileFsDeviceInformation,       // 4
	FileFsAttributeInformation,    // 5
	FileFsControlInformation,      // 6
	FileFsFullSizeInformation,     // 7
	FileFsObjectIdInformation,     // 8
	FileFsDriverPathInformation,   // 9
	FileFsVolumeFlagsInformation,  // 10
	FileFsSectorSizeInformation,   // 11
	FileFsDataCopyInformation,     // 12
	FileFsMetadataSizeInformation, // 13
	FileFsFullSizeInformationEx,   // 14
	FileFsMaximumInformation
} FS_INFORMATION_CLASS,
	*PFS_INFORMATION_CLASS;

#define DEVICE_TYPE ULONG

#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003A
#define FILE_DEVICE_INFINIBAND          0x0000003B
#define FILE_DEVICE_VMBUS               0x0000003E
#define FILE_DEVICE_CRYPT_PROVIDER      0x0000003F
#define FILE_DEVICE_WPD                 0x00000040
#define FILE_DEVICE_BLUETOOTH           0x00000041
#define FILE_DEVICE_MT_COMPOSITE        0x00000042
#define FILE_DEVICE_MT_TRANSPORT        0x00000043
#define FILE_DEVICE_BIOMETRIC           0x00000044
#define FILE_DEVICE_PMI                 0x00000045
#define FILE_DEVICE_EHSTOR              0x00000046
#define FILE_DEVICE_DEVAPI              0x00000047
#define FILE_DEVICE_GPIO                0x00000048
#define FILE_DEVICE_USBEX               0x00000049
#define FILE_DEVICE_CONSOLE             0x00000050
#define FILE_DEVICE_NFP                 0x00000051
#define FILE_DEVICE_SYSENV              0x00000052
#define FILE_DEVICE_VIRTUAL_BLOCK       0x00000053
#define FILE_DEVICE_POINT_OF_SERVICE    0x00000054
#define FILE_DEVICE_STORAGE_REPLICATION 0x00000055
#define FILE_DEVICE_TRUST_ENV           0x00000056
#define FILE_DEVICE_UCM                 0x00000057
#define FILE_DEVICE_UCMTCPCI            0x00000058
#define FILE_DEVICE_PERSISTENT_MEMORY   0x00000059
#define FILE_DEVICE_NVDIMM              0x0000005a
#define FILE_DEVICE_HOLOGRAPHIC         0x0000005b
#define FILE_DEVICE_SDFXHCI             0x0000005c
#define FILE_DEVICE_UCMUCSI             0x0000005d

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

NTSYSCALLAPI
NTSTATUS
NTAPI
NtLockFile(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
		   _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ PLARGE_INTEGER ByteOffset, _In_ PLARGE_INTEGER Length, _In_ ULONG Key,
		   _In_ BOOLEAN FailImmediately, _In_ BOOLEAN ExclusiveLock);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnlockFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ PLARGE_INTEGER ByteOffset, _In_ PLARGE_INTEGER Length,
			 _In_ ULONG Key);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryVolumeInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FsInformation,
							 _In_ ULONG Length, _In_ FS_INFORMATION_CLASS FsInformationClass);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDirectoryFileEx(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
					   _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
					   _In_ FILE_INFORMATION_CLASS FileInformationClass, _In_ ULONG QueryFlags, _In_opt_ PUNICODE_STRING FileName);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
					  _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG IoControlCode,
					  _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength,
					  _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFsControlFile(_In_ HANDLE FileHandle, _In_opt_ HANDLE Event, _In_opt_ PIO_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcContext,
				_Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ ULONG FsControlCode, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
				_In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength);

NTSYSAPI
NTSTATUS
NTAPI NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
							PULONG LengthNeeded);

NTSYSAPI
NTSTATUS
NTAPI NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);

#define SYMBOLIC_LINK_QUERY      0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenSymbolicLinkObject(_Out_ PHANDLE LinkHandle, _In_ ACCESS_MASK DesiredAccess, _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject(_In_ HANDLE LinkHandle, _Inout_ PUNICODE_STRING LinkTarget, _Out_opt_ PULONG ReturnedLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryObject(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
			  _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength,
			  _Out_opt_ PULONG ReturnLength);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationObject(_In_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
					   _In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength);

#define DUPLICATE_CLOSE_SOURCE    0x00000001
#define DUPLICATE_SAME_ACCESS     0x00000002
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDuplicateObject(_In_ HANDLE SourceProcessHandle, _In_ HANDLE SourceHandle, _In_opt_ HANDLE TargetProcessHandle,
				  _Out_opt_ PHANDLE TargetHandle, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG HandleAttributes, _In_ ULONG Options);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationToken(_In_ HANDLE TokenHandle, _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
						_Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
						_In_ ULONG TokenInformationLength, _Out_ PULONG ReturnLength);

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

//================ FileEndOfFileInformation ===================================

typedef struct _FILE_END_OF_FILE_INFORMATION
{
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

//================ FileStatInformation ========================================

typedef struct _FILE_POSITION_INFORMATION
{
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION
{
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION
{
	DEVICE_TYPE DeviceType;
	ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_ID_EXTD_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	ULONG ReparsePointTag;
	FILE_ID_128 FileId;
	_Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, *PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	ULONG ReparsePointTag;
	FILE_ID_128 FileId;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	_Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, *PFILE_ID_EXTD_BOTH_DIR_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#define CTL_CODE(DeviceType, Function, Method, Access) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define DEVICE_TYPE_FROM_CTL_CODE(ctrlCode)            (((ULONG)(ctrlCode & 0xffff0000)) >> 16)
#define METHOD_FROM_CTL_CODE(ctrlCode)                 ((ULONG)(ctrlCode & 3))

#define METHOD_BUFFERED             0
#define METHOD_IN_DIRECT            1
#define METHOD_OUT_DIRECT           2
#define METHOD_NEITHER              3
#define METHOD_DIRECT_TO_HARDWARE   METHOD_IN_DIRECT
#define METHOD_DIRECT_FROM_HARDWARE METHOD_OUT_DIRECT

#define FILE_ANY_ACCESS     0
#define FILE_SPECIAL_ACCESS (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS    (0x0001) // file & pipe
#define FILE_WRITE_ACCESS   (0x0002) // file & pipe

#define FSCTL_SET_REPARSE_POINT    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_GET_REPARSE_POINT    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)     // REPARSE_DATA_BUFFER
#define FSCTL_DELETE_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,

#define SYMLINK_FLAG_RELATIVE 0x00000001 // If set then this is a relative symlink.
#define SYMLINK_DIRECTORY \
	0x80000000 // If set then this is a directory symlink. This is not persisted on disk and is programmatically set by file system.
#define SYMLINK_FILE \
	0x40000000 // If set then this is a file symlink. This is not persisted on disk and is programmatically set by file system.

#define SYMLINK_RESERVED_MASK 0xF0000000 // We reserve the high nibble for internal use

typedef struct _REPARSE_DATA_BUFFER
{
	ULONG ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;

	_Field_size_bytes_(ReparseDataLength) union
	{
		struct
		{
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct
		{
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct
		{
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

typedef VOID(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);
typedef LONG KPRIORITY;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE   0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS  32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;

	// Plus a lot more to follow. We only need the above
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable : 4201) // we'll always use the Microsoft compiler
	union
	{
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PEB
{
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle; // Windows 2000 only
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, *PTEB;

#define NtCurrentProcess()      ((HANDLE)(LONG_PTR) - 1)
#define NtCurrentThread()       ((HANDLE)(LONG_PTR) - 2)
#define NtCurrentSession()      ((HANDLE)(LONG_PTR) - 3)
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR) - 4)
#define NtCurrentThreadToken()  ((HANDLE)(LONG_PTR) - 5)

#define NtCurrentPeb()         (NtCurrentTeb()->ProcessEnvironmentBlock)
#define NtCurrentProcessHeap() (NtCurrentPeb()->ProcessHeap)
#define NtCurrentProcessId()   ((DWORD)(INT_PTR)(NtCurrentTeb()->ClientId.UniqueProcess))
#define NtCurrentThreadId()    ((DWORD)(INT_PTR)(NtCurrentTeb()->ClientId.UniqueThread))

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size);

NTSYSAPI
PVOID
NTAPI
RtlReAllocateHeap(_In_ PVOID HeapHandle, _In_ ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress, _In_ SIZE_T Size);

NTSYSAPI
LOGICAL
NTAPI
RtlFreeHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress);

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

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeSidEx(_Out_writes_bytes_(SECURITY_SID_SIZE(SubAuthorityCount)) PSID Sid, _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
				   _In_ UCHAR SubAuthorityCount, ...);

NTSYSAPI
NTSTATUS
NTAPI RtlCreateAcl(PACL Acl, ULONG AclLength, ULONG AclRevision);

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAceEx(_Inout_ PACL Acl, _In_ ULONG AceRevision, _In_ ULONG AceFlags, _In_ ACCESS_MASK AccessMask, _In_ PSID Sid);

NTSYSAPI
NTSTATUS
NTAPI
RtlCopySid(_In_ ULONG DestinationSidLength, _Out_writes_bytes_(DestinationSidLength) PSID DestinationSid, _In_ PSID SourceSid);

NTSYSAPI
NTSTATUS
NTAPI
RtlCopySid(_In_ ULONG DestinationSidLength, _Out_writes_bytes_(DestinationSidLength) PSID DestinationSid, _In_ PSID SourceSid);

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(_In_ PSID Sid1, _In_ PSID Sid2);

#endif
