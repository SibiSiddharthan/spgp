/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>
#include <win32/os.h>
#include <win32/timestamp.h>

#include <io.h>

#include <ptr.h>
#include <round.h>

#include <stdlib.h>
#include <string.h>

static uint16_t dir_load_standard(void *data, dir_entry_t *entry)
{
	FILE_ID_EXTD_DIR_INFORMATION *direntry = data;
	DWORD attributes = direntry->FileAttributes;
	UTF8_STRING u8_path;
	UNICODE_STRING u16_path;
	USHORT pos = 0;

	// Zero the buffer
	memset(entry, 0, sizeof(dir_entry_t));

	// Copy only the lower 8 bytes, the upper 8 bytes will be zero on NTFS
	memcpy(&entry->entry_id, &direntry->FileId.Identifier, 8);

	/* For a junction both FILE_ATTRIBUTE_DIRECTORY and FILE_ATTRIBUTE_REPARSE_POINT is set.
	   To have it as DT_LNK we put this condition first.
	*/
	if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
	{
		entry->entry_type = ENTRY_TYPE_LINK;
	}
	else if (attributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		entry->entry_type = ENTRY_TYPE_DIRECTORY;
	}
	else if ((attributes & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
							 FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED |
							 FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_ENCRYPTED)) == 0)
	{
		entry->entry_type = ENTRY_TYPE_REGULAR;
	}
	else
	{
		entry->entry_type = ENTRY_TYPE_UNKNOWN;
	}

	u16_path.Length = (USHORT)direntry->FileNameLength;
	u16_path.MaximumLength = (USHORT)direntry->FileNameLength;
	u16_path.Buffer = direntry->FileName;

	u8_path.Buffer = (void *)&entry->entry_name;
	u8_path.Length = 0;
	u8_path.MaximumLength = 256;

	RtlUnicodeStringToUTF8String(&u8_path, &u16_path, FALSE);

	entry->entry_name_size = u8_path.Length;

	// Each entry is aligned to a 8 byte boundary, except the last one.
	pos += offsetof(FILE_ID_EXTD_DIR_INFORMATION, FileName) + direntry->FileNameLength;

	if (direntry->NextEntryOffset != 0)
	{
		pos = ROUND_UP(pos, 8);
	}

	return pos;
}

static uint16_t dir_load_extended(void *data, dir_entry_extended_t *entry)
{
	FILE_ID_EXTD_DIR_INFORMATION *direntry = data;
	DWORD attributes = direntry->FileAttributes;
	UTF8_STRING u8_path;
	UNICODE_STRING u16_path;
	USHORT pos = 0;

	// Zero the buffer
	memset(entry, 0, sizeof(dir_entry_extended_t));

	// Copy only the lower 8 bytes, the upper 8 bytes will be zero on NTFS
	memcpy(&entry->entry_id, &direntry->FileId.Identifier, 8);

	/* For a junction both FILE_ATTRIBUTE_DIRECTORY and FILE_ATTRIBUTE_REPARSE_POINT is set.
	   To have it as DT_LNK we put this condition first.
	*/
	if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
	{
		entry->entry_type = ENTRY_TYPE_LINK;
	}
	else if (attributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		entry->entry_type = ENTRY_TYPE_DIRECTORY;
	}
	else if ((attributes & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
							 FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED |
							 FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_ENCRYPTED)) == 0)
	{
		entry->entry_type = ENTRY_TYPE_REGULAR;
	}
	else
	{
		entry->entry_type = ENTRY_TYPE_UNKNOWN;
	}

	entry->entry_access_time = _os_time_to_timespec(direntry->LastAccessTime);
	entry->entry_modification_time = _os_time_to_timespec(direntry->LastWriteTime);
	entry->entry_change_time = _os_time_to_timespec(direntry->ChangeTime);
	entry->entry_created_time = _os_time_to_timespec(direntry->CreationTime);

	entry->entry_end_of_file = direntry->EndOfFile.QuadPart;
	entry->entry_allocation_size = direntry->AllocationSize.QuadPart;

	u16_path.Length = (USHORT)direntry->FileNameLength;
	u16_path.MaximumLength = (USHORT)direntry->FileNameLength;
	u16_path.Buffer = direntry->FileName;

	u8_path.Buffer = (void *)&entry->entry_name;
	u8_path.Length = 0;
	u8_path.MaximumLength = 256;

	RtlUnicodeStringToUTF8String(&u8_path, &u16_path, FALSE);

	entry->entry_name_size = u8_path.Length;

	// Each entry is aligned to a 8 byte boundary, except the last one.
	pos += offsetof(FILE_ID_EXTD_DIR_INFORMATION, FileName) + direntry->FileNameLength;

	if (direntry->NextEntryOffset != 0)
	{
		pos = ROUND_UP(pos, 8);
	}

	return pos;
}

void *dir_entry(dir_t *directory, dir_entry_class entry_class, void *buffer, uint32_t size)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK io = {0};

	// Validate parameters
	if (entry_class != DIR_ENTRY_STANDARD && entry_class != DIR_ENTRY_EXTENDED)
	{
		directory->status = 0;
		return NULL;
	}

	if (entry_class == DIR_ENTRY_STANDARD)
	{
		if (size < sizeof(dir_entry_t))
		{
			directory->status = 0;
			return NULL;
		}
	}

	if (entry_class == DIR_ENTRY_EXTENDED)
	{
		if (size < sizeof(dir_entry_extended_t))
		{
			directory->status = 0;
			return NULL;
		}
	}

	if (directory->pos == directory->received)
	{
		memset(directory->buffer, 0, directory->size);
		status = NtQueryDirectoryFileEx(directory->handle, NULL, NULL, NULL, &io, directory->buffer, directory->size,
										FileIdExtdDirectoryInformation, 0, NULL);
		if (status != STATUS_SUCCESS)
		{
			if (status != STATUS_NO_MORE_FILES)
			{
				directory->status = 0;
			}

			return NULL;
		}

		directory->pos = 0;
		directory->received = io.Information;
	}

	if (entry_class == DIR_ENTRY_STANDARD)
	{
		directory->pos += dir_load_standard(PTR_OFFSET(directory->buffer, directory->pos), buffer);
	}

	if (entry_class == DIR_ENTRY_EXTENDED)
	{
		directory->pos += dir_load_extended(PTR_OFFSET(directory->buffer, directory->pos), buffer);
	}

	return buffer;
}
