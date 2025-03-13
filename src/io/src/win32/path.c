/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>
#include <win32/os.h>

#include <os.h>
#include <ptr.h>

#include <ctype.h>

#define IS_ROOT_PATH(path) ((path[1] == '\0') && ((path[0] == '/') || (path[0] == '\\')))
#define IS_ABSOLUTE_PATH(path) \
	(/* Normal Windows way -> C: */ ((isalpha(path[0])) && (path[1] == ':')) || /* Cygwin way /c */ (path[0] == '/'))

static uint32_t path_components_size = 16;

typedef struct
{
	uint32_t start;  // starting offset
	uint32_t length; // length of component in bytes
} path_component;

static path_component *add_component(path_component *restrict components, uint32_t *restrict index, uint32_t start, uint32_t length)
{
	if (components == NULL)
	{
		components = (path_component *)RtlAllocateHeap(NtCurrentProcessHeap(), 0, path_components_size * sizeof(path_component));

		if (components == NULL)
		{
			errno = ENOMEM;
			return NULL;
		}
	}

	if (*index == path_components_size)
	{
		void *temp = RtlReAllocateHeap(NtCurrentProcessHeap(), 0, components, path_components_size * 2 * sizeof(path_component));

		if (temp == NULL)
		{
			errno = ENOMEM;
			return NULL;
		}

		components = (path_component *)temp;
		path_components_size *= 2;
	}

	components[*index].start = start;
	components[*index].length = length;
	(*index)++;

	return components;
}

static NTSTATUS dos_device_to_nt_device(CHAR volume, UNICODE_STRING **result)
{
	NTSTATUS status = 0;
	HANDLE handle = 0;
	OBJECT_ATTRIBUTES object = {0};
	UNICODE_STRING path = {0};

	WCHAR path_buffer[] = L"\\GLOBAL??\\$:"; // '$' will be replaced by the drive letter

	*result = NULL;

	path.Length = 24;
	path.MaximumLength = 26;
	path.Buffer = path_buffer;

	if (volume < 'A' || volume > 'Z')
	{
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}

	*result = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UNICODE_STRING) + 64);

	if (*result == NULL)
	{
		return STATUS_NO_MEMORY;
	}

	// Zero extension for UTF16-LE(Little Endian) works here
	path_buffer[10] = (WCHAR)volume;
	InitializeObjectAttributes(&object, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = NtOpenSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &object);

	if (status != STATUS_SUCCESS)
	{
		return status;
	}

	(*result)->Buffer = PTR_OFFSET(*result, sizeof(UNICODE_STRING));
	(*result)->Length = 0;
	(*result)->MaximumLength = 64;

	status = NtQuerySymbolicLinkObject(handle, *result, NULL);
	NtClose(handle);

	if (status != STATUS_SUCCESS)
	{
		// Mark the volume as non existent.
		RtlFreeHeap(NtCurrentProcessHeap(), 0, *result);
		return status;
	}

	return status;
}

static NTSTATUS get_handle_ntpath(HANDLE handle, UNICODE_STRING **result)
{
	NTSTATUS status;
	ULONG length;

	*result = NULL;

	*result = RtlAllocateHeap(NtCurrentProcessHeap(), 0, 1024);

	if (*result == NULL)
	{
		return STATUS_NO_MEMORY;
	}

	status = NtQueryObject(handle, ObjectNameInformation, *result, 1024, &length);

	if (status == STATUS_BUFFER_OVERFLOW)
	{
		*result = RtlReAllocateHeap(NtCurrentProcessHeap(), 0, *result, length);

		if (*result == NULL)
		{
			return STATUS_NO_MEMORY;
		}

		status = NtQueryObject(handle, ObjectNameInformation, *result, length, &length);
	}

	// If we have an open handle, this should not fail.
	if (status != STATUS_SUCCESS)
	{
		RtlFreeHeap(NtCurrentProcessHeap(), 0, *result);
		return status;
	}

	return status;
}

status_t os_path(handle_t root, const char *path, uint16_t length, char *buffer, uint16_t size, uint16_t *result)
{
	NTSTATUS status;

	UTF8_STRING u8_nt_path = {0};
	CHAR *u8_buffer = NULL;

	*result = 0;

	// Root Path
	if (IS_ROOT_PATH(path))
	{
		UNICODE_STRING *u16_root_path = NULL;
		UTF8_STRING u8_root_path = {.Buffer = buffer, .Length = 0, .MaximumLength = size};

		// UTF-16LE char truncation.
		status = dos_device_to_nt_device((CHAR)NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer[0], &u16_root_path);

		if (status != STATUS_SUCCESS)
		{
			*result = 0;
			return status;
		}

		status = RtlUnicodeStringToUTF8String(&u8_root_path, u16_root_path, FALSE);
		RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_root_path);

		if (status != STATUS_SUCCESS)
		{
			*result = (u16_root_path->Length / 2); // Estimate
			return status;
		}

		*result = u8_root_path.Length;

		return status;
	}

	// Network Shares
	if ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'))
	{
		u8_buffer = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, 12 + length); // (+) "\Device\Mup\"

		if (u8_buffer == NULL)
		{
			// errno = ENOMEM;
			return 0;
		}

		u8_nt_path.Buffer = u8_buffer;
		u8_nt_path.Length = 0;
		u8_nt_path.MaximumLength = 12 + length;

		memcpy(PTR_OFFSET(u8_nt_path.Buffer, u8_nt_path.Length), "\\Device\\Mup\\", 12);
		u8_nt_path.Length += 12;

		memcpy(PTR_OFFSET(u8_nt_path.Buffer, u8_nt_path.Length), PTR_OFFSET(path, 2), length - 2);
		u8_nt_path.Length += length - 2;

		goto path_coalesce;
	}

	if (IS_ABSOLUTE_PATH(path))
	{
		UNICODE_STRING *u16_nt_device = NULL;
		CHAR device = 0;

		// Cygwin path
		if (path[0] == '/')
		{
			if (!(isalpha(path[1]) && (path[2] == '/' || path[2] == '\0')))
			{
				// errno = ENOENT;
				return 0;
			}

			device = path[1];
		}
		else
		{
			device = path[0];
		}

		status = dos_device_to_nt_device(device, &u16_nt_device);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		u8_buffer = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, u16_nt_device->Length + length + 1);

		if (u8_buffer == NULL)
		{
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_nt_device);
			// errno = ENOENT;
			return 0;
		}

		u8_nt_path.Buffer = u8_buffer;
		u8_nt_path.Length = 0;
		u8_nt_path.Length = u16_nt_device->Length + length + 1;

		status = RtlUnicodeStringToUTF8String(&u8_nt_path, u16_nt_device, FALSE);
		RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_nt_device);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		memcpy(PTR_OFFSET(u8_nt_path.Buffer, u8_nt_path.Length), PTR_OFFSET(path, 2), length - 2);
		u8_nt_path.Length += length - 2;
	}
	else
	{
		UNICODE_STRING *u16_nt_path = NULL;

		status = get_handle_ntpath(root, &u16_nt_path);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		u8_buffer = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, u16_nt_path->Length + length + 1);

		if (u8_buffer == NULL)
		{
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_nt_path);
			return STATUS_NO_MEMORY;
		}

		u8_nt_path.Buffer = u8_buffer;
		u8_nt_path.Length = 0;
		u8_nt_path.Length = u16_nt_path->Length + length + 1;

		status = RtlUnicodeStringToUTF8String(&u8_nt_path, u16_nt_path, FALSE);
		RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_nt_path);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		memcpy(PTR_OFFSET(u8_nt_path.Buffer, u8_nt_path.Length), path, length);
		u8_nt_path.Length += length;
	}

path_coalesce:
	// Convert forward slashes to backward slashes
	for (uint16_t i = 0; i < u8_nt_path.Length; ++i)
	{
		if (u8_nt_path.Buffer[i] == L'/')
		{
			u8_nt_path.Buffer[i] = L'\\';
		}
	}

	/*
	   This works like a stack.
	   When the component is other than '..' or '.' we push the contents onto the stack.
	   When the component is '..' the stack is popped.
	   This is a zero copy stack, i.e the components are not copied at all.
	   We use the starting index and the length(in bytes) to reference each component.
	*/
	path_component *components = NULL;
	uint32_t index = 0;
	uint32_t start = 0;

	for (uint32_t i = 8;; i++) // start after \Device\:
	{
		if (buffer[i] == '\\' || buffer[i] == '\0')
		{
			if (i - start > 2) // not '.' or '..'
			{
				void *temp = add_component(components, &index, start, (i - start)); // push stack
				if (temp == NULL)
				{
					status = STATUS_NO_MEMORY;
					goto finish;
				}

				components = temp;
			}
			else
			{
				if (i - start == 2 && memcmp(buffer + start, "..", 2) == 0)
				{
					--index; // pop stack
					if (index < 1)
					{
						// root path -> C:/.. -> C:/, C:/../.. -> C:/
						index = 1;
					}
				}
				else if (i - start == 1 && memcmp(buffer + start, ".\\", 2) == 0)
				{
					; // do nothing
				}
				else
				{
					void *temp = add_component(components, &index, start, (i - start)); // push stack
					if (temp == NULL)
					{
						status = STATUS_NO_MEMORY;
						goto finish;
					}

					components = temp;
				}
			}

			if (buffer[i] == L'\0')
			{
				break;
			}

			start = i + 1;
		}
	}

	uint32_t required_size = 0;
	uint32_t pos = 0;

	for (uint32_t i = 0; i < index; i++)
	{
		required_size += components[i].length;
		required_size += (i != (index - 1)) ? 1 : 0;
	}

	required_size += (index == 1) ? 1 : 0;
	required_size += 1; // Terminating NULL

	if (size < required_size)
	{
		*result = (uint16_t)required_size;
		status = STATUS_BUFFER_OVERFLOW;

		goto finish;
	}

	for (uint32_t i = 0; i < index; i++)
	{
		memcpy(PTR_OFFSET(buffer, pos), PTR_OFFSET(u8_buffer, components[i].start), components[i].length);
		pos += components[i].length;

		if (i + 1 < index)
		{
			buffer[pos++] = '\\';
		}
	}

	if (index == 1)
	{
		// The case where we resolve a volume. eg C:
		// Always add trailing slash to the volume so that it can be treated as a directory by the NT calls.
		buffer[pos++] = '\\';
	}

	// Terminate with NULL
	buffer[pos] = '\0';

	*result = (uint16_t)pos;
	status = STATUS_SUCCESS;

finish:
	RtlFreeHeap(NtCurrentProcessHeap(), 0, components);
	RtlFreeHeap(NtCurrentProcessHeap(), 0, u8_buffer);

	return status;
}
