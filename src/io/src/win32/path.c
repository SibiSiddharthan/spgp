/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <win32/nt.h>
#include <win32/os.h>

#include <os.h>
#include <status.h>
#include <ptr.h>

#include <ctype.h>

#define IS_ROOT_PATH(path) ((path[1] == '\0') && ((path[0] == '/') || (path[0] == '\\')))
#define IS_ABSOLUTE_PATH(path) \
	(/* Normal Windows way -> C: */ ((isalpha(path[0])) && (path[1] == ':')) || /* Cygwin way /c */ (path[0] == '/'))

typedef struct
{
	uint32_t start;  // starting offset
	uint32_t length; // length of component in bytes
} path_component;

typedef struct _path_stack
{
	uint32_t length;

	uint32_t capacity;
	uint32_t count;
	path_component *components;
} path_stack;

static path_stack *push_path_component(path_stack *stack, uint32_t start, uint32_t length)
{
	if (stack->components == NULL)
	{
		stack->capacity = 4;
		stack->count = 0;

		stack->components =
			(path_component *)RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, stack->capacity * sizeof(path_component));

		if (stack->components == NULL)
		{
			return NULL;
		}
	}

	if (stack->count == stack->capacity)
	{
		stack->capacity *= 2;
		void *temp =
			RtlReAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, stack->components, stack->capacity * sizeof(path_component));

		if (temp == NULL)
		{
			return NULL;
		}

		stack->components = temp;
	}

	stack->components[stack->count].start = start;
	stack->components[stack->count].length = length;

	stack->count++;

	stack->length += length + sizeof(WCHAR);

	return stack;
}

static path_stack *pop_path_component(path_stack *stack)
{
	// root path -> C:/.. -> C:/, C:/../.. -> C:/
	if (stack->count > 1)
	{
		stack->length -= (stack->components[stack->count - 1].length + sizeof(WCHAR));
		stack->count--;
	}

	return stack;
}

static BYTE simple_path(const char *path, uint16_t length)
{
	// Check simple paths (not ./ or  ../)
	for (uint16_t i = 0; i < length; ++i)
	{
		if (path[i] == '.')
		{
			if ((i + 1) < length)
			{
				if (path[i + 1] == '/' || path[i + 1] == '\\')
				{
					return 0;
				}
			}
			else // i == length - 1
			{
				return 0;
			}
		}
	}

	return 1;
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

NTSTATUS _os_ntpath(void **result, handle_t root, const char *path, uint16_t length)
{
	NTSTATUS status;

	UNICODE_STRING *u16_ntpath = NULL;
	WCHAR *u16_buffer = NULL;
	SIZE_T u16_size = 0;

	*result = NULL;

	// Root Path
	if (IS_ROOT_PATH(path))
	{
		UNICODE_STRING *u16_root_path = NULL;

		// UTF-16LE char truncation.
		status = dos_device_to_nt_device((CHAR)NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer[0], &u16_root_path);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		*result = u16_root_path;

		return STATUS_SUCCESS;
	}

	// Network Shares
	if ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'))
	{
		UTF8_STRING u8_path = {0};
		UNICODE_STRING u16_path = {0};
		SIZE_T size = (12 + length) * sizeof(WCHAR); // (+) "\Device\Mup\"
		SIZE_T offset = 0;

		u16_buffer = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, size);

		if (u16_buffer == NULL)
		{
			return STATUS_NO_MEMORY;
		}

		memcpy(PTR_OFFSET(u16_buffer, offset), L"\\Device\\Mup\\", 12 * sizeof(WCHAR));
		offset += 12 * sizeof(WCHAR);
		u16_size += offset;

		// Skip //
		u8_path.Buffer = PTR_OFFSET(path, 2);
		u8_path.Length = length - 2;
		u8_path.MaximumLength = length - 2;

		u16_path.Buffer = PTR_OFFSET(u16_buffer, offset);
		u16_path.Length = 0;
		u16_path.MaximumLength = size - offset;

		status = RtlUTF8StringToUnicodeString(&u16_path, &u8_path, FALSE);

		if (status != STATUS_SUCCESS)
		{
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_buffer);
			return status;
		}

		u16_size += u16_path.Length;

		goto path_coalesce;
	}

	if (IS_ABSOLUTE_PATH(path))
	{
		UNICODE_STRING *u16_device = NULL;
		UNICODE_STRING u16_path = {0};
		UTF8_STRING u8_path = {0};
		SIZE_T offset = 0;
		CHAR device = 0;

		// Cygwin path
		if (path[0] == '/')
		{
			if (!(isalpha(path[1]) && (path[2] == '/' || path[2] == '\0')))
			{
				return OS_STATUS_PATH_NOT_FOUND;
			}

			device = path[1];
		}
		else
		{
			device = path[0];
		}

		status = dos_device_to_nt_device(toupper(device), &u16_device);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		u16_buffer = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, u16_device->Length + ((length + 1) * sizeof(WCHAR)));

		if (u16_buffer == NULL)
		{
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_device);
			return STATUS_NO_MEMORY;
		}

		memcpy(PTR_OFFSET(u16_buffer, offset), u16_device->Buffer, u16_device->Length);
		offset += u16_device->Length;
		u16_size += offset;

		if (length > 2)
		{
			u8_path.Buffer = PTR_OFFSET(path, 2);
			u8_path.Length = length - 2;
			u8_path.MaximumLength = length - 2;

			u16_path.Buffer = PTR_OFFSET(u16_buffer, offset);
			u16_path.Length = 0;
			u16_path.MaximumLength = (length + 1) * sizeof(WCHAR);

			status = RtlUTF8StringToUnicodeString(&u16_path, &u8_path, FALSE);
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_device);

			if (status != STATUS_SUCCESS)
			{
				RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_buffer);
				return status;
			}

			u16_size += u16_path.Length;
		}
	}
	else
	{
		UNICODE_STRING *u16_root_path = NULL;
		UNICODE_STRING u16_path = {0};
		UTF8_STRING u8_path = {0};
		SIZE_T offset = 0;

		if (simple_path(path, length))
		{
			// Convert the path to UTF-16 and replace forward slashes with backward slashes
			u16_ntpath = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UNICODE_STRING) + ((length + 1) * sizeof(WCHAR)));

			if (u16_ntpath == NULL)
			{
				return STATUS_NO_MEMORY;
			}

			u16_ntpath->Buffer = PTR_OFFSET(u16_ntpath, sizeof(UNICODE_STRING));
			u16_ntpath->MaximumLength = (length + 1) * sizeof(WCHAR);

			u8_path.Buffer = (CHAR *)path;
			u8_path.Length = length;
			u8_path.MaximumLength = length;

			status = RtlUTF8StringToUnicodeString(u16_ntpath, &u8_path, FALSE);

			if (status != STATUS_SUCCESS)
			{
				return status;
			}

			for (uint16_t i = 0; i < length; ++i)
			{
				if (u16_ntpath->Buffer[i] == L'/')
				{
					u16_ntpath->Buffer[i] = L'\\';
				}
			}

			*result = u16_ntpath;
			status = STATUS_SUCCESS;

			return status;
		}

		status = get_handle_ntpath(root, &u16_root_path);

		if (status != STATUS_SUCCESS)
		{
			return status;
		}

		u16_buffer = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, u16_root_path->Length + ((length + 2) * sizeof(WCHAR)));

		if (u16_buffer == NULL)
		{
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_root_path);
			return STATUS_NO_MEMORY;
		}

		memcpy(PTR_OFFSET(u16_buffer, offset), u16_root_path->Buffer, u16_root_path->Length);
		offset += u16_root_path->Length;
		u16_size += offset;

		u16_buffer[offset / sizeof(WCHAR)] = L'\\';
		offset += sizeof(WCHAR);
		u16_size += offset;

		u8_path.Buffer = (CHAR *)path;
		u8_path.Length = length;
		u8_path.MaximumLength = length;

		u16_path.Buffer = PTR_OFFSET(u16_buffer, offset);
		u16_path.Length = 0;
		u16_path.MaximumLength = (length + 1) * sizeof(WCHAR);

		status = RtlUTF8StringToUnicodeString(&u16_path, &u8_path, FALSE);
		RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_root_path);

		if (status != STATUS_SUCCESS)
		{
			RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_buffer);
			return status;
		}

		u16_size += u16_path.Length;
	}

path_coalesce:

	// Convert forward slashes to backward slashes
	for (uint16_t i = 0; i < (u16_size / 2); ++i)
	{
		if (u16_buffer[i] == L'/')
		{
			u16_buffer[i] = L'\\';
		}
	}

	/*
	   This works like a stack.
	   When the component is other than '..' or '.' we push the contents onto the stack.
	   When the component is '..' the stack is popped.
	   This is a zero copy stack, i.e the components are not copied at all.
	   We use the starting index and the length(in bytes) to reference each component.
	*/
	path_stack stack = {0};
	uint32_t start = 0;

	for (uint32_t i = 8;; ++i) // start after \Device\:
	{
		if (u16_buffer[i] == L'\\' || u16_buffer[i] == L'\0')
		{
			if (i - start > 2) // not '.' or '..'
			{
				void *temp = push_path_component(&stack, start, (i - start) * sizeof(WCHAR)); // push stack

				if (temp == NULL)
				{
					status = STATUS_NO_MEMORY;
					goto finish;
				}
			}
			else
			{
				if (i - start == 2 && (u16_buffer[start] == L'.' && u16_buffer[start + 1] == L'.'))
				{
					pop_path_component(&stack);
				}
				else if (i - start == 1 && u16_buffer[start] == L'.')
				{
					; // do nothing
				}
				else
				{
					void *temp = push_path_component(&stack, start, (i - start) * sizeof(WCHAR)); // push stack

					if (temp == NULL)
					{
						status = STATUS_NO_MEMORY;
						goto finish;
					}
				}
			}

			if (u16_buffer[i] == L'\0')
			{
				break;
			}

			start = i + 1;
		}
	}

	u16_ntpath = RtlAllocateHeap(NtCurrentProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UNICODE_STRING) + stack.length);

	if (u16_ntpath == NULL)
	{
		status = STATUS_NO_MEMORY;
		goto finish;
	}

	u16_ntpath->Buffer = PTR_OFFSET(u16_ntpath, sizeof(UNICODE_STRING));

	for (uint32_t i = 0; i < stack.count; i++)
	{
		memcpy(PTR_OFFSET(u16_ntpath->Buffer, u16_ntpath->Length), PTR_OFFSET(u16_buffer, stack.components[i].start * sizeof(WCHAR)),
			   stack.components[i].length);
		u16_ntpath->Length += stack.components[i].length;

		if (i + 1 < stack.count)
		{
			u16_ntpath->Buffer[u16_ntpath->Length / sizeof(WCHAR)] = L'\\';
			u16_ntpath->Length += 2;
		}
	}

	if (stack.count == 1)
	{
		// The case where we resolve a volume. eg C:
		// Always add trailing slash to the volume so that it can be treated as a directory by the NT calls.
		u16_ntpath->Buffer[u16_ntpath->Length / sizeof(WCHAR)] = L'\\';
		u16_ntpath->Length += 2;
	}

	// Terminate with NULL
	u16_ntpath->Buffer[u16_ntpath->Length / sizeof(WCHAR)] = L'\0';
	u16_ntpath->MaximumLength = u16_ntpath->Length + 2;

	*result = u16_ntpath;
	status = STATUS_SUCCESS;

finish:
	RtlFreeHeap(NtCurrentProcessHeap(), 0, stack.components);
	RtlFreeHeap(NtCurrentProcessHeap(), 0, u16_buffer);

	return status;
}
