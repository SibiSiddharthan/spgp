/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <buffer.h>

size_t peekline(buffer_t *buffer, void *out, size_t size)
{
	void *result = NULL;
	size_t copy_size = 0;

	result = memchr(buffer->data + buffer->pos, '\n', buffer->size - buffer->pos);

	// Copy the maximum amount allowable
	if (result == NULL)
	{
		copy_size = MIN(size, buffer->size - buffer->pos);
		memcpy(out, buffer->data + buffer->pos, copy_size);

		return copy_size;
	}

	copy_size = PTR_DIFF(result, buffer->data + buffer->pos);

	if (copy_size == 0)
	{
		// Nothing to copy.
		return 0;
	}

	// Check for \r
	if (buffer->data[buffer->pos + copy_size - 1] == '\r')
	{
		if (copy_size == 1)
		{
			// Again, nothing to copy
			return 0;
		}

		copy_size -= 1;
	}

	// Copy only what is possible
	memcpy(out, buffer->data + buffer->pos, MIN(size, copy_size));

	return MIN(size, copy_size);
}

size_t readline(buffer_t *buffer, void *out, size_t size)
{
	void *result = NULL;
	size_t copy_size = 0;
	size_t move_size = 0;

	result = memchr(buffer->data + buffer->pos, '\n', buffer->size - buffer->pos);

	// Copy the maximum amount allowable
	if (result == NULL)
	{
		copy_size = MIN(size, buffer->size - buffer->pos);
		memcpy(out, buffer->data + buffer->pos, copy_size);
		buffer->pos += copy_size;

		return copy_size;
	}

	copy_size = PTR_DIFF(result, buffer->data + buffer->pos);
	move_size = 1;

	if (copy_size == 0)
	{
		// Nothing to copy.
		// Move pos 1 character forward
		buffer->pos += 1;
		return 0;
	}

	// Check for \r
	if (buffer->data[buffer->pos + copy_size - 1] == '\r')
	{
		if (copy_size == 1)
		{
			// Again, nothing to copy
			// Move pos by 2 characters "\r\n"
			buffer->pos += 2;
			return 0;
		}

		copy_size -= 1;
		move_size += 1;
	}

	// Copy only what is possible
	if (size < copy_size)
	{
		memcpy(out, buffer->data + buffer->pos, size);
		buffer->pos += size;
	}
	else
	{
		memcpy(out, buffer->data + buffer->pos, copy_size);
		buffer->pos += copy_size + move_size;
	}

	return MIN(size, copy_size);
}

size_t writeline(buffer_t *buffer, void *in, size_t size, byte_t crlf)
{
	size_t required_size = size + (crlf ? 2 : 1);

	if ((buffer->pos + required_size) > buffer->size)
	{
		if (buffer->write == NULL)
		{
			return 0;
		}

		buffer->write(buffer, required_size);

		if (buffer->error)
		{
			return 0;
		}
	}

	memcpy(buffer->data + buffer->pos, in, size);
	buffer->pos += size;

	if (crlf)
	{
		buffer->data[buffer->pos++] = '\r';
		buffer->data[buffer->pos++] = '\n';
	}
	else
	{
		buffer->data[buffer->pos++] = '\n';
	}

	return required_size;
}

void memory_buffer_init(buffer_t *buffer, size_t size)
{
	size_t min_size = 256;

	memset(buffer, 0, sizeof(buffer_t));

	while (min_size < size)
	{
		min_size *= 2;
	}

	buffer->size = min_size;
	buffer->data = malloc(buffer->size);
	buffer->write = memory_buffer_write;

	if (buffer->data != NULL)
	{
		memset(buffer->data, 0, buffer->size);
	}
}

void memory_buffer_free(buffer_t *buffer)
{
	free(buffer->data);
	memset(buffer, 0, sizeof(buffer_t));
}

size_t memory_buffer_write(buffer_t *buffer, size_t size)
{
	size_t old_size = buffer->size;

	buffer->error = 0;

	if (size == 0)
	{
		// nop
		return 0;
	}

	if (buffer->size == 0)
	{
		// Allocate 64 bytes initially
		buffer->pos = 0;
		buffer->size = 64;

		// Grow to power of 2
		while (size > buffer->size)
		{
			buffer->size *= 2;
		}

		buffer->data = malloc(buffer->size);

		if (buffer->data == NULL)
		{
			buffer->error = 1;
			return 0;
		}

		memset(buffer->data, 0, buffer->size);
		return buffer->size;
	}

	// Grow to power of 2
	while (size > buffer->size - buffer->pos)
	{
		buffer->size *= 2;
	}

	buffer->data = realloc(buffer->data, buffer->size);

	if (buffer->data == NULL)
	{
		buffer->error = 1;
		return 0;
	}

	memset(PTR_OFFSET(buffer->data, old_size), 0, buffer->size - old_size);

	return buffer->size;
}
