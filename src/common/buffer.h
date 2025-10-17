/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef COMMON_BUFFER_H
#define COMMON_BUFFER_H

#include <types.h>
#include <minmax.h>
#include <byteswap.h>
#include <load.h>
#include <ptr.h>

#include <stdlib.h>
#include <string.h>

typedef struct _buffer_t
{
	byte_t *data;
	size_t pos;
	size_t size;

	void *ctx;
	size_t (*read)(struct _buffer_t *buffer, size_t size);
	size_t (*write)(struct _buffer_t *buffer, size_t size);
	uint32_t error;
} buffer_t;

static inline void advance(buffer_t *buffer, size_t step)
{
	buffer->pos = MIN(buffer->pos + step, buffer->size);
}

static inline size_t pending(buffer_t *buffer)
{
	return buffer->size - buffer->pos;
}

static inline void *current(buffer_t *buffer)
{
	return PTR_OFFSET(buffer->data, buffer->pos);
}

static inline void flush(buffer_t *buffer)
{
	buffer->write(buffer, 0);
}

static inline size_t read8(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 1) > buffer->size)
	{
		return 0;
	}

	LOAD_8(out, buffer->data + buffer->pos);
	buffer->pos += 1;

	return 1;
}

static inline size_t read16(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 2) > buffer->size)
	{
		return 0;
	}

	LOAD_16(out, buffer->data + buffer->pos);
	buffer->pos += 2;

	return 2;
}

static inline size_t read16_be(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 2) > buffer->size)
	{
		return 0;
	}

	LOAD_16BE(out, buffer->data + buffer->pos);
	buffer->pos += 2;

	return 2;
}

static inline size_t read32(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 4) > buffer->size)
	{
		return 0;
	}

	LOAD_32(out, buffer->data + buffer->pos);
	buffer->pos += 4;

	return 4;
}

static inline size_t read32_be(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 4) > buffer->size)
	{
		return 0;
	}

	LOAD_32BE(out, buffer->data + buffer->pos);
	buffer->pos += 4;

	return 4;
}

static inline size_t read64(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 8) > buffer->size)
	{
		return 0;
	}

	LOAD_64(out, buffer->data + buffer->pos);
	buffer->pos += 8;

	return 8;
}

static inline size_t read64_be(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 8) > buffer->size)
	{
		return 0;
	}

	LOAD_64BE(out, buffer->data + buffer->pos);
	buffer->pos += 8;

	return 8;
}

static inline byte_t readbyte(buffer_t *buffer)
{
	if ((buffer->pos + 1) > buffer->size)
	{
		return 0;
	}

	return buffer->data[buffer->pos++];
}

static inline size_t readn(buffer_t *buffer, void *out, size_t size)
{
	if ((buffer->pos + size) > buffer->size)
	{
		return 0;
	}

	memcpy(out, buffer->data + buffer->pos, size);
	buffer->pos += size;

	return size;
}

static inline byte_t peekbyte(buffer_t *buffer, uint32_t offset)
{
	if ((buffer->pos + offset) >= buffer->size)
	{
		return 0;
	}

	return buffer->data[buffer->pos + offset];
}

static inline size_t writebyte(buffer_t *buffer, byte_t byte)
{
	if ((buffer->pos + 1) > buffer->size)
	{
		if (buffer->write == NULL)
		{
			return 0;
		}

		buffer->write(buffer, 1);

		if (buffer->error)
		{
			return 0;
		}
	}

	buffer->data[buffer->pos] = byte;
	buffer->pos += 1;

	return 1;
}

static inline size_t writen(buffer_t *buffer, void *in, size_t size)
{
	if ((buffer->pos + size) > buffer->size)
	{
		if (buffer->write == NULL)
		{
			return 0;
		}

		buffer->write(buffer, size);

		if (buffer->error)
		{
			return 0;
		}
	}

	memcpy(buffer->data + buffer->pos, in, size);
	buffer->pos += size;

	return size;
}

size_t peekline(buffer_t *buffer, void *out, size_t size);
size_t readline(buffer_t *buffer, void *out, size_t size);
size_t writeline(buffer_t *buffer, void *in, size_t size, byte_t crlf);

void memory_buffer_init(buffer_t *buffer, size_t size);
void memory_buffer_free(buffer_t *buffer);
size_t memory_buffer_write(buffer_t *buffer, size_t size);

#define CHECK_READ(read, error) \
	if ((read) == 0)            \
	{                           \
		return (error);         \
	}

#endif
