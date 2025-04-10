/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_BUFFER_H
#define SPGP_BUFFER_H

#include <types.h>
#include <byteswap.h>
#include <load.h>
#include <string.h>

typedef struct _buffer_t
{
	byte_t *data;
	size_t pos;
	size_t size;
	size_t capacity;
} buffer_t;

typedef struct _buffer_range_t
{
	byte_t *data;
	size_t start;
	size_t end;
} buffer_range_t;

static inline size_t read8(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 1) >= buffer->size)
	{
		return 0;
	}

	LOAD_8(out, buffer + buffer->pos);
	buffer->pos += 1;

	return 1;
}

static inline size_t read16(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 2) >= buffer->size)
	{
		return 0;
	}

	LOAD_16(out, buffer + buffer->pos);
	buffer->pos += 2;

	return 2;
}

static inline size_t read16_be(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 2) >= buffer->size)
	{
		return 0;
	}

	LOAD_16BE(out, buffer + buffer->pos);
	buffer->pos += 2;

	return 2;
}

static inline size_t read32(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 4) >= buffer->size)
	{
		return 0;
	}

	LOAD_32(out, buffer + buffer->pos);
	buffer->pos += 4;

	return 4;
}

static inline size_t read32_be(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 4) >= buffer->size)
	{
		return 0;
	}

	LOAD_32BE(out, buffer + buffer->pos);
	buffer->pos += 4;

	return 4;
}

static inline size_t read64(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 8) >= buffer->size)
	{
		return 0;
	}

	LOAD_64(out, buffer + buffer->pos);
	buffer->pos += 8;

	return 8;
}

static inline size_t read64_be(buffer_t *buffer, void *out)
{
	if ((buffer->pos + 8) >= buffer->size)
	{
		return 0;
	}

	LOAD_64BE(out, buffer + buffer->pos);
	buffer->pos += 8;

	return 8;
}

static inline size_t readn(buffer_t *buffer, void *out, size_t size)
{
	if ((buffer->pos + size) >= buffer->size)
	{
		return 0;
	}

	memcpy(out, buffer + buffer->pos, size);
	buffer->pos += size;

	return size;
}

#define CHECK_READ(read, error) \
	if ((read) == 0)            \
	{                           \
		return (error);         \
	}

#endif
