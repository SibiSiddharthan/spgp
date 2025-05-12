/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <os.h>

#include <packet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static status_t spgp_read_disk_file(handle_t handle, size_t size, void **buffer, size_t *result)
{
	status_t status = 0;
	size_t read = 0;

	*buffer = malloc(size);

	if (*buffer == NULL)
	{
		return OS_STATUS_NO_MEMORY;
	}

	status = os_read(handle, *buffer, size, &read);

	if (status != OS_STATUS_SUCCESS)
	{
		free(*buffer);
	}

	*result = read;

	return status;
}

static status_t spgp_read_pipe_file(handle_t handle, void **buffer, size_t *result)
{
	status_t status = 0;
	size_t read = 0;
	size_t size = 0;

	size = 65536;
	*result = 0;
	*buffer = malloc(size);

	if (*buffer == NULL)
	{
		return OS_STATUS_NO_MEMORY;
	}

	while (1)
	{
		// Read in 64KB chunks
		status = os_read(handle, PTR_OFFSET(*buffer, read), 65536, &read);

		*result += read;

		if (*result == size)
		{
			void *temp = NULL;

			size *= 2;
			temp = realloc(*buffer, size);

			if (temp == NULL)
			{
				free(*buffer);
				return OS_STATUS_NO_MEMORY;
			}

			*buffer = temp;
		}

		if (status != OS_STATUS_SUCCESS)
		{
			if (status == OS_STATUS_END_OF_DATA)
			{
				status = OS_STATUS_SUCCESS;
				break;
			}

			free(*buffer);
			return status;
		}
	}

	return status;
}

static status_t spgp_read_handle(handle_t handle, void **buffer, size_t *size)
{
	status_t status = 0;
	stat_t stat = {0};

	status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

	if (status != OS_STATUS_SUCCESS)
	{
		return status;
	}

	if (STAT_IS_REG(stat.st_mode))
	{
		status = spgp_read_disk_file(handle, stat.st_size, buffer, size);
	}
	else
	{
		status = spgp_read_pipe_file(handle, buffer, size);
	}

	return status;
}

pgp_literal_packet *spgp_literal_read_file(const char *file, pgp_literal_data_format format)
{
	handle_t handle = 0;
	stat_t stat = {0};

	void *buffer = NULL;
	size_t size = 0;

	pgp_literal_packet *literal = NULL;

	if (file != NULL)
	{
		OS_CALL(os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_READ, 0, 0), printf("Unable to open file %s", file));
		OS_CALL(os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t)), printf("Unable to stat file %s", file));
	}
	else
	{
		handle = STDIN_HANDLE;
		OS_CALL(os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t)),
				printf("Unable to stat handle %u", OS_HANDLE_AS_UINT(handle)));
	}

	if (STAT_IS_REG(stat.st_mode))
	{
		OS_CALL(spgp_read_disk_file(handle, stat.st_size, &buffer, &size), printf("Unable to read handle %u", OS_HANDLE_AS_UINT(handle)));
	}
	else
	{
		OS_CALL(spgp_read_pipe_file(handle, &buffer, &size), printf("Unable to read handle %u", OS_HANDLE_AS_UINT(handle)));
	}

	PGP_CALL(pgp_literal_packet_new(&literal, PGP_HEADER, stat.st_mtim.tv_sec, (void *)file, strlen(file)));
	PGP_CALL(pgp_literal_packet_store(literal, format, buffer, size));

	free(buffer);

	if (file != NULL)
	{
		OS_CALL(os_close(handle), printf("Unable to close handle %u", OS_HANDLE_AS_UINT(handle)));
	}

	return literal;
}

void spgp_literal_write_file(const char *file, pgp_literal_packet *literal)
{
	handle_t handle = 0;
	size_t result = 0;

	if (file != NULL)
	{
		OS_CALL(os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_WRITE, FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700),
				printf("Unable to open file %s", file));
	}
	else
	{
		handle = STDOUT_HANDLE;
	}

	// Write the literal data
	OS_CALL(os_write(handle, literal->data, literal->data_size, &result),
			printf("Unable to write to handle %u", OS_HANDLE_AS_UINT(handle)));

	if (literal->partials != NULL)
	{
		for (uint32_t i = 0; i < literal->partials->count; ++i)
		{
			pgp_partial_packet *partial = literal->partials->packets[i];

			OS_CALL(os_write(handle, partial->data, partial->header.body_size, &result),
					printf("Unable to write to handle %u", OS_HANDLE_AS_UINT(handle)));
		}
	}

	if (file != NULL)
	{
		OS_CALL(os_close(handle), printf("Unable to close handle %u", OS_HANDLE_AS_UINT(handle)));
	}
}

pgp_stream_t *spgp_read_pgp_packets_from_handle(handle_t handle)
{
	status_t status = 0;

	byte_t *in = NULL;

	void *buffer = NULL;
	size_t size = 0;

	pgp_stream_t *stream = NULL;

	status = spgp_read_handle(handle, &buffer, &size);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to read file.\n");
		exit(2);
	}

	in = buffer;

	if (in[0] > 128)
	{
		PGP_CALL(pgp_stream_read(&stream, buffer, size));
	}
	else
	{
		PGP_CALL(pgp_stream_read_armor(&stream, buffer, size));
	}

	free(buffer);

	return stream;
}

pgp_stream_t *spgp_read_pgp_packets(const char *file)
{
	handle_t handle = 0;
	pgp_stream_t *stream = NULL;

	if (file != NULL)
	{
		OS_CALL(os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_READ, 0, 0), printf("Unable to open file %s", file));
	}
	else
	{
		handle = STDIN_HANDLE;
	}

	stream = spgp_read_pgp_packets_from_handle(handle);

	if (file != NULL)
	{
		OS_CALL(os_close(handle), printf("Unable to close handle %u", OS_HANDLE_AS_UINT(handle)));
	}

	return stream;
}

void spgp_write_pgp_packets_handle(handle_t handle, pgp_stream_t *stream, armor_options *options)
{
	void *buffer = NULL;
	size_t size = 0;
	size_t write = 0;

	if (options == NULL)
	{
		PGP_CALL(pgp_stream_write(stream, &buffer, &size));
	}
	else
	{
		PGP_CALL(pgp_stream_write_armor(stream, options, &buffer, &size));
	}

	OS_CALL(os_write(handle, buffer, size, &write), printf("Unable to write to file"));

	free(buffer);
}

void spgp_write_pgp_packets(const char *file, pgp_stream_t *stream, armor_options *options)
{
	handle_t handle = 0;

	if (file != NULL)
	{
		OS_CALL(os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_WRITE, FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700),
				printf("Unable to open file %s", file));
	}
	else
	{
		handle = STDOUT_HANDLE;
	}

	spgp_write_pgp_packets_handle(handle, stream, options);

	if (file != NULL)
	{
		OS_CALL(os_close(handle), printf("Unable to close handle %u", OS_HANDLE_AS_UINT(handle)));
	}
}
