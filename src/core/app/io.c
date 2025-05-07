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

status_t spgp_read_handle(handle_t handle, void **buffer, size_t *size)
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

pgp_literal_packet *spgp_read_file_as_literal(const char *file, pgp_literal_data_format format)
{
	status_t os_status = 0;
	handle_t handle = 0;
	stat_t stat = {0};

	void *buffer = NULL;
	size_t size = 0;

	pgp_error_t pgp_status = 0;
	pgp_literal_packet *literal = NULL;

	if (file != NULL)
	{
		os_status = os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_READ, 0, 0);

		if (os_status != OS_STATUS_SUCCESS)
		{
			printf("Unable to open file %s.\n", file);
			exit(2);
		}

		os_status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

		if (os_status != OS_STATUS_SUCCESS)
		{
			printf("Unable to stat file %s.\n", file);
			exit(2);
		}
	}
	else
	{
		handle = STDIN_HANDLE;
		os_status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

		if (os_status != OS_STATUS_SUCCESS)
		{
			printf("Unable to stat file %s.\n", file);
			exit(2);
		}
	}

	if (STAT_IS_REG(stat.st_mode))
	{
		os_status = spgp_read_disk_file(handle, stat.st_size, &buffer, &size);
	}
	else
	{
		os_status = spgp_read_pipe_file(handle, &buffer, &size);
	}

	pgp_status = pgp_literal_packet_new(&literal, PGP_HEADER, stat.st_mtim.tv_sec, (void *)file, strlen(file));

	if (pgp_status != PGP_SUCCESS)
	{
		printf("%s\n", pgp_error(pgp_status));
		exit(2);
	}

	pgp_status = pgp_literal_packet_store(literal, format, buffer, size);

	if (pgp_status != PGP_SUCCESS)
	{
		printf("%s\n", pgp_error(pgp_status));
		exit(2);
	}

	free(buffer);

	return literal;
}

void *spgp_read_file(const char *file, uint32_t options, size_t *size)
{
	status_t status = 0;
	handle_t handle = 0;
	stat_t stat = {0};

	void *buffer = NULL;

	if (file != NULL)
	{
		status = os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_READ, 0, 0);

		if (status != OS_STATUS_SUCCESS)
		{
			printf("Unable to open file %s.\n", file);
			exit(2);
		}

		status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

		if (status != OS_STATUS_SUCCESS)
		{
			printf("Unable to stat file %s.\n", file);
			exit(2);
		}
	}
	else
	{
		if (options & SPGP_STD_INPUT)
		{
			handle = STDIN_HANDLE;
			status = os_stat(handle, NULL, 0, STAT_NO_ACLS, &stat, sizeof(stat_t));

			if (status != OS_STATUS_SUCCESS)
			{
				printf("Unable to stat file %s.\n", file);
				exit(2);
			}
		}
	}

	if (handle == 0)
	{
		exit(2);
	}

	if (STAT_IS_REG(stat.st_mode))
	{
		status = spgp_read_disk_file(handle, stat.st_size, &buffer, size);
	}
	else
	{
		status = spgp_read_pipe_file(handle, &buffer, size);
	}

	if (file != NULL)
	{
		os_close(handle);
	}

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to read file %s.\n", file);
		exit(2);
	}

	return buffer;
}

pgp_stream_t *spgp_read_pgp_packets(const char *file, uint32_t options)
{
	void *buffer = NULL;
	size_t size = 0;

	pgp_error_t error = 0;
	pgp_stream_t *stream = pgp_stream_new(4);

	buffer = spgp_read_file(file, options, &size);
	error = pgp_stream_read(stream, buffer, size);

	free(buffer);

	if (error != PGP_SUCCESS)
	{
		printf("Invalid pgp stream.\n");
		exit(1);
	}

	return stream;
}

void *spgp_read_pgp_packet(const char *file, uint32_t options)
{
	void *buffer = NULL;
	void *packet = NULL;
	size_t size = 0;

	pgp_error_t error = 0;

	buffer = spgp_read_file(file, options, &size);
	error = pgp_packet_read(&packet, buffer, size);

	free(buffer);

	if (error != PGP_SUCCESS)
	{
		printf("Bad packet.\n");
		exit(1);
	}

	return packet;
}

pgp_stream_t *spgp_read_pgp_packets_from_handle(handle_t handle)
{
	status_t status = 0;

	void *buffer = NULL;
	size_t size = 0;

	pgp_error_t error = 0;
	pgp_stream_t *stream = pgp_stream_new(4);

	status = spgp_read_handle(handle, &buffer, &size);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to read file.\n");
		exit(2);
	}

	error = pgp_stream_read(stream, buffer, size);

	if (error != PGP_SUCCESS)
	{
		printf("Invalid pgp stream.\n");
		exit(1);
	}

	free(buffer);

	return stream;
}

void *spgp_read_pgp_packet_from_handle(handle_t handle)
{
	status_t status = 0;

	void *buffer = NULL;
	void *packet = NULL;
	size_t size = 0;

	pgp_error_t error = 0;

	status = spgp_read_handle(handle, &buffer, &size);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to read file.\n");
		exit(2);
	}

	error = pgp_packet_read(&packet, buffer, size);

	free(buffer);

	if (error != PGP_SUCCESS)
	{
		printf("Bad packet.\n");
		exit(1);
	}

	return packet;
}

size_t spgp_write_handle(handle_t handle, void *buffer, size_t size)
{
	status_t status = 0;
	size_t write = 0;

	status = os_write(handle, buffer, size, &write);

	return status;
}

size_t spgp_write_file(const char *file, uint32_t options, void *buffer, size_t size)
{
	status_t status = 0;
	handle_t handle = 0;

	size_t write = 0;

	if (file != NULL)
	{
		status = os_open(&handle, HANDLE_CWD, file, strlen(file), FILE_ACCESS_WRITE, FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700);

		if (status != OS_STATUS_SUCCESS)
		{
			printf("Unable to open file %s.\n", file);
			exit(2);
		}
	}
	else
	{
		if (options & SPGP_STD_OUTPUT)
		{
			handle = STDOUT_HANDLE;
		}
	}

	if (handle == 0)
	{
		exit(2);
	}

	status = os_write(handle, buffer, size, &write);

	if (file != NULL)
	{
		os_close(handle);
	}

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to write file %s.\n", file);
		exit(2);
	}

	return write;
}

size_t spgp_write_pgp_packets(const char *file, uint32_t options, pgp_stream_t *stream)
{
	void *buffer = NULL;
	size_t size = 0;
	size_t result = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		pgp_packet_header *header = stream->packets[i];

		size += PGP_PACKET_OCTETS(*header);
	}

	buffer = malloc(size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(1);
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		result += pgp_packet_write(stream->packets[i], PTR_OFFSET(buffer, result), size - result);
	}

	result = spgp_write_file(file, options, buffer, size);

	free(buffer);

	return result;
}

size_t spgp_write_pgp_packet(const char *file, uint32_t options, void *packet)
{
	void *buffer = NULL;

	pgp_packet_header *header = packet;
	size_t size = PGP_PACKET_OCTETS(*header);

	buffer = malloc(size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(1);
	}

	pgp_packet_write(packet, buffer, size);
	spgp_write_file(file, options, buffer, size);

	free(buffer);

	return size;
}

size_t spgp_write_pgp_packets_to_handle(handle_t handle, pgp_stream_t *stream)
{
	status_t status = 0;
	size_t write = 0;

	void *buffer = NULL;
	size_t size = 0;
	size_t result = 0;

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		pgp_packet_header *header = stream->packets[i];

		size += PGP_PACKET_OCTETS(*header);
	}

	buffer = malloc(size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(1);
	}

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		result += pgp_packet_write(stream->packets[i], PTR_OFFSET(buffer, result), size - result);
	}

	status = os_write(handle, buffer, size, &write);

	free(buffer);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to write to file.\n");
		exit(2);
	}

	return result;
}

size_t spgp_write_pgp_packet_to_handle(handle_t handle, void *packet)
{
	status_t status = 0;
	size_t write = 0;

	void *buffer = NULL;

	pgp_packet_header *header = packet;
	size_t size = PGP_PACKET_OCTETS(*header);

	buffer = malloc(size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(1);
	}

	pgp_packet_write(packet, buffer, size);

	status = os_write(handle, buffer, size, &write);

	free(buffer);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to write to file.\n");
		exit(2);
	}

	return write;
}
