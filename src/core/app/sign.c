/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <signature.h>

#include <stdio.h>
#include <string.h>

uint32_t spgp_sign(spgp_command *command)
{
	char buffer[65536] = {0};

	status_t status = 0;
	size_t size = 0;

	file_t file = {0};

	pgp_stream_t *key_stream = NULL;
	pgp_key_packet *key = NULL;

	if (command->sign.packet != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->sign.packet, strlen(command->sign.packet), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->sign.packet);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);

		key_stream = pgp_stream_read(buffer, size);
		key = key_stream->packets[0];
	}
	else
	{
		return 2;
	}

	if (command->sign.file != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->sign.file, strlen(command->sign.file), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->sign.file);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);
	}
	else
	{
		return 2;
	}

	if (command->passhprase != NULL)
	{
		pgp_key_packet_decrypt(key, command->passhprase, strlen(command->passhprase));
	}

	pgp_signature_packet *sign = pgp_signature_packet_new(PGP_SIGNATURE_V4, PGP_BINARY_SIGNATURE);

	pgp_signature_packet_sign(sign, key, PGP_SHA2_256, time(NULL), buffer, size);

	if (command->output != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->output, strlen(command->output), FILE_WRITE, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "Unable to create file: %s\n", (byte_t *)command->output);
			return 1;
		}

		size = pgp_packet_write(sign, buffer, 65536);

		file_write(&file, buffer, size);
		file_close(&file);
	}
	else
	{
		return 2;
	}

	return 0;
}

uint32_t spgp_verify(spgp_command *command)
{
	char buffer[65536] = {0};

	status_t status = 0;
	size_t size = 0;

	file_t file = {0};

	pgp_stream_t *key_stream = NULL;
	pgp_key_packet *key = NULL;
	pgp_signature_packet *sign = NULL;

	if (command->verify.packet != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->verify.packet, strlen(command->verify.packet), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->verify.packet);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);

		key_stream = pgp_stream_read(buffer, size);
		key = key_stream->packets[0];
	}
	else
	{
		return 2;
	}

	if (command->verify.sign != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->verify.sign, strlen(command->verify.sign), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->verify.sign);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);

		sign = pgp_signature_packet_read(buffer, size);
	}
	else
	{
		return 2;
	}

	if (command->verify.file != NULL)
	{
		status = file_open(&file, HANDLE_CWD, command->verify.file, strlen(command->verify.file), FILE_READ, 65536);

		if (status != OS_STATUS_SUCCESS)
		{
			fprintf(stderr, "File not found: %s\n", command->verify.file);
			return 1;
		}

		size = file_read(&file, buffer, 65536);

		file_close(&file);
	}
	else
	{
		return 2;
	}

	uint32_t result = pgp_signature_packet_verify(sign, key, buffer, size);

	printf("%s\n", result == 1 ? "Good Signature" : "Bad Signature");

	return 0;
}
