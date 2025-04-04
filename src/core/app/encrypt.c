/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <session.h>
#include <seipd.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t spgp_encrypt(spgp_command *command)
{
	pgp_stream_t *stream = NULL;
	pgp_skesk_packet *session = NULL;
	pgp_seipd_packet *seipd = NULL;

	pgp_s2k s2k = {.id = PGP_S2K_ITERATED,
				   .iterated = {.hash_id = PGP_SHA1, .count = 200, .salt = {0x06, 0xa1, 0x02, 0x2a, 0x22, 0x51, 0xc1, 0x6a}}};

	byte_t session_key[64] = {0};
	byte_t session_key_size = 0;

	void *buffer = NULL;
	size_t size = 0;

	buffer = spgp_read_file(command->decrypt.file, SPGP_STD_INPUT, &size);

	if (command->passhprase == NULL)
	{
		printf("Passphrase required.\n");
		exit(1);
	}

	session = pgp_skesk_packet_new(PGP_SKESK_V4, PGP_AES_128, 0, &s2k);
	session = pgp_skesk_packet_session_key_encrypt(session, command->passhprase, strlen(command->passhprase), NULL, 0, NULL, 0);

	session_key_size = pgp_s2k_hash(&s2k, command->passhprase, strlen(command->passhprase), session_key, 16);

	seipd = pgp_seipd_packet_new(PGP_SEIPD_V1, PGP_AES_128, 0, 0);
	seipd = pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, buffer, size);

	stream = pgp_stream_new(2);

	pgp_stream_push_packet(stream, session);
	pgp_stream_push_packet(stream, seipd);

	spgp_write_pgp_packets(command->output, SPGP_STD_OUTPUT, stream);

	free(buffer);

	return 0;
}

uint32_t spgp_decrypt(spgp_command *command)
{
	pgp_stream_t *stream = NULL;
	pgp_skesk_packet *session = NULL;
	pgp_seipd_packet *seipd = NULL;

	byte_t session_key[64] = {0};
	byte_t session_key_size = 0;

	void *buffer = NULL;
	uint32_t data_size = 0;

	stream = spgp_read_pgp_packets(command->decrypt.file, SPGP_STD_INPUT);

	if (stream == NULL)
	{
		printf("Invalid pgp stream.\n");
		exit(1);
	}

	session = stream->packets[0];
	seipd = stream->packets[1];

	if (command->passhprase == NULL)
	{
		printf("Passphrase required.\n");
		exit(1);
	}

	session_key_size = pgp_skesk_packet_session_key_decrypt(session, command->passhprase, strlen(command->passhprase), session_key, 64);

	if (session_key_size == 0)
	{
		printf("Passphrase required.\n");
		exit(1);
	}

	seipd->symmetric_key_algorithm_id = session->symmetric_key_algorithm_id;

	data_size = seipd->data_size;
	buffer = malloc(data_size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(2);
	}

	data_size = pgp_seipd_packet_decrypt(seipd, session_key, session_key_size, buffer, data_size);

	if (data_size == 0)
	{
		printf("Decryption failure.\n");
		exit(1);
	}

	spgp_write_file(command->output, SPGP_STD_OUTPUT, buffer, data_size);

	free(buffer);

	return 0;
}
