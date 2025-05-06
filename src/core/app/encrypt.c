/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <crypto.h>
#include <session.h>
#include <seipd.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// clang-format off
static const byte_t hex_to_nibble_table[256] = 
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,                       // 0 - 9
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // A - F
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,         // a - f
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};
// clang-format on

static pgp_key_packet *spgp_search_key_from_user(char *user)
{
	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t pos = 0;

	for (byte_t i = 0; user[i] != '\0';)
	{
		fingerprint[pos++] = (hex_to_nibble_table[(byte_t)user[i]] * 16) + hex_to_nibble_table[(byte_t)user[i + 1]];
		i += 2;
	}

	return spgp_read_key(fingerprint, pos);
}

uint32_t spgp_encrypt(spgp_command *command)
{
	pgp_stream_t *stream = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_literal_packet *literal = NULL;

	byte_t session_key[64] = {0};
	byte_t session_key_size = 0;

	void *file = NULL;
	void *buffer = NULL;
	size_t size = 0;

	void *lit_buffer = NULL;

	if (command->files != NULL)
	{
		file = command->files->packets[0];
	}

	buffer = spgp_read_file(file, SPGP_STD_INPUT, &size);

	if (file != NULL)
	{
		pgp_literal_packet_new(&literal, PGP_HEADER, 0, file, strlen(file));
	}
	else
	{
		pgp_literal_packet_new(&literal, PGP_HEADER, 0, NULL, 0);
	}

	pgp_literal_packet_store(literal, PGP_LITERAL_DATA_BINARY, buffer, size);

	lit_buffer = malloc(PGP_PACKET_OCTETS(literal->header));
	pgp_literal_packet_write(literal, lit_buffer, PGP_PACKET_OCTETS(literal->header));

	stream = pgp_stream_new(2);

	if (command->symmetric)
	{
		pgp_skesk_packet *session = NULL;
		pgp_s2k s2k = {.id = PGP_S2K_ITERATED,
					   .iterated = {.hash_id = PGP_SHA1, .count = 200, .salt = {0x06, 0xa1, 0x02, 0x2a, 0x22, 0x51, 0xc1, 0x6a}}};

		if (command->passhprase == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		pgp_skesk_packet_new(&session, PGP_SKESK_V4, PGP_AES_128, 0, &s2k);
		pgp_skesk_packet_session_key_encrypt(session, command->passhprase, strlen(command->passhprase), NULL, 0, NULL, 0);

		session_key_size = pgp_s2k_hash(&s2k, command->passhprase, strlen(command->passhprase), session_key, 16);

		pgp_stream_push(stream, session);
	}
	else
	{
		pgp_pkesk_packet *session = NULL;
		pgp_key_packet *key = NULL;

		key = spgp_search_key_from_user(command->user);
		pgp_pkesk_packet_new(&session, PGP_PKESK_V3);

		session_key_size = pgp_rand(session_key, 16);
		pgp_pkesk_packet_session_key_encrypt(session, key, 0, PGP_AES_128, session_key, session_key_size);

		pgp_stream_push(stream, session);
	}

	pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, PGP_AES_128, 0, 0);
	pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, NULL);

	pgp_stream_push(stream, seipd);

	spgp_write_pgp_packets(command->output, SPGP_STD_OUTPUT, stream);

	free(buffer);
	pgp_literal_packet_delete(literal);

	return 0;
}

uint32_t spgp_decrypt(spgp_command *command)
{
	pgp_stream_t *stream = NULL;
	pgp_stream_t *decrypted_stream = NULL;
	pgp_packet_header *header = NULL;

	pgp_seipd_packet *seipd = NULL;
	pgp_literal_packet *literal = NULL;

	byte_t session_key[64] = {0};
	byte_t session_key_size = 64;

	void *file = NULL;
	void *buffer = NULL;
	uint32_t data_size = 0;

	if (command->files != NULL)
	{
		file = command->files->packets[0];
	}

	stream = spgp_read_pgp_packets(file, SPGP_STD_INPUT);

	if (stream == NULL)
	{
		printf("Invalid pgp stream.\n");
		exit(1);
	}

	header = stream->packets[0];
	seipd = stream->packets[1];

	if (pgp_packet_get_type(header->tag) == PGP_PKESK)
	{
		pgp_pkesk_packet *session = stream->packets[0];
		pgp_key_packet *key = spgp_search_key_from_user(command->user);

		if (command->passhprase == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		pgp_key_packet_decrypt(key, command->passhprase, strlen(command->passhprase));

		pgp_pkesk_packet_session_key_decrypt(session, key, session_key, &session_key_size);
		seipd->symmetric_key_algorithm_id = session->symmetric_key_algorithm_id;
	}

	if (pgp_packet_get_type(header->tag) == PGP_SKESK)
	{
		pgp_skesk_packet *session = stream->packets[0];

		if (command->passhprase == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		pgp_skesk_packet_session_key_decrypt(session, command->passhprase, strlen(command->passhprase), session_key, &session_key_size);
		seipd->symmetric_key_algorithm_id = session->symmetric_key_algorithm_id;
	}

	if (session_key_size == 0)
	{
		printf("Invalid encrypted message.\n");
		exit(1);
	}

	data_size = seipd->data_size;
	buffer = malloc(data_size);

	if (buffer == NULL)
	{
		printf("No memory.\n");
		exit(2);
	}

	data_size = pgp_seipd_packet_decrypt(seipd, session_key, session_key_size, &decrypted_stream);

	if (data_size == 0)
	{
		printf("Decryption failure.\n");
		exit(1);
	}

	literal = decrypted_stream->packets[0];
	spgp_write_file(command->output, SPGP_STD_OUTPUT, literal->data, literal->data_size);

	free(buffer);

	return 0;
}
