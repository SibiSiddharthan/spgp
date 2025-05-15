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

static pgp_stream_t *spgp_encrypt_mdc(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									  pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	if (recipient_count == 0 && passphrase_count == 1)
	{
		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, PGP_AES_256, 0, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), NULL, 0, NULL, 0));

		pgp_stream_push(message, skesk);
	}

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, PGP_AES_256, 0, &s2k));
		PGP_CALL(
			pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), NULL, 0, session_key, session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, PGP_AES_256, 0, 0));
	PGP_CALL(pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, stream));

	pgp_stream_push(message, seipd);

	return message;
}

static pgp_stream_t *spgp_encrypt_aead(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									   pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_aead_packet *aead = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	byte_t iv[16] = {0};
	byte_t iv_size = pgp_aead_iv_size(PGP_AEAD_OCB);

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V5, PGP_AES_256, PGP_AEAD_OCB, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), iv, iv_size, session_key,
													  session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_aead_packet_new(&aead, PGP_AES_256, PGP_AEAD_OCB, PGP_MAX_CHUNK_SIZE));
	PGP_CALL(pgp_aead_packet_encrypt(aead, iv, iv_size, session_key, session_key_size, stream));

	pgp_stream_push(message, aead);

	return message;
}

static pgp_stream_t *spgp_encrypt_seipd(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
										pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 0;

	byte_t iv[16] = {0};
	byte_t iv_size = 0;

	byte_t salt[32] = {0};

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V6));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, PGP_AES_256, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V6, PGP_AES_256, PGP_AEAD_OCB, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), iv, iv_size, session_key,
													  session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V2, PGP_AES_256, PGP_AEAD_OCB, PGP_MAX_CHUNK_SIZE));
	PGP_CALL(pgp_seipd_packet_encrypt(seipd, salt, session_key, session_key_size, stream));

	pgp_stream_push(message, seipd);

	return message;
}

void spgp_encrypt(void)
{
	pgp_key_packet *key[16] = {0};
	pgp_user_info *uinfo[16] = {0};
	pgp_keyring_packet *keyring[16] = {0};

	pgp_literal_packet *literal = NULL;
	pgp_stream_t *stream = NULL;
	pgp_stream_t *message = NULL;

	uint32_t count = 0;

	armor_options options = {0};
	armor_marker marker = {0};
	armor_options *opts = NULL;

	if (command.encrypt && command.recipients == NULL)
	{
		printf("No recipient specified\n.");
		exit(1);
	}

	if (command.symmetric)
	{
		if (command.passhprases == NULL)
		{
			void *passphrase = spgp_prompt_passphrase();

			if (passphrase == NULL)
			{
				printf("No passphrase provided\n.");
				exit(1);
			}

			STREAM_CALL(command.passhprases = pgp_stream_push(command.passhprases, passphrase));
		}
	}

	count = command.recipients->count;

	// Search the keyring to find the keys
	for (uint32_t i = 0; i < count; ++i)
	{
		keyring[i] = spgp_search_keyring(&key[i], &uinfo[i], command.recipients->packets[i], strlen(command.recipients->packets[i]),
										 (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE));

		if (keyring[i] == NULL)
		{
			printf("Unable to find recipient %s\n.", (char *)command.recipients->packets[i]);
			exit(1);
		}

		if (key[i] == NULL)
		{
			printf("No Encryption key for recipient %s\n.", (char *)command.recipients->packets[i]);
			exit(1);
		}
	}

	// Literal or compressed packet
	STREAM_CALL(stream = pgp_stream_new(1));

	// Create the encrypted message
	if (command.files == NULL)
	{
		literal = spgp_literal_read_file(NULL, PGP_LITERAL_DATA_BINARY);
		stream = pgp_stream_push(stream, literal);

		switch (command.mode)
		{
		case SPGP_MODE_RFC2440:
		case SPGP_MODE_RFC4880:
			message = spgp_encrypt_mdc(key, count, command.passhprases->packets, command.passhprases->count, stream);
		case SPGP_MODE_LIBREPGP:
			message = spgp_encrypt_aead(key, count, command.passhprases->packets, command.passhprases->count, stream);
		case SPGP_MODE_OPENPGP:
			message = spgp_encrypt_seipd(key, count, command.passhprases->packets, command.passhprases->count, stream);
		}

		stream = pgp_stream_clear(stream, pgp_packet_delete);
	}
	else
	{
		for (uint32_t i = 0; i < count; ++i)
		{
			literal = spgp_literal_read_file(NULL, PGP_LITERAL_DATA_BINARY);
			stream = pgp_stream_push(stream, literal);

			switch (command.mode)
			{
			case SPGP_MODE_RFC2440:
			case SPGP_MODE_RFC4880:
				message = spgp_encrypt_mdc(key, count, command.passhprases->packets, command.passhprases->count, stream);
			case SPGP_MODE_LIBREPGP:
				message = spgp_encrypt_aead(key, count, command.passhprases->packets, command.passhprases->count, stream);
			case SPGP_MODE_OPENPGP:
				message = spgp_encrypt_seipd(key, count, command.passhprases->packets, command.passhprases->count, stream);
			}

			stream = pgp_stream_clear(stream, pgp_packet_delete);
		}
	}

	// Write output
	if (command.armor)
	{
		marker = (armor_marker){.header_line = PGP_ARMOR_BEGIN_SIGNATURE,
								.header_line_size = strlen(PGP_ARMOR_BEGIN_SIGNATURE),
								.trailer_line = PGP_ARMOR_END_SIGNATURE,
								.trailer_line_size = strlen(PGP_ARMOR_END_SIGNATURE)};

		options.marker = &marker;
		options.flags = ARMOR_EMPTY_LINE | ARMOR_CRLF_ENDING | ((command.mode == SPGP_MODE_OPENPGP) ? 0 : ARMOR_CHECKSUM_CRC24);

		opts = &options;
	}

	spgp_write_pgp_packets(command.output, message, opts);
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

	stream = spgp_read_pgp_packets(file);

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
		pgp_key_packet *key = NULL;

		if (command->passhprases == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		// pgp_key_packet_decrypt(key, command->passhprases, strlen(command->passhprases));

		pgp_pkesk_packet_session_key_decrypt(session, key, session_key, &session_key_size);
		seipd->symmetric_key_algorithm_id = session->symmetric_key_algorithm_id;
	}

	if (pgp_packet_get_type(header->tag) == PGP_SKESK)
	{
		pgp_skesk_packet *session = stream->packets[0];

		if (command->passhprases == NULL)
		{
			printf("Passphrase required.\n");
			exit(1);
		}

		// pgp_skesk_packet_session_key_decrypt(session, command->passhprases, strlen(command->passhprases), session_key,
		// &session_key_size);
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
	spgp_literal_write_file(command->output, literal);

	free(buffer);

	return 0;
}
