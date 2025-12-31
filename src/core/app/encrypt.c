/*
   Copyright (c) 2024 - 2026 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>

#include <pgp/packet.h>
#include <pgp/key.h>
#include <pgp/crypto.h>
#include <pgp/session.h>
#include <pgp/seipd.h>
#include <pgp/signature.h>

static pgp_stream_t *spgp_encrypt_sed(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									  pgp_symmetric_key_algorithms algorithm, pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_sed_packet *sed = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = pgp_symmetric_cipher_key_size(algorithm);

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	if (recipient_count == 0 && passphrase_count == 1)
	{
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);
		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, algorithm, 0, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), NULL, 0, NULL, 0));

		pgp_stream_push(message, skesk);

		PGP_CALL(pgp_s2k_hash(&s2k, passphrases[0], strlen(passphrases[0]), session_key, session_key_size));

		PGP_CALL(pgp_sed_packet_new(&sed));
		PGP_CALL(pgp_sed_packet_encrypt(sed, algorithm, session_key, session_key_size, stream));

		pgp_stream_push(message, sed);

		return message;
	}

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, algorithm, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, PGP_AES_128, 0, &s2k));
		PGP_CALL(
			pgp_skesk_packet_session_key_encrypt(skesk, passphrases[i], strlen(passphrases[i]), NULL, 0, session_key, session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_sed_packet_new(&sed));
	PGP_CALL(pgp_sed_packet_encrypt(sed, algorithm, session_key, session_key_size, stream));

	pgp_stream_push(message, sed);

	return message;
}

static pgp_stream_t *spgp_encrypt_mdc(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									  pgp_symmetric_key_algorithms algorithm, pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = pgp_symmetric_cipher_key_size(algorithm);

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	if (recipient_count == 0 && passphrase_count == 1)
	{
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);
		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, algorithm, 0, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), NULL, 0, NULL, 0));

		pgp_stream_push(message, skesk);

		PGP_CALL(pgp_s2k_hash(&s2k, passphrases[0], strlen(passphrases[0]), session_key, session_key_size));

		PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, algorithm, 0, 0));
		PGP_CALL(pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, stream));

		pgp_stream_push(message, seipd);

		return message;
	}

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, algorithm, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V4, &s2k);

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V4, PGP_AES_128, 0, &s2k));
		PGP_CALL(
			pgp_skesk_packet_session_key_encrypt(skesk, passphrases[i], strlen(passphrases[i]), NULL, 0, session_key, session_key_size));

		pgp_stream_push(message, skesk);
	}

	PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V1, algorithm, 0, 0));
	PGP_CALL(pgp_seipd_packet_encrypt(seipd, NULL, session_key, session_key_size, stream));

	pgp_stream_push(message, seipd);

	return message;
}

static pgp_stream_t *spgp_encrypt_aead(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
									   pgp_symmetric_key_algorithms cipher_algorithm, pgp_aead_algorithms aead_algorithm,
									   pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_aead_packet *aead = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = pgp_symmetric_cipher_key_size(cipher_algorithm);

	byte_t iv[16] = {0};
	byte_t iv_size = pgp_aead_iv_size(aead_algorithm);
	byte_t ocb_iv_size = pgp_aead_iv_size(PGP_AEAD_OCB);

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V3));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, cipher_algorithm, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{

		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V5, &s2k);

		// Generate IV for S2K
		PGP_CALL(pgp_rand(iv, ocb_iv_size));

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V5, PGP_AES_128, PGP_AEAD_OCB, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[i], strlen(passphrases[i]), iv, ocb_iv_size, session_key,
													  session_key_size));

		pgp_stream_push(message, skesk);
	}

	// Generate IV for encryption
	PGP_CALL(pgp_rand(iv, iv_size));

	PGP_CALL(pgp_aead_packet_new(&aead, cipher_algorithm, aead_algorithm, PGP_MAX_CHUNK_SIZE));
	PGP_CALL(pgp_aead_packet_encrypt(aead, iv, iv_size, session_key, session_key_size, stream));

	pgp_stream_push(message, aead);

	return message;
}

static pgp_stream_t *spgp_encrypt_seipd(pgp_key_packet **keys, uint32_t recipient_count, void **passphrases, uint32_t passphrase_count,
										pgp_symmetric_key_algorithms cipher_algorithm, pgp_aead_algorithms aead_algorithm,
										pgp_stream_t *stream)
{
	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;
	pgp_pkesk_packet *pkesk = NULL;
	pgp_skesk_packet *skesk = NULL;

	byte_t session_key[32] = {0};
	byte_t session_key_size = pgp_symmetric_cipher_key_size(cipher_algorithm);

	byte_t iv[16] = {0};
	byte_t iv_size = pgp_aead_iv_size(PGP_AEAD_OCB);

	byte_t salt[32] = {0};
	byte_t salt_size = 32;

	pgp_s2k s2k = {0};

	STREAM_CALL(message = pgp_stream_new(recipient_count + passphrase_count + 1));

	// Generate the session key
	PGP_CALL(pgp_rand(session_key, session_key_size));

	// Process PKESKs first
	for (uint32_t i = 0; i < recipient_count; ++i)
	{
		pkesk = NULL;

		PGP_CALL(pgp_pkesk_packet_new(&pkesk, PGP_PKESK_V6));
		PGP_CALL(pgp_pkesk_packet_session_key_encrypt(pkesk, keys[i], 0, cipher_algorithm, session_key, session_key_size));

		pgp_stream_push(message, pkesk);
	}

	for (uint32_t i = 0; i < passphrase_count; ++i)
	{
		skesk = NULL;

		memset(&s2k, 0, sizeof(pgp_s2k));
		preferred_s2k_algorithm(PGP_KEY_V6, &s2k);

		// Generate IV for S2K
		PGP_CALL(pgp_rand(iv, iv_size));

		PGP_CALL(pgp_skesk_packet_new(&skesk, PGP_SKESK_V6, PGP_AES_128, PGP_AEAD_OCB, &s2k));
		PGP_CALL(pgp_skesk_packet_session_key_encrypt(skesk, passphrases[0], strlen(passphrases[0]), iv, iv_size, session_key,
													  session_key_size));

		pgp_stream_push(message, skesk);
	}

	// Generate the salt
	PGP_CALL(pgp_rand(salt, salt_size));

	// Encrypt
	PGP_CALL(pgp_seipd_packet_new(&seipd, PGP_SEIPD_V2, cipher_algorithm, aead_algorithm, PGP_MAX_CHUNK_SIZE));
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
	pgp_compresed_packet *compressed = NULL;
	pgp_stream_t *stream = NULL;
	pgp_stream_t *message = NULL;

	uint32_t count = 0;

	armor_options options = {0};
	armor_marker marker = {0};
	armor_options *opts = NULL;

	void **passphrases = NULL;
	uint32_t passphrase_count = 0;

	byte_t compression_algorithm = 0;
	byte_t cipher_algorithm = 0;
	byte_t aead_algorithm = 0;
	uint16_t aead_pair = 0;

	byte_t features = 0xFF;

	if (command.encrypt && command.recipients == NULL)
	{
		printf("No recipient specified\n.");
		exit(1);
	}

	if (command.symmetric)
	{
		if (command.passhprases == NULL)
		{
			command.passphrase_size = spgp_prompt_passphrase(command.passphrase_buffer, "Enter passphrase to encrypt message.");

			if (command.passphrase_size == 0)
			{
				printf("No passphrase provided\n.");
				exit(1);
			}

			STREAM_CALL(command.passhprases = pgp_stream_push(command.passhprases, command.passphrase_buffer));
		}
	}

	if (command.passhprases != NULL)
	{
		passphrases = command.passhprases->data;
		passphrase_count = command.passhprases->count;
	}

	count = command.recipients != NULL ? command.recipients->count : 0;

	if (count > 0)
	{
		// Search the keyring to find the keys
		for (uint32_t i = 0; i < count; ++i)
		{
			keyring[i] = spgp_search_keyring(&key[i], &uinfo[i], command.recipients->data[i], strlen(command.recipients->data[i]),
											 (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE));

			if (keyring[i] == NULL)
			{
				printf("Unable to find recipient %s\n.", (char *)command.recipients->data[i]);
				exit(1);
			}

			if (key[i] == NULL)
			{
				printf("No Encryption key for recipient %s\n.", (char *)command.recipients->data[i]);
				exit(1);
			}

			features &= uinfo[i]->features;
		}

		compression_algorithm = preferred_compression_algorithm(uinfo, count);

		if (features & (PGP_FEATURE_SEIPD_V2 | PGP_FEATURE_AEAD))
		{
			aead_pair = preferred_aead_algorithm(uinfo, count);
			cipher_algorithm = aead_pair >> 8;
			aead_algorithm = aead_pair & 0xFF;
		}
		else
		{
			cipher_algorithm = preferred_cipher_algorithm(uinfo, count);
		}
	}
	else
	{
		// Defaults
		compression_algorithm = PGP_DEFALTE;
		cipher_algorithm = PGP_AES_128;
		aead_algorithm = PGP_AEAD_OCB;

		// Determine features depend on operation mode
		switch (command.mode)
		{
		case SPGP_MODE_RFC2440:
			features = 0;
			break;
		case SPGP_MODE_RFC4880:
			features = PGP_FEATURE_MDC;
			break;
		case SPGP_MODE_LIBREPGP:
			features = PGP_FEATURE_AEAD;
			break;
		case SPGP_MODE_OPENPGP:
			features = PGP_FEATURE_SEIPD_V2;
			break;
		}
	}

	// Armor setup
	if (command.armor)
	{
		marker = (armor_marker){.header_line = PGP_ARMOR_BEGIN_MESSAGE,
								.header_line_size = strlen(PGP_ARMOR_BEGIN_MESSAGE),
								.trailer_line = PGP_ARMOR_END_MESSAGE,
								.trailer_line_size = strlen(PGP_ARMOR_END_MESSAGE)};

		options.marker = &marker;
		options.flags = ARMOR_EMPTY_LINE | ARMOR_CRLF_ENDING | ((command.mode == SPGP_MODE_OPENPGP) ? 0 : ARMOR_CHECKSUM_CRC24);

		opts = &options;
	}

	// Literal or compressed packet
	STREAM_CALL(stream = pgp_stream_new(1));

	// Create the encrypted message
	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		literal = spgp_literal_read_file(command.args->data[i], PGP_LITERAL_DATA_BINARY);
		stream = pgp_stream_push(stream, literal);

		if (command.compression_level > 0 && compression_algorithm != PGP_UNCOMPRESSED)
		{
			PGP_CALL(pgp_compressed_packet_new(&compressed, PGP_HEADER, compression_algorithm));
			PGP_CALL(pgp_compressed_packet_compress(compressed, stream));

			stream = pgp_stream_clear(stream, pgp_packet_delete);
			stream = pgp_stream_push(stream, compressed);
		}

		if (features & PGP_FEATURE_SEIPD_V2)
		{
			message = spgp_encrypt_seipd(key, count, passphrases, passphrase_count, cipher_algorithm, aead_algorithm, stream);
		}
		else if (features & PGP_FEATURE_AEAD)
		{
			message = spgp_encrypt_aead(key, count, passphrases, passphrase_count, cipher_algorithm, aead_algorithm, stream);
		}
		else if (features & PGP_FEATURE_MDC)
		{
			message = spgp_encrypt_mdc(key, count, passphrases, passphrase_count, cipher_algorithm, stream);
		}
		else
		{
			message = spgp_encrypt_sed(key, count, passphrases, passphrase_count, cipher_algorithm, stream);
		}

		stream = pgp_stream_clear(stream, pgp_packet_delete);

		// Write output
		if (command.output != NULL)
		{
			spgp_write_pgp_packets(command.output, NULL, message, opts);
		}
		else
		{
			spgp_write_pgp_packets(command.args->data[i], opts == NULL ? SPGP_FILE_EXT : SPGP_ARMOR_EXT, message, opts);
		}
	}
}

static pgp_stream_t *spgp_decrypt_stream(pgp_stream_t *stream)
{
	pgp_error_t status = 0;

	pgp_stream_t *message = NULL;
	pgp_seipd_packet *seipd = NULL;

	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	void *encrypted_packet = NULL;
	byte_t algorithm = 0;

	byte_t session_key[32] = {0};
	byte_t session_key_size = 32;
	byte_t session_key_found = 0;

	byte_t version = 0;
	byte_t pkesk_version = 0;
	byte_t skesk_version = 0;
	byte_t seipd_version = 0;
	byte_t aead_version = 0;

	// Validate packet sequence
	for (uint32_t i = 0; i < stream->count - 1; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type != PGP_PKESK && type != PGP_SKESK)
		{
			printf("Bad PGP message sequence.\n");
			exit(1);
		}

		if (type == PGP_PKESK)
		{
			version = ((pgp_pkesk_packet *)stream->packets[i])->version;

			if (pkesk_version == 0)
			{
				pkesk_version = version;
			}
			else
			{
				if (pkesk_version != version)
				{
					printf("PKESK mulitple versions %hhu %hhu.\n", pkesk_version, version);
					exit(1);
				}
			}
		}

		if (type == PGP_SKESK)
		{
			version = ((pgp_skesk_packet *)stream->packets[i])->version;

			if (skesk_version == 0)
			{
				skesk_version = version;
			}
			else
			{
				if (skesk_version != version)
				{
					printf("SKESK mulitple versions %hhu %hhu.\n", skesk_version, version);
					exit(1);
				}
			}
		}
	}

	// The last packet should be an encryption container
	header = stream->packets[stream->count - 1];
	type = pgp_packet_type_from_tag(header->tag);

	if (type != PGP_SEIPD && type != PGP_AEAD && type != PGP_SED)
	{
		printf("Bad PGP message sequence.\n");
		exit(1);
	}

	if (type == PGP_SEIPD)
	{
		seipd_version = ((pgp_seipd_packet *)stream->packets[stream->count - 1])->version;
	}

	if (type == PGP_AEAD)
	{
		aead_version = ((pgp_aead_packet *)stream->packets[stream->count - 1])->version;
	}

	// Check legal packet versions
	if (pkesk_version == PGP_PKESK_V3)
	{
		// Allowed skesk v4 or v5
		if (skesk_version != 0 && skesk_version != PGP_SKESK_V4 && skesk_version != PGP_SKESK_V5)
		{
			printf("Incompatibale PKESK (V%hhu) and SKESK (V%hhu) versions.\n", pkesk_version, skesk_version);
			exit(1);
		}

		// Allowed sed, seipd v1, aead
		if (seipd_version != 0 && seipd_version != PGP_SEIPD_V1 && aead_version != PGP_AEAD_V1)
		{
			printf("Incompatibale PKESK and encryption container.\n");
			exit(1);
		}
	}

	if (pkesk_version == PGP_PKESK_V6)
	{
		// OpenPGP
		if (skesk_version != 0 && skesk_version != PGP_SKESK_V6)
		{
			printf("Incompatibale PKESK (V%hhu) and SKESK (V%hhu) versions.\n", pkesk_version, skesk_version);
			exit(1);
		}

		if (seipd_version != PGP_SEIPD_V2)
		{
			printf("Incompatibale PKESK (V%hhu) and SEIPD (V%hhu) versions.\n", pkesk_version, seipd_version);
			exit(1);
		}
	}

	if (skesk_version != 0)
	{
		// Allow V1 SEIPD and SED packets with V4 SKESK
		if (skesk_version == PGP_SKESK_V4 && seipd_version != PGP_SEIPD_V1 && seipd_version != 0 && aead_version != 0)
		{
			printf("Incompatibale SKESK and encryption container.\n");
			exit(1);
		}

		// LibrePGP
		if (skesk_version == PGP_SKESK_V5 && aead_version != PGP_AEAD_V1)
		{
			printf("Incompatibale SKESK and encryption container.\n");
			exit(1);
		}

		// OpenPGP
		if (skesk_version == PGP_SKESK_V6 && seipd_version != PGP_SEIPD_V2)
		{
			printf("Incompatibale SKESK and encryption container.\n");
			exit(1);
		}
	}

	// Search PKESKs first
	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];

		if (pgp_packet_type_from_tag(header->tag) == PGP_PKESK)
		{
			pgp_pkesk_packet *pkesk = stream->packets[i];

			pgp_key_packet *key = NULL;
			pgp_user_info *uinfo = NULL;
			pgp_keyring_packet *keyring = NULL;

			byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
			byte_t fingerprint_size = 0;

			if (pkesk->version == PGP_PKESK_V3)
			{
				fingerprint_size = PGP_KEY_ID_SIZE;
				memcpy(fingerprint, pkesk->key_id, fingerprint_size);
			}
			else
			{
				fingerprint_size = pgp_key_fingerprint_size(pkesk->key_version);
				memcpy(fingerprint, pkesk->key_fingerprint, fingerprint_size);
			}

			keyring =
				spgp_search_keyring(&key, &uinfo, fingerprint, fingerprint_size, (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE));

			if (key != NULL)
			{
				key = spgp_decrypt_key(keyring, key);
				status = pgp_pkesk_packet_session_key_decrypt(pkesk, key, session_key, &session_key_size);

				if (status == PGP_SUCCESS)
				{
					session_key_found = 1;

					if (pkesk->version == PGP_PKESK_V3)
					{
						algorithm = pkesk->symmetric_key_algorithm_id;
					}

					goto decrypt;
				}
			}
		}
	}

	if (skesk_version == 0)
	{
		printf("Unable to process\n");
		exit(1);
	}

	// Search SKESKs
	if (command.passhprases == NULL)
	{
		command.passphrase_size = spgp_prompt_passphrase(command.passphrase_buffer, "Enter passphrase to decrypt message.");

		if (command.passphrase_size == 0)
		{
			printf("No passphrase provided\n.");
			exit(1);
		}

		STREAM_CALL(command.passhprases = pgp_stream_push(command.passhprases, command.passphrase_buffer));
	}

	// Try all passphrases for all SKESKs
	for (uint32_t p = 0; p < command.passhprases->count; ++p)
	{
		void *passphrase = command.passhprases->data[p];
		uint32_t passphrase_size = strnlen(passphrase, SPGP_MAX_PASSPHRASE_SIZE);

		for (uint32_t i = 0; i < stream->count; ++i)
		{
			header = stream->packets[i];

			if (pgp_packet_type_from_tag(header->tag) == PGP_SKESK)
			{
				pgp_skesk_packet *skesk = stream->packets[i];

				status = pgp_skesk_packet_session_key_decrypt(skesk, passphrase, passphrase_size, session_key, &session_key_size);

				if (status == PGP_SUCCESS)
				{
					// For V4 packets do the decryption here itself.
					// There is no way to check whether the session key is correct other than decrypting seipd/sed packet.
					if (skesk->version == PGP_SKESK_V4)
					{
						header = stream->packets[stream->count - 1];
						encrypted_packet = stream->packets[stream->count - 1];

						if (pgp_packet_type_from_tag(header->tag) == PGP_SEIPD)
						{
							seipd = encrypted_packet;
							seipd->symmetric_key_algorithm_id = skesk->symmetric_key_algorithm_id;

							status = pgp_seipd_packet_decrypt(encrypted_packet, session_key, session_key_size, &message);

							if (status == PGP_SUCCESS)
							{
								goto finish;
							}
							else
							{
								continue;
							}
						}

						if (pgp_packet_type_from_tag(header->tag) == PGP_SED)
						{
							status = pgp_sed_packet_decrypt(encrypted_packet, skesk->symmetric_key_algorithm_id, session_key,
															session_key_size, &message);

							if (status == PGP_SUCCESS)
							{
								goto finish;
							}
							else
							{
								continue;
							}
						}
					}

					session_key_found = 1;

					goto decrypt;
				}
			}
		}
	}

	if (session_key_found == 0)
	{
		printf("Unable to process\n");
		exit(1);
	}

decrypt:
	header = stream->packets[stream->count - 1];
	encrypted_packet = stream->packets[stream->count - 1];

	switch (pgp_packet_type_from_tag(header->tag))
	{
	case PGP_SED:
	{
		PGP_CALL(pgp_sed_packet_decrypt(encrypted_packet, algorithm, session_key, session_key_size, &message));
	}
	break;
	case PGP_SEIPD:
	{
		// Set the algorithm for V1 packets
		seipd = encrypted_packet;

		if (seipd->version == PGP_SEIPD_V1)
		{
			seipd->symmetric_key_algorithm_id = algorithm;
		}

		PGP_CALL(pgp_seipd_packet_decrypt(encrypted_packet, session_key, session_key_size, &message));
	}
	break;
	case PGP_AEAD:
	{
		// Check whether the algorithm is correct
		seipd = encrypted_packet;

		if (algorithm != 0)
		{
			if (algorithm != seipd->symmetric_key_algorithm_id)
			{
				printf("Algorithm mismatch in AEAD packet.\n");
				exit(1);
			}
		}

		PGP_CALL(pgp_aead_packet_decrypt(encrypted_packet, session_key, session_key_size, &message));
	}
	break;
	default:
		printf("Bad PGP Message\n");
		exit(1);
	}

finish:
	return message;
}

static pgp_stream_t *spgp_decrypt_file(void *file)
{
	pgp_stream_t *stream = NULL;
	pgp_stream_t *result = NULL;
	pgp_stream_t message = {0};

	pgp_armor_packet *armor = NULL;
	pgp_packet_header *header = NULL;
	pgp_packet_type type = 0;

	uint32_t start = 0;
	uint32_t count = 0;

	stream = spgp_read_pgp_packets(file);
	stream = spgp_preprocess_stream(stream);

	for (uint32_t i = 0; i < stream->count; ++i)
	{
		header = stream->packets[i];
		type = pgp_packet_type_from_tag(header->tag);

		if (type == PGP_ARMOR)
		{
			armor = stream->packets[i];

			if (armor->marker_size != strlen(PGP_ARMOR_BEGIN_MESSAGE))
			{
				printf("Bad PGP message armor.\n");
				exit(1);
			}

			start = i + 1;
			continue;
		}

		count += 1;

		if (type == PGP_SEIPD || type == PGP_AEAD || type == PGP_SED)
		{
			message.count = message.capacity = count;
			message.packets = PTR_OFFSET(stream->packets, start * sizeof(void *));

			STREAM_CALL(result = pgp_stream_extend(result, spgp_decrypt_stream(&message)));

			count = 0;
			start = i + 1;
		}
	}

	if (count != 0)
	{
		message.count = message.capacity = count;
		message.packets = PTR_OFFSET(stream->packets, start * sizeof(void *));

		STREAM_CALL(result = pgp_stream_extend(result, spgp_decrypt_stream(&message)));
	}

	pgp_stream_delete(stream, pgp_packet_delete);

	return result;
}

void spgp_decrypt(void)
{
	pgp_stream_t *stream = NULL;
	pgp_packet_header *header = NULL;

	for (uint32_t i = 0; i < command.args->count; ++i)
	{
		stream = spgp_decrypt_file(command.args->data[i]);
		stream = spgp_preprocess_stream(stream);

		header = stream->packets[0];

		if (pgp_packet_type_from_tag(header->tag) == PGP_LIT)
		{
			spgp_literal_write_file(command.output, stream->packets[0]);
		}
	}
}
