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

static const char hex_upper_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static uint32_t key_filename(void *buffer, byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t fz)
{
	byte_t *out = buffer;
	byte_t pos = 0;

	for (uint32_t i = 0; i < fz; ++i)
	{
		byte_t a, b;

		a = ((byte_t *)fingerprint)[i] / 16;
		b = ((byte_t *)fingerprint)[i] % 16;

		out[pos++] = hex_upper_table[a];
		out[pos++] = hex_upper_table[b];
	}

	out[pos++] = '.';
	out[pos++] = 'k';
	out[pos++] = 'e';
	out[pos++] = 'y';
	out[pos] = '\0';

	return pos;
}

uint32_t spgp_import_keys(spgp_command *command)
{
	file_t keyring = {0};
	file_t keyfile = {0};

	pgp_stream_t *key_stream = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_id_packet *uid = NULL;
	pgp_keyring_packet *keyring_packet = NULL;

	byte_t primary_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};

	key_stream = spgp_read_pgp_packets(command->import.file, SPGP_STD_INPUT);

	char wb[65536] = {0};
	char fn[128] = {0};
	size_t sz = 0;
	size_t fiz = 0;
	size_t fz = 0;

	key = key_stream->packets[0];
	uid = key_stream->packets[1];

	fz = pgp_key_fingerprint(key, primary_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);

	// key->header.tag = pgp_packet_tag(PGP_HEADER, PGP_KEYDEF, key->header.body_size);
	fiz = key_filename(fn, primary_fingerprint, fz);
	sz = pgp_key_packet_write(key, wb, 65536);

	file_open(&keyfile, command->keys, fn, fiz, FILE_WRITE, 65536);
	file_write(&keyfile, wb, sz);
	file_close(&keyfile);

	keyring_packet = pgp_keyring_packet_new(key->version, PGP_TRUST_FULL, primary_fingerprint, uid->user_data, uid->header.body_size);

	for (uint16_t i = 2; i < key_stream->count; ++i)
	{
		pgp_packet_header *header = key_stream->packets[i];
		pgp_packet_type type = pgp_packet_get_type(header->tag);

		if (type == PGP_UID)
		{
			pgp_user_id_packet *other_uid = key_stream->packets[i];

			keyring_packet = pgp_keyring_packet_add_uid(keyring_packet, other_uid->user_data, other_uid->header.body_size);
		}

		if (type == PGP_PUBSUBKEY || type == PGP_SECSUBKEY)
		{
			pgp_key_packet *subkey = key_stream->packets[i];
			byte_t subkey_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};

			pgp_key_fingerprint(subkey, subkey_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
			keyring_packet = pgp_keyring_packet_add_subkey(keyring_packet, subkey_fingerprint);

			fiz = key_filename(fn, subkey_fingerprint, fz);
			sz = pgp_key_packet_write(key, wb, 65536);

			file_open(&keyfile, command->keys, fn, fiz, FILE_WRITE, 65536);
			file_write(&keyfile, wb, sz);
			file_close(&keyfile);
		}
	}

	// Lock the keyring

	sz = pgp_keyring_packet_write(keyring_packet, wb, 65536);

	file_open(&keyring, command->keyring, NULL, 0, FILE_READ | FILE_WRITE, 65536);
	file_write(&keyring, wb, sz);
	file_close(&keyring);

	// status = os_lock(command->keyring, 0, (size_t)-1, 0, 1);
	//
	// if (status != OS_STATUS_SUCCESS)
	//{
	//	fprintf(stderr, "Unable to lock keyring");
	//	return 1;
	//}
	//
	// os_unlock(command->keyring, 0, (size_t)-1);

	// Assume key stream for now. TODO

	return 0;
}
