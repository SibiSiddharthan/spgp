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
#include <stdlib.h>
#include <string.h>

static const char hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

static byte_t get_key_filename(char *buffer, byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size)
{
	byte_t pos = 0;

	for (uint32_t i = 0; i < size; ++i)
	{
		byte_t a, b;

		a = fingerprint[i] / 16;
		b = fingerprint[i] % 16;

		buffer[pos++] = hex_table[a];
		buffer[pos++] = hex_table[b];
	}

	// Append .key
	buffer[pos++] = '.';
	buffer[pos++] = 'k';
	buffer[pos++] = 'e';
	buffer[pos++] = 'y';
	buffer[pos] = '\0';

	return pos;
}

static byte_t get_cert_filename(char *buffer, byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size)
{
	byte_t pos = 0;

	for (uint32_t i = 0; i < size; ++i)
	{
		byte_t a, b;

		a = fingerprint[i] / 16;
		b = fingerprint[i] % 16;

		buffer[pos++] = hex_table[a];
		buffer[pos++] = hex_table[b];
	}

	// Append .key
	buffer[pos++] = '.';
	buffer[pos++] = 'c';
	buffer[pos++] = 'e';
	buffer[pos++] = 'r';
	buffer[pos++] = 't';
	buffer[pos] = '\0';

	return pos;
}

pgp_stream_t *spgp_read_certificate(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size)
{
	char filename[256] = {0};

	get_cert_filename(filename, fingerprint, size);

	return spgp_read_pgp_packet(filename, 0);
}

size_t spgp_write_certificate(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size, pgp_stream_t *stream)
{
	char filename[256] = {0};

	get_cert_filename(filename, fingerprint, size);

	return spgp_write_pgp_packets(filename, 0, stream);
}

pgp_key_packet *spgp_read_key(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size)
{
	status_t status = 0;
	handle_t handle = 0;

	char filename[256] = {0};
	uint32_t length = 0;

	pgp_key_packet *key = NULL;

	length = get_key_filename(filename, fingerprint, size);
	status = os_open(&handle, command.keys, filename, length, FILE_ACCESS_READ, 0, 0);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to open key file %s.\n", filename);
		exit(1);
	}

	key = spgp_read_pgp_packet_from_handle(handle);

	os_close(handle);

	return key;
}

void spgp_write_key(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t size, pgp_key_packet *key)
{
	status_t status = 0;
	handle_t handle = 0;

	char filename[256] = {0};
	uint32_t length = 0;

	length = get_key_filename(filename, fingerprint, size);
	status = os_open(&handle, command.keys, filename, length, FILE_ACCESS_WRITE, FILE_FLAG_CREATE | FILE_FLAG_TRUNCATE, 0700);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("Unable to open key file %s.\n", filename);
		exit(1);
	}

	spgp_write_pgp_packet_to_handle(handle, key);

	os_close(handle);
}

pgp_stream_t *spgp_read_keyring()
{
	return spgp_read_pgp_packets_from_handle(command.keyring);
}

uint32_t spgp_update_keyring(pgp_keyring_packet *key, uint32_t options)
{
	pgp_stream_t *stream = NULL;
	pgp_keyring_packet *packet = NULL;
	byte_t matching_keyring_found = 0;
	uint16_t keyring_index = 0;

	stream = spgp_read_pgp_packets_from_handle(command.keyring);

	if (stream != NULL)
	{
		for (uint16_t i = 0; i < stream->count; ++i)
		{
			packet = stream->packets[i];

			if (packet->key_version == key->key_version &&
				memcmp(packet->primary_fingerprint, key->primary_fingerprint, key->fingerprint_size) == 0)
			{
				matching_keyring_found = 1;
				keyring_index = i;
			}
		}
	}

	if (matching_keyring_found)
	{
		if (options & SPGP_KEYRING_REPLACE)
		{
			// Update the keyring
			pgp_keyring_packet_delete(stream->packets[keyring_index]);
			stream->packets[keyring_index] = key;
		}
		else
		{
			// free(stream);
			return 1;
		}
	}
	else
	{
		stream = pgp_stream_push_packet(stream, key);

		if (stream == NULL)
		{
			printf("Unable to add keyring.\n");
			exit(1);
		}
	}

	os_seek(command.keyring, 0, SEEK_SET);
	os_truncate(command.keyring, NULL, 0, 0);
	spgp_write_pgp_packets_to_handle(command.keyring, stream);

	return 0;
}

uint32_t spgp_import_keys(spgp_command *command)
{
	pgp_stream_t *key_stream = NULL;
	pgp_key_packet *key = NULL;
	pgp_user_id_packet *uid = NULL;
	pgp_signature_packet *sign = NULL;
	pgp_keyring_packet *keyring_packet = NULL;

	byte_t primary_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t primary_fingerprint_size = 0;

	key_stream = spgp_read_pgp_packets(command->import.file, SPGP_STD_INPUT);

	key = key_stream->packets[0];
	uid = key_stream->packets[1];
	sign = key_stream->packets[2];

	primary_fingerprint_size = pgp_key_fingerprint(key, primary_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
	key = pgp_key_packet_make_definition(key, sign);
	spgp_write_key(primary_fingerprint, primary_fingerprint_size, key);

	keyring_packet = pgp_keyring_packet_new(key->version, PGP_TRUST_FULL, primary_fingerprint, uid->user_data, uid->header.body_size);

	for (uint16_t i = 3; i < key_stream->count; ++i)
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
			pgp_signature_packet *subsign = NULL;

			byte_t subkey_fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
			byte_t subkey_fingerprint_size = 0;

			subkey_fingerprint_size = pgp_key_fingerprint(subkey, subkey_fingerprint, PGP_KEY_MAX_FINGERPRINT_SIZE);
			keyring_packet = pgp_keyring_packet_add_subkey(keyring_packet, subkey_fingerprint);

			if ((i + 1) < key_stream->count)
			{
				subsign = key_stream->packets[i + 1];

				if (pgp_packet_get_type(subsign->header.tag) == PGP_SIG)
				{
					subkey = pgp_key_packet_make_definition(subkey, subsign);
					i += 1;
				}
			}

			spgp_write_key(subkey_fingerprint, subkey_fingerprint_size, subkey);
		}
	}

	spgp_update_keyring(keyring_packet, SPGP_KEYRING_REPLACE);
	pgp_keyring_packet_delete(keyring_packet);

	return 0;
}

uint32_t spgp_list_keys(spgp_command *command)
{
	pgp_stream_t *stream = NULL;
	pgp_keyring_packet *keyring = NULL;
	pgp_key_packet *key = NULL;

	char buffer[65536] = {0};
	size_t pos = 0;

	stream = spgp_read_keyring();

	for (uint16_t i = 0; i < stream->count; ++i)
	{
		keyring = stream->packets[i];

		// Add primary key
		key = spgp_read_key(keyring->primary_fingerprint, keyring->fingerprint_size);
		pos += snprintf(PTR_OFFSET(buffer, pos), 65536, "%d %d %hhx%hhx\n", key->public_key_algorithm_id, key->capabilities,
						keyring->primary_fingerprint[0], keyring->primary_fingerprint[1]);

		// Add uids
		snprintf(PTR_OFFSET(buffer, pos), 65536, "%s\n", (char *)keyring->uids);

		// Add subkeys
		for (uint16_t j = 0; j < keyring->subkey_count; ++j)
		{
			key = spgp_read_key(PTR_OFFSET(keyring->subkey_fingerprints, keyring->fingerprint_size * j), keyring->fingerprint_size);
			pos += snprintf(PTR_OFFSET(buffer, pos), 65536, "%d %d %hhx%hhx\n", key->public_key_algorithm_id, key->capabilities,
							keyring->primary_fingerprint[0], keyring->primary_fingerprint[1]);
		}
	}

	printf("%s", buffer);

	return 0;
}
