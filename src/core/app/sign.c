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

uint32_t spgp_sign(spgp_command *command)
{
	void *buffer = NULL;
	void *file = NULL;
	size_t size = 0;

	pgp_key_packet *key = NULL;

	key = spgp_search_key_from_user(command->user);

	if (key == NULL)
	{
		printf("No key found.\n");
		exit(1);
	}

	if (command->files != NULL)
	{
		file = command->files->packets[0];
	}

	buffer = spgp_read_file(file, 0, &size);

	if (command->passhprase != NULL)
	{
		pgp_key_packet_decrypt(key, command->passhprase, strlen(command->passhprase));
	}
	else
	{
		printf("No passphrase given.\n");
		exit(1);
	}

	pgp_signature_packet *sign = pgp_signature_packet_new(PGP_SIGNATURE_V4, PGP_BINARY_SIGNATURE);

	pgp_signature_packet_sign(sign, key, PGP_SHA2_256, time(NULL), buffer, size);
	spgp_write_pgp_packet(command->output, SPGP_STD_OUTPUT, sign);

	free(buffer);

	return 0;
}

uint32_t spgp_verify(spgp_command *command)
{
	void *buffer = NULL;
	size_t size = 0;

	pgp_key_packet *key = NULL;
	pgp_signature_packet *sign = NULL;

	if (command->files == NULL || command->files->count != 2)
	{
		printf("Bad usage.\n");
		exit(1);
	}

	sign = spgp_read_pgp_packet(command->files->packets[0], SPGP_STD_INPUT);
	buffer = spgp_read_file(command->files->packets[1], 0, &size);

	if (sign->hashed_subpackets != NULL)
	{
		for (uint16_t i = 0; i < sign->hashed_subpackets->count; ++i)
		{
			pgp_subpacket_header *header = sign->hashed_subpackets->packets[i];
			pgp_signature_subpacket_type type = header->tag & PGP_SUBPACKET_TAG_MASK;

			if (type == PGP_ISSUER_FINGERPRINT_SUBPACKET)
			{
				pgp_issuer_fingerprint_subpacket *subpacket = sign->hashed_subpackets->packets[i];

				key = spgp_read_key(subpacket->fingerprint, subpacket->header.body_size - 1);
				break;
			}
		}
	}

	if (key == NULL)
	{
		printf("No key found.\n");
		exit(1);
	}

	uint32_t result = pgp_signature_packet_verify(sign, key, buffer, size);

	printf("%s\n", result == 1 ? "Good Signature" : "Bad Signature");

	free(buffer);

	return 0;
}
