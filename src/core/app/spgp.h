/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_H
#define SPGP_H

#define _CRT_SECURE_NO_WARNINGS

#include <types.h>
#include <buffer.h>

#include <packet.h>
#include <key.h>
#include <stream.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <load.h>

#include <status.h>
#include <os.h>
#include <io.h>

#include <stdlib.h>
#include <stdio.h>

// Configuration
#define SPGP_DEFAULT_HOME ".spgp"
#define SPGP_CONFIG       "spgp.conf"
#define SPGP_KEYRING      "keyring"

// Directories
#define SPGP_KEYS  "keys"
#define SPGP_CERTS "certs"

// Filename extensions
#define SPGP_KEY_EXT  ".key"
#define SPGP_CERT_EXT ".cert"

#define OS_CALL(EXPR, LOG)                             \
	{                                                  \
		status_t __os_status = 0;                      \
		__os_status = (EXPR);                          \
		if (__os_status != OS_STATUS_SUCCESS)          \
		{                                              \
			(LOG);                                     \
			printf(" (%s)\n", os_status(__os_status)); \
			exit(2);                                   \
		}                                              \
	}

#define PGP_CALL(EXPR)                               \
	{                                                \
		pgp_error_t __pgp_status = 0;                \
		__pgp_status = (EXPR);                       \
		if (__pgp_status != PGP_SUCCESS)             \
		{                                            \
			printf("%s\n", pgp_error(__pgp_status)); \
			exit(1);                                 \
		}                                            \
	}

#define STREAM_CALL(EXPR)              \
	{                                  \
		if ((EXPR) == NULL)            \
		{                              \
			printf("Out of Memory\n"); \
			exit(1);                   \
		}                              \
	}

#define OS_HANDLE_AS_UINT(HANDLE) ((uint32_t)(uintptr_t)(HANDLE))

typedef enum _spgp_mode
{
	SPGP_MODE_RFC2440 = 1,
	SPGP_MODE_RFC4880,
	SPGP_MODE_LIBREPGP,
	SPGP_MODE_OPENPGP
} spgp_mode;

typedef struct _spgp_command
{
	spgp_mode mode;

	handle_t home;
	handle_t keys;
	handle_t certs;
	handle_t keyring;

	pgp_stream_t *keyring_stream;

	void *homedir;
	void *output;

	pgp_stream_t *files;
	pgp_stream_t *users;
	pgp_stream_t *recipients;
	pgp_stream_t *passhprases;

	time_t timestamp;
	byte_t need_home;
	byte_t stateless;
	byte_t textmode;
	byte_t multifile;

	// Algorithm preferences
	byte_t cipher_algorithm;
	byte_t aead_algorithm;
	byte_t hash_algorithm;
	byte_t compression_algorithm;

	// Signature options
	void *expiration;
	pgp_stream_t *policy;
	pgp_stream_t *notation;
	pgp_stream_t *keyserver;

	// Compression
	byte_t compression_level;

	union
	{
		struct
		{
			byte_t armor : 1;
			byte_t dearmor : 1;

			byte_t sign : 1;
			byte_t detach_sign : 1;
			byte_t clear_sign : 1;
			byte_t verify : 1;

			byte_t encrypt : 1;
			byte_t symmetric : 1;
			byte_t decrypt : 1;

			byte_t import_keys : 1;
			byte_t export_keys : 1;
			byte_t export_secret_keys : 1;

			byte_t delete_keys : 1;
			byte_t delete_secret_keys : 1;

			byte_t list_keys : 1;
			byte_t list_secret_keys : 1;

			byte_t generate_key : 1;
			byte_t full_generate_key : 1;

			byte_t list_packets : 1;
			byte_t dump_packets : 1;
			byte_t no_print_mpis : 1;
		};

		uint64_t options;
	};

} spgp_command;

extern spgp_command command;

void spgp_generate_key(void);

void spgp_sign(void);
void spgp_verify(void);

void spgp_encrypt(void);
void spgp_decrypt(void);

void spgp_list_keys(void);
void spgp_list_packets(void);

void spgp_import_keys(void);
void spgp_export_keys(void);
uint32_t spgp_delete_keys(spgp_command *command);

pgp_literal_packet *spgp_literal_read_file(const char *file, pgp_literal_data_format format);
void spgp_literal_write_file(const char *file, pgp_literal_packet *literal);

pgp_stream_t *spgp_read_pgp_packets(const char *file);
void spgp_write_pgp_packets(const char *file, pgp_stream_t *stream, armor_options *options);

pgp_stream_t *spgp_read_pgp_packets_from_handle(handle_t handle);
void spgp_write_pgp_packets_handle(handle_t handle, pgp_stream_t *stream, armor_options *options);

pgp_key_packet *spgp_read_key(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t fingerprint_size);
void spgp_write_key(pgp_key_packet *key);

pgp_stream_t *spgp_read_certificate(byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE], byte_t fingerprint_size);
void spgp_write_certificate(pgp_stream_t *stream);

#define SPGP_KEYRING_REPLACE 0x1

pgp_stream_t *spgp_read_keyring();
pgp_keyring_packet *spgp_search_keyring(pgp_key_packet **key, pgp_user_info **user, void *input, uint32_t size, byte_t capabilities);
uint32_t spgp_update_keyring(pgp_keyring_packet *key, uint32_t options);

pgp_key_packet *spgp_decrypt_key(pgp_keyring_packet *keyring, pgp_key_packet *key);

uint32_t spgp_prompt_passphrase(byte_t passphrase[128], char *message);

pgp_hash_algorithms preferred_hash_algorithm_for_signature(pgp_key_packet *packet);
pgp_compression_algorithms preferred_compression_algorithm(pgp_user_info **users, uint32_t count);
pgp_symmetric_key_algorithms preferred_cipher_algorithm(pgp_user_info **users, uint32_t count);
uint16_t preferred_aead_algorithm(pgp_user_info **users, uint32_t count);

void preferred_s2k_algorithm(pgp_key_version version, pgp_s2k *s2k);

#endif
