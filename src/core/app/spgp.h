/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_H
#define SPGP_H

#include <types.h>
#include <buffer.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <load.h>

#include <status.h>
#include <os.h>
#include <io.h>

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

typedef enum _spgp_key_id
{
	SPGP_UNKNOWN = 0,

	// RSA
	SPGP_RSA2048,
	SPGP_RSA3072,
	SPGP_RSA4096,

	// DSA
	SPGP_DSA1024,
	SPGP_DSA2048,
	SPGP_DSA3072,

	// Elgamal
	SPGP_ELGAMAL1024,
	SPGP_ELGAMAL2048,
	SPGP_ELGAMAL3072,
	SPGP_ELGAMAL4096,

	// ECC
	SPGP_EC_NISTP256,
	SPGP_EC_NISTP384,
	SPGP_EC_NISTP521,
	SPGP_EC_BRAINPOOL256R1,
	SPGP_EC_BRAINPOOL384R1,
	SPGP_EC_BRAINPOOL512R1,
	SPGP_EC_CURVE25519,
	SPGP_EC_CURVE448,
	SPGP_EC_ED25519,
	SPGP_EC_ED448,

	// Legacy
	SPGP_EC_CURVE25519_LEGACY,
	SPGP_EC_ED25519_LEGACY,

} spgp_key_id;

typedef enum _spgp_mode
{
	SPGP_MODE_RFC4880 = 1,
	SPGP_MODE_OPENPGP,
	SPGP_MODE_LIBREPGP,
} spgp_mode;

typedef enum _spgp_operation
{
	// Reserved Command
	SPGP_OPERATION_NONE = 0,

	// Basic Commands
	SPGP_OPERATION_SIGN,
	SPGP_OPERATION_VERIFY,

	SPGP_OPERATION_ENCRYPT,
	SPGP_OPERATION_DECRYPT,

	SPGP_OPERATION_ARMOR,
	SPGP_OPERATION_DEARMOR,

	// Key Commands
	SPGP_OPERATION_LIST_KEYS,
	SPGP_OPERATION_DELETE_KEYS,
	SPGP_OPERATION_EXPORT_KEYS,
	SPGP_OPERATION_IMPORT_KEYS,
	SPGP_OPERATION_GENERATE_ROVOCATION,
	SPGP_OPERATION_GENERATE_KEY,

	// Packet Commands
	SPGP_OPERATION_LIST_PACKETS
} spgp_operation;

typedef struct _spgp_command
{
	spgp_operation operation;
	spgp_mode mode;

	handle_t home;
	handle_t keys;
	handle_t certs;
	handle_t keyring;

	void *homedir;
	void *output;
	void *passhprase;

	byte_t armor;
	time_t timestamp;

	union
	{
		struct
		{
			byte_t detach;
			byte_t cleartext;
			char *file;
			char *packet;
		} sign;

		struct
		{
			char *sign;
			char *file;
			char *packet;
		} verify;

		struct
		{
			byte_t dump;
			byte_t no_mpi;
			char *file;
		} list_packets;
	};

} spgp_command;

uint32_t spgp_generate_key(spgp_key_id id, const char *uid, uint16_t uid_size);
uint32_t spgp_delete_key(const char *key_id, uint16_t key_id_size, uint32_t options);

uint32_t spgp_export_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size);
uint32_t spgp_import_key(void *buffer, size_t buffer_size);

uint32_t spgp_search_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size, uint32_t options);
uint32_t spgp_list_keys(uint32_t options);

uint32_t spgp_sign(spgp_command *command);
uint32_t spgp_verify(spgp_command *command);

uint32_t spgp_list_packets(spgp_command *command);

#endif
