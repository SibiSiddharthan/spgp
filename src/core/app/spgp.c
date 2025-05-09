/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <argparse.h>
#include <algorithms.h>

#include <status.h>
#include <os.h>
#include <io.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

spgp_command command = {0};

static const char *version = "\
sgpg 0.1\n\
Copyright (c) 2024 - 2025 Sibi Siddharthan\n\
Distributed under the MIT license\n\
\n\
Supported algorithms:\n\
Public Key: RSA, DSA, ECDH, ECDSA, EDDSA, ED25519, ED448, X25519, X448\n\
Symmetric Ciphers: TDES, AES, CAMELLIA, TWOFISH\n\
Hash: MD5, RIPEMD160, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3-256, SHA3-512\n\
Compression: Uncompressed\n\
";

static const char *help = "\
Usage: sgpg [options] [files]\n\
Sign, Verify, Encrypt or Decrypt\n\
\n\
Basic Commands:\n\
\n\
 -s, --sign                     make a signature\n\
     --clear-sign               make a clear text signature\n\
 -b, --detach-sign              make a detached signature\n\
 -e, --encrypt                  encrypt data\n\
 -c, --symmetric                encryption only with symmetric cipher\n\
 -d, --decrypt                  decrypt data\n\
 -v  --verify                   verify a signature\n\
 -a, --armor                    create ascii armored output\n\
 -p  --dearmor                  create pgp packet output (default)\n\
\n\
Key Commands:\n\
\n\
 -k, --list-keys                list keys\n\
     --check-signatures         list and check key signatures\n\
 -K, --list-secret-keys         list secret keys\n\
 -g  --generate-key             generate a new key pair\n\
 -G  --full-generate-key        full featured key pair generation\n\
 -R  --generate-revocation      generate a revocation certificate\n\
 -w  --delete-keys              remove keys from the public keyring\n\
 -W  --delete-secret-keys       remove keys from the secret keyring\n\
     --sign-key                 sign a key\n\
     --edit-key                 sign or edit a key\n\
 -x  --export                   export keys\n\
 -X  --export-secret-keys       export secret keys\n\
 -i  --import                   import keys\n\
     --change-passphrase        change a passphrase\n\
     --send-keys                export keys to a keyserver\n\
     --receive-keys             import keys from a keyserver\n\
     --search-keys              search for keys on a keyserver\n\
     --refresh-keys             update all keys from a keyserver\n\
\n\
Packet Commands:\n\
 -L   --list-packets             list PGP packets\n\
 -D   --dump-packets             dump PGP packets\n\
\n\
Miscellaneous Commands:\n\
     -h, --help                 help\n\
     --version                  print SPGP version information\n\
\n\
Output Options:\n\
\n\
     --verbose                  verbose\n\
     --quiet                    quiet\n\
 -o, --output FILE              write output to FILE\n\
 -z  --compress-level N         compression level to N (0 disables)\n\
\n\
Key Selection:\n\
 -r, --recipient USER-ID        encrypt for USER-ID\n\
 -u, --local-user USER-ID       use USER-ID to sign or decrypt\n\
\n\
Algorithm Options:\n\
     --digest-algo ALGO         hash using ALGO\n\
     --cipher-algo ALGO         encrypt using ALGO\n\
     --compress-algo ALGO       compress using ALGO\n\
\n\
Operation Modes:\n\
     --rfc4880                  conform to rfc 4880 specification\n\
     --openpgp                  conform to openpgp specification\n\
     --librepgp                 conform to librepgp specification\n\
\n\
Miscellaneous Options:\n\
     --dry-run                  dry run (no modifications)\n\
     --interactive              prompt before overwriting\n\
     --batch                    enable batch mode\n\
     --expert                   enable expert mode\n\
     --no-mpis                  dont print mpis when dumping packets\n\
     --homedir                  set home directory for spgp\n\
     --passphrase PASS          use passphrase PASS\n\
     --faked-system-time TIME   use timestamp TIME\n\
\n\
";

typedef enum _spgp_option
{
	// Basic Commands
	SPGP_OPTION_SIGN = 1,
	SPGP_OPTION_DETACH_SIGN,
	SPGP_OPTION_CLEAR_SIGN,
	SPGP_OPTION_VERIFY,
	SPGP_OPTION_SYMMETRIC_ENCRYPT,
	SPGP_OPTION_ENCRYPT,
	SPGP_OPTION_DECRYPT,
	SPGP_OPTION_ARMOR,
	SPGP_OPTION_DEARMOR,

	// Key Commands
	SPGP_OPTION_LIST_KEYS,
	SPGP_OPTION_LIST_SECRET_KEYS,
	SPGP_OPTION_DELETE_KEYS,
	SPGP_OPTION_DELETE_SECRET_KEYS,
	SPGP_OPTION_EXPORT_KEYS,
	SPGP_OPTION_EXPORT_SECRET_KEYS,
	SPGP_OPTION_IMPORT_KEYS,
	SPGP_OPTION_GENERATE_REVOCATION,
	SPGP_OPTION_GENERATE_KEY,
	SPGP_OPTION_FULL_GENERATE_KEY,

	// Packet Commands
	SPGP_OPTION_LIST_PACKETS,
	SPGP_OPTION_DUMP_PACKETS,

	// Miscellaneous Commands
	SPGP_OPTION_HELP,
	SPGP_OPTION_VERSION,

	// Output Options
	SPGP_OPTION_VERBOSE,
	SPGP_OPTION_QUIET,
	SPGP_OPTION_OUTPUT,
	SPGP_OPTION_COMPRESS_LEVEL,

	// Processing Options
	SPGP_OPTION_TEXTMODE,
	SPGP_OPTION_MULTIFILE,

	// Key Selection
	SPGP_OPTION_RECIPIENT,
	SPGP_OPTION_USER_ID,

	// Algorithm Options
	SPGP_OPTION_DIGEST_ALGORITHM,
	SPGP_OPTION_CIPHER_ALGORITHM,
	SPGP_OPTION_COMPRESS_ALGORITHM,

	// Operation Modes
	SPGP_OPTION_RFC4880,
	SPGP_OPTION_OPENPGP,
	SPGP_OPTION_LIBREPGP,

	// Miscellaneous Options
	SPGP_OPTION_DRY_RUN,
	SPGP_OPTION_INTERACTIVE,
	SPGP_OPTION_BATCH,
	SPGP_OPTION_EXPERT,
	SPGP_OPTION_NO_MPIS,
	SPGP_OPTION_HOMEDIR,
	SPGP_OPTION_PASSPHRASE,
	SPGP_OPTION_FAKED_TIME,
} spgp_option;

static arg_option_t spgp_options[] = {

	// Basic Commands
	{"sign", 's', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_SIGN},
	{"detach-sign", 'b', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DETACH_SIGN},
	{"clear-sign", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_CLEAR_SIGN},
	{"verify", 'v', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_VERIFY},
	{"symmetric", 'c', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_SYMMETRIC_ENCRYPT},
	{"encrypt", 'e', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_ENCRYPT},
	{"decrypt", 'd', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DECRYPT},
	{"armor", 'a', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_ARMOR},
	{"dearmor", 'p', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DEARMOR},

	// Key Commands
	{"list-keys", 'k', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_LIST_KEYS},
	{"list-secret-keys", 'K', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_LIST_SECRET_KEYS},
	{"delete-keys", 'w', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DELETE_KEYS},
	{"delete-secret-keys", 'W', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DELETE_SECRET_KEYS},
	{"export-keys", 'x', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_EXPORT_KEYS},
	{"export-secret-keys", 'X', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_EXPORT_SECRET_KEYS},
	{"import-keys", 'i', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_IMPORT_KEYS},
	{"generate-revocation", 'R', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_GENERATE_REVOCATION},
	{"generate-key", 'g', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_GENERATE_KEY},
	{"full-generate-key", 'G', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_FULL_GENERATE_KEY},

	// Packet Commands
	{"list-packets", 'L', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_LIST_PACKETS},
	{"dump-packets", 'D', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DUMP_PACKETS},

	// Miscellaneous Commands
	{"help", 'h', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_HELP},
	{"version", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_VERSION},

	// Output Options
	{"verbose", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_VERBOSE},
	{"quiet", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_QUIET},
	{"output", 'o', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_OUTPUT},
	{"compress-level", 'z', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_COMPRESS_LEVEL},

	// Processing Options
	{"textmode", 't', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_TEXTMODE},
	{"multifile", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_MULTIFILE},

	// Key Selection
	{"recipient", 'r', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_RECIPIENT},
	{"local-user", 'u', ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_USER_ID},

	// Algorithm Options
	{"digest-algo", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_DIGEST_ALGORITHM},
	{"cipher-algo", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_CIPHER_ALGORITHM},
	{"compress-algo", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_COMPRESS_ALGORITHM},

	// Operation Modes
	{"rfc4880", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_RFC4880},
	{"openpgp", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_OPENPGP},
	{"librepgp", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_LIBREPGP},

	// Miscellaneous Options
	{"dry-run", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_DRY_RUN},
	{"interactive", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_INTERACTIVE},
	{"batch", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_BATCH},
	{"expert", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_EXPERT},
	{"no-mpis", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_OPTION_NO_MPIS},
	{"homedir", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_HOMEDIR},
	{"passphrase", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_PASSPHRASE},
	{"faked-system-time", 0, ARGPARSE_OPTION_ARGUMENT_REQUIRED, SPGP_OPTION_FAKED_TIME}

	// Compatibility Options
};

static void spgp_print_help(void)
{
	size_t result = 0;
	os_write(STDOUT_HANDLE, (void *)help, strlen(help), &result);
}

static void spgp_print_version(void)
{
	size_t result = 0;
	os_write(STDOUT_HANDLE, (void *)version, strlen(version), &result);
}

static status_t spgp_initialize_directory(handle_t *handle, handle_t root, char *dir, uint16_t length)
{
	status_t status = 0;

	status = os_open(handle, root, dir, length, FILE_ACCESS_READ, FILE_FLAG_DIRECTORY | FILE_FLAG_NO_INHERIT, 0);

	// If home directory does not exist try to create it.
	if (status == OS_STATUS_PATH_NOT_FOUND)
	{
		status = os_mkdir(root, dir, length, 0700);

		if (status != OS_STATUS_SUCCESS)
		{
			return status;
		}

		status = os_open(handle, root, dir, length, FILE_ACCESS_READ, FILE_FLAG_DIRECTORY | FILE_FLAG_NO_INHERIT, 0);

		if (status != OS_STATUS_SUCCESS)
		{
			return status;
		}
	}

	return status;
}

void spgp_initialize_home(spgp_command *spgp)
{
	status_t status = 0;
	handle_t handle = 0;

	// Initialize home
	if (spgp->home == NULL)
	{
		// Get base of home from the environment.
		// Prefer $HOME to $USERPROFILE
		char *home = NULL;

		home = getenv("HOME");

		if (home == NULL)
		{
			home = getenv("USERPROFILE");
		}

		if (home == NULL)
		{
			printf("%s", "Unable to initialize home.\n");
			exit(1);
		}

		status = os_open(&handle, HANDLE_CWD, home, strlen(home), FILE_ACCESS_READ, FILE_FLAG_DIRECTORY | FILE_FLAG_NO_INHERIT, 0);

		if (status != OS_STATUS_SUCCESS)
		{
			printf("%s", "Unable to initialize home.\n");
			exit(1);
		}

		status = spgp_initialize_directory(&spgp->home, handle, SPGP_DEFAULT_HOME, strlen(SPGP_DEFAULT_HOME));

		if (status != OS_STATUS_SUCCESS)
		{
			printf("%s", "Unable to initialize spgp home directory.\n");
			exit(1);
		}

		os_close(handle);
	}
	else
	{
		status = os_open(&spgp->home, HANDLE_CWD, spgp->homedir, strlen(spgp->homedir), FILE_ACCESS_READ,
						 FILE_FLAG_DIRECTORY | FILE_FLAG_NO_INHERIT, 0);

		if (status != OS_STATUS_SUCCESS)
		{
			printf("%s", "Unable to initialize home.\n");
			exit(1);
		}
	}

	// Initialize keys
	status = spgp_initialize_directory(&spgp->keys, spgp->home, SPGP_KEYS, strlen(SPGP_KEYS));

	if (status != OS_STATUS_SUCCESS)
	{
		printf("%s", "Unable to initialize spgp keys.\n");
		exit(1);
	}

	// Initialize certs
	status = spgp_initialize_directory(&spgp->certs, spgp->home, SPGP_CERTS, strlen(SPGP_CERTS));

	if (status != OS_STATUS_SUCCESS)
	{
		printf("%s", "Unable to initialize spgp certs.\n");
		exit(1);
	}

	// Initialize keyring
	status = os_open(&spgp->keyring, spgp->home, SPGP_KEYRING, strlen(SPGP_KEYRING), FILE_ACCESS_READ | FILE_ACCESS_WRITE,
					 FILE_FLAG_CREATE | FILE_FLAG_NON_DIRECTORY | FILE_FLAG_NO_INHERIT, 0700);

	if (status != OS_STATUS_SUCCESS)
	{
		printf("%s", "Unable to initialize spgp keyring.\n");
		exit(1);
	}
}

byte_t *spgp_prompt_passphrase(void)
{
	// TODO
	return NULL;
}

static uint32_t spgp_execute_operation(spgp_command *command)
{
	if (command->list_packets || command->dump_packets)
	{
		return spgp_list_packets(command);
	}

	if (command->sign || command->detach_sign || command->clear_sign)
	{
		spgp_sign();
	}

	if (command->verify)
	{
		return spgp_verify(command);
	}

	if (command->encrypt || command->symmetric)
	{
		return spgp_encrypt(command);
	}

	if (command->decrypt)
	{
		return spgp_decrypt(command);
	}

	if (command->import_keys)
	{
		return spgp_import_keys(command);
	}

	if (command->generate_key)
	{
		return spgp_generate_key();
	}

	if (command->list_keys || command->list_secret_keys)
	{
		return spgp_list_keys();
	}

	spgp_print_help();

	return 0;
}

static void spgp_parse_arguments(spgp_command *command, uint32_t argc, char **argv)
{
	argparse_t *actx = NULL;
	arg_result_t *result = NULL;

	actx = argparse_new(argc, (void **)argv, sizeof(spgp_options) / sizeof(arg_option_t), spgp_options, ARGPARSE_FLAG_SKIP_FIRST_ARGUMENT);

	while ((result = argparse(actx, 0)) != NULL)
	{
		switch (result->value)
		{
		// The important ones
		case SPGP_OPTION_VERSION:
		{
			spgp_print_version();
			exit(EXIT_SUCCESS);
		}
		break;
		case SPGP_OPTION_HELP:
		{
			spgp_print_help();
			exit(EXIT_SUCCESS);
		}
		break;

		// Basic Commands
		case SPGP_OPTION_SIGN:
			command->need_home = 1;
			command->sign = 1;
			break;
		case SPGP_OPTION_DETACH_SIGN:
			command->need_home = 1;
			command->detach_sign = 1;
			break;
		case SPGP_OPTION_CLEAR_SIGN:
			command->need_home = 1;
			command->clear_sign = 1;
			break;
		case SPGP_OPTION_VERIFY:
			command->need_home = 1;
			command->verify = 1;
			break;
		case SPGP_OPTION_ENCRYPT:
			command->need_home = 1;
			command->encrypt = 1;
			break;
			command->need_home = 1;
		case SPGP_OPTION_SYMMETRIC_ENCRYPT:
			command->need_home = 1;
			command->symmetric = 1;
			break;
		case SPGP_OPTION_DECRYPT:
			command->need_home = 1;
			command->decrypt = 1;
			break;
		case SPGP_OPTION_ARMOR:
			command->armor = 1;
			break;
		case SPGP_OPTION_DEARMOR:
			command->dearmor = 0;
			break;

		// Key Commands
		case SPGP_OPTION_LIST_KEYS:
			command->need_home = 1;
			command->list_keys = 1;
			break;
		case SPGP_OPTION_LIST_SECRET_KEYS:
			command->need_home = 1;
			command->list_secret_keys = 1;
			break;

		case SPGP_OPTION_IMPORT_KEYS:
			command->need_home = 1;
			command->import_keys = 1;
			break;

		case SPGP_OPTION_GENERATE_KEY:
			command->need_home = 1;
			command->generate_key = 1;
			break;
		case SPGP_OPTION_FULL_GENERATE_KEY:
			command->need_home = 1;
			command->full_generate_key = 1;
			break;

		// Packet Commands
		case SPGP_OPTION_LIST_PACKETS:
			command->list_packets = 1;
			break;
		case SPGP_OPTION_DUMP_PACKETS:
			command->dump_packets = 1;
			break;

		// Key Selection
		case SPGP_OPTION_USER_ID:
		{
			command->users = pgp_stream_push(command->users, result->data);

			if (command->users == NULL)
			{
				printf("No memory");
				exit(1);
			}
		}
		break;
		case SPGP_OPTION_RECIPIENT:
		{
			command->recipients = pgp_stream_push(command->recipients, result->data);

			if (command->recipients == NULL)
			{
				printf("No memory");
				exit(1);
			}
		}
		break;

		// Output Options
		case SPGP_OPTION_OUTPUT:
			command->output = result->data;
			break;

		// Processing Options
		case SPGP_OPTION_TEXTMODE:
			command->textmode = 1;
			break;

		case SPGP_OPTION_MULTIFILE:
			command->multifile = 1;
			break;

		// Operation Modes
		case SPGP_OPTION_RFC4880:
		{
			command->mode = SPGP_MODE_RFC4880;
		}
		break;
		case SPGP_OPTION_OPENPGP:
		{
			command->mode = SPGP_MODE_OPENPGP;
		}
		break;
		case SPGP_OPTION_LIBREPGP:
		{
			command->mode = SPGP_MODE_LIBREPGP;
		}
		break;

		// Miscellaneous Options
		case SPGP_OPTION_HOMEDIR:
		{
			command->home = result->data;
		}
		break;
		case SPGP_OPTION_PASSPHRASE:
		{
			command->passhprase = result->data;
		}
		break;
		case SPGP_OPTION_NO_MPIS:
		{
			command->no_print_mpis = 1;
		}
		break;

		case ARGPARSE_RETURN_NON_OPTION:
		{
			command->files = pgp_stream_push(command->files, result->data);

			if (command->files == NULL)
			{
				printf("No memory");
				exit(1);
			}
		}
		break;

		default:
			break;
		}
	}

	argparse_delete(actx);
}

int main(int argc, char **argv)
{
	uint32_t exit_code = 0;

	spgp_parse_arguments(&command, argc, argv);

	// No command given, print help
	if (command.options == 0)
	{
		spgp_print_help();
		exit(EXIT_SUCCESS);
	}

	// The operations do not require setting up the home directory, execute them immediately.
	if (command.need_home == 0)
	{
		return (int)spgp_execute_operation(&command);
	}

	// Setup home and execute.
	// If home initialization fails process will exit.
	if (command.stateless == 0)
	{
		spgp_initialize_home(&command);
	}

	exit_code = spgp_execute_operation(&command);

	return (int)exit_code;
}
