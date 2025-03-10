/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <spgp.h>
#include <algorithms.h>
#include <argparse.h>
#include <packet.h>
#include <stream.h>
#include <key.h>
#include <session.h>
#include <seipd.h>
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *help = "\
Usage: sgpg [options] [files]\
Sign, Verify, Encrypt or Decrypt\
\
Commands:\
\
 -s, --sign                     make a signature\
     --clear-sign               make a clear text signature\
 -b, --detach-sign              make a detached signature\
 -e, --encrypt                  encrypt data\
 -c, --symmetric                encryption only with symmetric cipher\
 -d, --decrypt                  decrypt data\
     --verify                   verify a signature\
 -k, --list-keys                list keys\
     --list-signatures          list keys and signatures\
     --check-signatures         list and check key signatures\
     --fingerprint              list keys and fingerprints\
 -K, --list-secret-keys         list secret keys\
     --generate-key             generate a new key pair\
     --full-generate-key        full featured key pair generation\
     --generate-revocation      generate a revocation certificate\
     --delete-keys              remove keys from the public keyring\
     --delete-secret-keys       remove keys from the secret keyring\
     --sign-key                 sign a key\
     --edit-key                 sign or edit a key\
     --export                   export keys\
     --import                   import/merge keys\
     --change-passphrase        change a passphrase\
     --send-keys                export keys to a keyserver\
     --receive-keys             import keys from a keyserver\
     --search-keys              search for keys on a keyserver\
     --refresh-keys             update all keys from a keyserver\
\
Options:\
 -v, --verbose                  verbose\
 -q, --quiet                    quiet\
 -h, --help                     help\
 -n, --dry-run                  dry run (no modifications)\
 -i, --interactive              prompt before overwriting\
 -a, --armor                    create ascii armored output\
 -o, --output FILE              write output to FILE\
     --textmode                 use canonical text mode\
 -z N                           compression level to N (0 disables)\
\
Keys:\
 -r, --recipient USER-ID        encrypt for USER-ID\
 -u, --local-user USER-ID       use USER-ID to sign or decrypt\
\
Packets:\
     --list-packets             List PGP packets\
     --dump-packets             Dump PGP packets\
\
";

typedef enum _spgp_option
{
	// Commands
	SPGP_SIGN = 1,
	SPGP_DETACH_SIGN,
	SPGP_CLEAR_SIGN,
	SPGP_VERIFY,
	SPGP_SYMMETRIC_ENCRYPT,
	SPGP_ENCRYPT,
	SPGP_DECRYPT,
	SPGP_LIST_KEYS,
	SPGP_LIST_SECRET_KEYS,
	SPGP_DELETE_KEYS,
	SPGP_DELETE_SECRET_KEYS,
	SPGP_ARMOR,
	SPGP_DEARMOR,
	SPGP_VERBOSE,
	SPGP_QUIET,
	SPGP_HELP,
	SPGP_VERSION,
	SPGP_OUTPUT,
	SPGP_LIST_PACKETS,
	SPGP_DUMP_PACKETS,
} spgp_option;

static arg_option_t spgp_options[] = {
	{"sign", 's', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_SIGN},
	{"detach-sign", 'b', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DETACH_SIGN},
	{"clear-sign", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_CLEAR_SIGN},
	{"verify", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_VERIFY},
	{"symmetric", 'c', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_SYMMETRIC_ENCRYPT},
	{"encrypt", 'e', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_ENCRYPT},
	{"decrypt", 'd', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DECRYPT},
	{"list-keys", 'k', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_KEYS},
	{"list-secret-keys", 'K', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_LIST_SECRET_KEYS},
	{"delete-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DELETE_KEYS},
	{"delete-secret-keys", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DELETE_SECRET_KEYS},
	{"armor", 'a', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_ARMOR},
	{"dearmor", 0, ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_DEARMOR},
	{"help", 'h', ARGPARSE_OPTION_ARGUMENT_NONE, SPGP_HELP},
	{"list-packets", 0, ARGPARSE_OPTION_ARGUMENT_OPTIONAL, SPGP_LIST_PACKETS},
	{"dump-packets", 0, ARGPARSE_OPTION_ARGUMENT_OPTIONAL, SPGP_DUMP_PACKETS},
};

static void spgp_print_help()
{
	printf("%s", help);
}

static void spgp_list_packets(char *file)
{
	char buffer[65536] = {0};
	char str[65536] = {0};

	size_t size = 0;

	FILE *f = fopen(file, "rb");
	size = fread(buffer, 1, 65536, f);

	fclose(f);

	pgp_stream_t *stream = pgp_stream_read(buffer, size);
	pgp_stream_print(stream, str, 65536, PGP_PRINT_HEADER_ONLY);

	printf("%s", str);
}

static void spgp_dump_packets(char *file)
{
	char buffer[65536] = {0};
	char str[65536] = {0};

	size_t size = 0;

	FILE *f = fopen(file, "rb");
	size = fread(buffer, 1, 65536, f);

	fclose(f);

	pgp_stream_t *stream = pgp_stream_read(buffer, size);
	pgp_stream_print(stream, str, 65536, 0);

	printf("%s", str);
}

int main(int argc, char **argv)
{
	argparse_t *actx = argparse_new(argc, (void **)argv, sizeof(spgp_options) / sizeof(arg_option_t), spgp_options, 0);
	arg_result_t *result = NULL;

	while ((result = argparse(actx)) != NULL)
	{
		switch (result->value)
		{
		case SPGP_HELP:
		{
			spgp_print_help();
		}
		break;
		case SPGP_LIST_PACKETS:
		{
			spgp_list_packets(result->data);
		}
		break;
		case SPGP_DUMP_PACKETS:
		{
			spgp_dump_packets(result->data);
		}
		break;
		}
	}

	return 0;
}
