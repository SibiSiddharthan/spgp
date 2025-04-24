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
#include <time.h>

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

typedef struct _key_specfication
{
	byte_t algorithm;
	byte_t capabilities;
	byte_t flags;

	uint32_t expiry;
	pgp_key_parameters parameters;

} key_specfication;

static void parse_algorithm(key_specfication *spec, byte_t *in, byte_t length)
{
	// RSA, DSA, Elgamal
	if (length == 3)
	{
		if (memcmp(in, "rsa", 3) == 0)
		{
			spec->algorithm = PGP_RSA_ENCRYPT_OR_SIGN;
			spec->parameters.bits = 4096;
			return;
		}

		if (memcmp(in, "dsa", 3) == 0)
		{
			spec->algorithm = PGP_DSA;
			spec->parameters.bits = 3072;
			return;
		}

		if (memcmp(in, "elg", 3) == 0)
		{
			spec->algorithm = PGP_ELGAMAL_ENCRYPT_ONLY;
			spec->parameters.bits = 4096;
			return;
		}
	}

	if (length == 7)
	{
		if (memcmp(in, "rsa1024", 7) == 0)
		{
			spec->algorithm = PGP_RSA_ENCRYPT_OR_SIGN;
			spec->parameters.bits = 1024;
			return;
		}

		if (memcmp(in, "rsa2048", 7) == 0)
		{
			spec->algorithm = PGP_RSA_ENCRYPT_OR_SIGN;
			spec->parameters.bits = 2048;
			return;
		}

		if (memcmp(in, "rsa3072", 7) == 0)
		{
			spec->algorithm = PGP_RSA_ENCRYPT_OR_SIGN;
			spec->parameters.bits = 3072;
			return;
		}

		if (memcmp(in, "rsa4096", 7) == 0)
		{
			spec->algorithm = PGP_RSA_ENCRYPT_OR_SIGN;
			spec->parameters.bits = 4096;
			return;
		}

		if (memcmp(in, "dsa1024", 7) == 0)
		{
			spec->algorithm = PGP_DSA;
			spec->parameters.bits = 1024;
			return;
		}

		if (memcmp(in, "dsa2048", 7) == 0)
		{
			spec->algorithm = PGP_RSA_ENCRYPT_OR_SIGN;
			spec->parameters.bits = 2048;
			return;
		}

		if (memcmp(in, "dsa3072", 7) == 0)
		{
			spec->algorithm = PGP_DSA;
			spec->parameters.bits = 3072;
			return;
		}

		if (memcmp(in, "elg1024", 7) == 0)
		{
			spec->algorithm = PGP_ELGAMAL_ENCRYPT_ONLY;
			spec->parameters.bits = 1024;
			return;
		}

		if (memcmp(in, "elg2048", 7) == 0)
		{
			spec->algorithm = PGP_ELGAMAL_ENCRYPT_ONLY;
			spec->parameters.bits = 2048;
			return;
		}

		if (memcmp(in, "elg3072", 7) == 0)
		{
			spec->algorithm = PGP_ELGAMAL_ENCRYPT_ONLY;
			spec->parameters.bits = 3072;
			return;
		}

		if (memcmp(in, "elg4096", 7) == 0)
		{
			spec->algorithm = PGP_ELGAMAL_ENCRYPT_ONLY;
			spec->parameters.bits = 4096;
			return;
		}
	}

	// Elliptic curves
	if (length == 5)
	{
		if (memcmp(in, "ed448", 5) == 0)
		{
			spec->algorithm = PGP_EDDSA;
			spec->parameters.curve = PGP_EC_ED448;
			return;
		}

		if (memcmp(in, "cv448", 5) == 0)
		{
			spec->algorithm = PGP_ECDH;
			spec->parameters.curve = PGP_EC_CURVE448;
			return;
		}
	}

	if (length == 7)
	{
		if (memcmp(in, "ed25519", 7) == 0)
		{
			spec->algorithm = PGP_EDDSA;
			spec->parameters.curve = PGP_EC_ED25519;
			return;
		}

		if (memcmp(in, "cv25519", 7) == 0)
		{
			spec->algorithm = PGP_ECDH;
			spec->parameters.curve = PGP_EC_CURVE25519;
			return;
		}
	}

	if (length == 8)
	{
		if (memcmp(in, "nistp256", 8) == 0)
		{
			spec->algorithm = PGP_ECDSA;
			spec->parameters.curve = PGP_EC_NIST_P256;
			return;
		}

		if (memcmp(in, "nistp384", 8) == 0)
		{
			spec->algorithm = PGP_ECDSA;
			spec->parameters.curve = PGP_EC_NIST_P384;
			return;
		}

		if (memcmp(in, "nistp521", 8) == 0)
		{
			spec->algorithm = PGP_ECDSA;
			spec->parameters.curve = PGP_EC_NIST_P521;
			return;
		}
	}

	if (length == 15)
	{
		if (memcmp(in, "brainpoolP256r1", 15) == 0)
		{
			spec->algorithm = PGP_ECDSA;
			spec->parameters.curve = PGP_EC_BRAINPOOL_256R1;
			return;
		}

		if (memcmp(in, "brainpoolP384r1", 15) == 0)
		{
			spec->algorithm = PGP_ECDSA;
			spec->parameters.curve = PGP_EC_BRAINPOOL_384R1;
			return;
		}

		if (memcmp(in, "brainpoolP512r1", 15) == 0)
		{
			spec->algorithm = PGP_ECDSA;
			spec->parameters.curve = PGP_EC_BRAINPOOL_512R1;
			return;
		}
	}

	if ((length == 6) && (memcmp(in, "x25519", 6) == 0))
	{
		spec->algorithm = PGP_X25519;
		return;
	}

	if ((length == 4) && (memcmp(in, "x448", 4) == 0))
	{
		spec->algorithm = PGP_X448;
		return;
	}

	printf("Bad algo");
	exit(1);
}

#define IS_NUM(c)   ((c) >= 48 && (c) <= 57)
#define TO_NUM(c)   ((c) - 48)
#define TO_UPPER(c) ((c) & ~0x20)

static void parse_capabilities(key_specfication *spec, byte_t *in, byte_t length)
{
	if (length > 4)
	{
		printf("Bad cap");
		exit(1);
	}

	for (byte_t i = 0; i < length; ++i)
	{
		if (TO_UPPER(in[i]) == 'C')
		{
			spec->capabilities |= PGP_KEY_FLAG_CERTIFY;
		}
		if (TO_UPPER(in[i]) == 'S')
		{
			spec->capabilities |= PGP_KEY_FLAG_SIGN;
		}
		if (TO_UPPER(in[i]) == 'E')
		{
			spec->capabilities |= (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE);
		}
		if (TO_UPPER(in[i]) == 'A')
		{
			spec->capabilities |= PGP_KEY_FLAG_AUTHENTICATION;
		}
	}
}

static void parse_expiry(key_specfication *spec, byte_t *in, byte_t length)
{
	uint32_t value = 0;

	for (byte_t i = 0; i < length; ++i)
	{
		if (IS_NUM(in[i]))
		{
			value = (value * 10) + TO_NUM(in[i]);
		}
		else
		{
			if (i != length - 1)
			{
				printf("Bad expiry");
				exit(1);
			}

			if (TO_UPPER(in[i]) == 'Y')
			{
				spec->expiry = value * 31536000;
			}
			else if (TO_UPPER(in[i]) == 'D')
			{
				spec->expiry = value * 86400;
			}
			else
			{
				printf("Bad expiry");
				exit(1);
			}
		}
	}

	// Seconds
	spec->expiry = value;
}

static void parse_key(key_specfication *spec, byte_t *in, byte_t length)
{
	byte_t count = 0;
	byte_t capabilities_offset = 0;
	byte_t expiry_offset = 0;

	for (byte_t i = 0; i < length; ++i)
	{
		if (in[i] == ':')
		{
			++count;

			if (count == 1)
			{
				capabilities_offset = i + 1;
			}

			if (count == 2)
			{
				expiry_offset = i + 1;
			}
		}

		if (count > 2)
		{
			printf("Bad spec:%s\n", in);
			exit(1);
		}
	}

	switch (count)
	{
	case 0:
		parse_algorithm(spec, in, length);
		break;
	case 1:
		parse_algorithm(spec, in, capabilities_offset - 2);
		parse_capabilities(spec, in + capabilities_offset, length - capabilities_offset);
		break;
	case 2:
		parse_algorithm(spec, in, capabilities_offset - 2);
		parse_capabilities(spec, in + capabilities_offset, expiry_offset - 2);
		parse_expiry(spec, in + expiry_offset, length - expiry_offset);
		break;
	}
}

// Key specification: algorithm[:usage[:expiry]]/algorithm[:usage[:expiry]]
static uint32_t parse_spec(byte_t *in, key_specfication **out)
{
	key_specfication *spec = NULL;
	uint32_t count = 0;

	// Count number of keys in spec.
	for (uint32_t i = 0; in[i] != '\0'; ++i)
	{
		if (in[i] == '/')
		{
			count += 1;
		}
	}

	spec = malloc(sizeof(key_specfication) * count);

	if (spec == NULL)
	{
		printf("No memory");
		exit(1);
	}

	memset(spec, 0, sizeof(key_specfication) * count);

	uint32_t start = 0;
	uint32_t end = 0;
	uint32_t pos = 0;
	uint32_t j = 0;

	// Parse each key
	for (uint32_t i = 0; i < count; ++i)
	{
		start = pos;

		for (j = pos; in[j] != '\0'; ++j)
		{
			if (in[j] == '/')
			{
				break;
			}

			pos += 1;
		}

		end = pos + 1;

		if (in[j] == '/')
		{
			pos += 2;
		}

		parse_key(&spec[i], PTR_OFFSET(in, pos), end - start);
	}

	*out = spec;

	return count;
}

uint32_t spgp_generate_key(void)
{
	void *uid = NULL;
	void *spec = NULL;

	key_specfication *key_specs = NULL;
	pgp_key_packet **key_packets = NULL;
	uint32_t count = 0;

	pgp_user_id_packet *user = NULL;

	if (command.files == NULL || command.files->count != 2)
	{
		printf("Bad usage");
		exit(1);
	}

	uid = command.files->packets[0];
	spec = command.files->packets[1];

	pgp_user_id_packet_new(&user, PGP_HEADER, uid, strlen(uid));

	count = parse_spec(spec, &key_specs);

	key_packets = malloc(sizeof(void *) * count);

	if (key_packets == NULL)
	{
		printf("No memory");
		exit(1);
	}

	memset(key_packets, 0, sizeof(void *) * count);

	for (uint32_t i = 0; i < count; ++i)
	{
		pgp_key_generate(&key_packets[i], PGP_KEY_V4, key_specs->algorithm, key_specs->capabilities, key_specs->flags, time(NULL),
						 key_specs->expiry, &key_specs->parameters);
	}

	return 0;
}
