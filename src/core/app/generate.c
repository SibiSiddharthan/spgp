/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <packet.h>
#include <key.h>
#include <signature.h>
#include <crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
			spec->algorithm = 0;
			spec->parameters.curve = PGP_EC_NIST_P256;
			return;
		}

		if (memcmp(in, "nistp384", 8) == 0)
		{
			spec->algorithm = 0;
			spec->parameters.curve = PGP_EC_NIST_P384;
			return;
		}

		if (memcmp(in, "nistp521", 8) == 0)
		{
			spec->algorithm = 0;
			spec->parameters.curve = PGP_EC_NIST_P521;
			return;
		}
	}

	if (length == 15)
	{
		if (memcmp(in, "brainpoolP256r1", 15) == 0)
		{
			spec->algorithm = 0;
			spec->parameters.curve = PGP_EC_BRAINPOOL_256R1;
			return;
		}

		if (memcmp(in, "brainpoolP384r1", 15) == 0)
		{
			spec->algorithm = 0;
			spec->parameters.curve = PGP_EC_BRAINPOOL_384R1;
			return;
		}

		if (memcmp(in, "brainpoolP512r1", 15) == 0)
		{
			spec->algorithm = 0;
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
				value = value * 31536000;
			}
			else if (TO_UPPER(in[i]) == 'D')
			{
				value = value * 86400;
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
		parse_algorithm(spec, in, capabilities_offset - 1);
		parse_capabilities(spec, in + capabilities_offset, length - capabilities_offset);
		break;
	case 2:
		parse_algorithm(spec, in, capabilities_offset - 1);
		parse_capabilities(spec, in + capabilities_offset, expiry_offset - capabilities_offset);
		parse_expiry(spec, in + expiry_offset, length - expiry_offset);
		break;
	}
}

static void process_key(key_specfication *spec)
{
	// Check unsupported algorithms
	if (command.mode == SPGP_MODE_OPENPGP)
	{
		if (spec->algorithm == PGP_DSA || spec->algorithm == PGP_ELGAMAL_ENCRYPT_ONLY)
		{
			printf("Unsupported V6 key algorithm.\n");
			exit(1);
		}
	}

	if (command.mode == SPGP_MODE_RFC4880)
	{
		if (spec->algorithm == PGP_EDDSA && spec->parameters.curve == PGP_EC_ED448)
		{
			printf("Unsupported V4 key algorithm.\n");
			exit(1);
		}
	}

	if (command.mode == SPGP_MODE_RFC2440)
	{
		if (spec->algorithm != PGP_RSA_ENCRYPT_OR_SIGN && spec->algorithm != PGP_RSA_ENCRYPT_ONLY && spec->algorithm != PGP_RSA_SIGN_ONLY &&
			spec->algorithm != PGP_DSA && spec->algorithm != PGP_ELGAMAL_ENCRYPT_ONLY)
		{
			printf("Unsupported key algorithm for RFC:2440 conformance.\n");
			exit(1);
		}
	}

	// Convert to openpgp algorithm identifiers
	if (command.mode == SPGP_MODE_OPENPGP)
	{
		if (spec->algorithm == PGP_EDDSA)
		{
			if (spec->parameters.curve == PGP_EC_ED25519)
			{
				spec->algorithm = PGP_ED25519;
			}

			if (spec->parameters.curve == PGP_EC_ED448)
			{
				spec->algorithm = PGP_ED448;
			}
		}

		if (spec->algorithm == PGP_ECDH)
		{
			if (spec->parameters.curve == PGP_EC_CURVE25519)
			{
				spec->algorithm = PGP_X25519;
			}

			if (spec->parameters.curve == PGP_EC_CURVE448)
			{
				spec->algorithm = PGP_X448;
			}
		}
	}

	// Convert to librepgp algorithm identifiers
	if (command.mode == SPGP_MODE_LIBREPGP)
	{
		if (spec->algorithm == PGP_X25519)
		{
			spec->algorithm = PGP_ECDH;
			spec->parameters.curve = PGP_EC_CURVE25519;
		}

		if (spec->algorithm == PGP_X448)
		{
			spec->algorithm = PGP_ECDH;
			spec->parameters.curve = PGP_EC_CURVE448;
		}
	}

	// Check elliptic curve capabilities
	if (spec->algorithm == 0)
	{
		if ((spec->capabilities & (PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN | PGP_KEY_FLAG_AUTHENTICATION)) &&
			(spec->capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE)))
		{
			printf("Cannot sign and encrypt");
			exit(1);
		}

		if (spec->capabilities & (PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN | PGP_KEY_FLAG_AUTHENTICATION))
		{
			spec->algorithm = PGP_ECDSA;
		}

		if (spec->capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
		{
			spec->algorithm = PGP_ECDH;
		}
	}

	// Check capabilities
	if (spec->capabilities & (PGP_KEY_FLAG_CERTIFY | PGP_KEY_FLAG_SIGN | PGP_KEY_FLAG_AUTHENTICATION))
	{
		if (spec->algorithm == PGP_ECDH || spec->algorithm == PGP_ELGAMAL_ENCRYPT_ONLY || spec->algorithm == PGP_X25519 ||
			spec->algorithm == PGP_X448)
		{
			printf("Bad signature algorithm");
			exit(1);
		}

		if (spec->capabilities & (PGP_KEY_FLAG_ENCRYPT_COM | PGP_KEY_FLAG_ENCRYPT_STORAGE))
		{
			if (spec->algorithm == PGP_DSA || spec->algorithm == PGP_ECDSA || spec->algorithm == PGP_EDDSA ||
				spec->algorithm == PGP_ED25519 || spec->algorithm == PGP_ED448)
			{
				printf("Bad encryption algorithm");
				exit(1);
			}
		}
	}

	// Set ECDH parameters
	if (spec->algorithm == PGP_ECDH)
	{
		switch (spec->parameters.curve)
		{
		case PGP_EC_NIST_P256:
		case PGP_EC_BRAINPOOL_256R1:
		case PGP_EC_CURVE25519:
			spec->parameters.hash_algorithm = PGP_SHA2_256;
			spec->parameters.cipher_algorithm = PGP_AES_128;
			break;
		case PGP_EC_NIST_P384:
		case PGP_EC_BRAINPOOL_384R1:
			spec->parameters.hash_algorithm = PGP_SHA2_384;
			spec->parameters.cipher_algorithm = PGP_AES_192;
			break;
		case PGP_EC_NIST_P521:
		case PGP_EC_BRAINPOOL_512R1:
		case PGP_EC_CURVE448:
			spec->parameters.hash_algorithm = PGP_SHA2_512;
			spec->parameters.cipher_algorithm = PGP_AES_256;
			break;

		default:
			break;
		}
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

	count += 1;
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

		end = pos;

		if (in[j] == '/')
		{
			pos += 1;
		}

		parse_key(&spec[i], PTR_OFFSET(in, start), end - start);

		// The primary key should always have certification capability
		if (i == 0)
		{
			spec[i].capabilities |= PGP_KEY_FLAG_CERTIFY;
		}

		process_key(&spec[i]);
	}

	*out = spec;

	return count;
}

static void make_default_preferences(pgp_user_info *info)
{
	// Set cipher, hash and compression preferences
	info->cipher_algorithm_preferences_octets = 3;
	info->cipher_algorithm_preferences[0] = PGP_AES_256;
	info->cipher_algorithm_preferences[1] = PGP_AES_192;
	info->cipher_algorithm_preferences[2] = PGP_AES_128;

	if (command.mode == SPGP_MODE_OPENPGP || command.mode == SPGP_MODE_LIBREPGP)
	{
		info->hash_algorithm_preferences_octets = 4;
		info->hash_algorithm_preferences[0] = PGP_SHA3_512;
		info->hash_algorithm_preferences[1] = PGP_SHA3_256;
		info->hash_algorithm_preferences[2] = PGP_SHA2_512;
		info->hash_algorithm_preferences[3] = PGP_SHA2_256;
	}
	else
	{
		info->hash_algorithm_preferences_octets = 3;
		info->hash_algorithm_preferences[0] = PGP_SHA2_512;
		info->hash_algorithm_preferences[1] = PGP_SHA2_256;
		info->hash_algorithm_preferences[2] = PGP_SHA1;
	}

	info->compression_algorithm_preferences_octets = 1;
	info->compression_algorithm_preferences[0] = PGP_UNCOMPRESSED;

	if (command.mode == SPGP_MODE_OPENPGP)
	{
		info->aead_algorithm_preferences_octets = 6;

		info->aead_algorithm_preferences[0][0] = PGP_AES_256;
		info->aead_algorithm_preferences[0][1] = PGP_AEAD_GCM;

		info->aead_algorithm_preferences[1][0] = PGP_AES_192;
		info->aead_algorithm_preferences[1][1] = PGP_AEAD_GCM;

		info->aead_algorithm_preferences[2][0] = PGP_AES_128;
		info->aead_algorithm_preferences[2][1] = PGP_AEAD_GCM;
	}

	// Set the features
	switch (command.mode)
	{
	case SPGP_MODE_RFC2440:
		info->features = 0;
		break;
	case SPGP_MODE_RFC4880:
		info->features = PGP_FEATURE_MDC;
		break;
	case SPGP_MODE_LIBREPGP:
		info->features = PGP_FEATURE_MDC | PGP_FEATURE_AEAD | PGP_FEATURE_KEY_V5;
		break;
	case SPGP_MODE_OPENPGP:
		info->features = PGP_FEATURE_SEIPD_V1 | PGP_FEATURE_SEIPD_V2;
		break;
	}

	info->flags = PGP_KEY_SERVER_NO_MODIFY;

	info->info_octets += info->cipher_algorithm_preferences_octets + info->hash_algorithm_preferences_octets +
						 info->compression_algorithm_preferences_octets + info->aead_algorithm_preferences_octets;
}

void spgp_generate_key(void)
{
	void *uid = NULL;
	void *spec = NULL;

	pgp_key_version key_version = 0;
	key_specfication *key_specs = NULL;
	pgp_key_packet **key_packets = NULL;
	uint32_t count = 0;

	pgp_user_id_packet *user = NULL;
	pgp_user_info *uinfo = NULL;

	pgp_signature_packet *signature = NULL;
	pgp_sign_info *sinfo = NULL;
	pgp_stream_t *certificate = NULL;
	pgp_keyring_packet *keyring = NULL;

	pgp_s2k s2k = {0};
	byte_t s2k_usage = 0;
	byte_t passphrase[SPGP_MAX_PASSPHRASE_SIZE] = {0};
	byte_t passphrase_size = 0;

	byte_t iv[16] = {0};
	byte_t iv_size = pgp_symmetric_cipher_block_size(PGP_AES_128);

	byte_t fingerprint[PGP_KEY_MAX_FINGERPRINT_SIZE] = {0};
	byte_t fingerprint_size = PGP_KEY_MAX_FINGERPRINT_SIZE;

	time_t creation_time = time(NULL);

	if (command.args == NULL || command.args->count != 2)
	{
		printf("Bad usage");
		exit(1);
	}

	uid = command.args->data[0];
	spec = command.args->data[1];

	// Set the version
	switch (command.mode)
	{
	case SPGP_MODE_RFC2440:
		key_version = PGP_KEY_V4;
		s2k_usage = 255;
		break;
	case SPGP_MODE_RFC4880:
		key_version = PGP_KEY_V4;
		s2k_usage = 254;
		break;
	case SPGP_MODE_LIBREPGP:
		key_version = PGP_KEY_V5;
		s2k_usage = 253;
		break;
	case SPGP_MODE_OPENPGP:
		key_version = PGP_KEY_V6;
		s2k_usage = 253;
		break;
	}

	// Set user id and preferences
	pgp_user_id_packet_new(&user, PGP_HEADER, uid, strlen(uid));

	// Create the keys
	count = parse_spec(spec, &key_specs);

	if (count == 0)
	{
		printf("No spec.\n");
		exit(1);
	}

	key_packets = malloc(sizeof(void *) * count);

	if (key_packets == NULL)
	{
		printf("No memory");
		exit(1);
	}

	memset(key_packets, 0, sizeof(void *) * count);

	for (uint32_t i = 0; i < count; ++i)
	{
		PGP_CALL(pgp_key_generate(&key_packets[i], key_version, key_specs[i].algorithm, key_specs[i].capabilities, key_specs[i].flags,
								  creation_time, key_specs[i].expiry, &key_specs[i].parameters));
	}

	// Create the certificate
	STREAM_CALL(certificate = pgp_stream_new(3 + ((count - 1) * 2)));

	pgp_stream_push(certificate, key_packets[0]);
	pgp_stream_push(certificate, user);

	PGP_CALL(pgp_user_info_new(&uinfo, uid, strlen(uid), NULL, 0, PGP_TRUST_ULTIMATE, 0, 0));
	make_default_preferences(uinfo);

	PGP_CALL(pgp_sign_info_new(&sinfo, PGP_POSITIVE_CERTIFICATION_SIGNATURE, preferred_hash_algorithm_for_signature(key_packets[0]),
							   creation_time, 0, 0, 0));
	PGP_CALL(pgp_generate_certificate_binding_signature(&signature, key_packets[0], NULL, sinfo, uinfo, user));

	pgp_sign_info_delete(sinfo);

	pgp_stream_push(certificate, signature);

	// Create the keyring
	PGP_CALL(pgp_key_fingerprint(key_packets[0], fingerprint, &fingerprint_size));
	PGP_CALL(pgp_keyring_packet_new(&keyring, key_version, fingerprint, uinfo));

	for (uint32_t i = 1; i < count; ++i)
	{
		signature = NULL;
		sinfo = NULL;

		pgp_stream_push(certificate, key_packets[i]);

		PGP_CALL(pgp_sign_info_new(&sinfo, PGP_SUBKEY_BINDING_SIGNATURE, preferred_hash_algorithm_for_signature(key_packets[0]),
								   creation_time, 0, 0, 0));
		PGP_CALL(pgp_generate_subkey_binding_signature(&signature, key_packets[0], key_packets[i], sinfo));

		pgp_stream_push(certificate, signature);
		pgp_sign_info_delete(sinfo);

		PGP_CALL(pgp_key_fingerprint(key_packets[i], fingerprint, &fingerprint_size));
		PGP_CALL(pgp_keyring_packet_add_subkey(keyring, fingerprint));
	}

	// Encrypt the key
	passphrase_size = spgp_prompt_passphrase(passphrase, "Enter passphrase to encrypt key (Leave empty for plaintext key).");

	if (passphrase_size > 0)
	{
		for (uint32_t i = 0; i < count; ++i)
		{
			// Generate S2K
			memset(&s2k, 0, sizeof(pgp_s2k));
			preferred_s2k_algorithm(key_version, &s2k);

			// Generate IV
			memset(iv, 0, iv_size);
			PGP_CALL(pgp_rand(iv, iv_size));

			PGP_CALL(pgp_key_packet_encrypt(key_packets[i], passphrase, passphrase_size, s2k_usage, &s2k, iv, iv_size, PGP_AES_128,
											PGP_AEAD_OCB));
		}
	}

	// Write the keys and certificate
	for (uint32_t i = 0; i < count; ++i)
	{
		spgp_write_key(key_packets[i]);
	}

	spgp_import_certificates(certificate);

	// Update keyring
	spgp_update_keyring(keyring, SPGP_KEYRING_REPLACE);
}
