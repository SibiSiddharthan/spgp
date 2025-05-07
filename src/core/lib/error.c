/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <error.h>

char *pgp_error(pgp_error_t status)
{
	switch (status)
	{
	// No error
	case PGP_SUCCESS:
		return "No Error";

	// General errors
	case PGP_NO_MEMORY:
		return "Out of Memory";
	case PGP_INSUFFICIENT_DATA:
		return "Insufficient Data Provided";
	case PGP_BUFFER_TOO_SMALL:
		return "Buffer Too Small";
	case PGP_INVALID_PARAMETER:
		return "Invalid Parameter";
	case PGP_INCORRECT_FUNCTION:
		return "Incorrect Functions";
	case PGP_EMPTY_PASSPHRASE:
		return "Passphrase Not Provided";
	case PGP_INTERNAL_BUG:
		return "Internal Bug (SHOULD NEVER HAPPEN)";

		// Packet errors
	case PGP_MALFORMED_PACKET_HEADER:
		return "Malformed Packet Header";
	case PGP_MALFORMED_PACKET_LEGACY_HEADER:
		return "Malformed Legacy Packet Header";
	case PGP_MALFORMED_SUBPACKET_HEADER:
		return "Malformed Subpacket Header";
	case PGP_MALFORMED_PARTIAL_LENGTH_HEADER:
		return "Malformed Partial Header";
	case PGP_UNKNOWN_HEADER_FORMAT:
		return "Unknown Header Format";
	case PGP_UNKNOWN_PACKET_TAG:
		return "Unknown Packet Tag";
	case PGP_INVALID_PARTIAL_PACKET_TYPE:
		return "Invalid Partial Packet Type";
	case PGP_INVALID_PARTIAL_PACKET_START_SIZE:
		return "Invalid Partial Packet Start Size";
	case PGP_UNKNOWN_CRITICAL_SUBPACKET:
		return "Unknown Critical Subpacket";
	case PGP_EMPTY_PACKET:
		return "Empty Packet";

	// Cryptographic errors
	case PGP_RAND_ERROR:
		return "DRBG Error";
	case PGP_UNKNOWN_HASH_ALGORITHM:
		return "Unknown Hash Algorithm";
	case PGP_UNKNOWN_CIPHER_ALGORITHM:
		return "Unknown Symmetric Key Algorithm";
	case PGP_UNKNOWN_PUBLIC_ALGORITHM:
		return "Unknown Public Key Algorithm";
	case PGP_UNKNOWN_SIGNATURE_ALGORITHM:
		return "Unknown Signature Algorithm";
	case PGP_UNKNOWN_KEY_EXCHANGE_ALGORITHM:
		return "Unknown Key Exchange Algorithm";
	case PGP_UNKNOWN_AEAD_ALGORITHM:
		return "Unknown AEAD Algorithm";
	case PGP_INVALID_AEAD_CIPHER_PAIR:
		return "Invalid (Cipher, AEAD) Algorithm Pair";
	case PGP_UNSUPPORTED_HASH_ALGORITHM:
		return "Unsupported Hash Algorithm";
	case PGP_UNSUPPORTED_CIPHER_ALGORITHM:
		return "Unsupported Symmetric Key Algorithm";
	case PGP_UNSUPPORTED_AEAD_ALGORITHM:
		return "Unsupported AEAD Algorithm";
	case PGP_UNSUPPORTED_SIGNATURE_ALGORITHM:
		return "Unsupported Signature Algorithm";
	case PGP_UNSUPPORTED_KEY_EXCHANGE_ALGORITHM:
		return "Unsupported Key Exchange Algorithm";
	case PGP_INVALID_CFB_IV_SIZE:
		return "Invalid CFB Initialization Vector Size";
	case PGP_INVALID_AEAD_IV_SIZE:
		return "Invalid AEAD Initialization Vector Size";
	case PGP_INVALID_HASH_SALT_SIZE:
		return "Invalid Hash Salt Size";
	case PGP_INVALID_CIPHER_KEY_SIZE:
		return "Invalid Cipher Key Size";
	case PGP_INVALID_HASH_SIZE_FOR_ALGORITHM:
		return "Invalid Hash Size For Algorithm";
	case PGP_EMPTY_IV:
		return "Initialization Vector Not Provided";
	case PGP_CFB_IV_CHECK_MISMATCH:
		return "PGP-CFB Mode Check Failed";
	case PGP_MDC_TAG_MISMATCH:
		return "Modification Detection Code Tag Mismatch";
	case PGP_AEAD_TAG_MISMATCH:
		return "AEAD Tag Mismatch";
	case PGP_QUICK_HASH_MISMATCH:
		return "Top 16 Bits Of Hash Not Matching";
	case PGP_ARGON2_HASH_ERROR:
		return "Argon2 Error";

	// Armor errors
	case PGP_ARMOR_UNKNOWN_MARKER:
		return "Unknown Armor Marker";
	case PGP_ARMOR_MARKER_MISMATCH:
		return "Invalid Armor Marker Begin And End";
	case PGP_ARMOR_UNKNOWN_HEADER:
		return "Unknown Armor Header";
	case PGP_ARMOR_LINE_TOO_BIG:
		return "Armor Line Too Long";
	case PGP_ARMOR_MALFORMED_BASE64_DATA:
		return "Bad Base64 Encoded Data";
	case PGP_ARMOR_CRC_MISMATCH:
		return "Armor CRC24 Mismatch";
	case PGP_ARMOR_INVALID_MARKER_FOR_TRANSFERABLE_PUBLIC_KEY:
		return "Armor Invalid Marker For Transferable Public Key";
	case PGP_ARMOR_INVALID_MARKER_FOR_TRANSFERABLE_SECRET_KEY:
		return "Armor Invalid Marker For Transferable Secret Key";
	case PGP_ARMOR_INVALID_MARKER_FOR_SIGNATURE:
		return "Armor Invalid Marker For Signature";

	// S2K errors
	case PGP_UNKNOWN_S2K_USAGE:
		return "Unknown String-to-Key (S2K) Usage";
	case PGP_UNKNOWN_S2K_SPECIFIER:
		return "Unknown String-to-Key (S2K) Specifier";
	case PGP_MALFORMED_S2K_SIZE:
		return "Malformed String-to-Key (S2K) Size";
	case PGP_EMPTY_S2K:
		return "Empty String-to-Key (S2K)";

	// Key errors
	case PGP_UNKNOWN_KEY_VERSION:
		return "Unknown Key Version";
	case PGP_INVALID_KEY_TYPE:
		return "Invalid Key Type";

	case PGP_MALFORMED_PUBLIC_KEY_PACKET:
		return "Malformed Public Key Packet";
	case PGP_MALFORMED_SECRET_KEY_PACKET:
		return "Malformed Secret Key Packet";
	case PGP_MALFORMED_PUBLIC_KEY_COUNT:
		return "Malformed Public Key Octet Count";
	case PGP_MALFORMED_SECRET_KEY_COUNT:
		return "Malformed Secret Key Octet Count";
	case PGP_MALFORMED_KEYDEF_PACKET:
		return "Malformed Key Definition Packet";

	case PGP_EMPTY_PUBLIC_KEY:
		return "Empty Public Key";
	case PGP_EMPTY_SECRET_KEY:
		return "Empty Secret Key";

	case PGP_MALFORMED_RSA_PUBLIC_KEY:
		return "Malformed RSA Public Packet";
	case PGP_MALFORMED_ELGAMAL_PUBLIC_KEY:
		return "Malformed Elgamal Public Packet";
	case PGP_MALFORMED_DSA_PUBLIC_KEY:
		return "Malformed DSA Public Packet";
	case PGP_MALFORMED_ECDSA_PUBLIC_KEY:
		return "Malformed ECDSA Public Packet";
	case PGP_MALFORMED_EDDSA_PUBLIC_KEY:
		return "Malformed EDDSA Public Packet";
	case PGP_MALFORMED_ECDH_PUBLIC_KEY:
		return "Malformed ECDH Public Packet";
	case PGP_MALFORMED_X25519_PUBLIC_KEY:
		return "Malformed X25519 Public Packet";
	case PGP_MALFORMED_X448_PUBLIC_KEY:
		return "Malformed X448 Public Packet";
	case PGP_MALFORMED_ED25519_PUBLIC_KEY:
		return "Malformed ED25519 Public Packet";
	case PGP_MALFORMED_ED448_PUBLIC_KEY:
		return "Malformed ED448 Public Packet";

	case PGP_MALFORMED_RSA_SECRET_KEY:
		return "Malformed RSA Secret Packet";
	case PGP_MALFORMED_ELGAMAL_SECRET_KEY:
		return "Malformed Elgamal Secret Packet";
	case PGP_MALFORMED_DSA_SECRET_KEY:
		return "Malformed DSA Secret Packet";
	case PGP_MALFORMED_ECDSA_SECRET_KEY:
		return "Malformed ECDSA Secret Packet";
	case PGP_MALFORMED_EDDSA_SECRET_KEY:
		return "Malformed EDDSA Secret Packet";
	case PGP_MALFORMED_ECDH_SECRET_KEY:
		return "Malformed ECDH Secret Packet";
	case PGP_MALFORMED_X25519_SECRET_KEY:
		return "Malformed X25519 Secret Packet";
	case PGP_MALFORMED_X448_SECRET_KEY:
		return "Malformed X448 Secret Packet";
	case PGP_MALFORMED_ED25519_SECRET_KEY:
		return "Malformed ED25519 Secret Packet";
	case PGP_MALFORMED_ED448_SECRET_KEY:
		return "Malformed ED448 Secret Packet";

	case PGP_INVALID_CIPHER_ALGORITHM_FOR_LEGACY_CFB:
		return "Invalid Cipher Alogrithm For Legacy CFB";
	case PGP_KEY_CHECKSUM_MISMATCH:
		return "Secret Key Checksum Mismatch";

	case PGP_UNUSABLE_KEY_FOR_CERTIFICATION:
		return "Unusable Key For Certification";
	case PGP_UNUSABLE_KEY_FOR_SIGNING:
		return "Unusable Key For Signing";
	case PGP_UNUSABLE_KEY_FOR_ENCRYPTION:
		return "Unusable Key For Ecryption";
	case PGP_UNUSABLE_KEY_FOR_AUTHENTICATION:
		return "Unusable Key For Authentication";

	case PGP_RSA_KEY_UNSUPPORTED_BIT_SIZE:
		return "Unsupported RSA Bit Size";
	case PGP_RSA_KEY_GENERATION_FAILURE:
		return "RSA Key Generation Failure";
	case PGP_DSA_KEY_UNSUPPORTED_BIT_SIZE:
		return "Unsupported DSA Bit Size";
	case PGP_DSA_KEY_GENERATION_FAILURE:
		return "DSA Key Generation Failure";
	case PGP_ELGAMAL_KEY_UNSUPPORTED_BIT_SIZE:
		return "Unsupported Elgamal Bit Size";
	case PGP_ELGAMAL_KEY_GENERATION_FAILURE:
		return "Elgamal Key Generation Failure";

	case PGP_UNSUPPORTED_ELLIPTIC_CURVE:
		return "Unsupported Elliptic Curve";
	case PGP_UNSUPPORTED_EDWARDS_CURVE:
		return "Unsupported Edwards Curve";
	case PGP_ELLIPTIC_CURVE_KEY_GENERATION_FAILURE:
		return "Elliptic Curve Key Generation Failure";
	case PGP_ECDSA_KEY_GENERATION_FAILURE:
		return "ECDSA Key Generation Failure";
	case PGP_EDDSA_KEY_GENERATION_FAILURE:
		return "EDDSA Key Generation Failure";
	case PGP_ECDH_KEY_GENERATION_FAILURE:
		return "ECDH Key Generation Failure";

	case PGP_X25519_KEY_GENERATION_FAILURE:
		return "X25519 Key Generation Failure";
	case PGP_X448_KEY_GENERATION_FAILURE:
		return "X448 Key Generation Failure";
	case PGP_ED25519_KEY_GENERATION_FAILURE:
		return "ED25519 Key Generation Failure";
	case PGP_ED448_KEY_GENERATION_FAILURE:
		return "ED448 Key Generation Failure";

	case PGP_INVALID_KEY_TRANSFORMATION:
		return "Invalid Key Transformation";
	case PGP_KEY_NOT_DECRYPTED:
		return "Key Not Decrypted";

	// Session errors
	case PGP_MALFORMED_RSA_SESSION_KEY:
		return "Malformed RSA Session Key";
	case PGP_MALFORMED_ELGAMAL_SESSION_KEY:
		return "Malformed Elgamal Session Key";
	case PGP_MALFORMED_ECDH_SESSION_KEY:
		return "Malformed ECDH Session Key";
	case PGP_MALFORMED_X25519_SESSION_KEY:
		return "Malformed X25519 Session Key";
	case PGP_MALFORMED_X448_SESSION_KEY:
		return "Malformed X448 Session Key";

	case PGP_UNKNOWN_PUBLIC_SESSION_PACKET_VERSION:
		return "Unknown Public Key Encrypted Session Key Packet Version";
	case PGP_MALFORMED_PUBLIC_SESSION_PACKET:
		return "Malformed Public Key Encrypted Session Key Packet";
	case PGP_MALFORMED_PUBLIC_SESSION_PACKET_COUNT:
		return "Malformed Public Key Encrypted Session Key Packet Octet Count";

	case PGP_UNKNOWN_SYMMETRIC_SESSION_PACKET_VERSION:
		return "Unknown Secret Key Encrypted Session Key Packet Version";
	case PGP_MALFORMED_SYMMETRIC_SESSION_PACKET_COUNT:
		return "Malformed Secret Key Encrypted Session Key Packet Octet Count";
	case PGP_MALFORMED_SYMMETRIC_SESSION_PACKET:
		return "Malformed Secret Key Encrypted Session Key Packet";

	case PGP_SESSION_KEY_CHECKSUM_MISMATCH:
		return "Session Key Checksum Mismatch";
	case PGP_SESSION_KEY_MALFORMED_PADDING:
		return "Malformed Session Key Padding";
	case PGP_INCORRECT_DECRYPTION_KEY:
		return "Incorrect Decryption Key";

	case PGP_RSA_ENCRYPTION_FAILURE:
		return "RSA Encryption Failure";
	case PGP_RSA_DECRYPTION_FAILURE:
		return "RSA Decryption Failure";
	case PGP_ELGAMAL_ENCRYPTION_FAILURE:
		return "Elgamal Encryption Failure";
	case PGP_ELGAMAL_DECRYPTION_FAILURE:
		return "Elgamal Decryption Failure";
	case PGP_ECDH_ENCRYPTION_FAILURE:
		return "ECDH Encryption Failure";
	case PGP_ECDH_DECRYPTION_FAILURE:
		return "ECDH Decryption Failure";
	case PGP_X25519_ENCRYPTION_FAILURE:
		return "X25519 Encryption Failure";
	case PGP_X25519_DECRYPTION_FAILURE:
		return "X25519 Decryption Failure";
	case PGP_X448_ENCRYPTION_FAILURE:
		return "X448 Encryption Failure";
	case PGP_X448_DECRYPTION_FAILURE:
		return "X448 Decryption Failure";

	// Signature errors
	case PGP_UNKNOWN_SIGNATURE_TYPE:
		return "Unknown Signature Type";
	case PGP_UNKNOWN_SIGNATURE_PACKET_VERSION:
		return "Unknown Signature Packet Version";
	case PGP_MALFORMED_SIGNATURE_PACKET:
		return "Malformed Signature Packet";
	case PGP_UNKNOWN_SIGNATURE_SUBPACKET_TAG:
		return "Unknown Signature Subpacket Tag";
	case PGP_MALFORMED_SIGNATURE_PACKET_SALT_SIZE:
		return "Malformed V6 Signature Packet Salt Size";
	case PGP_MALFORMED_SIGNATURE_HASHED_SUBPACKET_SIZE:
		return "Malformed Signature Packet Hashed Subpacket Octet Count";
	case PGP_MALFORMED_SIGNATURE_UNHASHED_SUBPACKET_SIZE:
		return "Malformed Signature Packet Unhashed Subpacket Octet Count";

	case PGP_UNKNOWN_ONE_PASS_SIGNATURE_PACKET_VERSION:
		return "Unknown One Pass Signature Packet Version";
	case PGP_MALFORMED_ONE_PASS_SIGNATURE_PACKET:
		return "Malformed One Pass Signature Packet";

	case PGP_MALFORMED_SIGNATURE_CREATION_TIME_SUBPACKET:
		return "Malformed Signature Creation Time Subpacket";
	case PGP_MALFORMED_SIGNATURE_EXPIRY_TIME_SUBPACKET:
		return "Malformed Signature Expiry Time Subpacket";
	case PGP_MALFORMED_KEY_EXPIRATION_TIME_SUBPACKET:
		return "Malformed Key Expiry Time Subpacket";
	case PGP_MALFORMED_EXPORTABLE_SUBPACKET:
		return "Malformed Signature Exportable Subpacket";
	case PGP_MALFORMED_REVOCABLE_SUBPACKET:
		return "Malformed Signature Revocable Subpacket";
	case PGP_MALFORMED_PRIMARY_USER_ID_SUBPACKET:
		return "Malformed Primary User ID Subpacket";
	case PGP_MALFORMED_KEY_SERVER_PREFERENCES_SUBPACKET:
		return "Malformed Key Server Preferences Subpacket";
	case PGP_MALFORMED_KEY_FLAGS_SUBPACKET:
		return "Malformed Key Flags Subpacket";
	case PGP_MALFORMED_FEATURES_SUBPACKET:
		return "Malformed Features Subpacket";
	case PGP_MALFORMED_PREFERRED_SYMMETRIC_CIPHERS_SUBPACKET:
		return "Malformed Preferred Symmetric Ciphers Algorithms Subpacket";
	case PGP_MALFORMED_PREFERRED_HASH_ALGORITHMS_SUBPACKET:
		return "Malformed Preferred Hash Algorithms Subpacket";
	case PGP_MALFORMED_PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET:
		return "Malformed Preferred Compression Algorithms Subpacket";
	case PGP_MALFORMED_PREFERRED_ENCRYPTION_MODES_SUBPACKET:
		return "Malformed Preferred Encryption Modes Algorithms Subpacket";
	case PGP_MALFORMED_PREFERRED_AEAD_CIPHERSUITES_SUBPACKET:
		return "Malformed Preferred AEAD Algorithms Subpacket";
	case PGP_MALFORMED_ISSUER_FINGERPRINT_SUBPACKET:
		return "Malformed Signature Issuer Fingerprint Subpacket";
	case PGP_MALFORMED_RECIPIENT_FINGERPRINT_SUBPACKET:
		return "Malformed Intended Recipient Fingerprint Subpacket";
	case PGP_MALFORMED_REGULAR_EXPRESSION_SUBPACKET:
		return "Malformed Regular Expression Subpacket";
	case PGP_MALFORMED_PREFERRED_KEY_SERVER_SUBPACKET:
		return "Malformed Preferred Key Server Subpacket";
	case PGP_MALFORMED_POLICY_URI_SUBPACKET:
		return "Malformed Policy URI Subpacket";
	case PGP_MALFORMED_SIGNER_USER_ID_SUBPACKET:
		return "Malformed Signer User ID Subpacket";
	case PGP_MALFORMED_TRUST_SIGNATURE_SUBPACKET:
		return "Malformed Trust Signature Subpacket";
	case PGP_MALFORMED_REVOCATION_KEY_SUBPACKET:
		return "Malformed Revocation Key Subpacket";
	case PGP_MALFORMED_ISSUER_KEY_ID_SUBPACKET:
		return "Malformed Issuer Key ID Subpacket";
	case PGP_MALFORMED_NOTATION_DATA_SUBPACKET:
		return "Malformed Notation Data Subpacket";
	case PGP_MALFORMED_REASON_FOR_REVOCATION_SUBPACKET:
		return "Malformed Reason For Revocation Subpacket";
	case PGP_MALFORMED_SIGNATURE_TARGET_SUBPACKET:
		return "Malformed Signature Target Subpacket";
	case PGP_MALFORMED_EMBEDDED_SIGNATURE_SUBPACKET:
		return "Malformed Embedded Signature Subpacket";
	case PGP_MALFORMED_ATTESTED_CERTIFICATIONS_SUBPACKET:
		return "Malformed Attested Certifications Subpacket";
	case PGP_MALFORMED_LITERAL_DATA_META_HASH_SUBPACKET:
		return "Malformed Literal Data Meta Hash Subpacket";

	case PGP_EMPTY_SIGNATURE:
		return "Empty Signature";
	case PGP_MALFORMED_RSA_SIGNATURE:
		return "Malformed RSA Signature";
	case PGP_MALFORMED_DSA_SIGNATURE:
		return "Malformed DSA Signature";
	case PGP_MALFORMED_ECDSA_SIGNATURE:
		return "Malformed ECDSA Signature";
	case PGP_MALFORMED_EDDSA_SIGNATURE:
		return "Malformed EDDSA Signature";
	case PGP_MALFORMED_ED25519_SIGNATURE:
		return "Malformed ED25519 Signature";
	case PGP_MALFORMED_ED448_SIGNATURE:
		return "Malformed ED448 Signature";

	case PGP_RSA_SIGNATURE_GENERATION_FAILURE:
		return "RSA Signature Generation Failure";
	case PGP_DSA_SIGNATURE_GENERATION_FAILURE:
		return "DSA Signature Generation Failure";
	case PGP_ECDSA_SIGNATURE_GENERATION_FAILURE:
		return "ECDSA Signature Generation Failure";
	case PGP_EDDSA_SIGNATURE_GENERATION_FAILURE:
		return "EDDSA Signature Generation Failure";
	case PGP_ED25519_SIGNATURE_GENERATION_FAILURE:
		return "ED25519 Signature Generation Failure";
	case PGP_ED448_SIGNATURE_GENERATION_FAILURE:
		return "ED448 Signature Generation Failure";

	case PGP_INCOMPATIBLE_SIGNATURE_AND_KEY_VERSION:
		return "Incompatible Signature And Key Version";
	case PGP_MISSING_EMBEDDED_SIGNATURE_PACKET:
		return "Missing Embedded Signature Packet For Signing Capable Subkey";
	case PGP_BAD_SIGNATURE:
		return "Bad Signature";

	case PGP_SIGNATURE_SALT_TOO_BIG:
		return "V6 Signature Salt Too Big";
	case PGP_INVALID_LITERAL_PACKET_FORMAT_FOR_TEXT_SIGNATURE:
		return "Invalid Literal Data Format For Text Signature";
	case PGP_UNKNOWN_REVOCATION_CLASS:
		return "Unknown Revocation Class";
	case PGP_INVALID_KEY_FINGERPRINT_SIZE:
		return "Invalid Key Fingerprint Size";

	// Encrypted Packet errors
	case PGP_MALFORMED_SEIPD_PACKET:
		return "Malformed SEIPD Packet";
	case PGP_UNKNOWN_SEIPD_PACKET_VERSION:
		return "Unknowne SEIPD Packet";
	case PGP_MALFORMED_AEAD_PACKET:
		return "Malformed AEAD Packet";
	case PGP_UNKNOWN_AEAD_PACKET_VERSION:
		return "Unknowne AEAD Packet";
	case PGP_INVALID_CHUNK_SIZE:
		return "Invalid Encryption Chunk Size";
	case PGP_RECURSIVE_ENCRYPTION_CONTAINER:
		return "Recursive Encryption Container";

	// Compressed Packet
	case PGP_UNSUPPORTED_COMPRESSION_ALGORITHM:
		return "Unsupported Compression Algorithm";
	case PGP_UNKNOWN_COMPRESSION_ALGORITHM:
		return "Unknown Compression Algorithm";
	case PGP_MALFORMED_COMPRESSED_PACKET:
		return "Malformed Compression Packet";
	case PGP_RECURSIVE_COMPRESSION_CONTAINER:
		return "Recursive Compression Container";

	// Marker Packet
	case PGP_MALFORMED_MARKER_PACKET:
		return "Malformed Marker Packet";

	// MDC Packet
	case PGP_MALFORMED_MDC_PACKET:
		return "Malformed Modification Detection Code (MDC) Packet";

	// Literal Packet
	case PGP_UNKNOWN_LITERAL_FORMAT:
		return "Unknown Literal Packet Format";
	case PGP_MALFORMED_LITERAL_PACKET:
		return "Malformed Literal Packet";
	case PGP_MALFORMED_LITERAL_PACKET_FILENAME_SIZE:
		return "Malformed Literal Packet Filename Size";

	// User ID Packet
	case PGP_EMPTY_USER_ID:
		return "Empty User ID";

	// User Attribute Packet
	case PGP_MALFORMED_USER_ATTRIBUTE_IMAGE:
		return "Malformed User Attribute Image";
	case PGP_MALFORMED_USER_ATTRIBUTE_ID:
		return "Malformed User Attribute ID";
	case PGP_UNKNOWN_USER_ATTRIBUTE_SUBPACKET_TAG:
		return "Unknown User Attribute Subpacket Tag";
	case PGP_UNSUPPORTED_IMAGE_TYPE:
		return "Unsupported Image Type";
	case PGP_IMAGE_NOT_PRESENT_IN_USER_ATTRIBUTE:
		return "Empty Image In User Attribute";
	case PGP_ID_NOT_PRESENT_IN_USER_ATTRIBUTE:
		return "Empty ID In User Attribute";

	// Trust Packet
	case PGP_UNKNOWN_TRUST_LEVEL:
		return "Unknown Trust Packet";
	case PGP_MALFORMED_TRUST_PACKET:
		return "Malformed Trust Packet";

	// Padding Packet
	case PGP_EMPTY_PADDING_PACKET:
		return "Empty Padding Packet";

	// Keyring Packet
	case PGP_MALFORMED_KEYRING_PACKET:
		return "Malformed Keyring Packet";
	case PGP_MALFORMED_KEYRING_PRIMARY_KEY:
		return "Malformed Primary Key In Keyring";
	case PGP_MALFORMED_KEYRING_SUBKEYS:
		return "Malformed Subkeys In Keyring";
	case PGP_MALFORMED_KEYRING_USER_INFO:
		return "Malformed User Info In Keyring";
	case PGP_KEYRING_PACKET_INVALID_SUBKEY_SIZE:
		return "Malformed Subkeys Size In Keyring";
	}

	return "Unknown Error";
}