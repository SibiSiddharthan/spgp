/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <spgp.h>
#include <armor.h>
#include <base64.h>
#include <crc24.h>

#include <stdlib.h>
#include <string.h>

// Refer RFC 9580 - OpenPGP, Section 6.2 Forming ASCII Armor, Section 7 Cleartext Signature Framework

static const char *begin_armor_message = "-----BEGIN PGP MESSAGE-----";
static const char *end_armor_message = "-----END PGP MESSAGE-----";

static const char *begin_armor_public_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
static const char *end_armor_public_key = "-----END PGP PUBLIC KEY BLOCK-----";

static const char *begin_armor_private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
static const char *end_armor_private_key = "-----END PGP PRIVATE KEY BLOCK-----";

static const char *begin_armor_signature = "-----BEGIN PGP SIGNATURE-----";
static const char *end_armor_signature = "-----END PGP SIGNATURE-----";

static const char *begin_armor_cleartext = "-----BEGIN PGP SIGNED MESSAGE-----";

static const char *version = "Version: ";
static const char *hash = "Hash: ";
static const char *charset = "Charset: ";
static const char *comment = "Comment: ";

static pgp_armor_ctx *pgp_armor_init_checked(void *ptr, pgp_armor_type type, uint32_t flags)
{
	pgp_armor_ctx *actx = ptr;

	memset(actx, 0, sizeof(pgp_armor_ctx));

	actx->type = type;
	actx->flags = flags;

	return actx;
}

pgp_armor_ctx *pgp_armor_init(void *ptr, size_t size, pgp_armor_type type, uint32_t flags)
{
	switch (type)
	{
	case PGP_ARMOR_MESSAGE:
	case PGP_ARMOR_PUBLIC_KEY:
	case PGP_ARMOR_PRIVATE_KEY:
	case PGP_ARMOR_SIGNATURE:
	case PGP_ARMOR_CLEARTEXT:
		break;
	default:
		return NULL;
	}

	if (flags > PGP_ARMOR_NO_CRC)
	{
		return NULL;
	}

	if (size < sizeof(pgp_armor_ctx))
	{
		return NULL;
	}

	return pgp_armor_init_checked(ptr, type, flags);
}

pgp_armor_ctx *pgp_armor_new(pgp_armor_type type, uint32_t flags)
{
	pgp_armor_ctx *actx = NULL;

	switch (type)
	{
	case PGP_ARMOR_MESSAGE:
	case PGP_ARMOR_PUBLIC_KEY:
	case PGP_ARMOR_PRIVATE_KEY:
	case PGP_ARMOR_SIGNATURE:
	case PGP_ARMOR_CLEARTEXT:
		break;
	default:
		return NULL;
	}

	if (flags > PGP_ARMOR_NO_CRC)
	{
		return NULL;
	}

	actx = malloc(sizeof(pgp_armor_ctx));

	if (actx == NULL)
	{
		return NULL;
	}

	return pgp_armor_init_checked(actx, type, flags);
}

void pgp_armor_delete(pgp_armor_ctx *ctx)
{
	free(ctx);
}

armor_status armor_set_header(pgp_armor_ctx *ctx, pgp_armor_header header, void *data, size_t size)
{
	buffer_t *buffer = NULL;

	switch (header)
	{
	case PGP_ARMOR_VERSION:
	{
		buffer = &ctx->version;
	}
	break;
	case PGP_ARMOR_COMMENT:
	{
		buffer = &ctx->comment;
	}
	break;
	case PGP_ARMOR_HASH:
	{
		buffer = &ctx->hash;
	}
	break;
	case PGP_ARMOR_CHARSET:
	{
		buffer = &ctx->charset;
	}
	break;
	default:
		return ARMOR_INVALID_HEADER;
	}

	buffer->data = data;
	buffer->size = size;
	buffer->capacity = size;

	return ARMOR_SUCCESS;
}

armor_status armor_set_data(pgp_armor_ctx *ctx, void *data, size_t size)
{
	ctx->data.data = data;
	ctx->data.size = size;
	ctx->data.capacity = size;

	if ((ctx->flags & PGP_ARMOR_NO_CRC) == 0)
	{
		ctx->crc = crc24_init();
		ctx->crc = crc24_update(ctx->crc, data, size);
		ctx->crc = crc24_final(ctx->crc);
	}

	return ARMOR_SUCCESS;
}

armor_status armor_set_cleartext(pgp_armor_ctx *ctx, void *data, size_t size)
{
	if (ctx->type != PGP_ARMOR_CLEARTEXT)
	{
		return ARMOR_INVALID_TYPE_FOR_CLEARTEXT;
	}

	ctx->cleartext.data = data;
	ctx->cleartext.size = size;
	ctx->cleartext.capacity = size;

	return ARMOR_SUCCESS;
}

static size_t encode_cleartext(byte_t *output, byte_t *input, size_t size)
{
	size_t j = 0;

	// First character
	// Dash Escapes
	if (input[0] == '-')
	{
		output[j++] = '-';
		output[j++] = ' ';
		output[j++] = '-';
	}

	// LF -> CRLF
	if (input[0] == '\n')
	{
		output[j++] = '\r';
		output[j++] = '\n';
	}

	for (size_t i = 1; i < size; ++i)
	{
		// Dash Escapes
		if (input[i] == '-' && input[i - 1] == '\n')
		{
			// Every line starting with '-' is prefixed with '-' and ' '.
			output[j++] = '-';
			output[j++] = ' ';
			output[j++] = '-';
		}

		// LF -> CRLF
		if (input[i] == '\n' && input[i - 1] != '\r')
		{
			output[j++] = '\r';
			output[j++] = '\n';
		}

		output[j++] = input[i];
	}

	return j;
}

int32_t armor_write(pgp_armor_ctx *ctx, void *ptr, size_t size)
{
	// The common convention
	const uint16_t columns = 64;

	byte_t *out = ptr;

	size_t required_size = 0;
	size_t pos = 0;

	const char *cleartext_line = NULL;
	const char *begin_line = NULL;
	const char *end_line = NULL;
	size_t cleartext_line_size = 0;
	size_t begin_line_size = 0;
	size_t end_line_size = 0;

	size_t version_size = 0;
	size_t hash_size = 0;
	size_t charset_size = 0;
	size_t comment_size = 0;

	byte_t *cleartext_buffer = NULL;
	size_t cleartext_size = 0;

	// Armor Structure
	// -----ARMOR HEADER-----
	// Optional Headers
	// Empty Line
	// Data
	// Optional Checksum
	// -----ARMOR FOOTER-----

	// Armor header line
	switch (ctx->type)
	{
	case PGP_ARMOR_MESSAGE:
		begin_line_size = strlen(begin_armor_message);
		end_line_size = strlen(end_armor_message);
		begin_line = begin_armor_message;
		end_line = end_armor_message;
		required_size += begin_line_size + end_line_size + 2;
	case PGP_ARMOR_PUBLIC_KEY:
		begin_line_size = strlen(begin_armor_public_key);
		end_line_size = strlen(end_armor_public_key);
		begin_line = begin_armor_public_key;
		end_line = end_armor_public_key;
		required_size += begin_line_size + end_line_size + 2;
		break;
	case PGP_ARMOR_PRIVATE_KEY:
		begin_line_size = strlen(begin_armor_private_key);
		end_line_size = strlen(end_armor_private_key);
		begin_line = begin_armor_private_key;
		end_line = end_armor_private_key;
		required_size += begin_line_size + end_line_size + 2;
		break;
	case PGP_ARMOR_SIGNATURE:
		begin_line_size = strlen(begin_armor_signature);
		end_line_size = strlen(end_armor_signature);
		begin_line = begin_armor_signature;
		end_line = end_armor_signature;
		required_size += begin_line_size + end_line_size + 2;
		break;
	case PGP_ARMOR_CLEARTEXT:
		cleartext_line_size = strlen(begin_armor_cleartext);
		begin_line_size = strlen(begin_armor_signature);
		end_line_size = strlen(end_armor_signature);
		begin_line = begin_armor_signature;
		end_line = end_armor_signature;
		required_size += cleartext_line_size + begin_line_size + end_line_size + 3;
	}

	// Armor header
	if (ctx->version.size > 0)
	{
		version_size = strlen(version);
		required_size += version_size + ctx->version.size + 1;
	}
	if (ctx->hash.size > 0)
	{
		hash_size = strlen(hash);
		required_size += hash_size + ctx->hash.size + 1;
	}
	if (ctx->charset.size > 0)
	{
		charset_size = strlen(charset);
		required_size += charset_size + ctx->charset.size + 1;
	}
	if (ctx->comment.size > 0)
	{
		comment_size = strlen(comment);
		required_size += comment_size + ctx->comment.size + 1;
	}

	// Empty line
	required_size += 1;

	// Cleartext
	if (ctx->type == PGP_ARMOR_CLEARTEXT)
	{
		cleartext_buffer = malloc(ctx->cleartext.size * 2);

		if (cleartext_buffer == NULL)
		{
			return -1;
		}

		cleartext_size = encode_cleartext(cleartext_buffer, ctx->cleartext.data, ctx->cleartext.size);
		required_size += cleartext_size + 1;
	}

	// Armor data
	required_size += BASE64_ENCODE_SIZE(ctx->data.size);
	required_size += CEIL_DIV(BASE64_ENCODE_SIZE(ctx->data.size), columns);

	if ((ctx->flags & PGP_ARMOR_NO_CRC) == 0)
	{
		required_size += 1 + 4 + 1; // '=XXXXn'
	}

	if (size < required_size)
	{
		free(cleartext_buffer);
		return (-1 * required_size);
	}

	// Checking done, begin writing

	// Special handling for cleartext.
	if (ctx->type == PGP_ARMOR_CLEARTEXT)
	{
		memcpy(out + pos, cleartext_line, cleartext_line_size);
		pos += cleartext_line_size;
		out[pos++] = '\n';

		// Only the hash header is allowed here.
		if (ctx->hash.size > 0)
		{
			memcpy(out + pos, hash, hash_size);
			pos += hash_size;

			memcpy(out + pos, ctx->hash.data, ctx->hash.size);
			pos += ctx->hash.size;

			out[pos++] = '\n';
		}

		memcpy(out + pos, cleartext_buffer, cleartext_size);
		pos += cleartext_size;
		out[pos++] = '\n';

		// Begin the signature part
		memcpy(out + pos, begin_line, begin_line_size);
		pos += begin_line_size;
		out[pos++] = '\n';

		free(cleartext_buffer);

		goto data;
	}

	// Begin
	{
		memcpy(out + pos, begin_line, begin_line_size);
		pos += begin_line_size;
		out[pos++] = '\n';
	}

	// Headers
	if (ctx->version.size > 0)
	{
		memcpy(out + pos, version, version_size);
		pos += version_size;

		memcpy(out + pos, ctx->version.data, ctx->version.size);
		pos += ctx->version.size;

		out[pos++] = '\n';
	}
	if (ctx->hash.size > 0)
	{
		memcpy(out + pos, hash, hash_size);
		pos += hash_size;

		memcpy(out + pos, ctx->hash.data, ctx->hash.size);
		pos += ctx->hash.size;

		out[pos++] = '\n';
	}
	if (ctx->charset.size > 0)
	{
		memcpy(out + pos, charset, charset_size);
		pos += charset_size;

		memcpy(out + pos, ctx->charset.data, ctx->charset.size);
		pos += ctx->charset.size;

		out[pos++] = '\n';
	}
	if (ctx->comment.size > 0)
	{
		memcpy(out + pos, comment, comment_size);
		pos += comment_size;

		memcpy(out + pos, ctx->comment.data, ctx->comment.size);
		pos += ctx->comment.size;

		out[pos++] = '\n';
	}

	out[pos++] = '\n';

data:
	// Data
	{
		size_t count = CEIL_DIV(ctx->data.size, 48);
		buffer_range_t input, output;

		input.data = ctx->data.data;
		input.start = 0;
		input.end = 48;

		output.data = out;
		output.start = pos;
		output.end = required_size;

		for (size_t i = 0; i < count - 1; ++i)
		{
			base64_encode(&output, &input, BASE64_CONTINUE);

			input.start += 48;
			input.end += 48;

			pos += 64;
			out[pos++] = '\n';

			output.start = pos;
		}

		// Last line of BASE-64 data
		input.end = ctx->data.size;

		base64_encode(&output, &input, BASE64_FINISH);

		pos = output.start;
		out[pos++] = '\n';

		// CRC
		if ((ctx->flags & PGP_ARMOR_NO_CRC) == 0)
		{
			ctx->crc = crc24_init();
			ctx->crc = crc24_update(ctx->crc, ctx->data.data, ctx->data.size);
			ctx->crc = crc24_final(ctx->crc);

			// Byteswap and ignore the first byte, it will be zero.
			ctx->crc = BSWAP_32(ctx->crc);

			input.data = (byte_t *)&ctx->crc;
			input.start = 1;
			input.end = 4;

			// ARMOR CRC starts with '='
			out[pos++] = '=';

			output.data = out;
			output.start = pos;
			output.end = required_size;

			base64_encode(&output, &input, BASE64_FINISH);

			out[pos++] = '=';
		}
	}

	// End
	{
		memcpy(out + pos, end_line, end_line_size);
		pos += end_line_size;
		out[pos++] = '\n';
	}

	return required_size;
}
