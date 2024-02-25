#include <stdlib.h>
#include <string.h>
#include "armor.h"
#include "base64.h"

static char *begin_armor_message = "-----BEGIN PGP MESSAGE-----";
static char *end_armor_message = "-----END PGP MESSAGE-----";

static char *begin_armor_public_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
static char *end_armor_public_key = "-----END PGP PUBLIC KEY BLOCK-----";

static char *begin_armor_private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
static char *end_armor_private_key = "-----END PGP PRIVATE KEY BLOCK-----";

static char *begin_armor_signature = "-----BEGIN PGP SIGNATURE-----";
static char *end_armor_signature = "-----END PGP SIGNATURE-----";

// static char *begin_armor_cleartext = 5
// static char *end_armor_cleartext = 5

armor_ctx *create_armor_encode_ctx(armor_type type, int flags)
{
	armor_ctx *ctx = malloc(sizeof(armor_ctx));
	memset(ctx, 0, sizeof(armor_ctx));

	ctx->type = type;
	ctx->flags = flags;

	return ctx;
}

void destroy_armor_ctx(armor_ctx *ctx)
{
	free(ctx->cleartext.data);
	free(ctx->data.data);

	free(ctx);
}

armor_status armor_add_header(armor_ctx *ctx, armor_header header, byte_t *value, size_t size)
{
	switch (header)
	{
	case ARMOR_VERSION:
	{
		if (size > 15)
		{
			return ARMOR_HEADER_TOO_BIG;
		}

		memcpy(&ctx->version, value, size);
		ctx->version_size = size;
	}
	break;
	case ARMOR_COMMENT:
	{
		if (size > 31)
		{
			return ARMOR_HEADER_TOO_BIG;
		}

		memcpy(&ctx->comment, value, size);
		ctx->comment_size = size;
	}
	break;
	case ARMOR_HASH:
	{
		if (ctx->type != ARMOR_CLEARTEXT)
		{
			return ARMOR_INCOMPATIBLE_TYPE_AND_HEADER;
		}
		if (size > 15)
		{
			return ARMOR_HEADER_TOO_BIG;
		}

		memcpy(&ctx->hash, value, size);
		ctx->hash_size = size;
	}
	break;
	case ARMOR_CHARSET:
	{
		if (size > 15)
		{
			return ARMOR_HEADER_TOO_BIG;
		}

		memcpy(&ctx->charset, value, size);
		ctx->charset_size = size;
	}
	break;
	default:
		return ARMOR_INVALID_HEADER;
	}

	return ARMOR_SUCCESS;
}

armor_status armor_encode_data(armor_ctx *ctx, const void *data, size_t size)
{
	buffer_range_t input, output;

	ctx->data.pos = 0;
	ctx->data.size = BASE64_ENCODE_SIZE(size);
	ctx->data.data = malloc(ctx->data.size);

	input.data = data;
	input.start = 0;
	input.end = size;

	output.data = ctx->data.data;
	output.start = 0;
	output.end = ctx->data.size;

	base64_encode(&output, &input, BASE64_FINISH);

	if ((ctx->flags & ARMOR_NO_CRC) == 0)
	{
		ctx->crc = crc24_init();
		ctx->crc = crc24_update(ctx->crc, data, size);
		ctx->crc = crc24_final(ctx->crc);
	}

	return ARMOR_SUCCESS;
}

armor_status armor_encode_cleartext(armor_ctx *ctx, void *data, size_t size)
{
	if (ctx->type != ARMOR_CLEARTEXT)
	{
		return ARMOR_INVALID_TYPE_FOR_CLEARTEXT;
	}

	ctx->cleartext.data = malloc(size);
	ctx->cleartext.pos = 0;
	ctx->cleartext.size = size;

	memcpy(ctx->cleartext.data, data, size);

	return ARMOR_SUCCESS;
}

buffer_t *armor_encode_finish(armor_ctx *ctx)
{
	buffer_t *buffer = NULL;
	size_t buffer_size = 0;

	char *begin_line = NULL;
	char *end_line = NULL;
	size_t begin_line_size = 0;
	size_t end_line_size = 0;

	// Armor header line
	switch (ctx->type)
	{
	case ARMOR_MESSAGE:
		begin_line_size = strlen(begin_armor_message);
		end_line_size = strlen(end_armor_message);
		begin_line = begin_armor_message;
		end_line = end_armor_message;
		buffer_size += begin_line_size + end_line_size + 2;
	case ARMOR_PUBLIC_KEY:
		begin_line_size = strlen(begin_armor_public_key);
		end_line_size = strlen(end_armor_public_key);
		begin_line = begin_armor_public_key;
		end_line = end_armor_public_key;
		buffer_size += begin_line_size + end_line_size + 2;
		break;
	case ARMOR_PRIVATE_KEY:
		begin_line_size = strlen(begin_armor_private_key);
		end_line_size = strlen(end_armor_private_key);
		begin_line = begin_armor_private_key;
		end_line = end_armor_private_key;
		buffer_size += begin_line_size + end_line_size + 2;
		break;
	case ARMOR_SIGNATURE:
		begin_line_size = strlen(begin_armor_signature);
		end_line_size = strlen(end_armor_signature);
		begin_line = begin_armor_signature;
		end_line = end_armor_signature;
		buffer_size += begin_line_size + end_line_size + 2;
		break;
	}

	// Armor header

	// Armor data
	buffer_size += ctx->data.size;
	buffer_size += ctx->data.size / 64; // Each column will be 64 characters wide.

	// Armor crc
	if ((ctx->flags & ARMOR_NO_CRC) == 0)
	{
		buffer_size += 6;
	}

	buffer = malloc(ROUNDUP(sizeof(buffer_t) + buffer_size, 64));

	buffer->pos = 0;
	buffer->size = buffer_size;
	buffer->data = buffer + sizeof(buffer_t);

	if (buffer == NULL)
	{
		return NULL;
	}

	// Begin
	{
		memcpy(buffer->data + buffer->pos, begin_line, begin_line_size);
		buffer->data[buffer->pos++] = '\n';
	}

	// Headers
	buffer->data[buffer->pos++] = '\n';

	// Data
	{
		size_t pos = 0;
		for (pos = 0; pos <= ctx->data.size; pos += 64)
		{
			memcpy(buffer->data + buffer->pos, ctx->data.data + pos, 64);

			buffer->pos += 64;
			buffer->data[buffer->pos++] = '\n';
		}

		if (pos != ctx->data.size)
		{
			memcpy(buffer->data + buffer->pos, ctx->data.data + pos, ctx->data.size - pos);

			buffer->pos += ctx->data.size - pos;
			buffer->data[buffer->pos++] = '\n';
		}
	}

	// CRC
	{
		if ((ctx->flags & ARMOR_NO_CRC) == 0)
		{
			buffer_range_t input, output;

			input.data = (byte_t *)&ctx->crc;
			input.start = 0;
			input.end = 3;

			output.data = buffer->data + buffer->pos;
			output.start = 0;
			output.end = 4;

			buffer->data[buffer->pos++] = '=';

			base64_encode(&output, &input, BASE64_FINISH);
		}

		buffer->data[buffer->pos++] = '\n';
	}

	// End
	{
		memcpy(buffer->data + buffer->pos, end_line, end_line_size);
		buffer->data[buffer->pos++] = '\n';
	}

	return buffer;
}
