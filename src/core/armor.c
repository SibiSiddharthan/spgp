/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <pgp.h>
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
static const char *message_id = "MessageID: ";

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

	memset(actx, 0, sizeof(pgp_armor_ctx));

	actx->type = type;
	actx->flags = flags;

	return actx;
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

static void get_line(void *ptr, size_t size, size_t *line_content_size, size_t *line_total_size)
{
	void *result = NULL;
	uintptr_t diff = 0;

	result = memchr(ptr, '\n', size);

	if (result == NULL)
	{
		*line_content_size = size;
		*line_total_size = size;

		goto strip_whitespace;
	}

	diff = (uintptr_t)result - (uintptr_t)ptr;

	// Start at next line
	*line_total_size = diff + 1;

	// Pointer to the end of line excluding the LF or CRLF
	*line_content_size = diff;

strip_whitespace:
	if (*line_content_size == 0)
	{
		return;
	}

	// Check for Whitespace characters
	while (*line_content_size != 0)
	{
		switch (((byte_t *)ptr)[*line_content_size - 1])
		{
		case ' ':
		case '\r':
		case '\t':
			*line_content_size -= 1;
			break;
		default:
			return;
		}
	}

	return;
}

static byte_t check_empty_line(void *ptr, size_t size)
{
	byte_t *in = ptr;

	for (size_t i = 0; i < size; ++i)
	{
		if (in[i] != ' ' && in[i] != '\t')
		{
			return 0;
		}
	}

	return 1;
}

static byte_t check_valid_pgp_armor_begin(void *ptr, size_t size, byte_t *cleartext)
{
	// Check the sizes
	if (size != strlen(begin_armor_message) && size != strlen(begin_armor_public_key) && size != strlen(begin_armor_private_key) &&
		size != strlen(begin_armor_signature) && size != strlen(begin_armor_cleartext))
	{
		return 0;
	}

	// begin
	if (memcmp(PTR_OFFSET(ptr, 0), "-----", 5) != 0)
	{
		return 0;
	}

	// end
	if (memcmp(PTR_OFFSET(ptr, size - 5), "-----", 5) != 0)
	{
		return 0;
	}

	// headers
	if (memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP MESSAGE", 17) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP PUBLIC KEY BLOCK", 26) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP PRIVATE KEY BLOCK", 27) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP SIGNATURE", 19) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP SIGNED MESSAGE", 24) == 0)
	{
		if (cleartext)
		{
			*cleartext = 1;
		}

		return 1;
	}

	return 0;
}

static byte_t check_valid_pgp_armor_end(void *ptr, size_t size)
{
	// Check the sizes
	if (size != strlen(end_armor_message) && size != strlen(end_armor_public_key) && size != strlen(end_armor_private_key) &&
		size != strlen(end_armor_signature))
	{
		return 0;
	}

	// begin
	if (memcmp(PTR_OFFSET(ptr, 0), "-----", 5) != 0)
	{
		return 0;
	}

	// end
	if (memcmp(PTR_OFFSET(ptr, size - 5), "-----", 5) != 0)
	{
		return 0;
	}

	// headers
	if (memcmp(PTR_OFFSET(ptr, 5), "END PGP MESSAGE", 15) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "END PGP PUBLIC KEY BLOCK", 24) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "END PGP PRIVATE KEY BLOCK", 25) == 0)
	{
		return 1;
	}

	if (memcmp(PTR_OFFSET(ptr, 5), "END PGP SIGNATURE", 17) == 0)
	{
		return 1;
	}

	return 0;
}

static pgp_armor_type get_begin_armor_type(void *ptr, size_t size)
{
	if (size == 27 && memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP MESSAGE", 17) == 0)
	{
		return PGP_ARMOR_MESSAGE;
	}

	if (size == 36 && memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP PUBLIC KEY BLOCK", 26) == 0)
	{
		return PGP_ARMOR_PUBLIC_KEY;
	}

	if (size == 37 && memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP PRIVATE KEY BLOCK", 27) == 0)
	{
		return PGP_ARMOR_PRIVATE_KEY;
	}

	if (size == 29 && memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP SIGNATURE", 19) == 0)
	{
		return PGP_ARMOR_SIGNATURE;
	}

	if (size == 34 && memcmp(PTR_OFFSET(ptr, 5), "BEGIN PGP SIGNED MESSAGE", 24) == 0)
	{
		return PGP_ARMOR_CLEARTEXT;
	}

	// Unreachable
	return 0;
}

static pgp_armor_type get_end_armor_type(void *ptr, size_t size)
{
	// headers
	if (size == 25 && memcmp(PTR_OFFSET(ptr, 5), "END PGP MESSAGE", 15) == 0)
	{
		return PGP_ARMOR_MESSAGE;
	}

	if (size == 34 && memcmp(PTR_OFFSET(ptr, 5), "END PGP PUBLIC KEY BLOCK", 24) == 0)
	{
		return PGP_ARMOR_PUBLIC_KEY;
	}

	if (size == 35 && memcmp(PTR_OFFSET(ptr, 5), "END PGP PRIVATE KEY BLOCK", 25) == 0)
	{
		return PGP_ARMOR_PRIVATE_KEY;
	}

	if (size == 27 && memcmp(PTR_OFFSET(ptr, 5), "END PGP SIGNATURE", 17) == 0)
	{
		return PGP_ARMOR_SIGNATURE;
	}

	// Unreachable
	return 0;
}

static armor_status get_armor_block(void *ptr, size_t size, size_t *start, size_t *end)
{
	byte_t *in = ptr;
	size_t pos = 0;

	size_t line_content_size = 0;
	size_t line_total_size = 0;
	size_t line_start = 0;

	size_t armor_start = 0;
	size_t armor_end = 0;

	byte_t begin_armor_found = 0;
	byte_t end_armor_found = 0;

	byte_t cleartext_armor = 0;
	byte_t cleartext_begin_armor_found = 0;
	byte_t cleartext_end_armor_found = 0;

	while (pos < size)
	{
		get_line(PTR_OFFSET(ptr, pos), size - pos, &line_content_size, &line_total_size);

		line_start = pos;
		pos += line_total_size;

		if (begin_armor_found)
		{
			if (cleartext_armor)
			{
				if (check_valid_pgp_armor_begin(PTR_OFFSET(ptr, pos), line_content_size, NULL))
				{
					cleartext_begin_armor_found = 1;
					continue;
				}

				if (check_valid_pgp_armor_end(PTR_OFFSET(ptr, pos), line_content_size))
				{
					cleartext_end_armor_found = 1;
					armor_end = line_start + line_total_size;

					break;
				}
			}

			if (check_valid_pgp_armor_end(PTR_OFFSET(ptr, pos), line_content_size))
			{
				end_armor_found = 1;
				armor_end = line_start + line_total_size;

				break;
			}
		}

		// Ignore comments (Lines starting with #) before the header
		if (in[line_start] == '#')
		{
			continue;
		}

		// Ignore empty lines or whitespace lines before the header
		if (check_empty_line(PTR_OFFSET(ptr, line_start), line_content_size))
		{
			continue;
		}

		if (check_valid_pgp_armor_begin(PTR_OFFSET(ptr, pos), line_content_size, &cleartext_armor))
		{
			begin_armor_found = 1;
			armor_start = line_start;

			continue;
		}

		return ARMOR_MALFORMED_DATA;
	}

	if (cleartext_armor)
	{
		if (cleartext_begin_armor_found == 0 || cleartext_end_armor_found == 0)
		{
			return ARMOR_MALFORMED_DATA;
		}
	}

	if (begin_armor_found == 0 || end_armor_found == 0)
	{
		return ARMOR_MALFORMED_DATA;
	}

	*start = armor_start;
	*end = armor_end;

	return ARMOR_SUCCESS;
}

armor_status pgp_armor_read(pgp_armor_ctx *ctx, void *ptr, size_t size, size_t *result)
{
	armor_status status = ARMOR_SUCCESS;
	byte_t *in = ptr;

	size_t start = 0;
	size_t end = 0;
	size_t armor_size = 0;

	size_t pos = 0;
	size_t offset = 0;
	size_t line_content_size = 0;
	size_t line_total_size = 0;

	size_t base64_start = 0;
	size_t base64_size = 0;

	byte_t crc_present = 0;
	byte_t crc[4] = {0};
	uint32_t crc_decoded = 0;

	void *temp = NULL;

	status = get_armor_block(ptr, size, &start, &end);

	if (status != ARMOR_SUCCESS)
	{
		return status;
	}

	pos = start;
	armor_size = end - start;

	// Get Header
	get_line(PTR_OFFSET(ptr, pos), armor_size, &line_content_size, &line_total_size);

	ctx->type = get_begin_armor_type(PTR_OFFSET(ptr, pos), line_content_size);
	pos += line_total_size;

	// Parse the headers
	while (pos < armor_size)
	{
		get_line(PTR_OFFSET(ptr, pos), armor_size, &line_content_size, &line_total_size);

		if (memcmp(PTR_OFFSET(ptr, pos), version, strlen(version)) == 0)
		{
			memcpy(ctx->version.data, PTR_OFFSET(ptr, pos + strlen(version)), line_content_size - strlen(version));
		}
		else if (memcmp(PTR_OFFSET(ptr, pos), hash, strlen(hash)) == 0)
		{
			memcpy(ctx->version.data, PTR_OFFSET(ptr, pos + strlen(hash)), line_content_size - strlen(hash));
		}
		else if (memcmp(PTR_OFFSET(ptr, pos), charset, strlen(charset)) == 0)
		{
			memcpy(ctx->version.data, PTR_OFFSET(ptr, pos + strlen(charset)), line_content_size - strlen(charset));
		}
		else if (memcmp(PTR_OFFSET(ptr, pos), comment, strlen(comment)) == 0)
		{
			memcpy(ctx->version.data, PTR_OFFSET(ptr, pos + strlen(comment)), line_content_size - strlen(comment));
		}
		else if (memcmp(PTR_OFFSET(ptr, pos), message_id, strlen(message_id)) == 0)
		{
			memcpy(ctx->version.data, PTR_OFFSET(ptr, pos + strlen(message_id)), line_content_size - strlen(message_id));
		}
		else
		{
			status = ARMOR_INVALID_HEADER;
			return status;
		}

		// Break on empty line
		if (check_empty_line(PTR_OFFSET(ptr, pos), line_content_size))
		{
			pos += line_total_size;
			break;
		}

		pos += line_total_size;
	}

	// Decode the data
	base64_start = pos;

	// Get the size of data
	while (pos < armor_size)
	{
		get_line(PTR_OFFSET(ptr, pos), armor_size, &line_content_size, &line_total_size);

		if (line_content_size > 76)
		{
			status = ARMOR_BASE64_LINE_TOO_BIG;
			return status;
		}

		// CRC starts
		if (line_content_size == 5 && in[pos] == '=')
		{
			crc_present = 1;
			memcpy(crc, in + pos + 1, 4);

			pos += line_total_size;
			break;
		}

		pos += line_total_size;
		base64_size += line_content_size;
	}

	pos = base64_start;

	ctx->data.data = malloc(BASE64_DECODE_SIZE(base64_size));
	temp = malloc(base64_size);

	if (ctx->data.data == NULL || temp == NULL)
	{
		free(temp);
		free(ctx->data.data);

		status = ARMOR_INSUFFICIENT_SYSTEM_MEMORY;
		return status;
	}

	ctx->data.size = BASE64_DECODE_SIZE(base64_size);
	ctx->data.capacity = BASE64_DECODE_SIZE(base64_size);

	while (pos < armor_size)
	{
		get_line(PTR_OFFSET(ptr, pos), armor_size, &line_content_size, &line_total_size);

		memcpy(PTR_OFFSET(temp, offset), PTR_OFFSET(ptr, pos), line_content_size);
		offset += line_content_size;

		// CRC starts
		if (line_content_size == 5 && in[pos] == '=')
		{
			pos += line_total_size;
			break;
		}

		pos += line_total_size;
	}

	base64_decode(&(buffer_range_t){.data = ctx->data.data, .start = 0, .end = BASE64_DECODE_SIZE(base64_size)},
				  &(buffer_range_t){.data = temp, .start = 0, .end = base64_size});

	free(temp);

	if (crc_present)
	{
		ctx->crc = crc24_init();
		ctx->crc = crc24_update(ctx->crc, ctx->data.data, ctx->data.size);
		ctx->crc = crc24_final(ctx->crc);

		base64_decode(&(buffer_range_t){.data = (byte_t *)&crc_decoded, .start = 0, .end = 3},
					  &(buffer_range_t){.data = crc, .start = 0, .end = 4});

		if (ctx->crc != BSWAP_32(crc_decoded))
		{
			status = ARMOR_BAD_CRC;
			return status;
		}
	}

	// Get footer
	get_line(PTR_OFFSET(ptr, pos), armor_size, &line_content_size, &line_total_size);

	if (!((ctx->type == get_end_armor_type(PTR_OFFSET(ptr, pos), line_content_size)) ||
		  (ctx->type == PGP_ARMOR_CLEARTEXT && get_end_armor_type(PTR_OFFSET(ptr, pos), line_content_size) == PGP_ARMOR_SIGNATURE)))
	{
		status = ARMOR_HEADER_MISMATCH;
	}

	pos += line_total_size;

	*result = end;

	return status;
}

armor_status pgp_armor_write(pgp_armor_ctx *ctx, void *ptr, size_t size, size_t *result)
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
			return ARMOR_INSUFFICIENT_SYSTEM_MEMORY;
		}

		cleartext_size = encode_cleartext(cleartext_buffer, ctx->cleartext.data, ctx->cleartext.size);
		required_size += cleartext_size + 1;
	}

	// Armor data
	required_size += BASE64_ENCODE_SIZE(ctx->data.size);
	required_size += CEIL_DIV(BASE64_ENCODE_SIZE(ctx->data.size), columns);

	if ((ctx->flags & PGP_ARMOR_NO_CRC) == 0)
	{
		required_size += 1 + 4 + 1; // '=XXXX\n'
	}

	if (size < required_size)
	{
		free(cleartext_buffer);
		*result = required_size;

		return ARMOR_INSUFFICIENT_OUTPUT_BUFFER;
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

	*result = required_size;

	return ARMOR_SUCCESS;
}
