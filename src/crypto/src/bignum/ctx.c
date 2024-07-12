/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <stdlib.h>
#include <string.h>

#include <bignum.h>
#include <minmax.h>
#include <round.h>

typedef struct _chunk
{
	void *next;
	void *ptr;
	size_t size;
} chunk;

struct _bignum_ctx
{
	void *next;
	chunk *head;
	chunk chunks[8];
	size_t total_size;
	size_t usable_size;
	size_t free_size;
};

#if 0
bignum_ctx *bignum_ctx_init(void *ptr, size_t size)
{
	bignum_ctx *bctx = ptr;
	size_t usable_size = size - sizeof(bignum_ctx);

	if (size < sizeof(bignum_ctx))
	{
		return NULL;
	}

	memset(bctx, 0, size);

	return bctx;
}
#endif

bignum_ctx *bignum_ctx_new(size_t size)
{
	bignum_ctx *bctx = NULL;
	size_t total_size = sizeof(bignum_ctx);

	// Make sure we allocate atleast 128 bytes for the chunks.
	size = ROUND_UP(MAX(size, 128), 64);
	total_size += size;

	bctx = malloc(total_size);

	if (bctx == NULL)
	{
		return NULL;
	}

	memset(bctx, 0, total_size);

	bctx->total_size = total_size;
	bctx->usable_size = size;
	bctx->free_size = size;

	// Setup the linked list of chunks.
	bctx->head = &bctx->chunks[0];
	bctx->chunks[7].next = NULL;

	for (uint8_t i = 0; i <= 6; ++i)
	{
		bctx->chunks[i].next = &bctx->chunks[i + 1];
	}

	return bctx;
}

void bignum_ctx_delete(bignum_ctx *bctx)
{
	bignum_ctx *temp = NULL;

	while ((temp = bctx))
	{
		bctx = bctx->next;

		// Zero contents before freeing.
		memset(temp, 0, temp->total_size);
		free(temp);
	}
}

void *bignum_ctx_allocate_raw(bignum_ctx *bctx, size_t size)
{
	return allocate_memory(bctx, size);
}

void bignum_ctx_release_raw(bignum_ctx *bctx, void *ptr)
{
	return free_memory(bctx, ptr);
}

bignum_t *bignum_ctx_allocate_bignum(bignum_ctx *bctx, uint32_t bits)
{
	size_t required_size = bignum_size((bits = ROUND_UP(bits, BIGNUM_BITS_PER_WORD)));
	void *ptr = bignum_ctx_allocate_raw(bctx, required_size);
	bignum_t *bn = NULL;

	if (ptr == NULL)
	{
		return NULL;
	}

	// Bignums allocated in ctx should not be resized.
	bn = bignum_init_checked(ptr, required_size, bits);
	bn->flags |= BIGNUM_FLAG_NO_RESIZE;

	return bn;
}

void bignum_ctx_release_bignum(bignum_ctx *bctx, bignum_t *bn)
{
	bignum_ctx_release_raw(bctx, bn);
}
