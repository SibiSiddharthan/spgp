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

#define BIGNUM_CTX_STACK_DEPTH 4

bignum_t *bignum_init_checked(void *ptr, size_t bn_size, uint32_t bits);

typedef struct _block
{
	void *base;
	size_t total_size;
	size_t usable_size;
	size_t free_size;
} block;

typedef struct _stack
{
	void *start;
	void *end;
	void *ptr;
} stack;

struct _bignum_ctx
{
	block *blocks;
	int8_t block_count;
	int8_t stack_count;
	stack stacks[BIGNUM_CTX_STACK_DEPTH];
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
	block *first_block = NULL;
	size_t total_size = sizeof(bignum_ctx) + sizeof(block);

	// Make sure we allocate atleast 256 bytes for the stacks.
	size = ROUND_UP(MAX(size, 256), 64);
	total_size += size;

	bctx = malloc(total_size);

	if (bctx == NULL)
	{
		return NULL;
	}

	memset(bctx, 0, total_size);

	// Initialize the first block. The first block will contain the entire bignum_ctx structure.
	first_block = (block *)((byte_t *)bctx + sizeof(bignum_ctx));

	// The usable memory region will lie after the block header.
	first_block->base = (byte_t *)first_block + sizeof(block);
	first_block->total_size = total_size;
	first_block->usable_size = size;
	first_block->free_size = size;

	bctx->block_count = 1;
	bctx->stack_count = 0;

	return bctx;
}

void bignum_ctx_delete(bignum_ctx *bctx)
{
	block *temp1 = NULL;
	block *temp2 = NULL;

	if (bctx == NULL)
	{
		return;
	}

	temp1 = bctx->blocks;

	while ((temp2 = temp1))
	{
		temp1 = temp1->next;

		// Zero contents before freeing.
		memset(temp2, 0, temp2->total_size);
		free(temp2);
	}
}

void bignum_ctx_start(bignum_ctx *bctx, size_t size)
{
	create_new_stack(bctx, size);
}

void bignum_ctx_end(bignum_ctx *bctx)
{
	cleanup_stack(bctx);
}

void *bignum_ctx_allocate_raw(bignum_ctx *bctx, size_t size)
{
	return allocate_memory(bctx, size);
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
