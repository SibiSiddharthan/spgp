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

static void *allocate_memory(bignum_ctx *bctx, size_t size)
{
	void *ptr = NULL;
	stack *current_stack = &bctx->stacks[bctx->stack_count - 1];

	// Stack has insufficient space.
	if ((uintptr_t)current_stack->end - (uintptr_t)current_stack->ptr < size)
	{
		return NULL;
	}

	ptr = current_stack->ptr;
	current_stack->ptr = (void *)((uintptr_t)current_stack->ptr + size);

	return ptr;
}

static block *create_new_block(bignum_ctx *bctx, size_t size)
{
	block *new_block = NULL;
	size_t total_size = sizeof(block) + ROUND_UP(size, 32);

	new_block = malloc(total_size);

	if (new_block == NULL)
	{
		return NULL;
	}

	// Zero the block.
	memset(new_block, 0, total_size);

	new_block->base = (byte_t *)new_block + sizeof(block);
	new_block->total_size = total_size;
	new_block->usable_size = size;
	new_block->free_size = size;

	bctx->block_count++;

	return new_block;
}

static stack *create_new_stack(bignum_ctx *bctx, size_t size)
{
	block *current_block = &bctx->blocks[bctx->block_count - 1];
	stack *new_stack = NULL;

	if (bctx->stack_count >= BIGNUM_CTX_STACK_DEPTH)
	{
		return NULL;
	}

	new_stack = &bctx->stacks[bctx->stack_count];

	if (current_block->free_size < size)
	{
		current_block = create_new_block(bctx, size);

		if (current_block == NULL)
		{
			return NULL;
		}
	}

	// Initialize the stack
	new_stack->start = (byte_t *)current_block->base + (current_block->usable_size - current_block->free_size);
	new_stack->end = (byte_t *)new_stack->start + size;
	new_stack->ptr = new_stack->start;

	bctx->stack_count++;

	return new_stack;
}

static void cleanup_stack(bignum_ctx *bctx)
{
	block *current_block = &bctx->blocks[bctx->block_count - 1];
	stack *current_stack = &bctx->stacks[bctx->stack_count - 1];

	if (bctx->stack_count <= 0)
	{
		return;
	}

	current_block->free_size += (uintptr_t)current_stack->end - (uintptr_t)current_stack->start;
	bctx->stack_count--;

	// If the stack is created on a new block, free the block if this is the only stack in it.
	if (bctx->block_count > 1)
	{
		if (current_block->free_size == current_block->usable_size)
		{
			memset(current_block, 0, current_block->total_size);
			free(current_block);

			bctx->block_count--;
		}
	}
}

// This is meant for internal use only. The size should always be big enough for only one block use throughout
// the structure's lifetime.
bignum_ctx *bignum_ctx_init(void *ptr, size_t size)
{
	bignum_ctx *bctx = ptr;
	block *first_block = NULL;
	size_t header_size = sizeof(bignum_ctx) + sizeof(block);
	size_t usable_size = size - header_size;

	const size_t min_size = 256;

	if (size < header_size + min_size)
	{
		return NULL;
	}

	memset(bctx, 0, size);

	// Initialize the first block. The first block will contain the entire bignum_ctx structure.
	first_block = (block *)((byte_t *)bctx + sizeof(bignum_ctx));

	// The usable memory region will lie after the block header.
	first_block->base = (byte_t *)first_block + sizeof(block);
	first_block->total_size = size;
	first_block->usable_size = usable_size;
	first_block->free_size = usable_size;

	bctx->block_count = 1;
	bctx->stack_count = 0;

	return bctx;

	return bctx;
}

bignum_ctx *bignum_ctx_new(size_t size)
{
	bignum_ctx *bctx = NULL;
	block *first_block = NULL;
	size_t total_size = sizeof(bignum_ctx) + sizeof(block);

	// Make sure we allocate atleast 256 bytes for the stacks.
	size = ROUND_UP(MAX(size, 256), 32);
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
	if (bctx == NULL)
	{
		return;
	}

	for (int8_t i = 0; i < bctx->block_count; ++i)
	{
		block *current_block = &bctx->blocks[i];

		// Zero contents before freeing.
		memset(current_block, 0, current_block->total_size);
		free(current_block);
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
