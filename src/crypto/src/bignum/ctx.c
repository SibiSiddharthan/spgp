/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <bignum.h>

#include <stdlib.h>
#include <string.h>

#define BIGNUM_CTX_ALIGNMENT 32

bignum_t *bignum_init_checked(void *ptr, size_t bn_size, uint32_t bits, uint16_t flags);

typedef struct _block
{
	struct _block *next; // Next block
	struct _block *prev; // Previous block

	void *base;         // Base address of usable memory
	size_t total_size;  // Total size of memory allocated
	size_t usable_size; // Usable memory size
	size_t free_size;   // Free memory size
} block;

typedef struct _stack
{
	struct _block *parent; // Block where the stack resides
	struct _stack *extent; // Next stack in case of insufficient space
	struct _stack *prev;   // Previous stack

	void *start; // Start of memory
	void *end;   // End of memory
	void *ptr;   // Current consumed memory
} stack;

struct _bignum_ctx
{
	block *current_block;
	stack *current_stack;
};

static block *create_new_block(bignum_ctx *bctx, size_t size)
{
	block *new_block = NULL;
	size_t struct_size = ROUND_UP(sizeof(block), BIGNUM_CTX_ALIGNMENT);
	size_t total_size = struct_size + ROUND_UP(size, BIGNUM_CTX_ALIGNMENT);

	size = ROUND_UP(size, BIGNUM_CTX_ALIGNMENT);

	new_block = malloc(total_size);

	if (new_block == NULL)
	{
		return NULL;
	}

	// Zero the block.
	memset(new_block, 0, total_size);

	new_block->base = (byte_t *)new_block + struct_size;
	new_block->total_size = total_size;
	new_block->usable_size = size;
	new_block->free_size = size;

	bctx->current_block->next = new_block;
	new_block->prev = bctx->current_block;

	bctx->current_block = new_block;

	return new_block;
}

static block *get_usable_block(bignum_ctx *bctx, size_t size)
{
	block *current_block = bctx->current_block;
	block *next_block = current_block->next;

	// Check current block
	if (current_block->free_size > size)
	{
		return current_block;
	}

	// Check next block
	if (next_block != NULL)
	{
		if (next_block->free_size > size)
		{
			bctx->current_block = next_block;
			return next_block;
		}
	}

	// The next block is unusable, free it.
	current_block->next = NULL;
	free(next_block);

	// Create a new one
	return create_new_block(bctx, size);
}

static stack *create_new_stack(bignum_ctx *bctx, size_t size)
{
	block *current_block = bctx->current_block;
	stack *new_stack = NULL;

	if (size == 0)
	{
		size = 2048;
	}

	if (current_block->free_size < (size + sizeof(stack)))
	{
		current_block = get_usable_block(bctx, size);

		if (current_block == NULL)
		{
			return NULL;
		}
	}

	// Initialize the stack
	new_stack = (void *)((byte_t *)current_block->base + (current_block->usable_size - current_block->free_size));

	new_stack->parent = current_block;
	new_stack->extent = NULL;
	new_stack->prev = bctx->current_stack;

	new_stack->start = (void *)((byte_t *)new_stack + sizeof(stack));
	new_stack->end = (void *)((byte_t *)new_stack->start + size);
	new_stack->ptr = new_stack->start;

	// Reduce free size of block
	current_block->free_size -= size + sizeof(stack);

	new_stack->prev = bctx->current_stack;
	bctx->current_stack = new_stack;

	return new_stack;
}

static stack *expand_stack(bignum_ctx *bctx, stack *current_stack, size_t grow)
{
	stack *new_extent = NULL;
	size_t size = 2 * ((uintptr_t)current_stack->end - (uintptr_t)current_stack->start);

	// Resize stack if we have enough space on the block
	if (current_stack->parent->free_size > grow)
	{
		current_stack->parent->free_size -= grow;
		current_stack->end = (byte_t *)current_stack->end + grow;

		return current_stack;
	}

	// Allocate new extension stack. This will be the current stack from now on.
	new_extent = create_new_stack(bctx, size);
	new_extent->extent = current_stack;

	return new_extent;
}

static void cleanup_stack(bignum_ctx *bctx)
{
	stack *current_stack = bctx->current_stack;
	block *parent_block = current_stack->parent;

	// Check for extents
	while (current_stack->extent != NULL)
	{
		stack *temp = current_stack;

		parent_block = current_stack->parent;
		current_stack = current_stack->extent;

		memset(temp->start, 0, (uintptr_t)temp->end - (uintptr_t)temp->start);
		parent_block->free_size += ((uintptr_t)temp->end - (uintptr_t)temp->start) + sizeof(stack);

		// Leave atmost one extra block, free the rest.
		if (current_stack->extent != NULL)
		{
			free(parent_block);
		}
	}

	// Main stack segment
	bctx->current_stack = current_stack->prev;

	memset(current_stack->start, 0, (uintptr_t)current_stack->end - (uintptr_t)current_stack->start);
	parent_block->free_size += ((uintptr_t)current_stack->end - (uintptr_t)current_stack->start) + sizeof(stack);
}

static void *allocate_memory(bignum_ctx *bctx, size_t size)
{
	void *ptr = NULL;
	stack *current_stack = bctx->current_stack;

	// Stack has insufficient space, try to expand it.
	if ((uintptr_t)current_stack->end - (uintptr_t)current_stack->ptr < size)
	{
		current_stack = expand_stack(bctx, current_stack, size - ((uintptr_t)current_stack->end - (uintptr_t)current_stack->ptr));
	}

	ptr = current_stack->ptr;
	current_stack->ptr = (void *)((uintptr_t)current_stack->ptr + size);

	return ptr;
}

// This is meant for internal use only. The size should always be big enough for only one block use throughout
// the structure's lifetime.
bignum_ctx *bignum_ctx_init(void *ptr, size_t size)
{
	bignum_ctx *bctx = ptr;
	block *first_block = NULL;
	size_t header_size = ROUND_UP(sizeof(bignum_ctx) + sizeof(block), BIGNUM_CTX_ALIGNMENT);
	size_t usable_size = size - header_size;

	memset(bctx, 0, size);

	// Initialize the first block. The first block will contain the entire bignum_ctx structure.
	bctx->current_stack = NULL;
	bctx->current_block = (void *)((byte_t *)bctx + sizeof(bignum_ctx));

	first_block = bctx->current_block;

	// The usable memory region will lie after the block header.
	first_block->base = (byte_t *)bctx + header_size;
	first_block->total_size = size;
	first_block->usable_size = usable_size;
	first_block->free_size = usable_size;

	return bctx;
}

bignum_ctx *bignum_ctx_new(size_t size)
{
	bignum_ctx *bctx = NULL;
	block *first_block = NULL;
	size_t header_size = ROUND_UP(sizeof(bignum_ctx) + sizeof(block), BIGNUM_CTX_ALIGNMENT);
	size_t total_size = header_size;
	size_t usable_size = 0;

	const size_t min_size = 4096;

	// Make sure we allocate atleast 4096 bytes for the stacks.
	size = ROUND_UP(MAX(size, min_size), BIGNUM_CTX_ALIGNMENT);
	total_size += size;

	usable_size = total_size - header_size;

	bctx = malloc(total_size);

	if (bctx == NULL)
	{
		return NULL;
	}

	memset(bctx, 0, total_size);

	// Initialize the first block. The first block will contain the entire bignum_ctx structure.
	bctx->current_stack = NULL;
	bctx->current_block = (void *)((byte_t *)bctx + sizeof(bignum_ctx));

	first_block = bctx->current_block;

	// The usable memory region will lie after the block header.
	first_block->base = (byte_t *)bctx + header_size;
	first_block->total_size = total_size;
	first_block->usable_size = usable_size;
	first_block->free_size = usable_size;

	return bctx;
}

void bignum_ctx_delete(bignum_ctx *bctx)
{
	block *temp = bctx->current_block;

	if (bctx == NULL)
	{
		return;
	}

	while (temp != NULL && temp->prev != NULL)
	{
		block *current = temp;
		temp = current->prev;

		// Zeroing memory here is pointless, as the calls to cleanup_stack should do it anyway.
		free(current);
	}

	// First block
	free(bctx);
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
	bn = bignum_init_checked(ptr, required_size, bits, BIGNUM_FLAG_NO_RESIZE);

	return bn;
}
