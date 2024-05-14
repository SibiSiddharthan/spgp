/*
   Copyright (c) 2024 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_BLAKE2_H
#define CRYPTO_BLAKE2_H

#include <types.h>

#define BLAKE2B_MAX_HASH_SIZE 64
#define BLAKE2B_MAX_KEY_SIZE  64
#define BLAKE2B_SALT_SIZE     32
#define BLAKE2B_PERSONAL_SIZE 32
#define BLAKE2B_BLOCK_SIZE    128

#define BLAKE2S_MAX_HASH_SIZE 32
#define BLAKE2S_MAX_KEY_SIZE  32
#define BLAKE2S_SALT_SIZE     16
#define BLAKE2S_PERSONAL_SIZE 16
#define BLAKE2S_BLOCK_SIZE    64

#define BLAKE2_PARAM_INIT(HASH_SIZE, KEY_SIZE) {.digest_size = HASH_SIZE, .key_size = KEY_SIZE, .fanout = 1, .depth = 1};

typedef struct _blake2s_param
{
	uint8_t digest_size;                     // 1
	uint8_t key_size;                        // 2
	uint8_t fanout;                          // 3
	uint8_t depth;                           // 4
	uint8_t leaf_size[4];                    // 8
	uint8_t node_offset[6];                  // 14
	uint8_t node_depth;                      // 15
	uint8_t inner_size;                      // 16
	uint8_t salt[BLAKE2S_SALT_SIZE];         // 24
	uint8_t personal[BLAKE2S_PERSONAL_SIZE]; // 32
} blake2s_param;

typedef struct _blake2b_param
{
	uint8_t digest_size;                     // 1
	uint8_t key_size;                        // 2
	uint8_t fanout;                          // 3
	uint8_t depth;                           // 4
	uint8_t leaf_size[4];                    // 8
	uint8_t node_offset[8];                  // 16
	uint8_t node_depth;                      // 17
	uint8_t inner_size;                      // 18
	uint8_t reserved[14];                    // 32
	uint8_t salt[BLAKE2B_SALT_SIZE];         // 48
	uint8_t personal[BLAKE2B_PERSONAL_SIZE]; // 64
} blake2b_param;

typedef struct _blake2b_ctx
{
	uint64_t state[8];
	uint8_t hash_size;
	uint8_t key_size;
	uint16_t unhashed;
	uint64_t size[2];
	byte_t internal[BLAKE2B_BLOCK_SIZE];
} blake2b_ctx;

typedef struct _blake2s_ctx
{
	uint32_t state[8];
	uint8_t hash_size;
	uint8_t key_size;
	uint16_t unhashed;
	uint64_t size;
	byte_t internal[BLAKE2S_BLOCK_SIZE];
} blake2s_ctx;

blake2b_ctx *blake2b_new(blake2b_param *param, void *key);
void blake2b_delete(blake2b_ctx *ctx);
void blake2b_reset(blake2b_ctx *ctx, blake2b_param *param, void *key);
void blake2b_update(blake2b_ctx *ctx, void *data, size_t size);
int32_t blake2b_final(blake2b_ctx *ctx, byte_t *buffer, size_t size);
int32_t blake2b_512_hash(void *data, size_t size, byte_t buffer[BLAKE2B_MAX_HASH_SIZE]);
int32_t blake2b_512_mac(void *data, size_t size, byte_t key[BLAKE2B_MAX_KEY_SIZE], byte_t buffer[BLAKE2B_MAX_HASH_SIZE]);

blake2s_ctx *blake2s_new(blake2s_param *param, void *key);
void blake2s_delete(blake2s_ctx *ctx);
void blake2s_reset(blake2s_ctx *ctx, blake2s_param *param, void *key);
void blake2s_update(blake2s_ctx *ctx, void *data, size_t size);
int32_t blake2s_final(blake2s_ctx *ctx, byte_t *buffer, size_t size);
int32_t blake2s_256_hash(void *data, size_t size, byte_t buffer[BLAKE2S_MAX_HASH_SIZE]);
int32_t blake2s_256_mac(void *data, size_t size, byte_t key[BLAKE2S_MAX_KEY_SIZE], byte_t buffer[BLAKE2S_MAX_HASH_SIZE]);

#endif
