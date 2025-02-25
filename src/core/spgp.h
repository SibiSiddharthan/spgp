/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef SPGP_H
#define SPGP_H

#include <types.h>
#include <buffer.h>

#include <byteswap.h>
#include <minmax.h>
#include <ptr.h>
#include <round.h>
#include <load.h>

uint32_t spgp_initialize_home(const char *home, uint32_t size);

uint32_t spgp_generate_key(uint32_t algorithm_id);
uint32_t spgp_delete_key(const char *key_id, uint16_t key_id_size, uint32_t options);

uint32_t spgp_export_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size);
uint32_t spgp_import_key(void *buffer, size_t buffer_size);

uint32_t spgp_search_key(const char *key_id, uint16_t key_id_size, void *buffer, size_t buffer_size, uint32_t options);
uint32_t spgp_list_keys(uint32_t options);

#endif
