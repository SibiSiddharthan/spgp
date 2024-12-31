/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#ifndef CRYPTO_COMPILER_H
#define CRYPTO_COMPILER_H

#if defined(__clang__)
#	define _CRYPTO_COMPILER_CLANG_
#elif defined(__GNUC__)
#	define _CRYPTO_COMPILER_GCC_
#elif defined(_MSC_VER)
#	define _CRYPTO_COMPILER_MSVC_
#else
#	error "Unsupported Compiler"
#endif

#endif
