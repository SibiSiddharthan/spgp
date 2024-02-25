
#ifndef SPGP_MACROS_H
#define SPGP_MACROS_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t byte_t;

typedef struct _buffer_t
{
	byte_t *data;
	size_t pos;
	size_t size;
} buffer_t;

typedef struct _buffer_range_t
{
	byte_t *data;
	size_t start;
	size_t end;
} buffer_range_t;


#define LITTLE_ENDIAN 1

#ifdef LITTLE_ENDIAN

#define BSWAP_16(x) _byteswap_ushort((x))
#define BSWAP_32(x) _byteswap_ulong((x))
#define BSWAP_64(x) _byteswap_uint64((x))

#else

#define BSWAP_16(x) (x)
#define BSWAP_32(x) (x)
#define BSWAP_64(x) (x)

#endif

#define LOAD_8(d, s)                       \
	{                                      \
		*(uint8_t *)(d) = *(uint8_t *)(s); \
	}
#define LOAD_16(d, s)                        \
	{                                        \
		*(uint16_t *)(d) = *(uint16_t *)(s); \
	}
#define LOAD_32(d, s)                        \
	{                                        \
		*(uint32_t *)(d) = *(uint32_t *)(s); \
	}
#define LOAD_64(d, s)                        \
	{                                        \
		*(uint64_t *)(d) = *(uint64_t *)(s); \
	}

#define ADLOAD_8(d, s)                     \
	{                                      \
		*(uint8_t *)(d) = *(uint8_t *)(s); \
		(byte_t *)d += 1;                  \
	}
#define ADLOAD_16(d, s)                      \
	{                                        \
		*(uint16_t *)(d) = *(uint16_t *)(s); \
		(byte_t *)d += 2;                    \
	}
#define ADLOAD_32(d, s)                      \
	{                                        \
		*(uint32_t *)(d) = *(uint32_t *)(s); \
		(byte_t *)d += 4;                    \
	}
#define ADLOAD_64(d, s)                      \
	{                                        \
		*(uint64_t *)(d) = *(uint64_t *)(s); \
		(byte_t *)d += 8;                    \
	}

#define ROUNDUP(x, y) ((((x) + ((y)-1)) / (y)) * (y))

#endif
