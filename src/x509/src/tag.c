/*
   Copyright (c) 2024 - 2025 Sibi Siddharthan

   Distributed under the MIT license.
   Refer to the LICENSE file at the root directory for details.
*/

#include <asn1/tag.h>

static size_t asn1_required_header_size(asn1_field *field)
{
	size_t required_size = 2; // tag, length

	if (field->context)
	{
		if (ASN1_CONSTRUCTED_TAG(field->context))
		{
			required_size += 1; // context tag
		}
	}

	if (field->size > 126)
	{
		size_t size = field->size;

		do
		{
			required_size += 1;
			size >>= 8;

		} while (size != 0);
	}

	return required_size;
}

