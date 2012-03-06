/*
 * Copyright (C) 2012 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "gmp_util.h"

#include <debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>

/**
 * See header.
 */
chunk_t gmp_mpz_to_chunk(const mpz_t value)
{
	chunk_t n;

	n.len = 1 + mpz_sizeinbase(value, 2) / BITS_PER_BYTE;
	n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, value);
	if (n.ptr == NULL)
	{	/* if we have zero in "value", gmp returns NULL */
		n.len = 0;
	}
	return n;
}

/**
 * See header.
 */
void gmp_mpz_clear_sensitive(mpz_t z)
{
	size_t len = mpz_size(z) * GMP_LIMB_BITS / BITS_PER_BYTE;
	u_int8_t *random = alloca(len);

	memset(random, 0, len);
	/* overwrite mpz_t with zero bytes before clearing it */
	mpz_import(z, len, 1, 1, 1, 0, random);
	mpz_clear(z);
}

/**
 * See header.
 */
chunk_t	gmp_emsa_pkcs1(hash_algorithm_t hash_algorithm, chunk_t data,
					   int keysize)
{
	chunk_t digestInfo = chunk_empty, em;
	int k;

	if (hash_algorithm != HASH_UNKNOWN)
	{
		hasher_t *hasher;
		chunk_t hash;
		int hash_oid;

		hash_oid = hasher_algorithm_to_oid(hash_algorithm);
		if (hash_oid == OID_UNKNOWN)
		{
			return chunk_empty;
		}

		hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm);
		if (hasher == NULL)
		{
			return chunk_empty;
		}
		hasher->allocate_hash(hasher, data, &hash);
		hasher->destroy(hasher);

		/* build DER-encoded digestInfo */
		digestInfo = asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_algorithmIdentifier(hash_oid),
						asn1_simple_object(ASN1_OCTET_STRING, hash)
					  );
		chunk_free(&hash);
		data = digestInfo;
	}

	k = (keysize + 7) / BITS_PER_BYTE;

	if (data.len > k - 3)
	{
		free(digestInfo.ptr);
		DBG1(DBG_LIB, "unable to sign %d bytes using a %d bit key", data.len,
			 keysize);
		return chunk_empty;
	}

	/* build chunk to rsa-decrypt:
	 * EM = 0x00 || 0x01 || PS || 0x00 || T.
	 * PS = 0xFF padding, with length to fill em
	 * T = encoded_hash
	 */
	em.len = k;
	em.ptr = malloc(em.len);

	/* fill em with padding */
	memset(em.ptr, 0xFF, em.len);

	/* set magic bytes */
	*(em.ptr) = 0x00;
	*(em.ptr+1) = 0x01;
	*(em.ptr + em.len - data.len - 1) = 0x00;

	/* set DER-encoded hash */
	memcpy(em.ptr + em.len - data.len, data.ptr, data.len);
	free(digestInfo.ptr);

	return em;
}
