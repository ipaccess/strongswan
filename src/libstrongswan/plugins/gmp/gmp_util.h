/*
 * Copyright (C) 2012 Andreasa Steffen
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

/**
 * @defgroup gmp_util gmp_util
 * @{ @ingroup gmp_p
 */

#ifndef GMP_UTIL_H_
#define GMP_UTIL_H_

#include <gmp.h>

#include <library.h>

#ifdef HAVE_MPZ_POWM_SEC
# undef mpz_powm
# define mpz_powm mpz_powm_sec
#endif

/**
 * Convert a MP integer into a chunk_t
 *
 * @param value		MP integer
 * @return 			MP integer returned as a chunk_t
 */
chunk_t gmp_mpz_to_chunk(const mpz_t value);

/**
 * Auxiliary function overwriting private key material with zero bytes
 *
 * @param z			MP integer to be cleared
 */
void gmp_mpz_clear_sensitive(mpz_t z);

/**
 * Computes a hash over a data block embedded in a PKCS#1 padding
 *
 * @param hash_algorithm	selected hash algorithm
 * @param data				data to be hashed
 * @param keysize			size of RSA modulus in bits
 */
chunk_t	gmp_emsa_pkcs1(hash_algorithm_t hash_algorithm, chunk_t data,
					   int keysize);

#endif /** GMP_UTIL_H_ @}*/
