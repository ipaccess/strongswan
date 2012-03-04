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
#include "gmp_rsa_private_key_share.h"

#include <debug.h>

typedef struct private_gmp_rsa_private_key_share_t private_gmp_rsa_private_key_share_t;

/**
 * Private data of a gmp_rsa_private_key_share_t object.
 */
struct private_gmp_rsa_private_key_share_t {
	/**
	 * Public interface for this signer.
	 */
	gmp_rsa_private_key_share_t public;

	/**
	 * Public modulus.
	 */
	mpz_t n;

	/**
	 * Public exponent.
	 */
	mpz_t e;

	/**
	 * Private exponent share.
	 */
	mpz_t d;

	/**
	 * Secret sharing threshold.
	 */
	u_int threshold;

	/**
	 * ID designating the location where the private key share was sampled.
	 */
	u_int share;

	/**
	 * Keysize in bytes.
	 */
	size_t k;

	/**
	 * reference count
	 */
	refcount_t ref;
};

/**
 * PKCS#1 RSADP function
 */
static chunk_t rsadp(private_gmp_rsa_private_key_share_t *this, chunk_t data)
{
	mpz_t t;
	chunk_t decrypted;

	mpz_init(t);
	mpz_import(t, data.len, 1, 1, 1, 0, data.ptr);

	/* decrypted = data^d mod n */
	mpz_powm(t, t, this->d, this->n);

	decrypted.len = this->k;
	decrypted.ptr = mpz_export(NULL, NULL, 1, decrypted.len, 1, 0, t);
	if (decrypted.ptr == NULL)
	{
		decrypted.len = 0;
	}

	gmp_mpz_clear_sensitive(t);

	return decrypted;
}

/**
 * PKCS#1 RSASP1 function
 */
static chunk_t rsasp1(private_gmp_rsa_private_key_share_t *this, chunk_t data)
{
	return rsadp(this, data);
}

/**
 * Build a signature using the PKCS#1 EMSA scheme
 */
static bool build_emsa_pkcs1_signature(private_gmp_rsa_private_key_share_t *this,
									   hash_algorithm_t hash_algorithm,
									   chunk_t data, chunk_t *signature)
{
	chunk_t em;

	em = gmp_emsa_pkcs1(hash_algorithm, data, mpz_sizeinbase(this->n, 2));
	if (!em.ptr)
	{
		return FALSE;
	}
	*signature = rsasp1(this, em);
	free(em.ptr);

	return TRUE;
}

METHOD(private_key_t, get_type, key_type_t,
	private_gmp_rsa_private_key_share_t *this)
{
	return KEY_RSA_SHARE;
}

METHOD(private_key_t, sign, bool,
	private_gmp_rsa_private_key_share_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return build_emsa_pkcs1_signature(this, HASH_UNKNOWN, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return build_emsa_pkcs1_signature(this, HASH_SHA1, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA224:
			return build_emsa_pkcs1_signature(this, HASH_SHA224, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA256:
			return build_emsa_pkcs1_signature(this, HASH_SHA256, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA384:
			return build_emsa_pkcs1_signature(this, HASH_SHA384, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA512:
			return build_emsa_pkcs1_signature(this, HASH_SHA512, data, signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return build_emsa_pkcs1_signature(this, HASH_MD5, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_gmp_rsa_private_key_share_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	chunk_t em, stripped;
	bool success = FALSE;

	if (scheme != ENCRYPT_RSA_PKCS1)
	{
		DBG1(DBG_LIB, "encryption scheme %N not supported",
			 encryption_scheme_names, scheme);
		return FALSE;
	}
	/* rsa decryption using PKCS#1 RSADP */
	stripped = em = rsadp(this, crypto);

	/* PKCS#1 v1.5 8.1 encryption-block formatting (EB = 00 || 02 || PS || 00 || D) */

	/* check for hex pattern 00 02 in decrypted message */
	if ((*stripped.ptr++ != 0x00) || (*(stripped.ptr++) != 0x02))
	{
		DBG1(DBG_LIB, "incorrect padding - probably wrong rsa key");
		goto end;
	}
	stripped.len -= 2;

	/* the plaintext data starts after first 0x00 byte */
	while (stripped.len-- > 0 && *stripped.ptr++ != 0x00)

	if (stripped.len == 0)
	{
		DBG1(DBG_LIB, "no plaintext data");
		goto end;
	}

	*plain = chunk_clone(stripped);
	success = TRUE;

end:
	chunk_clear(&em);
	return success;
}

METHOD(private_key_t, get_keysize, int,
	private_gmp_rsa_private_key_share_t *this)
{
	return mpz_sizeinbase(this->n, 2);
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_gmp_rsa_private_key_share_t *this)
{
	chunk_t n, e;
	public_key_t *public;

	n = gmp_mpz_to_chunk(this->n);
	e = gmp_mpz_to_chunk(this->e);

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
						BUILD_RSA_MODULUS, n, BUILD_RSA_PUB_EXP, e, BUILD_END);
	chunk_free(&n);
	chunk_free(&e);

	return public;
}

METHOD(private_key_t, get_key_share, private_key_t*,
	private_gmp_rsa_private_key_share_t *this, u_int share)
{
	return NULL;
}

METHOD(private_key_t, get_encoding, bool,
	private_gmp_rsa_private_key_share_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	chunk_t n, e, d;
	bool success;

	n = gmp_mpz_to_chunk(this->n);
	e = gmp_mpz_to_chunk(this->e);
	d = gmp_mpz_to_chunk(this->d);

	success = lib->encoding->encode(lib->encoding,
							type, NULL, encoding, CRED_PART_RSA_MODULUS, n,
							CRED_PART_RSA_PUB_EXP, e, CRED_PART_RSA_PRIV_EXP, d,
							CRED_PART_THRESHOLD, this->threshold,
							CRED_PART_SHARE, this->share, CRED_PART_END);
	chunk_free(&n);
	chunk_free(&e);
	chunk_clear(&d);

	return success;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_gmp_rsa_private_key_share_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	chunk_t n, e;
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	n = gmp_mpz_to_chunk(this->n);
	e = gmp_mpz_to_chunk(this->e);

	success = lib->encoding->encode(lib->encoding, type, this, fp,
			CRED_PART_RSA_MODULUS, n, CRED_PART_RSA_PUB_EXP, e, CRED_PART_END);
	chunk_free(&n);
	chunk_free(&e);

	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_gmp_rsa_private_key_share_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_gmp_rsa_private_key_share_t *this)
{
	if (ref_put(&this->ref))
	{
		mpz_clear(this->n);
		mpz_clear(this->e);

		gmp_mpz_clear_sensitive(this->d);

		lib->encoding->clear_cache(lib->encoding, this);
		free(this);
	}
}

/**
 * See header.
 */
gmp_rsa_private_key_share_t *gmp_rsa_private_key_share_load(key_type_t type, va_list args)
{
	private_gmp_rsa_private_key_share_t *this;
	chunk_t n = chunk_empty, e = chunk_empty, d = chunk_empty;
	u_int threshold = 1, share = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_RSA_MODULUS:
				n = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PUB_EXP:
				e = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PRIV_EXP:
				d = va_arg(args, chunk_t);
				continue;
			case BUILD_THRESHOLD:
				threshold = va_arg(args, u_int);
				continue;
			case BUILD_SHARE:
				share = va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.get_key_share = _get_key_share,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.threshold = threshold,
		.share = share,
		.ref = 1,
	);

	mpz_init(this->n);
	mpz_init(this->e);
	mpz_init(this->d);

	mpz_import(this->n, n.len, 1, 1, 1, 0, n.ptr);
	mpz_import(this->e, e.len, 1, 1, 1, 0, e.ptr);
	mpz_import(this->d, d.len, 1, 1, 1, 0, d.ptr);

	this->k = (mpz_sizeinbase(this->n, 2) + 7) / BITS_PER_BYTE;

	return &this->public;
}

