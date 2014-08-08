/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

/*
 * Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Code released into the public domain.
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 */

#include <string.h>
#include <stdint.h>

#include "curve25519_dh.h"

/**
 * GCC 128 bit type, requires a 64-bit platform
 */
typedef unsigned __int128 u_int128_t;

typedef struct private_curve25519_dh_t private_curve25519_dh_t;

/**
 * Private data of an curve25519_dh_t object.
 */
struct private_curve25519_dh_t {

	/**
	 * Public curve25519_dh_t interface.
	 */
	curve25519_dh_t public;

	/**
	 * Private key
	 */
	u_int8_t priv[32];

	/**
	 * Shared key, if computed
	 */
	u_int8_t shared[32];

	/**
	 * True if shared secret is computed and stored in my_public_value.
	 */
	bool computed;
};

/**
 * Sum two numbers: output += in
 */
static inline void fsum(u_int64_t *out, const u_int64_t *in)
{
	out[0] += in[0];
	out[1] += in[1];
	out[2] += in[2];
	out[3] += in[3];
	out[4] += in[4];
}

/**
 * Find the difference of two numbers: output = in - output
 *
 * Assumes that out[i] < 2**52
 * On return, out[i] < 2**55
 */
static inline void fdifference_backwards(u_int64_t out[5], const u_int64_t in[5])
{
	/* 152 is 19 << 3 */
	static const u_int64_t two54m152 = (((u_int64_t)1) << 54) - 152;
	static const u_int64_t two54m8 = (((u_int64_t)1) << 54) - 8;

	out[0] = in[0] + two54m152 - out[0];
	out[1] = in[1] + two54m8 - out[1];
	out[2] = in[2] + two54m8 - out[2];
	out[3] = in[3] + two54m8 - out[3];
	out[4] = in[4] + two54m8 - out[4];
}

/**
 * Multiply a number by a scalar: out = in * scalar
 */
static inline void fscalar_product(u_int64_t out[5], const u_int64_t in[5],
								   const u_int64_t scalar)
{
	u_int128_t a;

	a = ((u_int128_t) in[0]) * scalar;
	out[0] = ((u_int64_t)a) & 0x7ffffffffffff;

	a = ((u_int128_t) in[1]) * scalar + ((u_int64_t) (a >> 51));
	out[1] = ((u_int64_t)a) & 0x7ffffffffffff;

	a = ((u_int128_t) in[2]) * scalar + ((u_int64_t) (a >> 51));
	out[2] = ((u_int64_t)a) & 0x7ffffffffffff;

	a = ((u_int128_t) in[3]) * scalar + ((u_int64_t) (a >> 51));
	out[3] = ((u_int64_t)a) & 0x7ffffffffffff;

	a = ((u_int128_t) in[4]) * scalar + ((u_int64_t) (a >> 51));
	out[4] = ((u_int64_t)a) & 0x7ffffffffffff;

	out[0] += (a >> 51) * 19;
}

/**
 * Multiply two numbers: out = in2 * in
 *
 * out must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, out[i] < 2**52
 */
static inline void fmul(u_int64_t out[5],
						const u_int64_t in2[5], const u_int64_t in[5])
{
	u_int128_t t[5];
	u_int64_t r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	s0 = in2[0];
	s1 = in2[1];
	s2 = in2[2];
	s3 = in2[3];
	s4 = in2[4];

	t[0] = ((u_int128_t) r0) * s0;
	t[1] = ((u_int128_t) r0) * s1 + ((u_int128_t) r1) * s0;
	t[2] = ((u_int128_t) r0) * s2 + ((u_int128_t) r2) * s0
			+ ((u_int128_t) r1) * s1;
	t[3] = ((u_int128_t) r0) * s3 + ((u_int128_t) r3) * s0
			+ ((u_int128_t) r1) * s2 + ((u_int128_t) r2) * s1;
	t[4] = ((u_int128_t) r0) * s4 + ((u_int128_t) r4) * s0
			+ ((u_int128_t) r3) * s1 + ((u_int128_t) r1) * s3
			+ ((u_int128_t) r2) * s2;

	r4 *= 19;
	r1 *= 19;
	r2 *= 19;
	r3 *= 19;

	t[0] += ((u_int128_t) r4) * s1 + ((u_int128_t) r1) * s4
			+ ((u_int128_t) r2) * s3 + ((u_int128_t) r3) * s2;
	t[1] += ((u_int128_t) r4) * s2 + ((u_int128_t) r2) * s4
			+ ((u_int128_t) r3) * s3;
	t[2] += ((u_int128_t) r4) * s3 + ((u_int128_t) r3) * s4;
	t[3] += ((u_int128_t) r4) * s4;

	r0 = (u_int64_t)t[0] & 0x7ffffffffffff;
	c = (u_int64_t)(t[0] >> 51);
	t[1] += c;
	r1 = (u_int64_t)t[1] & 0x7ffffffffffff;
	c = (u_int64_t)(t[1] >> 51);
	t[2] += c;
	r2 = (u_int64_t)t[2] & 0x7ffffffffffff;
	c = (u_int64_t)(t[2] >> 51);
	t[3] += c;
	r3 = (u_int64_t)t[3] & 0x7ffffffffffff;
	c = (u_int64_t)(t[3] >> 51);
	t[4] += c;
	r4 = (u_int64_t)t[4] & 0x7ffffffffffff;
	c = (u_int64_t)(t[4] >> 51);
	r0 += c * 19;
	c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
	r1 += c;
	c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
	r2 += c;

	out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
}

static inline void fsquare_times(u_int64_t out[5], const u_int64_t in[5],
								 u_int64_t count)
{
	u_int128_t t[5];
	u_int64_t r0, r1, r2, r3, r4, c;
	u_int64_t d0, d1, d2, d4, d419;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	do
	{
		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;

		t[0] = ((u_int128_t) r0) * r0 + ((u_int128_t) d4) * r1
				+ (((u_int128_t) d2) * r3);
		t[1] = ((u_int128_t) d0) * r1 + ((u_int128_t) d4) * r2
				+ (((u_int128_t) r3) * (r3 * 19));
		t[2] = ((u_int128_t) d0) * r2 + ((u_int128_t) r1) * r1
				+ (((u_int128_t) d4) * r3);
		t[3] = ((u_int128_t) d0) * r3 + ((u_int128_t) d1) * r2
				+ (((u_int128_t) r4) * d419);
		t[4] = ((u_int128_t) d0) * r4 + ((u_int128_t) d1) * r3
				+ (((u_int128_t) r2) * r2);

		r0 = (u_int64_t)t[0] & 0x7ffffffffffff;
		c = (u_int64_t)(t[0] >> 51);
		t[1] += c;
		r1 = (u_int64_t)t[1] & 0x7ffffffffffff;
		c = (u_int64_t)(t[1] >> 51);
		t[2] += c;
		r2 = (u_int64_t)t[2] & 0x7ffffffffffff;
		c = (u_int64_t)(t[2] >> 51);
		t[3] += c;
		r3 = (u_int64_t)t[3] & 0x7ffffffffffff;
		c = (u_int64_t)(t[3] >> 51);
		t[4] += c;
		r4 = (u_int64_t)t[4] & 0x7ffffffffffff;
		c = (u_int64_t)(t[4] >> 51);
		r0 += c * 19;
		c = r0 >> 51;
		r0 = r0 & 0x7ffffffffffff;
		r1 += c;
		c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
		r2 += c;
	}
	while (--count);

	out[0] = r0;
	out[1] = r1;
	out[2] = r2;
	out[3] = r3;
	out[4] = r4;
}

/**
 * Load a little-endian 64-bit number
 */
static u_int64_t load_limb(const u_int8_t *in)
{
	return ((u_int64_t)in[0]) |
			(((u_int64_t)in[1]) << 8) |
			(((u_int64_t)in[2]) << 16) |
			(((u_int64_t)in[3]) << 24) |
			(((u_int64_t)in[4]) << 32) |
			(((u_int64_t)in[5]) << 40) |
			(((u_int64_t)in[6]) << 48) |
			(((u_int64_t)in[7]) << 56);
}

static void store_limb(u_int8_t *out, u_int64_t in)
{
	out[0] = in & 0xff;
	out[1] = (in >> 8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
	out[4] = (in >> 32) & 0xff;
	out[5] = (in >> 40) & 0xff;
	out[6] = (in >> 48) & 0xff;
	out[7] = (in >> 56) & 0xff;
}

/**
 * Take a little-endian, 32-byte number and expand it into polynomial form
 */
static void fexpand(u_int64_t *output, const u_int8_t *in)
{
	output[0] = load_limb(in) & 0x7ffffffffffff;
	output[1] = (load_limb(in+6) >> 3) & 0x7ffffffffffff;
	output[2] = (load_limb(in+12) >> 6) & 0x7ffffffffffff;
	output[3] = (load_limb(in+19) >> 1) & 0x7ffffffffffff;
	output[4] = (load_limb(in+24) >> 12) & 0x7ffffffffffff;
}

/**
 * Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void fcontract(u_int8_t *output, const u_int64_t in[5])
{
	u_int128_t t[5];

	t[0] = in[0];
	t[1] = in[1];
	t[2] = in[2];
	t[3] = in[3];
	t[4] = in[4];

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

	t[0] += 19;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffff;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000 - 19;
	t[1] += 0x8000000000000 - 1;
	t[2] += 0x8000000000000 - 1;
	t[3] += 0x8000000000000 - 1;
	t[4] += 0x8000000000000 - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
	t[4] &= 0x7ffffffffffff;

	store_limb(output,    t[0] | (t[1] << 51));
	store_limb(output+8,  (t[1] >> 13) | (t[2] << 38));
	store_limb(output+16, (t[2] >> 26) | (t[3] << 25));
	store_limb(output+24, (t[3] >> 39) | (t[4] << 12));
}

/**
 * Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 */
static void fmonty(u_int64_t *x2, u_int64_t *z2, /* output 2Q */
				   u_int64_t *x3, u_int64_t *z3, /* output Q + Q' */
				   u_int64_t *x, u_int64_t *z,   /* input Q */
				   u_int64_t *xprime, u_int64_t *zprime, /* input Q' */
				   const u_int64_t *qmqp /* input Q - Q' */)
{
	u_int64_t origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5],
	zzprime[5], zzzprime[5];

	memcpy(origx, x, 5 * sizeof(u_int64_t));
	fsum(x, z);
	fdifference_backwards(z, origx); /* does x - z */

	memcpy(origxprime, xprime, sizeof(u_int64_t) * 5);
	fsum(xprime, zprime);
	fdifference_backwards(zprime, origxprime);
	fmul(xxprime, xprime, z);
	fmul(zzprime, x, zprime);
	memcpy(origxprime, xxprime, sizeof(u_int64_t) * 5);
	fsum(xxprime, zzprime);
	fdifference_backwards(zzprime, origxprime);
	fsquare_times(x3, xxprime, 1);
	fsquare_times(zzzprime, zzprime, 1);
	fmul(z3, zzzprime, qmqp);

	fsquare_times(xx, x, 1);
	fsquare_times(zz, z, 1);
	fmul(x2, xx, zz);
	fdifference_backwards(zz, xx); /* does zz = xx - zz */
	fscalar_product(zzz, zz, 121665);
	fsum(zzz, xx);
	fmul(z2, zz, zzz);
}

/**
 * Maybe swap the contents of two limb arrays (@a and @b), each @len elements
 * long. Perform the swap iff @swap is non-zero.
 *
 * This function performs the swap without leaking any side-channel
 * information.
 */
static void swap_conditional(u_int64_t a[5], u_int64_t b[5], u_int64_t iswap)
{
	unsigned i;
	const u_int64_t swap = -iswap;

	for (i = 0; i < 5; ++i)
	{
		const u_int64_t x = swap & (a[i] ^ b[i]);
		a[i] ^= x;
		b[i] ^= x;
	}
}

/**
 * Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void cmult(u_int64_t *resultx, u_int64_t *resultz,
				  const u_int8_t *n, const u_int64_t *q)
{
	u_int64_t a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
	u_int64_t *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
	u_int64_t e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
	u_int64_t *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

	unsigned i, j;

	memcpy(nqpqx, q, sizeof(u_int64_t) * 5);

	for (i = 0; i < 32; ++i)
	{
		u_int8_t byte = n[31 - i];
		for (j = 0; j < 8; ++j)
		{
			const u_int64_t bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2, nqpqx2, nqpqz2, nqx, nqz, nqpqx, nqpqz, q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(u_int64_t) * 5);
	memcpy(resultz, nqz, sizeof(u_int64_t) * 5);
}

static void crecip(u_int64_t out[5], const u_int64_t z[5])
{
	u_int64_t a[5], t0[5], b[5], c[5];

	/* 2 */ fsquare_times(a, z, 1); /* a = 2 */
	/* 8 */ fsquare_times(t0, a, 2);
	/* 9 */ fmul(b, t0, z); /* b = 9 */
	/* 11 */ fmul(a, b, a); /* a = 11 */
	/* 22 */ fsquare_times(t0, a, 1);
	/* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
	/* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
	/* 2^10 - 2^0 */ fmul(b, t0, b);
	/* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
	/* 2^20 - 2^0 */ fmul(c, t0, b);
	/* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
	/* 2^40 - 2^0 */ fmul(t0, t0, c);
	/* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
	/* 2^50 - 2^0 */ fmul(b, t0, b);
	/* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
	/* 2^100 - 2^0 */ fmul(c, t0, b);
	/* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
	/* 2^200 - 2^0 */ fmul(t0, t0, c);
	/* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
	/* 2^250 - 2^0 */ fmul(t0, t0, b);
	/* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
	/* 2^255 - 21 */ fmul(out, t0, a);
}

static int curve25519(u_int8_t *mypublic,
					  const u_int8_t *secret, const u_int8_t *basepoint)
{
	u_int64_t bp[5], x[5], z[5], zmone[5];

	fexpand(bp, basepoint);
	cmult(x, z, secret, bp);
	crecip(zmone, z);
	fmul(z, x, zmone);
	fcontract(mypublic, z);
	return 0;
}

METHOD(diffie_hellman_t, set_other_public_value, void,
	private_curve25519_dh_t *this, chunk_t value)
{
	if (value.len == 32)
	{
		curve25519(this->shared, this->priv, value.ptr);
		this->computed = TRUE;
	}
}

METHOD(diffie_hellman_t, get_my_public_value, void,
	private_curve25519_dh_t *this, chunk_t *value)
{
	const u_int8_t basepoint[32] = { 9 };

	*value = chunk_alloc(32);

	curve25519(value->ptr, this->priv, basepoint);
}

METHOD(diffie_hellman_t, get_shared_secret, status_t,
	private_curve25519_dh_t *this, chunk_t *secret)
{
	if (!this->computed)
	{
		return FAILED;
	}
	*secret = chunk_clone(chunk_from_thing(this->shared));
	return SUCCESS;
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_curve25519_dh_t *this)
{
	return CURVE_25519;
}

METHOD(diffie_hellman_t, destroy, void,
	private_curve25519_dh_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
curve25519_dh_t *curve25519_dh_create(diffie_hellman_group_t group)
{
	private_curve25519_dh_t *this;
	rng_t *rng;

	if (group != CURVE_25519)
	{
		return FALSE;
	}

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
	);

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1(DBG_LIB, "no RNG found for quality %N",
			 rng_quality_names, RNG_STRONG);
		destroy(this);
		return NULL;
	}
	if (!rng->get_bytes(rng, sizeof(this->priv), this->priv))
	{
		rng->destroy(rng);
		destroy(this);
		return NULL;
	}
	rng->destroy(rng);

	this->priv[0] &= 248;
	this->priv[32 - 1] &= 127;
	this->priv[32 - 1] |= 64;

	return &this->public;
}
