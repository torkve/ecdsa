/*
 * misc.h
 * Common methods
 *
 * Copyright © 2014, Vsevolod Velichko
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#pragma once

#ifdef __FreeBSD__
#include <netinet/in.h>
#endif
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#ifdef DEBUG_ECDSA
#include <stdio.h>
#define debug(format, ...) fprintf(stderr, "%s: " format "\n", __func__, ##__VA_ARGS__)
#define debugs(format) fprintf(stderr, "%s: " format "\n", __func__)
#define debug_bn(name, bn) \
	fprintf(stderr, "%s: BN %s=", __func__, #name); \
	BN_print_fp(stderr, bn); \
	fprintf(stderr, "\n");
#else
#define debug(...)
#define debugs(...)
#define debug_bn(...)
#endif

/* Helper functions */

typedef struct
{
	char *name;
	int nid;
	int bits;
	char *curve_name;
} keytype;

static const keytype keytypes[] =
{
	{"ecdsa-sha2-nistp256", NID_X9_62_prime256v1, 256, "nistp256"},
	{"ecdsa-sha2-nistp384", NID_secp384r1, 384, "nistp384"},
	{"ecdsa-sha2-nistp521", NID_secp521r1, 521, "nistp521"},
	{NULL},
};

static inline void explicit_bzero(void *mem, size_t mem_len)
{
#pragma optimize("-no-dead-code-removal")
#pragma optimize("-no-dce")
	volatile void *vmem = (volatile void *)mem;
	memset((void *)vmem, 0, mem_len);
#pragma optimize("-dead-code-removal")
#pragma optimize("-dce")
}

static inline const char *curve_name_of_nid(int nid)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->nid == nid)
			return kt->curve_name;
	return NULL;
}

static inline int nid_of_curve_name(const char *name)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (strcmp(kt->curve_name, name) == 0)
			return kt->nid;
	return 0;
}

static inline const char *nid_name_of_nid(int nid)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->nid == nid)
			return kt->name;
	return NULL;
}

static inline int nid_of_nid_name(const char *name)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (strcmp(kt->name, name) == 0)
			return kt->nid;
	return 0;
}

static inline int nid_of_bits(int bits)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->bits == bits)
			return kt->nid;
	return 0;
}

static inline int bits_of_nid(int nid)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->nid == nid)
			return kt->bits;
	return 0;
}

static inline const char *nid_name_of_bits(int bits)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->bits == bits)
			return kt->name;
	return NULL;
}

static inline int nid_of_key(EC_KEY *key)
{
	EC_GROUP *g;
	BN_CTX *bnctx;
	int nid = 0;
	const keytype *kt;
	const EC_GROUP *curve = EC_KEY_get0_group(key);

	if ((nid = EC_GROUP_get_curve_name(curve)) > 0)
		return nid;

	if ((bnctx = BN_CTX_new()) == NULL)
		return 0;

	nid = 0;

	for (kt = keytypes; kt->name != NULL; ++kt)
	{
		if ((g = EC_GROUP_new_by_curve_name(kt->nid)) == NULL)
			goto nid_of_key_cleanup;
		if (EC_GROUP_cmp(g, curve, bnctx) == 0)
		{
			EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
			if (EC_KEY_set_group(key, g) != 1)
			{
				EC_GROUP_free(g);
				goto nid_of_key_cleanup;
			}
			nid = kt->nid;
			goto nid_of_key_cleanup;
		}
		EC_GROUP_free(g);
	}

nid_of_key_cleanup:
	if (bnctx)
		BN_CTX_free(bnctx);
	return nid;
}

static inline void write_u32(char **str, uint32_t i)
{
	(*str)[0] = (unsigned char)(i >> 24) & 0xff;
	(*str)[1] = (unsigned char)(i >> 16) & 0xff;
	(*str)[2] = (unsigned char)(i >> 8) & 0xff;
	(*str)[3] = (unsigned char)i & 0xff;
	debug("wrote u32 to %lx: %u", (size_t)*str, i);
	*str += 4;
}

static inline void write_str(char **str, const char *v, uint32_t len)
{
	write_u32(str, len);
	memcpy(*str, v, len);
	debug("wrote str to %lx (%u): `%s`", (size_t)*str, len, *str);
	*str += len;
}

static inline int str_of_bn(BIGNUM *bn, char **dst, size_t *dst_len)
{
	int wtn = 0;
	char *ptr = NULL, *ptr2 = NULL;
	size_t len = 0;
	*dst = NULL;

	if (BN_is_zero(bn))
	{
		debugs("BN is zero");
		*dst = (char *)malloc(4);
		if (!*dst)
			return 0;
		ptr = *dst;
		write_u32(&ptr, 0u);
		*dst_len = 4;
		return 1;
	}
	debugs("BN is not zero");

	if (bn->neg)
	{
		debugs("BN is negative, not supported");
		return 0;
	}

	len = 4 + BN_num_bytes(bn) + 1;
	debug("expected BN size is %lu", len);
	if (len < 6)
		return 0;

	*dst = (char *)malloc(len);
	if (!*dst)
	{
		debugs("couldn't allocate memory for BN");
		return 0;
	}

	ptr = *dst;
	write_u32(&ptr, len - 4);

	ptr[0] = 0;

	wtn = BN_bn2bin(bn, (unsigned char *)ptr + 1);
	debug("wrote BN to %lx (%d): `%s`", (size_t)(ptr + 1), wtn, (char *)(ptr + 1));
	if (wtn <= 0 || (size_t)wtn != len - 5)
	{
		debug("write BN failed, written %d instead of %lu", wtn, len - 5);
		free(*dst);
		*dst = NULL;
		return 0;
	}

	if ((unsigned char)(ptr[1]) & 0x80)
	{
		debug("first byte is %u, returning as is", (unsigned char)ptr[1]);
		*dst_len = len;
		return 1;
	}

	debug("first byte is %u, stripping zero byte", (unsigned char)ptr[1]);
	ptr = (char *)malloc(len - 1);
	if (!ptr)
	{
		debugs("allocation for BN substring failed");
		explicit_bzero(*dst, len);
		free(*dst);
		*dst = NULL;
		return 0;
	}
	ptr2 = ptr;
	write_u32(&ptr2, len - 5);
	memcpy(ptr2, *dst + 5, len - 5);
	debug("moved BN[1:] (%lu): `%s`", len - 5, ptr2);
	explicit_bzero(*dst, len);
	free(*dst);
	*dst = ptr;
	*dst_len = len - 1;
	return 1;
}

static inline uint32_t read_u32(char **s, size_t *s_len)
{
	uint32_t res;
	unsigned char *ptr = (unsigned char *)*s;
	res = (uint32_t)(ptr[0]) << 24;
	res |= (uint32_t)(ptr[1]) << 16;
	res |= (uint32_t)(ptr[2]) << 8;
	res |= (uint32_t)(ptr[3]);
	debug("read u32 from %lx: %u", (size_t)*s, res);
	*s += 4;
	*s_len -= 4;
	return res;
}

static inline int read_str(char **src, size_t *src_len, char **str, size_t *len)
{
	*str = NULL;
	if (*src_len <= 4)
		return 0;

	*len = (size_t)read_u32(src, src_len);

	if (*len > *src_len || *len == 0)
		return 0;

	if ((*str = (char *)malloc(*len + 1)) == NULL)
		return 0;

	memcpy(*str, *src, *len);
	(*str)[*len] = 0;
	debug("read str from %lx (%lu): `%s`", (size_t)*str, *len, *str);
	*src += *len;
	*src_len -= *len;

	return 1;
}

static inline int read_point(char **str, size_t *str_len, const EC_GROUP *curve, EC_POINT *point)
{
	BN_CTX *bnctx = NULL;
	int res = 0;
	char *buf;
	size_t buf_len;

	if (!read_str(str, str_len, &buf, &buf_len))
		goto rp_cleanup;
	if (!buf_len)
		goto rp_cleanup;

	if (buf[0] != POINT_CONVERSION_UNCOMPRESSED)
		goto rp_cleanup;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto rp_cleanup;

	if (EC_POINT_oct2point(curve, point, (unsigned char *)buf, buf_len, bnctx) != 1)
		goto rp_cleanup;

	res = 1;
rp_cleanup:
	if (buf)
	{
		explicit_bzero(buf, buf_len);
		free(buf);

	}
	if (bnctx)
		BN_CTX_free(bnctx);

	return res;
}

static inline int read_bn(char **str, size_t *str_len, BIGNUM *bn)
{
	uint32_t len = 0;
	if (*str_len < 4)
		return 0;

	len = read_u32(str, str_len);
	if (len > 0 && ((*str)[0] & 0x80))
	{
		debug("first character is unexpectedly %u, fail", (*str)[0]);
		return 0;
	}

	if (len > *str_len)
	{
		debug("%lu bytes left in string, at least %u expected", *str_len, len);
		return 0;
	}
	if (BN_bin2bn((unsigned char *)*str, len, bn) == NULL)
	{
		debug("failed to read BN (%lu)", *str_len);
		return 0;
	}

	*str += len;
	*str_len -= len;

	return 1;
}

static inline int decode_base64(const char *src, size_t src_len, char **dst, size_t *dst_len)
{
	int sz;
	*dst = NULL;

	/* Practically only 3/4 * src_len is needed, but let's alloc equal size for simplicity */
	if ((*dst = (char *)malloc(src_len + 1)) == NULL)
		return 0;

	if ((sz = b64_pton(src, (unsigned char *)*dst, src_len)) <= 0)
	{
		explicit_bzero(*dst, src_len);
		free(*dst);
		*dst = NULL;
		return 0;
	}
	(*dst)[sz] = 0;
	*dst_len = (size_t)sz;
	return 1;
}

static inline int encode_base64(const char *src, size_t src_len, char **dst, size_t *dst_len)
{
	int sz;
	*dst = NULL;

	/* Practically only 4/3 * src_len is needed, but let's alloc double size for simplicity */
	if ((*dst = (char *)malloc(src_len * 2 + 1)) == NULL)
		return 0;

	if ((sz = b64_ntop((unsigned char *)src, src_len, *dst, src_len * 2)) <= 0)
	{
		explicit_bzero(*dst, src_len * 2);
		free(*dst);
		*dst = NULL;
		return 0;
	}
	(*dst)[sz] = 0;
	*dst_len = (size_t)sz;
	return 1;

}
/* vim:set ts=8 sts=8 sw=8 noet: */
