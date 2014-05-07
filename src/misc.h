#pragma once

#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

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
	return -1;
}

static inline const char *nid_name_of_bits(int bits)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->bits == bits)
			return kt->name;
	return NULL;
}

static inline void write_u32(char **str, uint32_t i)
{
	(*str)[0] = (unsigned char)(i >> 24) & 0xff;
	(*str)[1] = (unsigned char)(i >> 16) & 0xff;
	(*str)[2] = (unsigned char)(i >> 8) & 0xff;
	(*str)[3] = (unsigned char)i & 0xff;
	*str += 4;
}

static inline void write_str(char **str, const char *v, uint32_t len)
{
	write_u32(str, len);
	memcpy(*str, v, len);
	*str += len;
}

static inline uint32_t read_u32(char **s, size_t *s_len)
{
	uint32_t res;
	res = (uint32_t)((*s)[0]) << 24;
	res |= (uint32_t)((*s)[1]) << 16;
	res |= (uint32_t)((*s)[2]) << 8;
	res |= (uint32_t)((*s)[3]);
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
	*src += *len;
    *src_len -= *len;

	return 1;
}

static inline int read_point(char **str, size_t *str_len, const EC_GROUP *curve, EC_POINT *point)
{
	BN_CTX *bnctx;
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

	if (EC_POINT_oct2point(curve, point, buf, buf_len, bnctx) != 1)
		goto rp_cleanup;

	res = 1;
rp_cleanup:
	if (buf)
	{
#pragma optimize("-no-dead-code-removal")
		memset((void *)buf, 0, buf_len);
#pragma optimize("-dead-code-removal")
		free(buf);

	}
	if (bnctx)
		BN_CTX_free(bnctx);

	return res;
}

static inline int decode_base64(const char *src, size_t src_len, char **dst, size_t *dst_len)
{
	int sz;
	*dst = NULL;

	/* Practically only 3/4 * src_len is needed, but let's alloc equal size for simplicity */
	if ((*dst = (char *)malloc(src_len + 1)) == NULL)
		return 0;

	if ((sz = b64_pton(src, *dst, src_len)) <= 0)
	{
#pragma optimize("-no-dead-code-removal")
		memset((void *)*dst, 0, src_len);
#pragma optimize("-dead-code-removal")
		free(*dst);
		*dst = NULL;
		return 0;
	}
	(*dst)[sz] = 0;
	*dst_len = (size_t)sz;
	return 1;
}

