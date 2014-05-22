/*
 * key.c
 * Python ecdsa.Key class
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

#include <Python.h>
#include "misc.h"
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#ifndef PyLong_FromLong
#define PyLong_FromLong PyInt_FromLong
#endif

#define MD5_LEN 16

typedef struct
{
	PyObject_HEAD
	int nid;
	EC_KEY *key;
} KeyObject;

static inline int validate_public_key(const EC_GROUP *curve, const EC_POINT *point)
{
	BN_CTX *bnctx = NULL;
	BIGNUM *x, *y, *order, *tmp;
	EC_POINT *q = NULL;

	int res = 0;

	if ((bnctx = BN_CTX_new()) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create key buffer");
		goto vpk_cleanup;
	}
	BN_CTX_start(bnctx);

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(curve)) != NID_X9_62_prime_field)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid prime field");
		goto vpk_cleanup;
	}

	if (EC_POINT_is_at_infinity(curve, point))
	{
		PyErr_SetString(PyExc_ValueError, "Degenerated public key (inifinity)");
		goto vpk_cleanup;
	}

	if (
		(x = BN_CTX_get(bnctx)) == NULL
		|| (y = BN_CTX_get(bnctx)) == NULL
		|| (order = BN_CTX_get(bnctx)) == NULL
		|| (tmp = BN_CTX_get(bnctx)) == NULL
	)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create key buffer");
		goto vpk_cleanup;
	}

	if (EC_GROUP_get_order(curve, order, bnctx) != 1)
	{
		PyErr_SetString(PyExc_ValueError, "Can't get key order");
		goto vpk_cleanup;
	}
	if (EC_POINT_get_affine_coordinates_GFp(curve, point, x, y, bnctx) != 1)
	{
		PyErr_SetString(PyExc_ValueError, "Can't get key affine coordinates");
		goto vpk_cleanup;
	}
	if ((BN_num_bits(x) <= BN_num_bits(order) / 2) || (BN_num_bits(y) <= BN_num_bits(order) / 2))
	{
		PyErr_SetString(PyExc_ValueError, "Public key coordinates are too small");
		goto vpk_cleanup;
	}

	if ((q = EC_POINT_new(curve)) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create key point");
		goto vpk_cleanup;
	}
	if (EC_POINT_mul(curve, q, NULL, point, order, bnctx) != 1)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot multiply points");
		goto vpk_cleanup;
	}
	if (EC_POINT_is_at_infinity(curve, q) != 1)
	{
		 PyErr_SetString(PyExc_ValueError, "Degenerated public key");
		 goto vpk_cleanup;
	}
	if (!BN_sub(tmp, order, BN_value_one()) || (BN_cmp(x, tmp) >= 0) || (BN_cmp(y, tmp) >= 0))
	{
		PyErr_SetString(PyExc_ValueError, "Point coordinates don't match the order");
		goto vpk_cleanup;
	}

	res = 1;
vpk_cleanup:
	if (bnctx)
		BN_CTX_free(bnctx);
	if (q)
		EC_POINT_free(q);

	return res;
}

static inline int validate_private_key(const EC_KEY *key)
{
	BN_CTX *bnctx;
	BIGNUM *order, *tmp;
	int res = 0;

	if ((bnctx = BN_CTX_new()) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create key buffer");
		goto vprk_cleanup;
	}

	BN_CTX_start(bnctx);
	if (
		(order = BN_CTX_get(bnctx)) == NULL
		|| (tmp = BN_CTX_get(bnctx)) == NULL
	)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create key buffer");
		goto vprk_cleanup;
	}

	if (EC_GROUP_get_order(EC_KEY_get0_group(key), order, bnctx) != 1)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid private key");
		goto vprk_cleanup;
	}

	if (BN_num_bits(EC_KEY_get0_private_key(key)) <= BN_num_bits(order) / 2)
	{
		PyErr_SetString(PyExc_ValueError, "Private key too small");
		goto vprk_cleanup;
	}

	if (!BN_sub(tmp, order, BN_value_one()) || BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
	{
		PyErr_SetString(PyExc_ValueError, "Point coordinates don't match the order");
		goto vprk_cleanup;
	}

	res = 1;
vprk_cleanup:
	if (bnctx)
		BN_CTX_free(bnctx);
	return res;
}

static inline int serialize_key(char **buffer, size_t *len, EC_KEY *key, int nid, int dump_private)
{
	const EC_GROUP *curve;
	const EC_POINT *point;
	BN_CTX *bnctx = NULL;
	const BIGNUM *pkey = NULL;
	char *buffer_in = NULL;
	size_t point_len = 0;
	uint32_t nid_name_len = 0, curve_name_len = 0;
	int res = 0;
	char *exponent = NULL;
	size_t exponent_len = 0;

	const char *nid_name = nid_name_of_nid(nid);
	const char *curve_name = curve_name_of_nid(nid);

	*buffer = NULL;

	if (!nid_name || !curve_name)
	{
		PyErr_SetString(PyExc_ValueError, "Key is broken, can't detect its type");
		return -1;
	}

	nid_name_len = strlen(nid_name);
	curve_name_len = strlen(curve_name);

	curve = EC_KEY_get0_group(key);
	point = EC_KEY_get0_public_key(key);

	if ((bnctx = BN_CTX_new()) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't create buffer context");
		goto pks_cleanup;
	}

	if (dump_private && ((pkey = EC_KEY_get0_private_key(key)) != NULL))
	{
		debug_bn(exponent, pkey);
		if (!str_of_bn(pkey, &exponent, &exponent_len))
		{
			PyErr_SetString(PyExc_MemoryError, "Can't allocate memory for key");
			goto pks_cleanup;
		}
	}

	point_len = EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
	*len = 4 + nid_name_len + 4 + curve_name_len + 4 + point_len;

	if (pkey)
		*len += exponent_len;

	*buffer = (char *)malloc(*len + 1);
	if (!*buffer)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory for key");
		goto pks_cleanup;
	}

	buffer_in = *buffer;
	write_str(&buffer_in, nid_name, nid_name_len);
	write_str(&buffer_in, curve_name, curve_name_len);
	write_u32(&buffer_in, point_len);
	EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char *)buffer_in, point_len, bnctx);
	debug("wrote point to %lx (%lu)", (size_t)buffer_in, point_len);
	buffer_in += point_len;
	if (exponent)
	{
		memcpy(buffer_in, exponent, exponent_len);
		debug("wrote bn to %lx (%lu): `%s`", (size_t)buffer_in, exponent_len, exponent);
		buffer_in += exponent_len;
	}
	buffer_in[0] = 0;

	res = 1;
pks_cleanup:
	if (bnctx)
		BN_CTX_free(bnctx);
	if (exponent)
	{
		explicit_bzero(exponent, exponent_len);
		free(exponent);
	}
	return res;
}

static inline int unserialize_key(EC_KEY **key, char *str, size_t str_len, int allow_private)
{
	EC_POINT *point = NULL;

	char *buffer = str;
	size_t buffer_len = str_len;

	char *key_name = NULL;
	size_t key_name_len = 0;

	char *curve_name = NULL;
	size_t curve_name_len = 0;

	int nid = 0;

	BIGNUM *exponent = NULL;

	*key = NULL;

	if (str_len == 0)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid string provided");
		goto uk_fail;
	}

	if (!read_str(&buffer, &buffer_len, &key_name, &key_name_len))
	{
		PyErr_SetString(PyExc_ValueError, "Can't read key type from key");
		goto uk_fail;
	}
	if ((nid = nid_of_nid_name(key_name)) == 0)
	{
		PyErr_SetString(PyExc_ValueError, "Unsupported key format");
		goto uk_fail;
	}

	if (!read_str(&buffer, &buffer_len, &curve_name, &curve_name_len))
	{
		PyErr_SetString(PyExc_ValueError, "Can't read curve type from key");
		goto uk_fail;
	}
	if (nid != nid_of_curve_name(curve_name))
	{
		PyErr_SetString(PyExc_ValueError, "Key and curve types don't match");
		goto uk_fail;
	}

	*key = EC_KEY_new_by_curve_name(nid);

	if ((point = EC_POINT_new(EC_KEY_get0_group(*key))) == NULL)
	{
		PyErr_SetString(PyExc_ValueError, "Can't create key point");
		goto uk_fail;
	}

	if (!read_point(&buffer, &buffer_len, EC_KEY_get0_group(*key), point))
	{
		PyErr_SetString(PyExc_ValueError, "Can't read key point");
		goto uk_fail;
	}

	if (EC_KEY_set_public_key(*key, point) != 1)
	{
		PyErr_SetString(PyExc_ValueError, "Can't apply public key");
		goto uk_fail;
	}

	if (!allow_private && buffer_len)
	{
		PyErr_SetString(PyExc_ValueError, "Trailing characters left");
		goto uk_fail;
	}

	if (buffer_len)
	{
		if ((exponent = BN_new()) == NULL)
		{
			PyErr_SetString(PyExc_MemoryError, "Can't allocate memory for private key");
			goto uk_fail;
		}
		if (!read_bn(&buffer, &buffer_len, exponent))
		{
			PyErr_SetString(PyExc_ValueError, "Can't read private key");
			goto uk_fail;
		}
		if(EC_KEY_set_private_key(*key, exponent) != 1)
		{
			PyErr_SetString(PyExc_ValueError, "Can't set private key");
			goto uk_fail;
		}
		debug_bn(exponent, exponent);
	}

	if (buffer_len)
	{
		debug("%ld characters left", buffer_len);
		PyErr_SetString(PyExc_ValueError, "Trailing characters left");
		goto uk_fail;
	}

	if (!validate_public_key(EC_KEY_get0_group(*key), point))
		goto uk_fail;
	if (exponent && !validate_private_key(*key))
		goto uk_fail;

	goto uk_cleanup;

uk_fail:
	nid = 0;
	if (*key)
	{
		EC_KEY_free(*key);
		*key = NULL;
	}
uk_cleanup:
	if(key_name)
		free(key_name);
	if(curve_name)
		free(curve_name);
	if (point)
		EC_POINT_free(point);
	if (exponent)
		BN_clear_free(exponent);

	return nid;
}

/* Object methods */

static PyObject* KeyObject_bits(PyObject *s)
{
	KeyObject *self = (KeyObject *)s;
	int bits = bits_of_nid(self->nid);
	return PyInt_FromLong(bits);
}

static const char bits_doc[] = "k.bits(): get the bit size of the key.\n:return: int bits";

static PyObject* KeyObject_nid_name(PyObject *s)
{
	KeyObject *self = (KeyObject *)s;
	const char *name = nid_name_of_nid(self->nid);
	if (!name)
		Py_RETURN_NONE;
	return (PyObject*)PyString_FromString(name);
}

static const char nid_name_doc[] = "k.nid_name(): get the curve name.\n:return: string name or None";

static PyObject* KeyObject_fingerprint(PyObject *s)
{
	KeyObject *self = (KeyObject *)s;

	EVP_MD_CTX md5ctx;
	char *blob = NULL, *digest = NULL;
	size_t blob_len;
	size_t digest_len = MD5_LEN; /* MD5 length */
	uint32_t dlen;
	PyObject *ret = NULL;

	if (!serialize_key(&blob, &blob_len, self->key, self->nid, 0))
		goto fp_cleanup;

	digest = (char *)malloc(digest_len + 1);
	if (!digest)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory for fingerprint");
		goto fp_cleanup;
	}

	EVP_MD_CTX_init(&md5ctx);
	if (EVP_DigestInit_ex(&md5ctx, EVP_md5(), NULL) != 1)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't initiliaze hash algorithm");
		goto fp_cleanup;
	}
	if (EVP_DigestUpdate(&md5ctx, blob, blob_len) != 1)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't initiliaze hash algorithm");
		goto fp_cleanup;
	}
	if (EVP_DigestFinal_ex(&md5ctx, (unsigned char *)digest, &dlen) != 1)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't make fingerprint");
		goto fp_cleanup;
	}
	if (digest_len != dlen)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't make fingerprint");
		goto fp_cleanup;
	}

	ret = PyString_FromStringAndSize(digest, digest_len);
fp_cleanup:
	EVP_MD_CTX_cleanup(&md5ctx);
	explicit_bzero(&md5ctx, sizeof(md5ctx));

	if (blob != NULL)
	{
		/* Cleanup memory for security reasons */
		explicit_bzero(blob, blob_len);
		free(blob);
	}
	if (digest != NULL)
	{
		/* Cleanup memory for security reasons */
		explicit_bzero(digest, digest_len);
		free(digest);
	}
	return ret;
}

static const char fingerprint_doc[] = "k.fingerprint(): get the key MD5 fingerprint.\n:return: string 16 bytes with raw MD5 key hash";

static PyObject* KeyObject_to_pem(PyObject *s)
{
	BIO *bio = NULL;
	KeyObject *self = (KeyObject *)s;
	const BIGNUM *pk = EC_KEY_get0_private_key(self->key);
	char *blob = NULL;
	int blob_len = 0;
	PyObject *ret = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create buffer");
		goto ktp_cleanup;
	}

	if (pk)
	{
		/* TODO: support passphrase */
		if (!PEM_write_bio_ECPrivateKey(bio, self->key, NULL, NULL, 0, NULL, NULL))
		{
			PyErr_SetString(PyExc_ValueError, "Cannot write key");
			goto ktp_cleanup;
		}
	}
	else
	{
		if(!PEM_write_bio_EC_PUBKEY(bio, self->key))
		{
			PyErr_SetString(PyExc_ValueError, "Cannot write key");
			goto ktp_cleanup;
		}
	}

	if ((blob_len = BIO_get_mem_data(bio, &blob)) <= 0)
		goto ktp_cleanup;

	ret = PyString_FromStringAndSize(blob, blob_len);

ktp_cleanup:
	if (bio)
		BIO_free(bio);

	return ret;
}

static const char to_pem_doc[] = "k.to_pem(): get the key PEM-encoded.\nEncodes public or private key into PEM container. Passwords are not currently supported.\n:return: string PEM-encoded key";

static PyObject* KeyObject_to_raw(PyObject *s)
{
	char *blob = NULL;
	size_t blob_len;
	PyObject *ret = NULL;
	KeyObject *self = (KeyObject *)s;

	debugs("dumping key in raw format");
	if (!serialize_key(&blob, &blob_len, self->key, self->nid, 1))
		goto ktr_cleanup;

	ret = PyString_FromStringAndSize(blob, blob_len);
ktr_cleanup:
	if (blob)
	{
		/* Cleanup memory for security reasons */
		explicit_bzero(blob, blob_len);
		free(blob);
	}

	return ret;
}

static const char to_raw_doc[] = "k.to_raw(): get the key network-encoded.\nEncodes key for network transmission, as SSH does.\n:return: raw sequence of bytes, containing your private or public key";

static PyObject* KeyObject_to_ssh(PyObject *s)
{
	char *blob = NULL;
	char *b64 = NULL;
	size_t blob_len;
	size_t b64_len = 0;
	PyObject *ret = NULL;
	KeyObject *self = (KeyObject *)s;

	if (!serialize_key(&blob, &blob_len, self->key, self->nid, 0))
		goto kts_cleanup;

	if (!encode_base64(blob, blob_len, &b64, &b64_len))
		goto kts_cleanup;

	ret = PyString_FromStringAndSize(b64, b64_len);

kts_cleanup:
	if (blob)
	{
		/* Cleanup memory for security reasons */
		explicit_bzero(blob, blob_len);
		free(blob);
	}

	if (b64)
	{
		explicit_bzero(b64, b64_len);
		free(b64);
	}
	return ret;
}

static const char to_ssh_doc[] = "k.to_ssh(): get the key in SSH authorized_keys compatible format.\nEncodes only public key and neither key type prefix nor comment string are added.\n:return: string SSH-encoded key";

static PyObject* KeyObject_sign(PyObject *s, PyObject *data)
{
	KeyObject *self = (KeyObject *)s;
	Py_ssize_t data_len = PyString_Size(data);
	const BIGNUM *pk = EC_KEY_get0_private_key(self->key);
	ECDSA_SIG *sig = NULL;
	PyObject *ret = NULL;
	size_t ret_len = 0;
	char *ret_str = NULL, *tmp = NULL, *tmp2 = NULL, *tmp3 = NULL;
	size_t tmp_len = 0, tmp2_len = 0;
	const char *nid_name = nid_name_of_nid(self->nid);

	if (!pk)
	{
		PyErr_SetString(PyExc_ValueError, "Key has no private exponent and cannot sign");
		goto sign_cleanup;
	}

	if (data_len <= 0)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid string provided");
		goto sign_cleanup;
	}

	sig = ECDSA_do_sign((unsigned char *)PyString_AsString(data), data_len, self->key);

	if (!sig)
	{
		PyErr_SetString(PyExc_ValueError, "Failed making signature");
		goto sign_cleanup;
	}

	debugs("dumping r");
	debug_bn(r, sig->r);
	if(!str_of_bn(sig->r, &tmp, &tmp_len))
	{
		PyErr_SetString(PyExc_ValueError, "Failed making signature");
		goto sign_cleanup;
	}
	debugs("dumping s");
	debug_bn(s, sig->s);
	if (!str_of_bn(sig->s, &tmp2, &tmp2_len))
	{
		PyErr_SetString(PyExc_ValueError, "Failed making signature");
		goto sign_cleanup;
	}

	ret_len = 4 + strlen(nid_name) + 4 + tmp_len + tmp2_len;
	ret_str = (char *)malloc(ret_len);
	if (!ret_str)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create string for signature");
		goto sign_cleanup;
	}

	debugs("dumping signature");
	tmp3 = ret_str;
	write_str(&tmp3, nid_name, strlen(nid_name));
	debug("wrote nid_name (%lu): `%s`", strlen(nid_name), nid_name);
	write_u32(&tmp3, tmp_len + tmp2_len);
	debug("wrote blob_len (%lu)", tmp_len + tmp2_len);
	memcpy(tmp3, tmp, tmp_len);
	debug("wrote r (%lu): `%s`", tmp_len, tmp);
	tmp3 += tmp_len;
	memcpy(tmp3, tmp2, tmp2_len);
	debug("wrote s (%lu): `%s`", tmp2_len, tmp2);
	debug("finished whole signature (%lu)", ret_len);

	ret = PyBytes_FromStringAndSize(ret_str, ret_len);

sign_cleanup:
	if (sig)
		ECDSA_SIG_free(sig);
	if (tmp)
	{
		explicit_bzero(tmp, tmp_len);
		free(tmp);
	}
	if (tmp2)
	{
		explicit_bzero(tmp2, tmp2_len);
		free(tmp2);
	}
	if (ret_str)
	{
		explicit_bzero(ret_str, ret_len);
		free(ret_str);
	}
	return ret;
}

static const char sign_doc[] = "k.sign(data): sign the piece of data.\nThe key must have private component to sign the data.\nNote that to sign data for SSH or any similar systems you must provide corresponding data digest instead of raw data.\n:param string data: data or digest to sign\n:return: string signature";

static PyObject* KeyObject_verify(PyObject *s, PyObject *args)
{
	PyObject *data = NULL, *sig = NULL, *ret = NULL;
	size_t data_len = 0, sig_len = 0;

	KeyObject *self = (KeyObject *)s;

	char *tmp = NULL;

	char *curve_name = NULL, *blob = NULL;
	size_t curve_name_len = 0, blob_len = 0;

	ECDSA_SIG *signature = NULL;

	if (!PyArg_ParseTuple(args, "SS", &data, &sig))
		return NULL;

	sig_len = (size_t)PyString_Size(sig);
	data_len = (size_t)PyString_Size(data);
	tmp = PyString_AsString(sig);

	if (!sig_len || !data_len)
	{
		debug("Length check failed: %lu and %lu", sig_len, data_len);
		goto verify_fail;
	}

	debugs("reading signature");

	if (!read_str(&tmp, &sig_len, &curve_name, &curve_name_len))
	{
		debugs("can't read curve name from sign");
		goto verify_fail;
	}
	debug("read curve_name (%lu): `%s`", curve_name_len, curve_name);

	if (strcmp(curve_name, nid_name_of_nid(self->nid)) != 0)
	{
		debugs("curve name don't match sign name");
		goto verify_fail;
	}

	if (!read_str(&tmp, &sig_len, &blob, &blob_len))
	{
		debugs("can't read blob from sign");
		goto verify_fail;
	}

	debug("read blob (%lu): `%s`", blob_len, blob);

	if (sig_len)
	{
		debug("trailing characters at the end of signature (%lu)", sig_len);
		goto verify_fail;
	}

	if ((signature = ECDSA_SIG_new()) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot allocate memory for signature");
		goto verify_cleanup;
	}

	tmp = blob;
	sig_len = blob_len;

	debugs("verifying signature!");

	if (!read_bn(&tmp, &sig_len, signature->r))
	{
		debugs("couldn't read r");
		goto verify_fail;
	}
	debug_bn(r, signature->r);
	if (!read_bn(&tmp, &sig_len, signature->s))
	{
		debugs("couldn't read s");
		goto verify_fail;
	}
	debug_bn(s, signature->s);
	if (sig_len)
	{
		debug("trailing characters on the end of the blob (%lu)", sig_len);
		goto verify_fail;
	}

	if (ECDSA_do_verify((unsigned char *)PyString_AsString(data), data_len, signature, self->key) != 1)
	{
		debugs("verify failed(");
		goto verify_fail;
	}

	ret = Py_True;
	Py_INCREF(ret);
	goto verify_cleanup;

verify_fail:
	ret = Py_False;
	Py_INCREF(ret);

verify_cleanup:
	if (curve_name)
	{
		explicit_bzero(curve_name, curve_name_len);
		free(curve_name);
	}

	if (blob)
	{
		explicit_bzero(blob, curve_name_len);
		free(blob);
	}

	if (signature)
		ECDSA_SIG_free(signature);
	return ret;
}

static const char verify_doc[] = "k.verify(data, signature): verify the signature of data.\nNote that to verify data encoded by SSH or any similar systems you must provide data digest instead of raw data.\n:param string data: data or digest to verify\n:param string signature: signature of the data given\n:return: boolean if the signature is valid";

static PyObject* KeyObject_has_private(PyObject *s)
{
	KeyObject *self = (KeyObject *)s;
	const BIGNUM *pk = EC_KEY_get0_private_key(self->key);
	if (pk)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static const char has_private_doc[] = "k.has_private(): check if the key has private component required to sign the data.\n:return: boolean check result";

static PyObject* KeyObject_public_key(PyObject *s);
static const char public_key_doc[] = "k.public_key(): get key without private exponent.\n:return: self if key is public, else corresponding public ecdsa.Key";

static PyObject* KeyObject_from_string(PyObject *c, PyObject *string);
static const char from_string_doc[] = "Key.from_string(str): read the key from str, deducing the encoding type.\nCurrently PEM encoding and SSH-encoding without prefixes/suffixes are supported.\n:raise ValueError: in case of key cannot be parsed\n:return: Key object";
static PyObject* KeyObject_from_pem(PyObject *c, PyObject *string);
static const char from_pem_doc[] = "Key.from_pem(s): read the PEM-encoded key from s.\n:param string s: PEM-encoded key\n:raise ValueError: in case of key cannot be parsed\n:return: Key object";
static PyObject* KeyObject_from_ssh(PyObject *c, PyObject *string);
static const char from_ssh_doc[] = "Key.from_ssh(s): read the SSH-encoded key from s.\n:param string s: SSH-encoded key\n:raise ValueError: in case of key cannot be parsed\n:return: Key object";
static PyObject* KeyObject_from_raw(PyObject *c, PyObject *string);
static const char from_raw_doc[] = "Key.from_raw(s): read the SSH-compatible network-encoded key from s.\n:param string s: raw sequence of bytes with public or private key\n:raise ValueError; in case of key cannot be parsed\n:return Key object";
static PyObject* KeyObject_generate(PyObject *c, PyObject *args);
static const char generate_doc[] = "Key.generate(bits): generate new ECDSA private key using bits length curve.\n:param int bits: bits number, only 256, 384 and 521 are supported\n:raise ValueError: if key cannot be generated for some reasons\n:return: Key object";

static PyMethodDef KeyObject_methods[] =
{
	{"nid_name", (PyCFunction)KeyObject_nid_name, METH_NOARGS, nid_name_doc},
	{"bits", (PyCFunction)KeyObject_bits, METH_NOARGS, bits_doc},
	{"fingerprint", (PyCFunction)KeyObject_fingerprint, METH_NOARGS, fingerprint_doc},
	{"from_string", (PyCFunction)KeyObject_from_string, METH_CLASS|METH_O, from_string_doc},
	{"from_pem", (PyCFunction)KeyObject_from_pem, METH_CLASS|METH_O, from_pem_doc},
	{"from_ssh", (PyCFunction)KeyObject_from_ssh, METH_CLASS|METH_O, from_ssh_doc},
	{"from_raw", (PyCFunction)KeyObject_from_raw, METH_CLASS|METH_O, from_raw_doc},
	{"generate", (PyCFunction)KeyObject_generate, METH_CLASS|METH_VARARGS, generate_doc},
	{"to_pem", (PyCFunction)KeyObject_to_pem, METH_NOARGS, to_pem_doc},
	{"to_ssh", (PyCFunction)KeyObject_to_ssh, METH_NOARGS, to_ssh_doc},
	{"to_raw", (PyCFunction)KeyObject_to_raw, METH_NOARGS, to_raw_doc},
	{"sign", (PyCFunction)KeyObject_sign, METH_O, sign_doc},
	{"verify", (PyCFunction)KeyObject_verify, METH_VARARGS, verify_doc},
	{"has_private", (PyCFunction)KeyObject_has_private, METH_NOARGS, has_private_doc},
	{"public_key", (PyCFunction)KeyObject_public_key, METH_NOARGS, public_key_doc},
	{NULL, NULL, 0, NULL},
};

static void KeyObject_dealloc(KeyObject *self)
{
	if (self->key)
		EC_KEY_free(self->key);
	self->key = NULL;
	PyObject_Del(self);
}

static int KeyObject_init(KeyObject *self, PyObject *args, PyObject **kwargs)
{
	PyErr_SetString(PyExc_TypeError, "You mustn't instantiate Key object yourself");
	return -1; /* One mustn't call */
}

static PyObject* KeyObject_getattr(PyObject *s, char *name)
{
	KeyObject *self = (KeyObject*)s;
	if (strcmp(name, "nid") == 0)
		return PyLong_FromLong((long)self->nid);
	return Py_FindMethod(KeyObject_methods, s, name);
}

static PyTypeObject key_Type =
{
	PyObject_HEAD_INIT(NULL)
	0,                              /* ob_size */
	"ecdsa.Key",			/* tp_name */
	sizeof(KeyObject),		/* tp_basicsize */
	0,				/* tp_itemsize */
	(destructor)KeyObject_dealloc,	/* tp_dealloc */
	0,				/* tp_print */
	KeyObject_getattr,		/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	"ECDSA key",			/* tp_doc */
};

static PyObject* KeyObject_public_key(PyObject *s)
{
	KeyObject *self = (KeyObject *)s;
	KeyObject *copy = NULL;
	if (EC_KEY_get0_private_key(self->key) == NULL)
	{
		Py_INCREF(s);
		return s;
	}

	if ((copy = PyObject_New(KeyObject, &key_Type)) == NULL)
		return NULL;

	copy->nid = self->nid;
	if ((copy->key = EC_KEY_dup(self->key)) == NULL)
	{
		KeyObject_dealloc(copy);
		PyErr_SetString(PyExc_MemoryError, "Can't create key copy");
		return NULL;
	}
	EC_KEY_set_private_key(copy->key, NULL);
	return (PyObject *)copy;
}

/* Class methods */

static PyObject* KeyObject_generate(PyObject *c, PyObject *args)
{
	EC_KEY *private;
	KeyObject *key;
	int bits = 0;
	int nid;

	if (!PyArg_ParseTuple(args, "i", &bits))
		return NULL;
	nid = nid_of_bits(bits);
	if (!nid)
	{
		PyErr_SetString(PyExc_ValueError, "Key size must be one of 256, 384 or 521");
		return NULL;
	}

	key = PyObject_New(KeyObject, &key_Type);
	if (key == NULL)
		return NULL;

	private = EC_KEY_new_by_curve_name(nid);
	if (!private)
	{
		PyErr_SetString(PyExc_ValueError, "Can't create curve");
		return NULL;
	}
	if (EC_KEY_generate_key(private) != 1)
	{
		EC_KEY_free(private);
		PyErr_SetString(PyExc_ValueError, "Can't generate key");
		return NULL;
	}
	EC_KEY_set_asn1_flag(private, OPENSSL_EC_NAMED_CURVE);

	key->nid = nid;
	key->key = private;

	return (PyObject *)key;
}

static PyObject* KeyObject_from_string(PyObject *c, PyObject *string)
{
	PyObject *ret = NULL;

	ret = KeyObject_from_pem(c, string);

	PyErr_Clear();

	if (!ret)
		ret = KeyObject_from_ssh(c, string);

	PyErr_Clear();

	if (!ret)
		PyErr_SetString(PyExc_ValueError, "Key not found in string");
	return ret;
}

static PyObject* KeyObject_from_pem(PyObject *c, PyObject *string)
{
	BIO *bio = NULL;
	EVP_PKEY *pk = NULL;
	KeyObject *ret = NULL;
	int is_public = 1;

	Py_ssize_t string_len = PyString_Size(string);

	if (string_len <= 0)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid string provided");
		goto key_from_pem_cleanup;
	}

	if ((bio = BIO_new_mem_buf((void*)PyString_AsString(string), string_len)) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't create read buffer");
		goto key_from_pem_cleanup;
	}

	/* TODO: support for passphrase */
	/* pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, (char *)passphrase); */
	pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, (char *)"");

	if (pk != NULL)
	{
		debug("loaded private key: %lx", (size_t)pk);
		is_public = 0;
	}
	else
	{
		if (BIO_reset(bio) != 1)
		{
			PyErr_SetString(PyExc_ValueError, "Failed to read key");
			goto key_from_pem_cleanup;

		}
		pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		debug("loaded public key: %lx", (size_t)pk);
	}

	if (pk == NULL)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid key");
		goto key_from_pem_cleanup;
	}
	if (pk->type != EVP_PKEY_EC)
	{
		PyErr_SetString(PyExc_ValueError, "Key type is not ECDSA");
		goto key_from_pem_cleanup;
	}


	ret = (KeyObject *)PyObject_New(KeyObject, &key_Type);
	if (ret == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't create key object");
		goto key_from_pem_cleanup;
	}

	ret->key = EVP_PKEY_get1_EC_KEY(pk);
	ret->nid = nid_of_key(ret->key);
	debug("key object is %lx", (size_t)ret->key);
	debug("nid is %d", ret->nid);
	if (
		ret->nid == 0
		|| !curve_name_of_nid(ret->nid)
		|| !validate_public_key(EC_KEY_get0_group(ret->key), EC_KEY_get0_public_key(ret->key))
		|| !(is_public || validate_private_key(ret->key))
	)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid key");
		KeyObject_dealloc(ret);
		ret = NULL;
		goto key_from_pem_cleanup;
	}
key_from_pem_cleanup:
	if (bio)
		BIO_free(bio);
	if (pk)
		EVP_PKEY_free(pk);
	return (PyObject *)ret;
}

static PyObject* KeyObject_from_ssh(PyObject *c, PyObject *string)
{
	char *buffer = NULL;
	size_t buffer_len = 0;

	KeyObject *ret = NULL;
	EC_KEY *key = NULL;
	int nid = 0;

	Py_ssize_t string_len = PyString_Size(string);

	if (string_len <= 0)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid string provided");
		goto key_from_ssh_cleanup;
	}
	if (!decode_base64(PyString_AsString(string), string_len, &buffer, &buffer_len))
	{
		PyErr_SetString(PyExc_ValueError, "Invalid Base64 data");
		goto key_from_ssh_cleanup;
	}

	nid = unserialize_key(&key, buffer, buffer_len, 0);
	if (!nid)
		goto destroy_key_from_ssh_cleanup;

	if (!key)
	{
		PyErr_SetString(PyExc_ValueError, "WTH? Key is null!");
		goto key_from_ssh_cleanup;
	}
	EC_KEY_set_asn1_flag(key, 1);

	ret = (KeyObject *)PyObject_New(KeyObject, &key_Type);
	if (ret == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't create key object");
		goto destroy_key_from_ssh_cleanup;
	}

	ret->nid = nid;
	ret->key = key;

	goto key_from_ssh_cleanup;

destroy_key_from_ssh_cleanup:
	if (key)
		EC_KEY_free(key);
key_from_ssh_cleanup:
	if(buffer)
	{
		explicit_bzero(buffer, buffer_len);
		free(buffer);
	}

	return (PyObject *)ret;
}

static PyObject* KeyObject_from_raw(PyObject *c, PyObject *string)
{
	KeyObject *ret = NULL;
	EC_KEY *key = NULL;
	int nid = 0;
	Py_ssize_t string_len = PyString_Size(string);

	debug("reading raw key (%ld): `%s`", string_len, PyString_AsString(string));

	if (string_len <= 0)
	{
		PyErr_SetString(PyExc_ValueError, "Invalid string provided");
		goto key_from_raw_cleanup;
	}
	if ((nid = unserialize_key(&key, PyString_AsString(string), string_len, 1)) == 0)
		goto key_from_raw_cleanup;

	ret = (KeyObject *)PyObject_New(KeyObject, &key_Type);
	if (ret == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't create key object");
		goto destroy_key_from_raw_cleanup;
	}

	ret->nid = nid;
	ret->key = key;

	goto key_from_raw_cleanup;

destroy_key_from_raw_cleanup:
	if (key)
		EC_KEY_free(key);
key_from_raw_cleanup:
	return (PyObject *)ret;
}

/* Module init */

static PyMethodDef module_methods[] =
{
	{NULL, NULL, 0, NULL}   /* end-of-list sentinel value */
};

PyMODINIT_FUNC
initecdsa()
{
	PyObject *module;

	key_Type.tp_new = PyType_GenericNew;
	key_Type.tp_methods = KeyObject_methods;
	key_Type.tp_init = (initproc)KeyObject_init;
	if (PyType_Ready(&key_Type) < 0)
		return;

	module = Py_InitModule3("ecdsa", module_methods, "Module providing support for common ECDSA key operations. See `Key` class.");
	if (module == NULL)
		return;

	Py_INCREF(&key_Type);
	PyModule_AddObject(module, "Key", (PyObject *)&key_Type);
}

/* vim:set ts=8 sts=8 sw=8 noet: */
