#include "misc.h"
#include <Python.h>
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

int validate_public_key(const EC_GROUP *curve, const EC_POINT *point)
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

int validate_private_key(const EC_KEY *key)
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

int public_key_to_ssh(char **buffer, size_t *len, EC_KEY *key, int nid)
{
	const EC_GROUP *curve;
	const EC_POINT *point;
	BN_CTX *bnctx;
	char *buffer_in;
	size_t point_len;
	uint32_t nid_name_len, curve_name_len;
	int res = 0;

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

	point_len = EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bnctx);
	*len = 4 + nid_name_len + 4 + curve_name_len + 4 + point_len;

	*buffer = (char *)malloc(*len + 1);
	if (!*buffer)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory for fingerprint");
		goto pks_cleanup;
	}

	buffer_in = *buffer;
	write_str(&buffer_in, nid_name, nid_name_len);
	write_str(&buffer_in, curve_name, curve_name_len);
	write_u32(&buffer_in, point_len);
	EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char *)buffer_in, point_len, bnctx);
	buffer_in[point_len] = 0;

	res = 1;
pks_cleanup:
	if (bnctx)
		BN_CTX_free(bnctx);
	return res;
}

/* Object methods */

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
	char *blob = NULL, *digest;
	size_t blob_len;
	size_t digest_len = MD5_LEN; /* MD5 length */
	uint32_t dlen;
	PyObject *ret = NULL;

	if (!public_key_to_ssh(&blob, &blob_len, self->key, self->nid))
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

	if (!pk)
	{
		PyErr_SetString(PyExc_ValueError, "Key has no private exponent and cannot be serialized");
		goto ktp_cleanup;
	}

	if ((bio = BIO_new(BIO_s_mem())) == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Cannot create buffer");
		goto ktp_cleanup;
	}

	/* TODO: support passphrase */
	if (!PEM_write_bio_ECPrivateKey(bio, self->key, NULL, NULL, 0, NULL, NULL))
	{
		PyErr_SetString(PyExc_ValueError, "Cannot write key");
		goto ktp_cleanup;
	}

	if ((blob_len = BIO_get_mem_data(bio, &blob)) <= 0)
		goto ktp_cleanup;

	ret = PyString_FromStringAndSize(blob, blob_len);

ktp_cleanup:
	if (bio)
		BIO_free(bio);

	return ret;
}

static const char to_pem_doc[] = "k.to_pem(): get the key PEM-encoded.\nEncodes private key into PEM container. Neither passwords nor public key encoding is currently suppoered.\n:return: string PEM-encoded key";

static PyObject* KeyObject_to_ssh(PyObject *s)
{
	char *blob = NULL;
	char *b64 = NULL;
	size_t blob_len;
	size_t b64_len;
	PyObject *ret = NULL;
	KeyObject *self = (KeyObject *)s;

	if (!public_key_to_ssh(&blob, &blob_len, self->key, self->nid))
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

static PyObject* KeyObject_from_string(PyObject *c, PyObject *string);
static const char from_string_doc[] = "Key.from_string(str): read the key from str, deducing the encoding type.\nCurrently PEM encoding and SSH-encoding without prefixes/suffixes are supported.\n:raise ValueError: in case of key cannot be parsed\n:return: Key object";
static PyObject* KeyObject_from_pem(PyObject *c, PyObject *string);
static const char from_pem_doc[] = "Key.from_pem(s): read the PEM-encoded key from s.\n:param string s: PEM-encoded key\n:raise ValueError: in case of key cannot be parsed\n:return: Key object";
static PyObject* KeyObject_from_ssh(PyObject *c, PyObject *string);
static const char from_ssh_doc[] = "Key.from_ssh(s): read the SSH-encoded key from s.\n:param string s: SSH-encoded key\n:raise ValueError: in case of key cannot be parsed\n:return: Key object";
static PyObject* KeyObject_generate(PyObject *c, PyObject *args);
static const char generate_doc[] = "Key.generate(bits): generate new ECDSA private key using bits length curve.\n:param int bits: bits number, only 256, 384 and 521 are supported\n:raise ValueError: if key cannot be generated for some reasons\n:return: Key object";

static PyMethodDef KeyObject_methods[] =
{
	{"nid_name", (PyCFunction)KeyObject_nid_name, METH_NOARGS, nid_name_doc},
	{"fingerprint", (PyCFunction)KeyObject_fingerprint, METH_NOARGS, fingerprint_doc},
	{"from_string", (PyCFunction)KeyObject_from_string, METH_CLASS|METH_O, from_string_doc},
	{"from_pem", (PyCFunction)KeyObject_from_pem, METH_CLASS|METH_O, from_pem_doc},
	{"from_ssh", (PyCFunction)KeyObject_from_ssh, METH_CLASS|METH_O, from_ssh_doc},
	{"generate", (PyCFunction)KeyObject_generate, METH_CLASS|METH_VARARGS, generate_doc},
	{"to_pem", (PyCFunction)KeyObject_to_pem, METH_NOARGS, to_pem_doc},
	{"to_ssh", (PyCFunction)KeyObject_to_ssh, METH_NOARGS, to_ssh_doc},
	{"sign", (PyCFunction)KeyObject_sign, METH_O, sign_doc},
	{"verify", (PyCFunction)KeyObject_verify, METH_VARARGS, verify_doc},
	{"has_private", (PyCFunction)KeyObject_has_private, METH_NOARGS, has_private_doc},
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
	if (nid == -1)
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
	pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, (char*)"");

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
	if (
		(ret->nid = nid_of_key(ret->key)) == 0
		|| !curve_name_of_nid(ret->nid)
		|| !validate_public_key(EC_KEY_get0_group(ret->key), EC_KEY_get0_public_key(ret->key))
		|| !validate_private_key(ret->key)
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
	EC_POINT *point;

	char *buffer = NULL, *buffer_in;
	size_t buffer_len = 0, buffer_in_len = 0;

	char *key_name = NULL;
	size_t key_name_len = 0;

	char *curve_name = NULL;
	size_t curve_name_len = 0;

	KeyObject *ret = NULL;
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

	buffer_in = buffer;
	buffer_in_len = buffer_len;

	if (!read_str(&buffer_in, &buffer_in_len, &key_name, &key_name_len))
	{
		PyErr_SetString(PyExc_ValueError, "Can't read key type from key");
		goto key_from_ssh_cleanup;
	}
	if ((nid = nid_of_nid_name(key_name)) == 0)
	{
		PyErr_SetString(PyExc_ValueError, "Unsupported key format");
		goto key_from_ssh_cleanup;
	}

	if (!read_str(&buffer_in, &buffer_in_len, &curve_name, &curve_name_len))
	{
		PyErr_SetString(PyExc_ValueError, "Can't read curve type from key");
		goto key_from_ssh_cleanup;
	}
	if (nid != nid_of_curve_name(curve_name))
	{
		PyErr_SetString(PyExc_ValueError, "Key and curve types don't match");
		goto key_from_ssh_cleanup;
	}

	ret = (KeyObject *)PyObject_New(KeyObject, &key_Type);
	if (ret == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "Can't create key object");
		goto key_from_ssh_cleanup;
	}

	ret->nid = nid;
	ret->key = EC_KEY_new_by_curve_name(nid);

	if ((point = EC_POINT_new(EC_KEY_get0_group(ret->key))) == NULL)
	{
		PyErr_SetString(PyExc_ValueError, "Can't create key point");
		goto destroy_key_from_ssh_cleanup;
	}

	if (!read_point(&buffer_in, &buffer_in_len, EC_KEY_get0_group(ret->key), point))
	{
		PyErr_SetString(PyExc_ValueError, "Can't read key point");
		goto destroy_key_from_ssh_cleanup;
	}

	if (EC_KEY_set_public_key(ret->key, point) != 1)
	{
		PyErr_SetString(PyExc_ValueError, "Can't apply public key");
		goto destroy_key_from_ssh_cleanup;
	}

	if (!validate_public_key(EC_KEY_get0_group(ret->key), point))
		goto destroy_key_from_ssh_cleanup;
	
	goto key_from_ssh_cleanup;

destroy_key_from_ssh_cleanup:
	if(ret)
	{
		KeyObject_dealloc(ret);
		ret = NULL;
	}
key_from_ssh_cleanup:
	if(key_name)
		free(key_name);
	if(curve_name)
		free(curve_name);
	if(buffer)
	{
		explicit_bzero(buffer, buffer_len);
		free(buffer);
	}

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
