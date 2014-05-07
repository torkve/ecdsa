#include "Python.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#ifndef PyLong_FromLong
#define PyLong_FromLong PyInt_FromLong
#endif

#define MD5_LEN 16

typedef struct
{
	char *name;
	int nid;
	int bits;
} keytype;

static const keytype keytypes[] =
{
	{"ecdsa-sha2-nistp256", NID_X9_62_prime256v1, 256},
	{"ecdsa-sha2-nistp384", NID_secp384r1, 384},
	{"ecdsa-sha2-nistp521", NID_secp521r1, 521},
	{NULL, 0, 0},
};

/* Helper functions */

static const char *curve_name_of_nid(int nid)
{
	if (nid == NID_X9_62_prime256v1)
		return "nistp256";
	if (nid == NID_secp384r1)
		return "nistp384";
	if (nid == NID_secp521r1)
		return "nistp521";
	return NULL;
}

static const char *nid_name_of_nid(int nid)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->nid == nid)
			return kt->name;
	return NULL;
}

static int nid_of_bits(int bits)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->bits == bits)
			return kt->nid;
	return -1;
}

static const char *nid_name_of_bits(int bits)
{
	const keytype *kt;
	for (kt = keytypes; kt->name != NULL; ++kt)
		if (kt->bits == bits)
			return kt->name;
	return NULL;
}

inline void write_u32(char **str, uint32_t i)
{
	(*str)[0] = (unsigned char)(i >> 24) & 0xff;
	(*str)[1] = (unsigned char)(i >> 16) & 0xff;
	(*str)[2] = (unsigned char)(i >> 8) & 0xff;
	(*str)[3] = (unsigned char)i & 0xff;
	*str += 4;
}

inline void write_str(char **str, const char *v, uint32_t len)
{
	write_u32(str, len);
	memcpy(*str, v, len);
	*str += len;
}

typedef struct
{
	PyObject_HEAD
	int nid;
	EC_KEY *key;
} KeyObject; 

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
		return NULL;
	return (PyObject*)PyString_FromString(name);
}

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
#pragma optimize("-no-dead-code-removal")
	memset((void *)&md5ctx, 0, sizeof(md5ctx));
#pragma optimize("-dead-code-removal")

	if (blob != NULL)
	{
		/* Cleanup memory for security reasons */
#pragma optimize("-no-dead-code-removal")
		memset((void *)blob, 0, blob_len);
#pragma optimize("-dead-code-removal")
		free(blob);
	}
	if (digest != NULL)
	{
		/* Cleanup memory for security reasons */
#pragma optimize("-no-dead-code-removal")
		memset((void *)digest, 0, digest_len);
#pragma optimize("-dead-code-removal")
		free(digest);
	}
	return ret;
}

static PyObject* KeyObject_to_pem(PyObject *s)
{
	return NULL;
}

static PyObject* KeyObject_to_ssh(PyObject *s)
{
	return NULL;
}

static PyObject* KeyObject_sign(PyObject *s, PyObject *data)
{
	return NULL;
}

static PyObject* KeyObject_verify(PyObject *s, PyObject *args)
{
	return NULL;
}

static PyObject* KeyObject_from_string(PyObject *c, PyObject *string);
static PyObject* KeyObject_from_pem(PyObject *c, PyObject *string);
static PyObject* KeyObject_from_ssh(PyObject *c, PyObject *string);
static PyObject* KeyObject_generate(PyObject *c, PyObject *args);

static PyMethodDef KeyObject_methods[] =
{
	{"nid_name", (PyCFunction)KeyObject_nid_name, METH_NOARGS, "Get the curve NID name"},
	{"fingerprint", (PyCFunction)KeyObject_fingerprint, METH_NOARGS, "Get the key MD5 fingerprint"},
	{"from_string", (PyCFunction)KeyObject_from_string, METH_CLASS|METH_O, "Create the key from the string, deducing the encoding type"},
	{"from_pem", (PyCFunction)KeyObject_from_pem, METH_CLASS|METH_O, "Create the key from the PEM encoding (DER + base64)"},
	{"from_ssh", (PyCFunction)KeyObject_from_ssh, METH_CLASS|METH_O, "Create the key from the SSH pubkey format"},
	{"generate", (PyCFunction)KeyObject_generate, METH_CLASS|METH_VARARGS, "Generate new private key"},
	{"to_pem", (PyCFunction)KeyObject_to_pem, METH_NOARGS, "Dump key as PEM string"},
	{"to_ssh", (PyCFunction)KeyObject_to_ssh, METH_NOARGS, "Dump key as SSH pubkey string"},
	{"sign", (PyCFunction)KeyObject_sign, METH_O, "Sign a piece of data"},
	{"verify", (PyCFunction)KeyObject_verify, METH_VARARGS, "Verify a signature of data"},
	{NULL, NULL, 0, NULL},
};

static void KeyObject_dealloc(KeyObject *self)
{
	if (self->key)
		EC_KEY_free(self->key);
	self->key = NULL;
	PyObject_Del(self);
}

/*static int KeyObject_init(KeyObject *self, PyObject *args, PyObject **kwargs)
{
	PyObject *flag = NULL;
	static char *kwlist[] = {"internal_flag__", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "", kwlist, &first))
		return -1; // One mustn't call 
}*/

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
	if (!PyArg_ParseTuple(args, "i", &bits))
	{
		return NULL;
	}
	int nid = nid_of_bits(bits);
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
	return NULL;
}

static PyObject* KeyObject_from_pem(PyObject *c, PyObject *string)
{
	return NULL;
}

static PyObject* KeyObject_from_ssh(PyObject *c, PyObject *string)
{
	return NULL;
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
	if (PyType_Ready(&key_Type) < 0)
		return;

	module = Py_InitModule3("ecdsa", module_methods, "Module providing support for common ECDSA key operations. See `Key` class.");
	if (module == NULL)
		return;

	Py_INCREF(&key_Type);
	PyModule_AddObject(module, "Key", (PyObject *)&key_Type);
}

/* vim:set ts=8 sts=8 sw=8 noet: */
