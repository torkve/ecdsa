ecdsa
=====

ECDSA keys implementation for Python.

This extension uses OpenSSL for elliptic cryptography and is written in pure C.
Its main purpose is to provide an interface suitable to the key operations used
in OpenSSH. It means key save/load and data sign/verify.


Compilation
===========

The only requirements are CMake as build system, OpenSSL and Python.

To build the extension just use:

```sh
ecdsa$ mkdir build && cd build
ecdsa/build$ cmake ..
ecdsa/build$ make && make install
```

All the paths are detected automatically by default, but you can specify:

1. Where to find OpenSSL:

    ```sh
    cmake \ 
        -DOPENSSL_CRYPYO_LIBRARY=/home/openssl/lib/libcrypto.so \
        -DOPENSSL_INCLUDE_DIR=/home/openssl/include \
        -DOPENSSL_SSL_LIBRARY=/home/openssl/lib/libssl.so  
        ..
    ```

2. Where to find Python:

    ```sh
    cmake \
        -DPYTHON_EXECUTABLE=/home/python/bin/python \
        -DPYTHON_INCLUDE_DIR=/home/python/include/python2.7 \
        -DPYTHON_LIBRARY=/home/python/lib/libpython2.7.so \
        ..
    ```
    
3. Python site-packages directory where to install (taken from python itself by default):

    ```sh
   cmake -DINSTALL_DIR=lib/python2.7/dist-packages -DCMAKE_INSTALL_PREFIX=/usr ..
   ```

4. Install the whole package into custom location

    ```sh
    make DESTDIR=../debian/tmp install
    ```
  
All the options can be used in any combinations.


Usage
=====

```python
from ecdsa import Key

# Read the key
privateKeyString = open('/home/user/.ssh/id_ecdsa').read()
publicKeyString = open('/home/user/.ssh/id_ecdsa.pub').read().split(' ')[1]  # strip prefix and comment

privateKey = Key.from_string(privateKeyString)
publicKey = Key.from_string(publicKeyString)

# Now sign something
data = 'some my data'
signature = privateKey.sign(data)

# And verify the signature
assert publicKey.verify(data, signature), "public key not belongs to the private one"
assert privateKey.verify(data, signature), "you should be able to verify by private key, as well"

# Check if the key can sign
assert privateKey.has_private()
assert not publicKey.has_private()


# generate new key
key = Key.generate(521)

# Display its fingerprint in SSH-compatible format
fp = ':'.join(x.encode('hex') for x in key.fingerprint())
print "Generated key ({kt}): {fp}".format(kt=key.nid_name(), fp=fp)

# write it for ssh
open('/home/user/.ssh/id_ecdsa', 'wb').write(key.to_pem())
open('/home/user/.ssh/id_ecdsa.pub', 'wb').write(
    "{keyType} {key} {comment}".format(keyType=key.nid_name(), key=key.to_ssh(), comment="uzba@go.is")
)

```
