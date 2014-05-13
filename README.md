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

    ecdsa$ mkdir build && cd build
    ecdsa/build$ cmake ..
    ecdsa/build$ make && make install
  
All the paths are detected automatically by default, but you can specify:

1. Where to find OpenSSL:

    cmake \
        -DOPENSSL_CRYPYO_LIBRARY=/home/openssl/lib/libcrypto.so \
        -DOPENSSL_INCLUDE_DIR=/home/openssl/include \
        -DOPENSSL_SSL_LIBRARY=/home/openssl/lib/libssl.so \
        ..

2. Where to find Python:

    cmake \
        -DPYTHON_EXECUTABLE=/home/python/bin/python \
        -DPYTHON_INCLUDE_DIR=/home/python/include/python2.7 \
        -DPYTHON_LIBRARY=/home/python/lib/libpython2.7.so \
        ..
    
3. Python site-packages directory where to install (taken from python itself by default):

   cmake -DINSTALL_DIR=lib/python2.7/dist-packages -DCMAKE_INSTALL_PREFIX=/usr ..

4. Install the whole package into custom location

    make DESTDIR=../debian/tmp install
  
All the options can be used in any combinations.


Usage
=====

```python
from ecdsa import Key

privateKey = Key.from_string(open('/home/user/.ssh/id_ecdsa').read())
publicKey = Key.from_string(open('/home/user/.ssh/id_ecdsa.pub').read().split(' ')[1])
```
