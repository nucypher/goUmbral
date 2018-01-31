package openssl

/*
#cgo !windows LDFLAGS: -lcrypto
#cgo windows LDFLAGS: /DEV/openssl-1.0.2a/libcrypto.a -lgdi32
#cgo windows CFLAGS: -I /DEV/openssl-1.0.2a/include

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
*/
import "C"
import "unsafe"
