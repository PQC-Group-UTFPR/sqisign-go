package sqisign

import (
	"crypto"
	"fmt"
	"io"
	"strings"
	"unsafe"
)

/*
#cgo LDFLAGS: -L /usr/local/lib/sqisign

#cgo lvl1 CFLAGS: -DSECURITY_LEVEL=1
#cgo lvl1 LDFLAGS: -l:libsqisign_lvl1_nistapi.a
#cgo lvl1 LDFLAGS: -l:libsqisign_lvl1.a
#cgo lvl1 LDFLAGS: -l:libsqisign_protocols_lvl1.a
#cgo lvl1 LDFLAGS: -l:libsqisign_gf_lvl1.a
#cgo lvl1 LDFLAGS: -l:libsqisign_id2iso_lvl1.a
#cgo lvl1 LDFLAGS: -l:libsqisign_ec_lvl1.a
#cgo lvl1 LDFLAGS: -l:libsqisign_klpt_lvl1.a
#cgo lvl1 LDFLAGS: -l:libsqisign_precomp_lvl1.a

#cgo lvl3 CFLAGS: -DSECURITY_LEVEL=3
#cgo lvl3 LDFLAGS: -l:libsqisign_lvl3_nistapi.a
#cgo lvl3 LDFLAGS: -l:libsqisign_lvl3.a
#cgo lvl3 LDFLAGS: -l:libsqisign_protocols_lvl3.a
#cgo lvl3 LDFLAGS: -l:libsqisign_gf_lvl3.a
#cgo lvl3 LDFLAGS: -l:libsqisign_id2iso_lvl3.a
#cgo lvl3 LDFLAGS: -l:libsqisign_ec_lvl3.a
#cgo lvl3 LDFLAGS: -l:libsqisign_klpt_lvl3.a
#cgo lvl3 LDFLAGS: -l:libsqisign_precomp_lvl3.a

#cgo lvl5 CFLAGS: -DSECURITY_LEVEL=5
#cgo lvl5 LDFLAGS: -l:libsqisign_lvl5_nistapi.a
#cgo lvl5 LDFLAGS: -l:libsqisign_lvl5.a
#cgo lvl5 LDFLAGS: -l:libsqisign_protocols_lvl5.a
#cgo lvl5 LDFLAGS: -l:libsqisign_gf_lvl5.a
#cgo lvl5 LDFLAGS: -l:libsqisign_id2iso_lvl5.a
#cgo lvl5 LDFLAGS: -l:libsqisign_ec_lvl5.a
#cgo lvl5 LDFLAGS: -l:libsqisign_klpt_lvl5.a
#cgo lvl5 LDFLAGS: -l:libsqisign_precomp_lvl5.a

#cgo LDFLAGS: -l:libsqisign_quaternion_generic.a
#cgo LDFLAGS: -l:libsqisign_common_sys.a
#cgo LDFLAGS: -l:libsqisign_intbig_generic.a
#cgo LDFLAGS: -lgmp

#include <stdio.h>
#include <stdlib.h>

#if SECURITY_LEVEL == 1
#include "sqisign/lvl1/api.h"

#elif SECURITY_LEVEL == 3
#include "sqisign/lvl3/api.h"

#elif SECURITY_LEVEL == 5
#include "sqisign/lvl5/api.h"

#endif

// C function to print hex values
static void print_hex(const unsigned char *hex, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x", hex[i]);
    }
    printf("\n");
}
*/
import "C"

var CRYPTO_SECRETKEYBYTES int = C.CRYPTO_SECRETKEYBYTES
var CRYPTO_PUBLICKEYBYTES int = C.CRYPTO_PUBLICKEYBYTES
var CRYPTO_BYTES int = C.CRYPTO_BYTES
var CRYPTO_ALGNAME string = C.CRYPTO_ALGNAME

var C_CRYPTO_SECRETKEYBYTES C.int = C.CRYPTO_SECRETKEYBYTES
var C_CRYPTO_PUBLICKEYBYTES C.int = C.CRYPTO_PUBLICKEYBYTES
var C_CRYPTO_BYTES C.int = C.CRYPTO_BYTES

func CryptoSignKeyPair(pk *C.uchar, sk *C.uchar) int {
	return int(C.crypto_sign_keypair(pk, sk))
}

func CryptoSign(sm *C.uchar, smlen *C.ulonglong, m *C.uchar,
	mlen C.ulonglong, sk *C.uchar) int {
	return int(C.crypto_sign(sm, smlen, m, mlen, sk))
}

func CryptoSignOpen(m *C.uchar, mlen *C.ulonglong, sm *C.uchar,
	smlen C.ulonglong, pk *C.uchar) int {
	return int(C.crypto_sign_open(m, mlen, sm, smlen, pk))
}

type PublicKey struct {
	CPublicKey *C.uchar
}

type PrivateKey struct {
	CSecretKey *C.uchar
}

var public_key *PublicKey
var private_key *PrivateKey

func GenerateKey() (pk *PublicKey, sk *PrivateKey, err error) {
	pk_c := (*C.uchar)(unsafe.Pointer(C.CString(strings.Repeat("0", CRYPTO_PUBLICKEYBYTES))))
	sk_c := (*C.uchar)(unsafe.Pointer(C.CString(strings.Repeat("0", CRYPTO_SECRETKEYBYTES))))
	ok := CryptoSignKeyPair(pk_c, sk_c)
	public_key = &PublicKey{CPublicKey: pk_c}
	private_key = &PrivateKey{CSecretKey: sk_c}
	if err = nil; ok != 0 {
		err = fmt.Errorf("error during key generation process")
	}
	return public_key, private_key, err
}

func (priv *PrivateKey) Public() PublicKey {
	return *public_key
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	m := C.CString(string(digest[:]))
	defer C.free(unsafe.Pointer(m))
	mlen := len(digest)
	sm := C.CString(strings.Repeat("0", CRYPTO_BYTES+mlen))
	defer C.free(unsafe.Pointer(sm))
	smlen := CRYPTO_BYTES + mlen
	ok := CryptoSign((*C.uchar)(unsafe.Pointer(sm)), (*C.ulonglong)(unsafe.Pointer(&smlen)),
		(*C.uchar)(unsafe.Pointer(m)), (C.ulonglong)(mlen), priv.CSecretKey)
	signature = C.GoBytes((unsafe.Pointer(sm)), (C.int)(CRYPTO_BYTES+mlen))
	if err = nil; ok != 0 {
		err = fmt.Errorf("error during signing process")
	}
	return
}

func (pub *PublicKey) Verify(mlen int, signature []byte) (msg []byte, err error) {
	m := C.CString(strings.Repeat("0", mlen))
	defer C.free(unsafe.Pointer(m))
	smlen := len(signature)
	sm := C.CString(string(signature))
	defer C.free(unsafe.Pointer(sm))
	ok := CryptoSignOpen((*C.uchar)(unsafe.Pointer(m)), (*C.ulonglong)(unsafe.Pointer(&mlen)),
		(*C.uchar)(unsafe.Pointer(sm)), (C.ulonglong)(smlen), pub.CPublicKey)
	msg = []byte(C.GoString(m))
	if err = nil; ok != 0 {
		err = fmt.Errorf("error during verification process")
	}
	return
}

func PrintHex(hex *C.uchar, len C.int) {
	C.print_hex(hex, len)
}
