package sqisign

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

/*
#cgo LDFLAGS: -L /usr/local/lib/sqisign
#cgo LDFLAGS: -L ${SRCDIR}/build

#cgo CFLAGS: -DSECURITY_LEVEL=1
#cgo LDFLAGS: -l:libsqisign_lvl1_nistapi.a
#cgo LDFLAGS: -l:libsqisign_lvl1.a
#cgo LDFLAGS: -l:libsqisign_protocols_lvl1.a
#cgo LDFLAGS: -l:libsqisign_gf_lvl1.a
#cgo LDFLAGS: -l:libsqisign_id2iso_lvl1.a
#cgo LDFLAGS: -l:libsqisign_ec_lvl1.a
#cgo LDFLAGS: -l:libsqisign_klpt_lvl1.a
#cgo LDFLAGS: -l:libsqisign_precomp_lvl1.a

#cgo LDFLAGS: -l:libsqisign_quaternion_generic.a
#cgo LDFLAGS: -l:libsqisign_common_sys.a
#cgo LDFLAGS: -l:libsqisign_intbig_generic.a
#cgo LDFLAGS: -lgmp

#include <stdio.h>
#include <stdlib.h>

#include "sqisign-api.h"

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
	cPublicKey *C.uchar
}

type PrivateKey struct {
	cSecretKey *C.uchar
	publicKey *PublicKey
}

func PublicKeyFromBytes(data []byte) (*PublicKey, error) {
	if len(data) != CRYPTO_PUBLICKEYBYTES {
		return nil, fmt.Errorf("sqisign: invalid public key size")
	}

	cPubKeyPtr := C.CBytes(data)
	if cPubKeyPtr == nil {
		return nil, fmt.Errorf("sqisign: failed to allocate memory")
	}

	publicKey := &PublicKey{cPublicKey: (*C.uchar)(cPubKeyPtr)}

	runtime.SetFinalizer(publicKey, func(p *PublicKey) {
		C.free(unsafe.Pointer(p.cPublicKey))
	})

	return publicKey, nil
}

func PrivateKeyFromBytes(data []byte) (*PrivateKey, error) {
	if len(data) != CRYPTO_SECRETKEYBYTES {
		return nil, fmt.Errorf("sqisign: invalid private key size")
	}

	cSecKeyPtr := C.CBytes(data)
	if cSecKeyPtr == nil {
		return nil, fmt.Errorf("sqisign: failed to allocate memory")
	}

	priv := &PrivateKey{cSecretKey: (*C.uchar)(cSecKeyPtr), publicKey: nil}

	runtime.SetFinalizer(priv, func(p *PrivateKey) {
		C.free(unsafe.Pointer(p.cSecretKey))
	})

	return priv, nil
}

func (pub *PublicKey) Bytes() []byte {
	if pub.cPublicKey == nil {
		return nil
	}

	return C.GoBytes(unsafe.Pointer(pub.cPublicKey), C.int(CRYPTO_PUBLICKEYBYTES))
}

func (priv *PrivateKey) Bytes() []byte {
	if priv.cSecretKey == nil {
		return nil
	}

	return C.GoBytes(unsafe.Pointer(priv.cSecretKey), C.int(CRYPTO_SECRETKEYBYTES))
}

func GenerateKey() (pk *PublicKey, sk *PrivateKey, err error) {
	pkc := (*C.uchar)(C.malloc(C.size_t(CRYPTO_PUBLICKEYBYTES)))
	skc := (*C.uchar)(C.malloc(C.size_t(CRYPTO_SECRETKEYBYTES)))

	if pkc == nil || skc == nil {
		C.free(unsafe.Pointer(pkc))
		return nil, nil, fmt.Errorf("sqisign: failed to allocate memory")
	}

	if CryptoSignKeyPair(pkc, skc) != 0 {
		C.free(unsafe.Pointer(pkc))
		C.free(unsafe.Pointer(skc))
		return nil, nil, fmt.Errorf("sqisign: CryptoSignKeyPair failed")
	}

	pub := &PublicKey{cPublicKey: pkc}
	priv := &PrivateKey{cSecretKey: skc, publicKey: pub}

	runtime.SetFinalizer(pub, func(p *PublicKey) {
		C.free(unsafe.Pointer(p.cPublicKey))
	})
	runtime.SetFinalizer(priv, func(p *PrivateKey) {
		C.free(unsafe.Pointer(p.cSecretKey))
	})

	return pub, priv, err
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.publicKey
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	mlen := len(digest)
	smlen_c := C.ulonglong(mlen + CRYPTO_BYTES)

	m_c := C.CBytes(digest)
	defer C.free(m_c)

	sm_c := C.malloc(C.size_t(smlen_c))
	if sm_c == nil {
		return nil, fmt.Errorf("sqisign: failed to allocate memory")
	}
	defer C.free(sm_c)

	if CryptoSign((*C.uchar)(sm_c), &smlen_c, (*C.uchar)(m_c), C.ulonglong(mlen), priv.cSecretKey) != 0 {
		return nil, fmt.Errorf("sqisign: error during signing process")
	}

	return C.GoBytes(sm_c, C.int(smlen_c)), nil
}

func (pub *PublicKey) Verify(digest, signature []byte) error {
	smlen := len(signature)
	if smlen < CRYPTO_BYTES {
		return fmt.Errorf("sqisign: invalid signature size")
	}

	ex_mlen := smlen - CRYPTO_BYTES
	m := C.malloc(C.size_t(ex_mlen))
	if m == nil {
		return fmt.Errorf("sqisign: failed to allocate memory")
	}
	defer C.free(m)

	sm := C.CBytes(signature)
	defer C.free(sm)

	var mlen C.ulonglong
	if CryptoSignOpen((*C.uchar)(m), &mlen, (*C.uchar)(sm), C.ulonglong(smlen), pub.cPublicKey) != 0 {
		return fmt.Errorf("sqisign: signature verification failed")
	}

	mGo := C.GoBytes(m, C.int(mlen))
	if !bytes.Equal(mGo, digest) {
		return fmt.Errorf("sqisign: message does not match digest")
	}

	return nil
}

func PrintHex(data []byte) {
	cData := C.CBytes(data)
	defer C.free(cData)
	C.print_hex((*C.uchar)(cData), C.int(len(data)))
}
