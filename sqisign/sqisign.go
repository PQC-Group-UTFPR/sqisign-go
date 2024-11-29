package sqisign

/*
#cgo CFLAGS: -I../external/the-sqisign/src -I../external/the-sqisign/src/protocols/ref/include
#cgo LDFLAGS: -L../external/the-sqisign/src/protocols/ref/lvl1 -lsqisign_protocols_lvl1 -static

#include "sqisign.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"errors"
	"unsafe"
)

const (
    PublicKeyBytes = 64   // CRYPTO_PUBLICKEYBYTES
    SecretKeyBytes = 64   // CRYPTO_SECRETKEYBYTES
    SignatureBytes = 177  // CRYPTO_BYTES
)

// Keypair generates a public/private keypair.
func Keypair() ([]byte, []byte, error) {
    pk := make([]byte, PublicKeyBytes)
    sk := make([]byte, SecretKeyBytes)

    ret := C.sqisign_keypair((*C.uchar)(unsafe.Pointer(&pk[0])), (*C.uchar)(unsafe.Pointer(&sk[0])))
    if ret != 0 {
        return nil, nil, errors.New("failed to generate keypair")
    }

    return pk, sk, nil
}

// Sign signs the hashed message `m` with the secret key `sk` and returns the signed message.
func Sign(m []byte, sk []byte) ([]byte, error) {
    sm := make([]byte, len(m)+SignatureBytes) // Buffer for signature + message
    smlen := C.ulonglong(0)

    ret := C.sqisign_sign(
        (*C.uchar)(unsafe.Pointer(&sm[0])),
        (*C.ulonglong)(unsafe.Pointer(&smlen)),
        (*C.uchar)(unsafe.Pointer(&m[0])),
        C.ulonglong(len(m)),
        (*C.uchar)(unsafe.Pointer(&sk[0])),
    )
    if ret != 0 {
        return nil, errors.New("failed to sign message")
    }

    return sm[:smlen], nil
}

// Open verifies the signed message `sm` with the public key `pk` and returns the original message.
func Open(sm []byte, pk []byte) ([]byte, error) {
    m := make([]byte, len(sm)-SignatureBytes) // Buffer for original message
    mlen := C.ulonglong(0)

    ret := C.sqisign_open(
        (*C.uchar)(unsafe.Pointer(&m[0])),
        (*C.ulonglong)(unsafe.Pointer(&mlen)),
        (*C.uchar)(unsafe.Pointer(&sm[0])),
        C.ulonglong(len(sm)),
        (*C.uchar)(unsafe.Pointer(&pk[0])),
    )
    if ret != 0 {
        return nil, errors.New("failed to open signed message")
    }

    return m[:mlen], nil
}

// Verify verifies the signature `sig` of the message `m` with the public key `pk`.
func Verify(m []byte, sig []byte, pk []byte) (bool, error) {
    ret := C.sqisign_verify(
        (*C.uchar)(unsafe.Pointer(&m[0])),
        C.ulonglong(len(m)),
        (*C.uchar)(unsafe.Pointer(&sig[0])),
        C.ulonglong(len(sig)),
        (*C.uchar)(unsafe.Pointer(&pk[0])),
    )
    if ret != 0 {
        return false, errors.New("failed to verify signature")
    }

    return true, nil
}

func main() {
    fmt.Println("Hello, World!")

    fmt.Println("testing sqisign access!")
}
