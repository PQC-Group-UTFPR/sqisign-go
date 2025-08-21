# SQISign-Go

This is a repository for Go bindinds of the [SQISign](https://github.com/SQISign/the-sqisign) algorithm made in C using CGo, forked from [Zinho02](https://github.com/zinho02/sqisign-go).

## Getting Started

First, clone the `sqisign-go` repository:

```bash
$ git clone git@github.com:PQC-Group-UTFPR/sqisign-go.git
```

## Usage

```go
package main

import (
	"fmt"
	"github.com/PQC-Group-UTFPR/sqisign-go"
)

func main() {
	message := []byte("message to be signed")

	// Generate a new key pair
	pub, priv, err := sqisign.GenerateKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Public key: %x\n", pub.Bytes())
	fmt.Printf("Private key: %x\n", priv.Bytes())

	signature, err := priv.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Message: ", string(message))
	fmt.Printf("Signature: %x\n", signature)

	err = pub.Verify(message, signature)
	if err != nil {
		fmt.Println("Invalid signature")
	} else {
		fmt.Println("Valid signature")
	}
}
```

## API

The `sqisign-go` binding provides functions for key management and cryptographic operations. The key types, `PublicKey` and `PrivateKey`, implement the `crypto.PublicKey` and `crypto.Signer` interfaces from the Go standard library.

- func GenerateKey() (\*PublicKey, \*PrivateKey, error)
- func PublicKeyFromBytes(data []byte) (\*PublicKey, error)
- func PrivateKeyFromBytes(data []byte) (\*PrivateKey, error)
- func (pub \*PublicKey) Bytes() []byte
- func (priv \*PrivateKey) Bytes() []byte
- func (priv \*PrivateKey) Public() crypto.PublicKey
- func (priv \*PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, error)
- func (pub \*PublicKey) Verify(digest, signature []byte) error

## Running the tests

```bash
$ go test -v .
```

The tests cover key generation, signing, verification with valid and invalid signatures, and key serialization/deserialization.
