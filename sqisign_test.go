package sqisign

import (
	"bytes"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	if pub == nil || priv == nil {
		t.Fatalf("GenerateKey() returned a nil key")
	}

	if len(pub.Bytes()) != CRYPTO_PUBLICKEYBYTES {
		t.Errorf("public key has incorrect length: got %d, expected %d", len(pub.Bytes()), CRYPTO_PUBLICKEYBYTES)
	}
	if len(priv.Bytes()) != CRYPTO_SECRETKEYBYTES {
		t.Errorf("private key has incorrect length: got %d, expected %d", len(priv.Bytes()), CRYPTO_SECRETKEYBYTES)
	}
}

func TestValidSignature(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	message := []byte("this is a test message")

	signature, err := priv.Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatalf("Sign() returned an empty signature")
	}

	err = pub.Verify(message, signature)
	if err != nil {
		t.Fatalf("Verify() failed for a valid signature: %v", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	message := []byte("this is a test message")

	signature, err := priv.Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) > 0 {
		signature[0] ^= 0xff // tamper the signature, flip the first byte
	} else {
		t.Fatalf("Sign() returned an empty signature")
	}

	err = pub.Verify(message, signature)
	if err == nil {
		t.Fatalf("Verify() succeeded for an invalid signature, but it should have failed")
	}
}

func TestKeySerialization(t *testing.T) {
	pubOrig, privOrig, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	pubBytes := pubOrig.Bytes()
	privBytes := privOrig.Bytes()

	pubNew, err := PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes() failed: %v", err)
	}

	privNew, err := PrivateKeyFromBytes(privBytes)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes() failed: %v", err)
	}

	if !bytes.Equal(pubOrig.Bytes(), pubNew.Bytes()) {
		t.Fatalf("deserialized public key does not match the original")
	}

	if !bytes.Equal(privOrig.Bytes(), privNew.Bytes()) {
		t.Fatalf("deserialized private key does not match the original")
	}
}
