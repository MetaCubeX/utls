package mldsa65

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFIPS204CompatibilityVector(t *testing.T) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	publicKey, privateKey := NewKeyFromSeed(&seed)
	signature := make([]byte, SignatureSize)
	message := []byte("mihomo REALITY ML-DSA-65")
	if err := SignTo(privateKey, message, nil, false, signature); err != nil {
		t.Fatal(err)
	}
	assertDigest(t, "public key", publicKey.Bytes(), "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9")
	assertDigest(t, "private key", privateKey.Bytes(), "9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063")
	assertDigest(t, "signature", signature, "2333cb81f2688503d4787837ae164cada683344a7a1d5c9a4659675fe879aaa9")
	if !Verify(publicKey, message, nil, signature) {
		t.Fatal("Verify() = false")
	}
	signature[0] ^= 1
	if Verify(publicKey, message, nil, signature) {
		t.Fatal("Verify() accepted a modified signature")
	}
}

func assertDigest(t *testing.T, name string, value []byte, want string) {
	t.Helper()
	digest := sha256.Sum256(value)
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("%s digest = %s, want %s", name, got, want)
	}
}
