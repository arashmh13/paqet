package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeys(t *testing.T) {
	psk := []byte("super-secret-password-1234567890123456")
	c2s, s2c, err := DeriveKeys(psk, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(c2s) != KeySize || len(s2c) != KeySize {
		t.Fatalf("invalid key lengths: c2s=%d, s2c=%d", len(c2s), len(s2c))
	}

	if bytes.Equal(c2s, s2c) {
		t.Fatal("directional keys must be distinct")
	}

	// Deterministic derivation test
	c2s2, s2c2, _ := DeriveKeys(psk, nil)
	if !bytes.Equal(c2s, c2s2) || !bytes.Equal(s2c, s2c2) {
		t.Fatal("key derivation must be deterministic for identical PSK and salt")
	}

	// Empty PSK must fail
	if _, _, err := DeriveKeys(nil, nil); err == nil {
		t.Fatal("expected error for empty PSK")
	}
}

func TestAEADEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("failed to create AEAD: %v", err)
	}

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	plaintext := []byte("Hello, Paqet-NG authenticated world!")
	aad := []byte("metadata-aad-1234")

	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)

	// Valid decrypt
	decrypted, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}

	// Tampered ciphertext must fail
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := aead.Open(nil, nonce[:], tampered, aad); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}

	// Mismatched AAD must fail
	if _, err := aead.Open(nil, nonce[:], ciphertext, []byte("wrong-aad")); err == nil {
		t.Fatal("expected authentication failure on mismatched AAD")
	}
}
