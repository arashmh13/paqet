package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

var (
	ErrInvalidKey = errors.New("crypto: invalid key length")
	ErrDecrypt    = errors.New("crypto: decryption failed or authentication tag mismatch")
)

// DeriveKeys derives directional 32-byte subkeys from a pre-shared master secret (PSK).
// It returns (clientToServerKey, serverToClientKey, error).
func DeriveKeys(psk []byte, salt []byte) ([]byte, []byte, error) {
	if len(psk) == 0 {
		return nil, nil, ErrInvalidKey
	}
	if len(salt) == 0 {
		salt = []byte("paqet-ng-v2-hkdf-salt")
	}

	extractor := hkdf.New(sha256.New, psk, salt, []byte("paqet-ng-directional-v2"))

	c2s := make([]byte, KeySize)
	s2c := make([]byte, KeySize)

	if _, err := io.ReadFull(extractor, c2s); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive c2s key: %w", err)
	}
	if _, err := io.ReadFull(extractor, s2c); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive s2c key: %w", err)
	}

	return c2s, s2c, nil
}

// NewAEAD returns an AES-256-GCM cipher from a 32-byte key.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes init error: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm init error: %w", err)
	}
	return aead, nil
}

// GenerateNonce creates a secure 12-byte random nonce.
func GenerateNonce() ([NonceSize]byte, error) {
	var n [NonceSize]byte
	_, err := io.ReadFull(rand.Reader, n[:])
	return n, err
}
