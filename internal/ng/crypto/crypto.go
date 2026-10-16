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

// DeriveServerTrafficKeys derives server-specific directional keys using HKDF (RFC 5869)
// with explicit domain separation.
// c2sKey is derived from c2sPSK (shared root secret allowing authorized servers to decrypt queries).
// s2cKey is derived from serverResponseSecret (unique per-server response secret held exclusively by serverID).
// If serverResponseSecret is empty, it falls back to c2sPSK for single-server standalone operation.
func DeriveServerTrafficKeys(c2sPSK []byte, serverResponseSecret []byte, salt []byte, serverID string) ([]byte, []byte, error) {
	if len(c2sPSK) == 0 {
		return nil, nil, ErrInvalidKey
	}
	if len(salt) == 0 {
		salt = []byte("paqet-ng-v3-hkdf-salt")
	}
	if serverID == "" {
		serverID = "default"
	}

	c2sExtractor := hkdf.New(sha256.New, c2sPSK, salt, []byte("paqet-ng-v3-c2s"))
	c2s := make([]byte, KeySize)
	if _, err := io.ReadFull(c2sExtractor, c2s); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive c2s v3 key: %w", err)
	}

	resSecret := serverResponseSecret
	if len(resSecret) == 0 {
		resSecret = c2sPSK
	}
	s2cInfo := []byte(fmt.Sprintf("paqet-ng-v3-s2c:%s", serverID))
	s2cExtractor := hkdf.New(sha256.New, resSecret, salt, s2cInfo)
	s2c := make([]byte, KeySize)
	if _, err := io.ReadFull(s2cExtractor, s2c); err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive s2c v3 key: %w", err)
	}

	return c2s, s2c, nil
}

// DeriveServerResponseKey derives only the server-to-client response key from serverResponseSecret and serverID.
func DeriveServerResponseKey(serverResponseSecret []byte, salt []byte, serverID string) ([]byte, error) {
	if len(serverResponseSecret) == 0 {
		return nil, ErrInvalidKey
	}
	if len(salt) == 0 {
		salt = []byte("paqet-ng-v3-hkdf-salt")
	}
	if serverID == "" {
		serverID = "default"
	}

	s2cInfo := []byte(fmt.Sprintf("paqet-ng-v3-s2c:%s", serverID))
	extractor := hkdf.New(sha256.New, serverResponseSecret, salt, s2cInfo)
	s2c := make([]byte, KeySize)
	if _, err := io.ReadFull(extractor, s2c); err != nil {
		return nil, fmt.Errorf("crypto: failed to derive s2c v3 key for server %s: %w", serverID, err)
	}
	return s2c, nil
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
