package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

const (
	Version   = 0x01
	KeySize   = 32 // AES-256
	NonceSize = 12 // GCM standard
)

var (
	ErrInvalidBlob    = errors.New("invalid blob format")
	ErrDecryptFailed  = errors.New("decryption failed")
	ErrInvalidVersion = errors.New("unsupported blob version")
)

// GenerateKey generates a 32-byte random key for AES-256
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns blob: version(1) || nonce(12) || ciphertext+tag
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// blob format: version || nonce || ciphertext+tag
	blob := make([]byte, 1+NonceSize+len(ciphertext))
	blob[0] = Version
	copy(blob[1:1+NonceSize], nonce)
	copy(blob[1+NonceSize:], ciphertext)

	return blob, nil
}

// Decrypt decrypts a blob using AES-256-GCM
func Decrypt(blob, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	// minimum: version(1) + nonce(12) + tag(16)
	if len(blob) < 1+NonceSize+16 {
		return nil, ErrInvalidBlob
	}

	version := blob[0]
	if version != Version {
		return nil, ErrInvalidVersion
	}

	nonce := blob[1 : 1+NonceSize]
	ciphertext := blob[1+NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// EncodeKey encodes a key as base64url
func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64url key
func DecodeKey(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

// EncodeBlob encodes a blob as base64url
func EncodeBlob(blob []byte) string {
	return base64.RawURLEncoding.EncodeToString(blob)
}

// DecodeBlob decodes a base64url blob
func DecodeBlob(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}
