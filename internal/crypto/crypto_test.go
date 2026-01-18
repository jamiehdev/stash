package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello world")
	blob, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(blob, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDifferentKeysDifferentCiphertext(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	plaintext := []byte("same plaintext")
	blob1, _ := Encrypt(plaintext, key1)
	blob2, _ := Encrypt(plaintext, key2)

	// ciphertexts should be different (different keys)
	if bytes.Equal(blob1, blob2) {
		t.Error("different keys should produce different ciphertexts")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	plaintext := []byte("secret data")
	blob, _ := Encrypt(plaintext, key1)

	_, err := Decrypt(blob, key2)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestBlobStartsWithVersion(t *testing.T) {
	key, _ := GenerateKey()
	blob, _ := Encrypt([]byte("test"), key)

	if blob[0] != 0x01 {
		t.Errorf("blob should start with version byte 0x01, got 0x%02x", blob[0])
	}
}

func TestKeySize(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(key) != 32 {
		t.Errorf("key should be 32 bytes, got %d", len(key))
	}
}

func TestNonceSize(t *testing.T) {
	key, _ := GenerateKey()
	blob, _ := Encrypt([]byte("test"), key)

	// blob format: version(1) + nonce(12) + ciphertext
	// nonce is bytes 1-12
	nonce := blob[1:13]
	if len(nonce) != 12 {
		t.Errorf("nonce should be 12 bytes, got %d", len(nonce))
	}
}

func TestEncodeDecodeKey(t *testing.T) {
	key, _ := GenerateKey()
	encoded := EncodeKey(key)
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key, decoded) {
		t.Error("key encode/decode roundtrip failed")
	}
}

func TestEncodeDecodeBlob(t *testing.T) {
	key, _ := GenerateKey()
	blob, _ := Encrypt([]byte("test data"), key)

	encoded := EncodeBlob(blob)
	decoded, err := DecodeBlob(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(blob, decoded) {
		t.Error("blob encode/decode roundtrip failed")
	}
}

func TestInvalidBlobTooShort(t *testing.T) {
	key, _ := GenerateKey()
	_, err := Decrypt([]byte{0x01}, key)
	if err != ErrInvalidBlob {
		t.Errorf("expected ErrInvalidBlob, got %v", err)
	}
}

func TestInvalidVersion(t *testing.T) {
	key, _ := GenerateKey()
	blob, _ := Encrypt([]byte("test"), key)
	blob[0] = 0x02 // wrong version

	_, err := Decrypt(blob, key)
	if err != ErrInvalidVersion {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key, _ := GenerateKey()
	blob, err := Encrypt([]byte{}, key)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypt(blob, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != 0 {
		t.Error("empty plaintext should decrypt to empty")
	}
}
