package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
)

const (
	aes256GCMKeySize = 32
	aesGCMVersion    = byte(1)
)

var (
	// ErrInvalidAESKey means the key is not a 32-byte AES-256 key.
	ErrInvalidAESKey = errors.New("invalid aes-256-gcm key")
	// ErrInvalidCiphertext means a stored encrypted payload is malformed.
	ErrInvalidCiphertext = errors.New("invalid aes-256-gcm ciphertext")
)

// SealCredentialPayload encrypts plaintext with AES-256-GCM. The returned
// payload contains a version byte, nonce, and ciphertext so it can be stored as
// a single database value.
func SealCredentialPayload(key, plaintext, additionalData []byte, random io.Reader) ([]byte, error) {
	gcm, err := newAES256GCM(key)
	if err != nil {
		return nil, err
	}
	if random == nil {
		return nil, errors.New("random reader is required")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("read aes-gcm nonce: %w", err)
	}

	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, aesGCMVersion)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, additionalData)
	return out, nil
}

// OpenCredentialPayload decrypts a payload created by SealCredentialPayload.
func OpenCredentialPayload(key, payload, additionalData []byte) ([]byte, error) {
	gcm, err := newAES256GCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < 1+nonceSize+gcm.Overhead() || payload[0] != aesGCMVersion {
		return nil, ErrInvalidCiphertext
	}

	nonce := payload[1 : 1+nonceSize]
	ciphertext := payload[1+nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

func newAES256GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != aes256GCMKeySize {
		return nil, ErrInvalidAESKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
