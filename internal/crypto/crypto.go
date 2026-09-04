package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

// MasterKeyFingerprint returns a 16-character hex representation of SHA-256(key).
func MasterKeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return "none"
	}
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])[:16]
}

var noncePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 12)
		return &b
	},
}

// GenerateRandomKey generates a random 32-byte key.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-GCM with the provided key.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	noncePtr := noncePool.Get().(*[]byte)
	defer noncePool.Put(noncePtr)
	nonce := *noncePtr

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	dst := make([]byte, 0, len(nonce)+len(plaintext)+gcm.Overhead())
	dst = append(dst, nonce...)
	ciphertext := gcm.Seal(dst, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM with the provided key.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
