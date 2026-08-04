package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for recovery seed key derivation.
// These are deliberately CPU/memory-intensive to resist brute-force attacks.
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4
	Argon2KeyLen  = 32 // 256-bit AES key
	SaltLen       = 16 // 128-bit random salt
)

// Argon2idKey derives a 32-byte AES key from a passphrase and salt using Argon2id.
// The salt must be SaltLen bytes and should be stored alongside the encrypted payload.
func Argon2idKey(passphrase string, salt []byte) ([]byte, error) {
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("argon2id: salt must be %d bytes, got %d", SaltLen, len(salt))
	}
	if passphrase == "" {
		return nil, fmt.Errorf("argon2id: passphrase cannot be empty")
	}
	key := argon2.IDKey([]byte(passphrase), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return key, nil
}

// GenerateArgon2Salt produces a cryptographically random SaltLen-byte salt.
func GenerateArgon2Salt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate argon2 salt: %w", err)
	}
	return salt, nil
}

// GenerateMnemonic generates a BIP39-compatible 24-word recovery mnemonic
// using the embedded English wordlist and a cryptographically random 256-bit entropy.
// The resulting mnemonic encodes 256 bits of entropy (+ 8-bit checksum = 264 bits = 24 words).
func GenerateMnemonic() (string, error) {
	// 256 bits of entropy for 24 words
	entropy := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}
	return EntropyToMnemonic(entropy)
}

// EntropyToMnemonic converts 32 bytes of entropy to a 24-word BIP39 mnemonic.
func EntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != 32 {
		return "", fmt.Errorf("entropy must be 32 bytes for 24-word mnemonic")
	}

	// Calculate SHA256 checksum (first 8 bits)
	checksum := sha256.Sum256(entropy)
	checksumBit := (checksum[0] >> 7) & 1 // only need 8 bits for 256-bit entropy

	// Combine entropy + checksum nibble into 264-bit stream
	// 256 bits entropy + 8 bits checksum = 264 bits = 24 * 11 bits
	bits := make([]bool, 264)
	for i, b := range entropy {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (b>>(7-j))&1 == 1
		}
	}
	// Append checksum byte's 8 bits
	for j := 0; j < 8; j++ {
		bits[256+j] = (checksum[0]>>(7-j))&1 == 1
	}
	_ = checksumBit // used via bits above

	wordlist := bip39Wordlist()
	words := make([]string, 24)
	for i := 0; i < 24; i++ {
		// Extract 11-bit index
		var idx uint16
		for j := 0; j < 11; j++ {
			if bits[i*11+j] {
				idx |= 1 << (10 - j)
			}
		}
		words[i] = wordlist[idx]
	}
	return strings.Join(words, " "), nil
}

// MnemonicToEntropy converts a 24-word BIP39 mnemonic back to 32 bytes of entropy.
// Returns an error if the mnemonic is invalid or the checksum fails.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(strings.TrimSpace(mnemonic))
	if len(words) != 24 {
		return nil, fmt.Errorf("mnemonic must have 24 words, got %d", len(words))
	}

	wordlist := bip39Wordlist()
	// Build reverse index
	reverseIdx := make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		reverseIdx[w] = i
	}

	bits := make([]bool, 264)
	for i, word := range words {
		idx, ok := reverseIdx[word]
		if !ok {
			return nil, fmt.Errorf("mnemonic word %q is not in BIP39 wordlist", word)
		}
		for j := 0; j < 11; j++ {
			bits[i*11+j] = (idx>>(10-j))&1 == 1
		}
	}

	entropy := make([]byte, 32)
	for i := range entropy {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				b |= 1 << (7 - j)
			}
		}
		entropy[i] = b
	}

	// Extract checksum byte
	var checksumByte byte
	for j := 0; j < 8; j++ {
		if bits[256+j] {
			checksumByte |= 1 << (7 - j)
		}
	}

	// Verify checksum
	expected := sha256.Sum256(entropy)
	if expected[0] != checksumByte {
		return nil, fmt.Errorf("mnemonic checksum verification failed — mnemonic may be corrupted")
	}

	return entropy, nil
}

// MnemonicValid returns true if the 24-word BIP39 mnemonic is valid and its checksum passes.
func MnemonicValid(mnemonic string) bool {
	_, err := MnemonicToEntropy(mnemonic)
	return err == nil
}

// MnemonicToPassphrase converts a 24-word mnemonic to a passphrase string
// suitable for Argon2id key derivation (simply the joined normalized mnemonic).
func MnemonicToPassphrase(mnemonic string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(mnemonic)), " ")
}

// bip39CheckIndex returns the index of a word in the BIP39 wordlist, -1 if not found.
func bip39CheckIndex(word string) int {
	for i, w := range bip39Wordlist() {
		if w == word {
			return i
		}
	}
	return -1
}

// randUint64 reads a random uint64 for internal use.
func randUint64() (uint64, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}
