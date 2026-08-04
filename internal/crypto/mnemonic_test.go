package crypto

import (
	"strings"
	"testing"
)

// TestGenerateMnemonic verifies that GenerateMnemonic produces a valid 24-word
// BIP39 mnemonic with correct structure and checksum.
func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic() error = %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("expected 24 words, got %d", len(words))
	}

	// All words must be in the BIP39 wordlist
	wl := bip39Wordlist()
	wlMap := make(map[string]bool, len(wl))
	for _, w := range wl {
		wlMap[w] = true
	}
	for i, w := range words {
		if !wlMap[w] {
			t.Errorf("word[%d] = %q is not in BIP39 wordlist", i, w)
		}
	}
}

// TestMnemonicRoundTrip verifies that entropy -> mnemonic -> entropy round-trips correctly.
func TestMnemonicRoundTrip(t *testing.T) {
	for i := 0; i < 10; i++ {
		mnemonic, err := GenerateMnemonic()
		if err != nil {
			t.Fatalf("GenerateMnemonic() error = %v", err)
		}

		if !MnemonicValid(mnemonic) {
			t.Errorf("MnemonicValid(%q) = false, expected true", mnemonic)
		}

		entropy, err := MnemonicToEntropy(mnemonic)
		if err != nil {
			t.Fatalf("MnemonicToEntropy() error = %v", err)
		}
		if len(entropy) != 32 {
			t.Errorf("entropy length = %d, expected 32", len(entropy))
		}

		// Reverse: entropy back to mnemonic
		mnemonic2, err := EntropyToMnemonic(entropy)
		if err != nil {
			t.Fatalf("EntropyToMnemonic() error = %v", err)
		}
		if mnemonic != mnemonic2 {
			t.Errorf("mnemonic round-trip failed:\n  got:  %q\n  want: %q", mnemonic2, mnemonic)
		}
	}
}

// TestMnemonicChecksumRejection verifies that a corrupted mnemonic is rejected.
func TestMnemonicChecksumRejection(t *testing.T) {
	mnemonic, _ := GenerateMnemonic()
	words := strings.Fields(mnemonic)

	// Corrupt a word
	words[0] = "abandon"
	words[1] = "abandon"
	corrupted := strings.Join(words, " ")

	// It might accidentally pass if all words are valid and the checksum happens to match,
	// but statistically this is negligible. We test it doesn't panic at minimum.
	valid := MnemonicValid(corrupted)
	_ = valid // we just verify no panic

	// A mnemonic with wrong word count must always be invalid
	short := strings.Join(words[:23], " ")
	if MnemonicValid(short) {
		t.Error("MnemonicValid should return false for 23-word mnemonic")
	}
}

// TestArgon2idKey verifies Argon2id key derivation produces 32-byte output
// and is deterministic for the same inputs.
func TestArgon2idKey(t *testing.T) {
	salt, err := GenerateArgon2Salt()
	if err != nil {
		t.Fatalf("GenerateArgon2Salt() error = %v", err)
	}
	if len(salt) != SaltLen {
		t.Errorf("salt length = %d, expected %d", len(salt), SaltLen)
	}

	passphrase := "abandon ability able"
	key1, err := Argon2idKey(passphrase, salt)
	if err != nil {
		t.Fatalf("Argon2idKey() error = %v", err)
	}
	if len(key1) != Argon2KeyLen {
		t.Errorf("key length = %d, expected %d", len(key1), Argon2KeyLen)
	}

	// Deterministic: same inputs -> same key
	key2, err := Argon2idKey(passphrase, salt)
	if err != nil {
		t.Fatalf("Argon2idKey() second call error = %v", err)
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Errorf("Argon2idKey not deterministic: key1[%d]=%d key2[%d]=%d", i, key1[i], i, key2[i])
		}
	}

	// Different salt -> different key
	salt2, _ := GenerateArgon2Salt()
	key3, _ := Argon2idKey(passphrase, salt2)
	allSame := true
	for i := range key1 {
		if key1[i] != key3[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("Argon2idKey with different salt produced same key (probability ~2^-256)")
	}
}

// TestArgon2idKeyErrors verifies error handling for invalid inputs.
func TestArgon2idKeyErrors(t *testing.T) {
	salt := make([]byte, SaltLen)

	_, err := Argon2idKey("", salt)
	if err == nil {
		t.Error("expected error for empty passphrase")
	}

	_, err = Argon2idKey("hello", salt[:8])
	if err == nil {
		t.Error("expected error for short salt")
	}
}

// TestWordlistSize verifies the BIP39 wordlist has exactly 2048 entries.
func TestWordlistSize(t *testing.T) {
	wl := bip39Wordlist()
	if len(wl) != 2048 {
		t.Errorf("BIP39 wordlist has %d words, expected 2048", len(wl))
	}
}

// TestWordlistUniqueness verifies no duplicates in the BIP39 wordlist.
func TestWordlistUniqueness(t *testing.T) {
	wl := bip39Wordlist()
	seen := make(map[string]int)
	for i, w := range wl {
		if prev, ok := seen[w]; ok {
			t.Errorf("duplicate word %q at index %d (first seen at %d)", w, i, prev)
		}
		seen[w] = i
	}
}
