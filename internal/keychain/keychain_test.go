package keychain

import (
	"bytes"
	"testing"
)

func TestKeychainLifecycle(t *testing.T) {
	service := "sec_test_service"
	account := "test_user"
	secret := []byte("super-secret-password-123")

	// 1. Clean up first
	_ = Delete(service, account)

	// 2. Set the secret
	err := Set(service, account, secret)
	if err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}

	// 3. List the secrets (should see 'test_user')
	accounts, err := List(service)
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	found := false
	for _, acc := range accounts {
		if acc == account {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find account %q in list, but got: %v", account, accounts)
	}

	// 4. Retrieve the secret
	// NOTE: This will trigger a physical Touch ID prompt.
	t.Log("Note: This test may trigger a physical Touch ID/password prompt. Please accept or cancel.")
	retrieved, err := Get(service, account)
	if err != nil {
		// We expect either success or user cancellation / auth failure
		t.Logf("Get secret returned error (this is normal if canceled): %v", err)
	} else {
		if !bytes.Equal(retrieved, secret) {
			t.Errorf("Expected retrieved secret to be %q, but got %q", string(secret), string(retrieved))
		}
	}

	// 5. Clean up
	err = Delete(service, account)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}
}
