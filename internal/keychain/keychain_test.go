package keychain

import (
	"bytes"
	"os"
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

	// 4. Retrieve the secret (Physical Touch ID prompt gated for headless test runs)
	if testing.Short() || os.Getenv("ENABLE_INTERACTIVE_KEYCHAIN_TEST") != "1" {
		t.Log("Skipping interactive Touch ID Keychain Get test during automated runs (enable via ENABLE_INTERACTIVE_KEYCHAIN_TEST=1)")
	} else {
		t.Log("Note: This test will trigger a physical Touch ID/password prompt. Please accept or cancel.")
		retrieved, err := Get(service, account)
		if err != nil {
			t.Logf("Get secret returned error (this is normal if canceled): %v", err)
		} else {
			if !bytes.Equal(retrieved, secret) {
				t.Errorf("Expected retrieved secret to be %q, but got %q", string(secret), string(retrieved))
			}
		}
	}

	// 5. Clean up
	err = Delete(service, account)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}
}

func TestKeychainVersionedPromptsAndAccessPair(t *testing.T) {
	t.Setenv("SEC_TEST_MODE", "1")

	// Verify SetVersion updates package state
	SetVersion("v9.9.9")
	if currentVersion != "v9.9.9" {
		t.Errorf("expected currentVersion to be 'v9.9.9', got %q", currentVersion)
	}

	// Verify GetKeychainAccessPair for default profile
	getterDef, setterDef := GetKeychainAccessPair("default")
	if getterDef == nil || setterDef == nil {
		t.Fatalf("expected non-nil getter and setter for default profile")
	}

	// Verify GetKeychainAccessPair for custom named profile
	getterNamed, setterNamed := GetKeychainAccessPair("work-profile")
	if getterNamed == nil || setterNamed == nil {
		t.Fatalf("expected non-nil getter and setter for work-profile")
	}

	testSecret := []byte("versioned-prompt-test-key-32bytes!")
	if err := setterNamed(testSecret); err != nil {
		t.Fatalf("setterNamed failed: %v", err)
	}

	// Verify listing under isolated test profile
	accounts, err := List("sec-test-session:profile_work-profile")
	if err != nil {
		t.Fatalf("failed to list accounts: %v", err)
	}
	found := false
	for _, a := range accounts {
		if a == "master" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'master' account in test profile accounts, got: %v", accounts)
	}

	// Clean up
	_ = Delete("sec-test-session:profile_work-profile", "master")
}

func TestResealCurrentSetAndMetadata(t *testing.T) {
	t.Setenv("SEC_TEST_MODE", "1")

	service := "sec-test-session:profile_reseal-test"
	account := "master"
	secret1 := []byte("first-secret-key-material-32byte")
	secret2 := []byte("resealed-secret-key-material-32b")

	// 1. Initial cleanup
	_ = Delete(service, account)

	// 2. Metadata on non-existent item
	meta, err := GetItemMetadata(service, account)
	if err != nil {
		t.Fatalf("GetItemMetadata failed on non-existent item: %v", err)
	}
	if meta.Exists {
		t.Errorf("expected item to not exist, got exists=true")
	}

	// 3. Set initial secret
	if err := SetCurrentSet(service, account, secret1); err != nil {
		t.Fatalf("SetCurrentSet failed: %v", err)
	}

	// 4. Metadata on existing item
	meta, err = GetItemMetadata(service, account)
	if err != nil {
		t.Fatalf("GetItemMetadata failed: %v", err)
	}
	if !meta.Exists {
		t.Errorf("expected item to exist, got exists=false")
	}
	if meta.Service != service || meta.Account != account {
		t.Errorf("unexpected meta service/account: got %s/%s, want %s/%s", meta.Service, meta.Account, service, account)
	}
	if meta.AccessControl != "BiometryCurrentSet" {
		t.Errorf("expected AccessControl 'BiometryCurrentSet', got %q", meta.AccessControl)
	}

	// 5. Test ResealCurrentSet
	if err := ResealCurrentSet(service, account, secret2); err != nil {
		t.Fatalf("ResealCurrentSet failed: %v", err)
	}

	// 6. Test ResealKeychainForProfile helper
	if err := ResealKeychainForProfile("reseal-test", secret2); err != nil {
		t.Fatalf("ResealKeychainForProfile failed: %v", err)
	}

	// 7. Clean up
	_ = Delete(service, account)
}

