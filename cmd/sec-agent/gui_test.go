package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func TestGUIServerProfileSwitchingAndLockIsolation(t *testing.T) {
	os.Setenv("SEC_TEST_MODE", "1")
	os.Unsetenv("SEC_SESSION_TOKEN")

	guiTokensMutex.Lock()
	guiTokens = make(map[store.ProfileName]string)
	guiTokensMutex.Unlock()

	dir, err := config.GetConfigDir()
	if err != nil {
		t.Fatalf("failed to get config dir: %v", err)
	}

	// Create two distinct encrypted store files for test profiles
	p1Path, _ := store.GetStorePath("testprofile1")
	p2Path, _ := store.GetStorePath("testprofile2")

	s1 := &store.EncryptedStore{Secrets: map[store.SecretKey]store.SecretEntry{
		"KEY_P1": {Value: "val1", Version: 1},
	}}
	s2 := &store.EncryptedStore{Secrets: map[store.SecretKey]store.SecretEntry{
		"KEY_P2": {Value: "val2", Version: 1},
	}}

	mockKey := make([]byte, 32)
	for i := range mockKey {
		mockKey[i] = byte(i + 1)
	}

	_ = store.SaveStore(p1Path, s1, mockKey)
	_ = store.SaveStore(p2Path, s2, mockKey)
	defer os.Remove(p1Path)
	defer os.Remove(p2Path)

	activeGUIToken = "test_gui_token_123"

	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("profile")
		if p == "" {
			p = "testprofile1"
		}
		tok := getGUIToken(store.ProfileName(p))
		resp, err := queryDaemon(p, daemon.IPCRequest{Action: "backup", Token: tok})
		unlocked := (err == nil && resp != nil && resp.Success)

		dbs, _ := discoverDatabases()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GUIStatusResponseDTO{
			Profile:            p,
			Unlocked:           unlocked,
			AvailableDatabases: dbs,
		})
	})

	mux.HandleFunc("/api/secrets", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("profile")
		if p == "" {
			p = "testprofile1"
		}
		tok := getGUIToken(store.ProfileName(p))
		resp, err := queryDaemon(p, daemon.IPCRequest{Action: daemon.IPCActionBackup, Token: tok})
		if err != nil || resp == nil || !resp.Success {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(GUIUnlockResponseDTO{Profile: p, Unlocked: false, Error: "Session locked"})
			return
		}

		var list []SecretItem
		for k, v := range resp.Secrets {
			list = append(list, SecretItem{Key: store.SecretKey(k), Value: v.Value})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GUISecretsListDTO{
			Profile: p,
			Count:   len(list),
			Secrets: list,
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Test 1: Query unauthenticated testprofile1 status -> unlocked must be false
	req, _ := http.NewRequest("GET", ts.URL+"/api/status?profile=testprofile1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to query /api/status: %v", err)
	}
	var statusData GUIStatusResponseDTO
	_ = json.NewDecoder(resp.Body).Decode(&statusData)
	resp.Body.Close()

	if statusData.Unlocked {
		t.Errorf("expected testprofile1 to be locked initially, got unlocked=true")
	}

	// Test 2: Query unauthenticated testprofile2 status -> unlocked must be false
	req2, _ := http.NewRequest("GET", ts.URL+"/api/status?profile=testprofile2", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("failed to query /api/status for secondary profile: %v", err)
	}
	var statusData2 GUIStatusResponseDTO
	_ = json.NewDecoder(resp2.Body).Decode(&statusData2)
	resp2.Body.Close()

	if statusData2.Unlocked {
		t.Errorf("expected secondary profile to be locked initially, got unlocked=true")
	}

	// Test 3: Query /api/secrets for secondary profile -> must return 401 Unauthorized
	req3, _ := http.NewRequest("GET", ts.URL+"/api/secrets?profile=testprofile2", nil)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("failed to query /api/secrets for secondary profile: %v", err)
	}
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for locked secondary profile, got status %d", resp3.StatusCode)
	}
	resp3.Body.Close()

	_ = dir
}
