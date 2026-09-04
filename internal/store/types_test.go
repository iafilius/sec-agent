package store

import (
	"testing"
)

func TestSecretKeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid key", "db/password", false},
		{"valid simple key", "API_KEY", false},
		{"empty key", "", true},
		{"whitespace key", "   ", true},
		{"control character key", "db/pass\x00word", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, err := NewSecretKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewSecretKey(%q) expected error, got nil", tt.key)
				}
			} else {
				if err != nil {
					t.Errorf("NewSecretKey(%q) unexpected error: %v", tt.key, err)
				}
				if sk.String() != tt.key {
					t.Errorf("sk.String() = %q, want %q", sk.String(), tt.key)
				}
			}
		})
	}
}

func TestProfileNameValidation(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		wantErr     bool
	}{
		{"valid profile", "production", false},
		{"valid default", "default", false},
		{"empty profile", "", true},
		{"whitespace in profile", "my profile", true},
		{"control char profile", "prod\n", true},
		{"relative path traversal profile", "../tmp/test", true},
		{"absolute path traversal profile", "/etc/shadow", true},
		{"windows path traversal profile", "..\\windows\\system32", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pn, err := NewProfileName(tt.profile)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewProfileName(%q) expected error, got nil", tt.profile)
				}
			} else {
				if err != nil {
					t.Errorf("NewProfileName(%q) unexpected error: %v", tt.profile, err)
				}
				if pn.String() != tt.profile {
					t.Errorf("pn.String() = %q, want %q", pn.String(), tt.profile)
				}
			}
		})
	}
}

func TestSecretScopeValidation(t *testing.T) {
	tests := []struct {
		name    string
		scope   SecretScope
		wantErr bool
	}{
		{"global scope", ScopeGlobal, false},
		{"workspace scope", ScopeWorkspace, false},
		{"empty scope", "", false},
		{"invalid scope", SecretScope("unknown"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scope.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("scope %q expected error, got nil", tt.scope)
			} else if !tt.wantErr && err != nil {
				t.Errorf("scope %q unexpected error: %v", tt.scope, err)
			}
		})
	}
}
