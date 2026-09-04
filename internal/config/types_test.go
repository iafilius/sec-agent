package config

import (
	"testing"
)

func TestEnvVarKeyValidation(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"DATABASE_URL", false},
		{"API_KEY_123", false},
		{"_PRIVATE_KEY", false},
		{"123INVALID", true},
		{"KEY=VALUE", true},
		{"", true},
	}

	for _, tt := range tests {
		k, err := NewEnvVarKey(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewEnvVarKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if err == nil && k.String() != tt.input {
			t.Errorf("NewEnvVarKey(%q).String() = %q, want %q", tt.input, k.String(), tt.input)
		}
	}
}

func TestEnvInjectionModeValidation(t *testing.T) {
	if err := InjectionSubshell.Validate(); err != nil {
		t.Errorf("InjectionSubshell validation failed: %v", err)
	}
	if err := EnvInjectionMode("invalid").Validate(); err == nil {
		t.Errorf("Expected error for invalid injection mode")
	}
}

func TestShellTypeValidation(t *testing.T) {
	if err := ShellZsh.Validate(); err != nil {
		t.Errorf("ShellZsh validation failed: %v", err)
	}
	if err := ShellType("tcsh").Validate(); err == nil {
		t.Errorf("Expected error for invalid shell type")
	}
}

func TestEnvironmentTierValidation(t *testing.T) {
	if tier := ParseEnvironmentTier("PROD"); tier != TierProd || !tier.IsProduction() {
		t.Errorf("ParseEnvironmentTier('PROD') = %v, expected %v", tier, TierProd)
	}
	if tier := ParseEnvironmentTier("staging"); tier != TierStaging {
		t.Errorf("ParseEnvironmentTier('staging') = %v, expected %v", tier, TierStaging)
	}
	if err := TierDev.Validate(); err != nil {
		t.Errorf("TierDev validation failed: %v", err)
	}
	if err := EnvironmentTier("invalid").Validate(); err == nil {
		t.Errorf("Expected error for invalid environment tier")
	}
}
