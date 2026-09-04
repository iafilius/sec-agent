package config

import (
	"fmt"
	"strings"
)

// EnvVarKey represents a strongly-typed environment variable key name.
type EnvVarKey string

// NewEnvVarKey validates and creates an EnvVarKey.
func NewEnvVarKey(raw string) (EnvVarKey, error) {
	k := EnvVarKey(strings.TrimSpace(raw))
	if err := k.Validate(); err != nil {
		return "", err
	}
	return k, nil
}

// String returns the string representation.
func (k EnvVarKey) String() string {
	return string(k)
}

// Validate checks whether the key name contains valid environment variable characters.
func (k EnvVarKey) Validate() error {
	s := strings.TrimSpace(string(k))
	if s == "" {
		return fmt.Errorf("environment variable key cannot be empty")
	}
	for i, r := range s {
		if r < 32 || r == 127 || r == '=' || r == ' ' || r == '\t' {
			return fmt.Errorf("environment variable key contains illegal character %q", r)
		}
		if i == 0 && (r >= '0' && r <= '9') {
			return fmt.Errorf("environment variable key cannot start with a digit")
		}
	}
	return nil
}

// EnvVarValue represents a strongly-typed environment variable value.
type EnvVarValue string

// String returns the string representation.
func (v EnvVarValue) String() string {
	return string(v)
}

// EnvInjectionMode represents the mechanism used to inject secrets into process environments.
type EnvInjectionMode string

const (
	InjectionSubshell EnvInjectionMode = "subshell"
	InjectionStream   EnvInjectionMode = "stream"
	InjectionExec     EnvInjectionMode = "exec"
)

// Validate checks whether the injection mode is supported.
func (m EnvInjectionMode) Validate() error {
	switch m {
	case InjectionSubshell, InjectionStream, InjectionExec:
		return nil
	default:
		return fmt.Errorf("unsupported injection mode: %q", m)
	}
}

// ShellType represents target shell environments for completion and export scripts.
type ShellType string

const (
	ShellZsh  ShellType = "zsh"
	ShellBash ShellType = "bash"
	ShellFish ShellType = "fish"
)

// Validate checks whether the shell type is supported.
func (s ShellType) Validate() error {
	switch s {
	case ShellZsh, ShellBash, ShellFish:
		return nil
	default:
		return fmt.Errorf("unsupported shell type: %q", s)
	}
}

// EnvironmentTier represents an environment deployment tier (dev, staging, prod).
type EnvironmentTier string

const (
	TierDev     EnvironmentTier = "dev"
	TierStaging EnvironmentTier = "staging"
	TierProd    EnvironmentTier = "prod"
	TierUnset   EnvironmentTier = "unset"
)

// ParseEnvironmentTier normalizes raw environment tier strings.
func ParseEnvironmentTier(raw string) EnvironmentTier {
	norm := strings.ToLower(strings.TrimSpace(raw))
	switch norm {
	case "dev", "development":
		return TierDev
	case "dta", "test", "testing", "staging":
		return TierStaging
	case "prod", "production":
		return TierProd
	default:
		return TierUnset
	}
}

// String returns the string representation.
func (t EnvironmentTier) String() string {
	return string(t)
}

// IsProduction returns true if the tier is production.
func (t EnvironmentTier) IsProduction() bool {
	return t == TierProd
}

// Validate checks whether the tier is a recognized environment tier.
func (t EnvironmentTier) Validate() error {
	switch t {
	case TierDev, TierStaging, TierProd, TierUnset:
		return nil
	default:
		return fmt.Errorf("unsupported environment tier: %q", t)
	}
}
