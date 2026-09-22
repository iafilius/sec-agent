package main

import (
	"fmt"
	"os"
	"path/filepath"
	"secure_secrets/internal/store"
	"strings"
	"testing"
)

func TestParseStreamPlaceholders(t *testing.T) {
	template := `
DB_URL={{db/url}}
CA_CERT={{@sandbox:certs/ca}}
API_KEY={{ @xuntos-prod:api/token }}
STATIC="unchanged"
`
	placeholders := parseStreamPlaceholders(template)
	if len(placeholders) != 3 {
		t.Fatalf("expected 3 placeholders, got %d", len(placeholders))
	}

	// 1. Standard placeholder
	if placeholders[0].ProfileSpec != "" || placeholders[0].KeyPath != "db/url" {
		t.Errorf("unexpected placeholder 0: %+v", placeholders[0])
	}

	// 2. Cross-profile with environment alias
	if placeholders[1].ProfileSpec != "sandbox" || placeholders[1].KeyPath != "certs/ca" {
		t.Errorf("unexpected placeholder 1: %+v", placeholders[1])
	}

	// 3. Cross-profile with direct profile and spaces
	if placeholders[2].ProfileSpec != "xuntos-prod" || placeholders[2].KeyPath != "api/token" {
		t.Errorf("unexpected placeholder 2: %+v", placeholders[2])
	}
}

func TestRenderStreamTemplateMixed(t *testing.T) {
	wsCfg := &WorkspaceConfig{
		Version: 2,
		Default: "dev",
		Environments: map[string]WorkspaceEnvironment{
			"dev": {
				Profile: store.ProfileName("xuntos-dev"),
				Tier:    "dev",
			},
			"sandbox": {
				Profile: store.ProfileName("xuntos-prod"),
				Tier:    "prod",
			},
		},
	}
	normalizeWorkspaceConfig(wsCfg)

	mockFetcher := func(profile string) (map[string]string, error) {
		switch profile {
		case "xuntos-dev":
			return map[string]string{
				"db/url": "postgres://localhost/dev",
			}, nil
		case "xuntos-prod":
			return map[string]string{
				"certs/ca":  "CA_CERT_DATA_PROD",
				"api/token": "PROD_SECRET_TOKEN",
			}, nil
		default:
			return nil, fmt.Errorf("unknown profile %q", profile)
		}
	}

	template := "DATABASE={{db/url}}\nCA={{@sandbox:certs/ca}}\nTOKEN={{@xuntos-prod:api/token}}"
	rendered, err := renderStreamTemplate("xuntos-dev", template, wsCfg, mockFetcher)
	if err != nil {
		t.Fatalf("renderStreamTemplate failed: %v", err)
	}

	expected := "DATABASE=postgres://localhost/dev\nCA=CA_CERT_DATA_PROD\nTOKEN=PROD_SECRET_TOKEN"
	if rendered != expected {
		t.Errorf("expected rendered output:\n%s\ngot:\n%s", expected, rendered)
	}
}

func TestRenderStreamTemplateTargetLocked(t *testing.T) {
	wsCfg := &WorkspaceConfig{
		Version: 2,
		Environments: map[string]WorkspaceEnvironment{
			"sandbox": {
				Profile: store.ProfileName("xuntos-prod"),
				Tier:    "prod",
			},
		},
	}

	mockFetcher := func(profile string) (map[string]string, error) {
		if profile == "xuntos-prod" {
			return nil, fmt.Errorf("daemon session for profile %q is locked", profile)
		}
		return map[string]string{"foo": "bar"}, nil
	}

	template := "KEY={{@sandbox:secret/key}}"
	_, err := renderStreamTemplate("default", template, wsCfg, mockFetcher)
	if err == nil {
		t.Fatalf("expected error when cross-profile daemon is locked, got nil")
	}

	if !strings.Contains(err.Error(), "xuntos-prod") || !strings.Contains(err.Error(), "locked") {
		t.Errorf("expected locked error naming 'xuntos-prod', got: %v", err)
	}
}

func TestStreamTemplateFileInput(t *testing.T) {
	tmpDir := t.TempDir()
	tmplFile := filepath.Join(tmpDir, "sample.yaml.tmpl")
	content := "API_KEY={{api/key}}\nDB={{db/name}}"
	if err := os.WriteFile(tmplFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed writing temp template file: %v", err)
	}

	wsCfg := &WorkspaceConfig{
		Version: 2,
		Environments: map[string]WorkspaceEnvironment{
			"dev": {
				Profile: store.ProfileName("test-prof"),
				Tier:    "dev",
			},
		},
	}
	normalizeWorkspaceConfig(wsCfg)

	mockFetcher := func(profile string) (map[string]string, error) {
		return map[string]string{
			"api/key": "secret-api-val",
			"db/name": "production-db",
		}, nil
	}

	expected := "API_KEY=secret-api-val\nDB=production-db"

	// 1. Test parsing via --file
	t.Run("--file flag", func(t *testing.T) {
		data, err := os.ReadFile(tmplFile)
		if err != nil {
			t.Fatalf("failed reading file: %v", err)
		}
		rendered, err := renderStreamTemplate("test-prof", string(data), wsCfg, mockFetcher)
		if err != nil {
			t.Fatalf("render error: %v", err)
		}
		if rendered != expected {
			t.Errorf("expected %q, got %q", expected, rendered)
		}
	})

	// 2. Test fallback when --template is passed an existing file path
	t.Run("--template filepath fallback", func(t *testing.T) {
		arg := tmplFile
		templateStr := arg
		if fi, err := os.Stat(templateStr); err == nil && !fi.IsDir() {
			if data, err := os.ReadFile(templateStr); err == nil {
				templateStr = string(data)
			}
		}
		rendered, err := renderStreamTemplate("test-prof", templateStr, wsCfg, mockFetcher)
		if err != nil {
			t.Fatalf("render error: %v", err)
		}
		if rendered != expected {
			t.Errorf("expected %q, got %q", expected, rendered)
		}
	})
}

