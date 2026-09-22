package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"secure_secrets/internal/daemon"
	"strings"
)

// StreamPlaceholder represents a parsed template placeholder.
type StreamPlaceholder struct {
	FullMatch   string
	ProfileSpec string // e.g. "sandbox" or "xuntos-prod" (empty if active profile)
	KeyPath     string // e.g. "certs/ca" or "db/url"
}

// streamRegex matches standard {{key}} and cross-profile {{@env_or_profile:key}} placeholders.
var streamRegex = regexp.MustCompile(`\{\{\s*(?:@([a-zA-Z0-9_\-\.]+):)?([a-zA-Z0-9_\-\./]+)\s*\}\}`)

// parseStreamPlaceholders parses all placeholders from the template.
func parseStreamPlaceholders(templateStr string) []StreamPlaceholder {
	matches := streamRegex.FindAllStringSubmatch(templateStr, -1)
	var list []StreamPlaceholder
	for _, m := range matches {
		if len(m) >= 3 {
			list = append(list, StreamPlaceholder{
				FullMatch:   m[0],
				ProfileSpec: strings.TrimSpace(m[1]),
				KeyPath:     strings.TrimSpace(m[2]),
			})
		}
	}
	return list
}

// resolveTargetProfileName maps an environment alias or direct profile name to a concrete profile.
func resolveTargetProfileName(spec string, wsCfg *WorkspaceConfig) string {
	if spec == "" {
		return ""
	}
	if wsCfg != nil && wsCfg.Environments != nil {
		if env, ok := wsCfg.Environments[spec]; ok && env.Profile != "" {
			return env.Profile.String()
		}
	}
	return spec
}

// renderStreamTemplate interpolates template placeholders against active and cross-profile vaults.
func renderStreamTemplate(activeProfile string, templateStr string, wsCfg *WorkspaceConfig, secretFetcher func(p string) (map[string]string, error)) (string, error) {
	placeholders := parseStreamPlaceholders(templateStr)
	if len(placeholders) == 0 {
		return templateStr, nil
	}

	cache := make(map[string]map[string]string)
	neededProfiles := make(map[string]bool)

	for _, ph := range placeholders {
		p := ph.ProfileSpec
		if p == "" {
			neededProfiles[activeProfile] = true
		} else {
			concreteProfile := resolveTargetProfileName(p, wsCfg)
			neededProfiles[concreteProfile] = true
		}
	}

	for p := range neededProfiles {
		secrets, err := secretFetcher(p)
		if err != nil {
			return "", err
		}
		cache[p] = secrets
	}

	rendered := streamRegex.ReplaceAllStringFunc(templateStr, func(match string) string {
		sub := streamRegex.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		profileSpec := strings.TrimSpace(sub[1])
		keyPath := strings.TrimSpace(sub[2])

		targetProfile := activeProfile
		if profileSpec != "" {
			targetProfile = resolveTargetProfileName(profileSpec, wsCfg)
		}

		if secrets, ok := cache[targetProfile]; ok {
			if val, exists := secrets[keyPath]; exists {
				return val
			}
		}
		return match
	})

	return rendered, nil
}

func handleStream(profile string, args []string) {
	templateStr := ""
	for i := 0; i < len(args); i++ {
		if (args[i] == "--template" || args[i] == "-t") && i+1 < len(args) {
			templateStr = args[i+1]
			i++
		}
	}

	if templateStr == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fail("STDIN_READ_ERROR", fmt.Errorf("failed reading stream input: %v", err), "")
		}
		templateStr = string(data)
	}

	wsCfg := loadWorkspaceConfig()

	fetcher := func(p string) (map[string]string, error) {
		resp, err := queryDaemon(p, daemon.IPCRequest{Action: "backup"})
		if err != nil {
			return nil, fmt.Errorf("daemon for profile %q is not running: %w", p, err)
		}
		if !resp.Success {
			if strings.Contains(resp.Error, "locked") {
				return nil, fmt.Errorf("daemon session for profile %q is locked", p)
			}
			return nil, fmt.Errorf("failed fetching secrets for profile %q: %s", p, resp.Error)
		}
		res := make(map[string]string)
		for k, v := range resp.Secrets {
			res[k] = v.Value
		}
		return res, nil
	}

	rendered, err := renderStreamTemplate(profile, templateStr, wsCfg, fetcher)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "not running") {
			fail("DAEMON_NOT_RUNNING", err, "Ensure target profile daemon is running and unlocked via 'sec open --profile <name>'.")
		} else if strings.Contains(errStr, "locked") {
			fail("SESSION_LOCKED", err, "Unlock the target profile session via 'sec open --profile <name>'.")
		}
		fail("STREAM_TEMPLATE_ERROR", err, "")
	}

	fmt.Print(rendered)
}
