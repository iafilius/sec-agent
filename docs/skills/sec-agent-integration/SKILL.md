---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, and manage backups.
---

# sec-agent Secrets Management Integration

This skill enables AI coding agents and autonomous assistants to use the `sec-agent` CLI tool (v1.9.1+) to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, and manage KeePassXC `.kdbx` backups on macOS.

---

## 1. Quick Diagnostics & Verification

At the start of work, if the user mentions secrets, environment variables, or testing credentials, check if the `sec-agent` utility is available:

```bash
# Check CLI binary version and query active background daemon status
sec-agent version

# Output programmatic JSON metadata
sec-agent version --json
```

### Interpretation of `sec-agent version` Outputs:
*   **Daemon "Active" / "Running"**: The session is unlocked and secrets are queryable.
*   **Daemon "Session locked" / "Not running"**: The daemon is active but locked, or inactive. Tell the user to run:
    ```bash
    eval $(sec-agent open)
    ```
*   **Version mismatch warning**: If the CLI and Daemon versions mismatch, advise the user to restart:
    ```bash
    sec-agent lock && eval $(sec-agent open)
    ```

---

## 2. Common Operations

### 2.1. Executing Applications & Pipelines with Secrets
Instead of reading from unencrypted `.env` files, wrap process executions (e.g. `npm test`, `go test`, `terraform plan`, `make deploy`):
```bash
sec-agent run [--profile <profile-name>] [--auto-open] -- <command-line>
```
*   **How it works**: The CLI queries the background daemon, fetches keys, translates path strings or `--env-alias` names, injects them into child process memory, and executes the target script.

### 2.2. Batch Loading Scoped Secrets for Purpose/Environment
For project environments (e.g. Terraform `dev` vs `acceptance`), load or run scoped groups by prefix in one go:
```bash
# Execute command with only secrets matching prefix injected (prefix is automatically trimmed)
sec-agent run --group my-project/terraform/acceptance -- terraform plan

# Export shell environment variables for a specific purpose/group (eval friendly)
eval $(sec-agent load my-project/terraform/acceptance)
```

### 2.3. Storing Secrets Securely (Interactive Prompt & Stdin)
```bash
# 1. Interactive Hidden Prompt (Prevents shell history & ps aux process list leakage)
sec-agent set app-secrets/db-pass

# 2. Pipe secret value from Stdin
echo "secret-value" | sec-agent set app-secrets/db-pass --stdin

# 3. Direct Positional Value
sec-agent set app-secrets/db-pass "secret-value"
```
*   **Security Best Practice**: Avoid passing sensitive secret values directly as positional arguments in production, as command-line arguments can be logged to `.zsh_history` or observed via `ps aux`. Use interactive prompts or `--stdin` for high-security credentials.

### 2.4. Query a Group of Secrets Matching a Path Prefix
```bash
sec-agent get my-project/terraform/acceptance/ --prefix [--json]
```

### 2.5. Renaming & Refactoring Secret Namespaces
```bash
# Rename a single secret path (preserves comments, metadata, and creation dates)
sec-agent mv old-path/db-pass new-path/db-pass

# Refactor an entire prefix hierarchy in a single atomic transaction
sec-agent mv legacy-project/ new-project/ --prefix
```

### 2.6. Path Listing, Deletion, Diagnostics & Security Audits
```bash
# List secret paths without exposing raw values
sec-agent ls [prefix] [--json]

# Delete a single secret or prefix group
sec-agent rm <path> [--prefix]

# Inspect daemon health, TTLs, and store metrics
sec-agent status

# Read structured security access audit log
sec-agent audit [--limit 50] [--json]
```

### 2.7. Advanced Developer & Vault Tools
```bash
# Compare secret key paths against another profile or .env file (without exposing values)
sec-agent diff --other-profile prod [--prefix <prefix>]
sec-agent diff .env

# Run system health diagnostics (Secure Enclave, socket permissions, Hardened Runtime)
sec-agent doctor

# Generate high-entropy random password and save to path
sec-agent gen <path> [--length 32] [--no-symbols] [--comment <description>]

# Duplicate a single key path or prefix namespace
sec-agent cp <src-path> <dst-path> [--prefix]

# Bulk import secrets from JSON, Doppler, or AWS Secrets Manager payloads
sec-agent import <file.json> [--format doppler|aws|json] [--prefix <prefix>]

# Pre-flight validation of required vault keys or template file before CI/CD runs
sec-agent check --template .env.example
sec-agent check --required VCO_URL,VCO_TOKEN
```

### 2.8. Storing Secrets & Custom Environment Aliases
```bash
# Store secret with optional comment and custom environment variable alias
sec-agent set <path> "<value>" [--env-alias BGP_INBOUND_PASSWORD] [--comment "<description>"] [--meta owner=devops] [--profile <profile>]
```

### 2.9. Retrieving Secrets
```bash
# Get raw plaintext secret value
sec-agent get <path> [--profile <profile>]

# Get raw secret string without newline or stderr warnings for clean shell assignment
val=$(sec-agent get <path> -r)

# Output JSON structure with metadata and timestamps
sec-agent get <path> --json [--profile <profile>]
```

### 2.10. Onboarding Plaintext Env Files
If a plaintext `.env` file containing credentials exists in the workspace, migrate it to eliminate disk exposure:
```bash
sec-agent migrate-local <dotenv-file> --prefix <prefix> --profile <profile-name>
```
*   This securely imports all keys into the enclave store and replaces raw values inside the `.env` file with safe `"<migrated_to_sec>"` placeholders.

### 2.11. Portable Backups, Vault Exports & Onboarding Templates
```bash
# Export active store to a KeePassXC encrypted .kdbx file
sec-agent backup <backup-name>.kdbx

# Restore secrets from a KeePassXC .kdbx file (non-destructive merge)
sec-agent restore <backup-name>.kdbx --merge

# Export sanitized .env.example template for repository onboarding
sec-agent export --format template [--prefix <prefix>]

# Export secrets to Doppler or AWS Secrets Manager JSON formats
sec-agent export --format doppler
sec-agent export --format aws
```

### 2.12. Workspace Configuration (`.secrc`), Auto-Open & Shell Completions
*   **Workspace `.secrc`**: Place a `.secrc` or `.sec.json` in your repository root to configure project defaults:
    ```json
    {
      "profile": "velocloud-provider",
      "prefix": "velocloud-provider/acceptance/",
      "auto_open": true
    }
    ```
*   **Auto-Open**: Pass `--auto-open` or set `export SEC_AUTO_OPEN=1` to automatically trigger Touch ID unlock inline if the session is locked.
*   **Shell Completions**: Generate tab completions: `sec-agent completion zsh > ~/.zsh/completion/_sec-agent`

### 2.13. Environment Isolation & Safety Guards
```bash
# Tag a profile with an environment classification (dev, dta, staging, prod)
sec-agent profile set-env prod --profile velocloud-provider-prod

# Execute against production profile (requires --confirm-prod or Touch ID confirmation)
sec-agent run --confirm-prod --profile velocloud-provider-prod -- terraform apply
```
*   Displays visual terminal badges (`🟢 [ENV: DEV]`, `🟡 [ENV: STAGING]`, `🔴 [ENV: PROD - CAUTION!]`).

### 2.14. Time-Bound Secret Leases (`sec-agent lease`)
```bash
# Grant a 15-minute temporary lease token for an AI subagent or background task
lease_token=$(sec-agent lease velocloud-provider-dev/vco_token --ttl 15m)
```
*   **Why Use Leases**: Delegate temporary credential access to autonomous AI subagents or background test scripts with **zero credential lingering**. The lease token self-destructs automatically after the specified TTL expires.

### 2.15. Cross-Profile Matrix Diffing (`sec-agent diff-profiles`) & Real-Time Stream Redactor (`sec-agent run`)
```bash
# Compare structural key alignment between dev and prod profiles
sec-agent diff-profiles velocloud-provider-dev velocloud-provider-prod

# Execute command with REAL-TIME SECRET REDACTION ENABLED BY DEFAULT in logs
sec-agent run -- make testacc

# Restrict injection strictly to specified keys/aliases (Principle of Least Privilege)
sec-agent run --allow-keys VCO_URL,VCO_ENTERPRISE_ID -- make test-unit

# Inspect injection mapping plan without executing command or prompting for Touch ID
sec-agent run --dry-run -- make testacc

# Opt out of log redaction if raw output is required
sec-agent run --no-redact -- make testacc
```
*   **Default-On Redaction**: Automatically intercepts child process `stdout` and `stderr` streams in real time and replaces active secret values with `[REDACTED_BY_SEC]` to guarantee zero log leaks in CI/CD or terminal scrollbacks.
*   **Allowlist Scoping**: Restricts environment variable injection to specific keys for AI subagents or unit tests.
*   **Dry-Run Inspection**: Previews the injection plan without starting the subprocess.

### 2.16. Password Entropy Linter (`sec-agent check --scan-weak`) & History Leak Audit (`sec-agent check --leaks`)
```bash
# Run side-channel safe password entropy & weakness scan
sec-agent check --scan-weak

# Run dual-engine workstation shell history leak audit (.zsh_history, .bash_history)
sec-agent check --leaks

# Export/import encrypted vault package for team distribution
sec-agent sync export ./team-dev-vault.kdbx
sec-agent sync import ./team-dev-vault.kdbx
```

### 2.17. Automated Token Rotation (`sec-agent rotate`) & Expiring Inventory (`sec-agent ls --expiring`)
```bash
# Register a token rotation command and rotation TTL
sec-agent set velocloud-provider-dev/vco_token "..." --expires 30d \
  --rotate-cmd "sec-agent run --profile velocloud-provider-dev -- curl -s -X POST \$VCO_URL/portal/rest/login/enterpriseLogin -d '{\"username\":\"admin\",\"password\":\"\$VCO_PASSWORD\"}' | jq -r .token" \
  --rotate-ttl 30d

# Trigger one-command token rotation
sec-agent rotate velocloud-provider-dev/vco_token

# Inspect all secrets expiring within N days across profiles
sec-agent ls --expiring 14d
```

### 2.18. Global Workstation Status Dump (`sec-agent status --all`)
```bash
# Output single-pane-of-glass status matrix across all vault profiles and daemons
sec-agent status --all
```
*   **Global Diagnostics**: Discovers all registered profiles, checks background daemon socket PIDs, reports Touch ID session unlock state (`UNLOCKED` vs `LOCKED`), active/expired key counts, and namespace prefixes.

### 2.19. Migration Prompts & Git History Security Protocol
*   **AI Assistant Migration Prompt**:
    > *"Migrate all plaintext credentials from `.env` in this workspace into a project-scoped `sec-agent` vault profile named `<project-dev>`, sanitize `.env` to `<migrated_to_sec>` placeholders, and create a `.secrc` file in the project root."*
*   **Git History Exposure Caution**:
    > ⚠️ **CAUTION**: Running `sec-agent migrate-local .env` sanitizes disk files to `<migrated_to_sec>` placeholders. **However, if `.env` was previously committed to Git, those credentials STILL EXIST in Git commit history!**
    > Purge files from Git history using `git-filter-repo`:
    > ```bash
    > pip install git-filter-repo
    > git filter-repo --path .env --invert-paths --force
    > git push origin --force --all --tags
    > ```
    > *Note: Force-pushing rewritten history requires **Repository Admin privileges** to temporarily bypass branch protection rules on `main`/`master`. Always rotate exposed credentials immediately regardless.*

### 2.20. Project Vault Governance Best Practices
*   **One Profile Per Environment**: Always scope vaults per environment (`--profile <project>-dev`, `--profile <project>-prod`).
*   **Namespace Prefixes**: Group secrets under functional namespace prefixes (`orchestrator/`, `database/`, `aws/`).
*   **Workspace `.secrc`**: Always check for or create a `.secrc` file in repository roots to ensure seamless, flagless execution for team colleagues.
*   **Optional Shell Alias**: Developers who do not have the Perl `sec` tool installed can add `alias sec=sec-agent` to `~/.zshrc`.

### 2.21. Session Restart & Locking
```bash
# Restart daemon, apply binary updates, and re-authenticate in one step
eval $(sec-agent restart)

# Lock session and flush keys from memory
sec-agent lock
```
*   Instantly locks the database and flushes all master keys from system memory.

---

## 3. Handling Error Responses

If a command fails, `sec-agent` returns programmatic JSON or text error blocks:

| Error Code | Root Cause | Remediation Hint to User & AI Auto-Open Recovery |
| :--- | :--- | :--- |
| `DAEMON_NOT_RUNNING` | The background socket is inactive. | Ask user to run `eval $(sec-agent open)` or pass `--auto-open` |
| `SESSION_LOCKED` | Touch ID grace period expired or locked. | Ask user to run `eval $(sec-agent open)` or pass `--auto-open` / `export SEC_AUTO_OPEN=1` |
| `INVALID_TOKEN` / `ACCESS DENIED` | `SEC_SESSION_TOKEN` missing or mismatched in sub-shell. | Ask user to run `eval $(sec-agent open)`, or use `--auto-open` / `SEC_AUTO_OPEN=1` to auto-trigger Touch ID and update process token |
| `SECRET_NOT_FOUND` | Path does not exist in store. | Ask user to check path or run `sec-agent set <path>` |
| `ACCESS_DENIED_HIJACK` | Remote SSH or ScreenSharing detected. | Session locked automatically for anti-hijack security |

---

## 4. Key Takeaways for AI Assistants

1. **Always Favor `sec-agent run -- <cmd>`**: Never ask users to write plaintext secrets to `.env` files.
2. **Handle Locks & Unset Session Tokens Gracefully**: If a tool call errors with `DAEMON_NOT_RUNNING` or `ACCESS DENIED: Invalid or missing session token`, either:
   * Tell the user: *"Please run `eval $(sec-agent open)` in your terminal to authorize this shell session."*, OR
   * Use `--auto-open` (e.g. `sec-agent set <path> --auto-open` or `export SEC_AUTO_OPEN=1`), which automatically triggers an inline Touch ID prompt, updates `SEC_SESSION_TOKEN` in process memory, and retries the command cleanly.
3. **Use Scoped Profiles**: Always pass `--profile` or inspect `.secrc` to ensure secrets are isolated per project.
4. **Use Interactive Prompts or Stdin for `sec-agent set`**: Avoid outputting raw secret strings in command arguments when adding keys (use `--stdin` or interactive prompts).

