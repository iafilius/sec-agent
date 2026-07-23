---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, and manage backups.
---

# sec-agent Secrets Management Integration

This skill enables AI coding agents and autonomous assistants to use the `sec` CLI tool (v1.2.0+) to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, and manage KeePassXC `.kdbx` backups on macOS.

---

## 1. Quick Diagnostics & Verification

At the start of work, if the user mentions secrets, environment variables, or testing credentials, check if the `sec` utility is available:

```bash
# Check CLI binary version and query active background daemon status
sec version

# Output programmatic JSON metadata
sec version --json
```

### Interpretation of `sec version` Outputs:
*   **Daemon "Active" / "Running"**: The session is unlocked and secrets are queryable.
*   **Daemon "Session locked" / "Not running"**: The daemon is active but locked, or inactive. Tell the user to run:
    ```bash
    eval $(sec open)
    ```
*   **Version mismatch warning**: If the CLI and Daemon versions mismatch, advise the user to restart:
    ```bash
    sec lock && eval $(sec open)
    ```

---

## 2. Common Operations

### 2.1. Executing Applications & Pipelines with Secrets
Instead of reading from unencrypted `.env` files, wrap process executions (e.g. `npm test`, `go test`, `terraform plan`, `make deploy`):
```bash
sec run [--profile <profile-name>] [--auto-open] -- <command-line>
```
*   **How it works**: The CLI queries the background daemon, fetches keys, translates path strings or `--env-alias` names, injects them into child process memory, and executes the target script.

### 2.2. Batch Loading Scoped Secrets for Purpose/Environment
For project environments (e.g. Terraform `dev` vs `acceptance`), load or run scoped groups by prefix in one go:
```bash
# Execute command with only secrets matching prefix injected (prefix is automatically trimmed)
sec run --group my-project/terraform/acceptance -- terraform plan

# Export shell environment variables for a specific purpose/group (eval friendly)
eval $(sec load my-project/terraform/acceptance)

# Query a group of secrets matching a path prefix
sec get my-project/terraform/acceptance/ --prefix [--json]
```

### 2.3. Renaming & Refactoring Secret Namespaces
```bash
# Rename a single secret path (preserves comments, metadata, and creation dates)
sec mv old-path/db-pass new-path/db-pass

# Refactor an entire prefix hierarchy in a single atomic transaction
sec mv legacy-project/ new-project/ --prefix
```

### 2.4. Path Listing, Deletion, Diagnostics & Security Audits
```bash
# List secret paths without exposing raw values
sec ls [prefix] [--json]

# Delete a single secret or prefix group
sec rm <path> [--prefix]

# Inspect daemon health, TTLs, and store metrics
sec status

# Read structured security access audit log
sec audit [--limit 50] [--json]
```

### 2.5. Advanced Developer & Vault Tools
```bash
# Compare secret key paths against another profile or .env file (without exposing values)
sec diff --other-profile prod [--prefix <prefix>]
sec diff .env

# Run system health diagnostics (Secure Enclave, socket permissions, Hardened Runtime)
sec doctor

# Generate high-entropy random password and save to path
sec gen <path> [--length 32] [--no-symbols] [--comment <description>]

# Duplicate a single key path or prefix namespace
sec cp <src-path> <dst-path> [--prefix]

# Bulk import secrets from JSON, Doppler, or AWS Secrets Manager payloads
sec import <file.json> [--format doppler|aws|json] [--prefix <prefix>]

# Pre-flight validation of required vault keys or template file before CI/CD runs
sec check --template .env.example
sec check --required VCO_URL,VCO_TOKEN
```

### 2.6. Storing Secrets & Custom Environment Aliases
```bash
# Store secret with optional comment and custom environment variable alias
sec set <path> "<value>" [--env-alias BGP_INBOUND_PASSWORD] [--comment "<description>"] [--meta owner=devops] [--profile <profile>]
```

### 2.7. Retrieving Secrets
```bash
# Get raw plaintext secret value
sec get <path> [--profile <profile>]

# Get raw secret string without newline or stderr warnings for clean shell assignment
val=$(sec get <path> -r)

# Output JSON structure with metadata and timestamps
sec get <path> --json [--profile <profile>]
```

### 2.8. Onboarding Plaintext Env Files
If a plaintext `.env` file containing credentials exists in the workspace, migrate it to eliminate disk exposure:
```bash
sec migrate-local <dotenv-file> --prefix <prefix> --profile <profile-name>
```
*   This securely imports all keys into the enclave store and replaces raw values inside the `.env` file with safe `"<migrated_to_sec>"` placeholders.

### 2.9. Portable Backups, Vault Exports & Onboarding Templates
```bash
# Export active store to a KeePassXC encrypted .kdbx file
sec backup <backup-name>.kdbx

# Restore secrets from a KeePassXC .kdbx file (non-destructive merge)
sec restore <backup-name>.kdbx --merge

# Export sanitized .env.example template for repository onboarding
sec export --format template [--prefix <prefix>]

# Export secrets to Doppler or AWS Secrets Manager JSON formats
sec export --format doppler
sec export --format aws
```

### 2.10. Workspace Configuration (`.secrc`), Auto-Open & Shell Completions
*   **Workspace `.secrc`**: Place a `.secrc` or `.sec.json` in your repository root to configure project defaults:
    ```json
    {
      "profile": "velocloud-provider",
      "prefix": "velocloud-provider/acceptance/",
      "auto_open": true
    }
    ```
*   **Auto-Open**: Pass `--auto-open` or set `export SEC_AUTO_OPEN=1` to automatically trigger Touch ID unlock inline if the session is locked.
*   **Shell Completions**: Generate tab completions: `sec completion zsh > ~/.zsh/completion/_sec`

### 2.11. Environment Isolation & Safety Guards
```bash
# Tag a profile with an environment classification (dev, dta, staging, prod)
sec profile set-env prod --profile velocloud-provider-prod

# Execute against production profile (requires --confirm-prod or Touch ID confirmation)
sec run --confirm-prod --profile velocloud-provider-prod -- terraform apply
```
*   Displays visual terminal badges (`🟢 [ENV: DEV]`, `🟡 [ENV: STAGING]`, `🔴 [ENV: PROD - CAUTION!]`).

### 2.12. Time-Bound Secret Leases (`sec lease`)
```bash
# Grant a 15-minute temporary lease token for an AI subagent or background task
lease_token=$(sec lease velocloud-provider-dev/vco_token --ttl 15m)
```
*   **Why Use Leases**: Delegate temporary credential access to autonomous AI subagents or background test scripts with **zero credential lingering**. The lease token self-destructs automatically after the specified TTL expires.

### 2.13. Cross-Profile Matrix Diffing (`sec diff-profiles`) & Stream Redactor (`sec run --redact`)
```bash
# Compare structural key alignment between dev and prod profiles
sec diff-profiles velocloud-provider-dev velocloud-provider-prod

# Execute command with real-time secret stream redaction
sec run --redact -- make testacc
```

### 2.14. Session Restart & Locking
```bash
# Restart daemon, apply binary updates, and re-authenticate in one step
eval $(sec restart)

# Lock session and flush keys from memory
sec lock
```
*   Instantly locks the database and flushes all master keys from system memory.

---

## 3. Handling Error Responses

If a command fails, `sec` returns programmatic JSON or text error blocks:

| Error Code | Root Cause | Remediation Hint to User |
| :--- | :--- | :--- |
| `DAEMON_NOT_RUNNING` | The background socket is inactive. | Ask user to run `eval $(sec open)` or use `--auto-open` |
| `SESSION_LOCKED` | Active session has expired or been locked. | Ask user to run `eval $(sec open)` or use `--auto-open` |
| `INVALID_TOKEN` | The current shell session is not authorized. | Ask user to run `eval $(sec open)` to sync session token |
| `PRODUCTION_GUARD_BLOCKED` | Command execution against PRODUCTION profile requires confirmation. | Pass `--confirm-prod` flag or complete interactive Touch ID prompt. |
| `ACCESS_DENIED_HIJACK` | Connection blocked due to detected SSH or remote sharing ancestry. | Connection rejected due to remote/hijack safety guards. Must run from local physical terminal. |
