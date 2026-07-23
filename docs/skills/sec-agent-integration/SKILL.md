---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, and manage backups.
---

# sec-agent Secrets Management Integration

This skill enables AI coding agents and autonomous assistants to use the `sec` CLI tool to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, and manage KeePassXC `.kdbx` backups on macOS.

---

## 1. Quick Diagnostics & Verification

At the start of work, if the user mentions secrets, environment variables, or testing credentials, check if the `sec` utility is available:

```bash
# Check CLI binary version and query active background daemon status
sec version
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
sec run [--profile <profile-name>] -- <command-line>
```
*   **How it works**: The CLI queries the background daemon, fetches keys, translates path strings to uppercase environment variables (e.g. `tf-vars/db-password` -> `TF_VARS_DB_PASSWORD`), injects them into child process memory, and executes the target script.

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
```

### 2.6. Storing Secrets
```bash
sec set <path> "<value>" [--comment "<description>"] [--meta owner=devops] [--profile <profile>]
```

### 2.6. Retrieving Secrets
```bash
# Get raw plaintext secret value
sec get <path> [--profile <profile>]

# Output JSON structure with metadata and timestamps
sec get <path> --json [--profile <profile>]
```

### 2.7. Onboarding Plaintext Env Files
If a plaintext `.env` file containing credentials exists in the workspace, migrate it to eliminate disk exposure:
```bash
sec migrate-local <dotenv-file> --prefix <prefix> --profile <profile-name>
```
*   This securely imports all keys into the enclave store and replaces raw values inside the `.env` file with safe `"<migrated_to_sec>"` placeholders.

### 2.8. Portable Backups & Vault Exports
```bash
# Export active store to a KeePassXC encrypted .kdbx file
sec backup <backup-name>.kdbx

# Restore secrets from a KeePassXC .kdbx file
sec restore <backup-name>.kdbx

# Export secrets to Doppler JSON format
sec export --format doppler

# Export secrets to AWS Secrets Manager JSON format
sec export --format aws
```

### 2.9. Session Locking
```bash
sec lock
```
*   Instantly locks the database and flushes all master keys from system memory.

---

## 3. Handling Error Responses

If a command fails, `sec` returns programmatic JSON or text error blocks:

| Error Code | Root Cause | Remediation Hint to User |
| :--- | :--- | :--- |
| `DAEMON_NOT_RUNNING` | The background socket is inactive. | Ask user to run `eval $(sec open)` |
| `SESSION_LOCKED` | Active session has expired or been locked. | Ask user to run `eval $(sec open)` and complete Touch ID auth |
| `INVALID_TOKEN` | The current shell session is not authorized. | Ask user to run `eval $(sec open)` to sync session token |
| `ACCESS_DENIED_HIJACK` | Connection blocked due to detected SSH or remote sharing ancestry. | Connection rejected due to remote/hijack safety guards. Must run from local physical terminal. |
