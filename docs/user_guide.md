# Enclave Session Agent (`sec`) - User Guide

The `sec` CLI tool is a free, 100% offline, local secrets manager designed to protect developer credentials on corporate-managed macOS machines against session takeovers (e.g. hijacked terminal sessions, remote SSH access, or administrative screen monitoring).

---

## 1. Security Architecture

Unlike standard tools, `sec` uses a **hybrid biometric and memory-isolated agent** design:

*   **Touch ID Verification (`sec open`)**: Prompts the user once to authorize the session using native macOS `LocalAuthentication` APIs. This physical verification cannot be triggered or spoofed by a remote attacker.
*   **Hardware-Secured Session Key**: Stores the master key in the macOS Keychain under strict hardware-enforced `SecAccessControl` (`kSecAccessControlBiometryAny | kSecAccessControlUserPresence`). The operating system intercepts any attempt to read this key and prompts for physical Touch ID verification, preventing other user-space scripts from silently extracting your master key.
*   **Encrypted Local Store**: Secrets are saved on disk encrypted with AES-256 GCM in `~/.config/sec/secrets.enc` (restricted with `0600` permissions).
*   **Hardened Session Daemon**: Spawns a background process that holds decrypted secrets in RAM for 8 hours (default TTL). The daemon is compiled under **macOS Hardened Runtime**, preventing root users from attaching debuggers to dump memory under SIP.
*   **Anti-Hijacking Checks**: The daemon checks the caller's process tree for `sshd` and checks for active screen sharing (`screensharingd`) on every read. If detected, the memory cache is immediately wiped and locked.

---

## 2. Installation & Build

Compile and codesign the binary with Hardened Runtime using the provided Makefile:

```bash
# Clean, compile, and sign the binary
make clean build codesign
```

This compiles the `sec` binary and signs it with the ad-hoc hardened runtime signature flags. You can move the compiled binary to a directory in your PATH (e.g., `/usr/local/bin/sec` or `~/bin/sec`).

---

## 3. Command Usage

### 3.1. Open Session (`sec open`)
Initializes the background daemon and triggers a Touch ID prompt on your physical screen to unlock the session key cache.

You can configure a custom session duration (Hard TTL) and a sliding activity-based grace period. If you perform a query (such as reading a secret) near the end of the session, the grace period extends the session to ensure long-running scripts or active operations do not break.

#### Shell Session Token Security
To prevent other processes running under your local user account (such as a compromised web browser, malicious browser extensions, or remote terminal hijackers) from accessing the daemon socket, `sec` uses environment-isolated session tokens. When you unlock the daemon, it generates a cryptographically secure token.

You must set this token in your shell environment (`SEC_SESSION_TOKEN`) to run queries. Because environment variables are strictly isolated to the terminal's process tree, background processes and web browsers are blind to this token.

**Recommended usage (eval)**:
Run the following to authorize your shell session in one step:
```bash
eval $(sec open)
# Authorizing session via Touch ID...
# Session unlocked successfully. Cache active. TTL: 8h. Inactivity Grace: 30m.
```

**Alternative manual copy-paste**:
```bash
sec open
# Authorizing session via Touch ID...
# Session unlocked successfully. Cache active. TTL: 8h. Inactivity Grace: 30m.
export SEC_SESSION_TOKEN="3a9f07a7e80d94b..."
# Tip: Run 'eval $(sec open)' to automatically authorize this shell session.
```

#### Options:
*   `--ttl <duration>` / `-t <duration>`: Hard session duration limit. Expiry forces full lock. Defaults to `8h`.
*   `--grace <duration>` / `-g <duration>`: Inactivity grace window. If the hard TTL expires but a query was performed within this sliding grace window, the session remains active. Defaults to `30m`.

#### Custom Durations:
```bash
eval $(sec open --ttl 12h --grace 45m)
# or
eval $(sec open -t 12h -g 45m)
```

### 3.2. Write Secret (`sec set`)
Stores a secret under a given path, with optional comments, metadata key-value pairs, and expiration limits. This automatically encrypts and saves it to the encrypted store on disk.

```bash
# Standard set:
sec set database/prod/password "my-ultra-secure-pass"

# Set with comments and metadata:
sec set database/prod/password "my-ultra-secure-pass" --comment "production db password" --meta owner=devops --meta env=prod
# Secret saved successfully.

# Set with expiration limit (relative duration):
sec set database/test/key "temporary-value" --expires 30d    # Expires in 30 days
sec set database/test/key "temporary-value" --expires 12h    # Expires in 12 hours

# Set with expiration limit (absolute datetime):
sec set database/test/key "temporary-value" --expires "2026-12-31T23:59:59Z"
```

### 3.3. Read Secret (`sec get`)
Frictionless retrieval from the memory cache of the daemon. This is extremely fast and can be called hundreds of times a day in your local pipelines and scripts with zero GUI prompts.

*   **Raw Output (Default)**:
    ```bash
    sec get database/prod/password
    # my-ultra-secure-pass
    ```
*   **JSON Format**: Outputs all data including comments, metadata, and timestamps (creation, last modification, and expiration date if configured).
    ```bash
    sec get database/prod/password --json
    # {
    #   "value": "my-ultra-secure-pass",
    #   "comment": "production db password",
    #   "metadata": {
    #     "env": "prod",
    #     "owner": "devops"
    #   },
    #   "created": "2026-07-20T22:04:14Z",
    #   "last_modified": "2026-07-20T22:15:30Z"
    # }
    ```
*   **Read Comment**:
    ```bash
    sec get database/prod/password --comment
    # production db password
    ```
*   **Read Specific Metadata Field**:
    ```bash
    sec get database/prod/password --meta owner
    # devops
    ```

### 3.3.1. Batch Group Loading (`sec load` & `sec run --group`)
For project environments organized by hierarchy (e.g. `project/terraform/acceptance/` vs `project/terraform/dev/`), you can load or run scoped groups by path prefix in a single Unix Domain Socket IPC call:

*   **Scoped Shell Sourcing (`sec load`)**:
    ```bash
    eval $(sec load project/terraform/acceptance)
    # Automatically exports:
    # export DB_PASS="..."
    # export AWS_KEY="..."
    ```
*   **Scoped Process Injection (`sec run --group`)**:
    ```bash
    sec run --group project/terraform/acceptance -- terraform plan
    ```
*   **Batch Group Query (`sec get --prefix`)**:
    ```bash
    sec get project/terraform/acceptance/ --prefix [--json]
    ```

### 3.3.2. Secret Path Renaming & Namespace Refactoring (`sec mv` / `sec rename`)
Redesign your secret taxonomy without reading, deleting, and re-creating paths manually:

*   **Single Secret Move**:
    ```bash
    sec mv old-path/db-pass new-path/db-pass
    # Renamed secret "old-path/db-pass" to "new-path/db-pass"
    ```
    *Preserves original secret values, comments, custom metadata, and creation timestamps.*

*   **Prefix Group Refactoring**:
    ```bash
    sec mv legacy-project/ terraform/dev/ --prefix
    # Renamed 5 secrets under prefix "legacy-project/" to "terraform/dev/"
    ```

### 3.3.3. Path Listing, Deletion, Diagnostics & Security Audits
Enterprise controls for discovery, deletion, environment diagnostics, and compliance logging:

*   **Secret Path Listing (`sec ls` / `sec list`)**:
    ```bash
    sec ls project/ [--json]
    # Displays matching key paths without revealing raw values to terminal logs.
    ```
*   **Single & Group Secret Deletion (`sec rm` / `sec delete`)**:
    ```bash
    sec rm old-path/db-pass             # Delete single secret
    sec rm legacy-project/ --prefix      # Batch delete matching prefix group
    ```
*   **Session & Environment Diagnostics (`sec status`)**:
    ```bash
    sec status
    # === sec-agent Status & Diagnostics ===
    # Active Profile:       default
    # Daemon Version:       v1.1.0
    # Session Status:       UNLOCKED (Authorized via Touch ID)
    # Stored Secrets:       14 total (0 expired)
    # Hard TTL Limit:       8h0m0s
    # Inactivity Grace:     30m0s
    ```
*   **Security Access Audit Logging (`sec audit` / `sec log`)**:
    ```bash
    sec audit [--limit 50] [--json]
    # Displays JSON records from ~/.config/sec/audit.log tracking process PIDs and actions.
    ```

### 3.3.4. Advanced Developer & Vault Tools (`sec diff`, `sec doctor`, `sec gen`, `sec cp`, `sec import`)
*   **Environment Key Diff (`sec diff`)**:
    ```bash
    sec diff --other-profile prod [--prefix project/dev/]
    sec diff .env
    # Outputs added/missing key path diffs between profiles without exposing values.
    ```
*   **System Health Doctor (`sec doctor`)**:
    ```bash
    sec doctor
    # Runs automated checks on Secure Enclave biometrics, Keychain, socket permissions, and runtime signing.
    ```
*   **Cryptographic Password Generator (`sec gen`)**:
    ```bash
    sec gen database/prod/password --length 32 [--no-symbols]
    # Generates 32-character random string using crypto/rand and saves it directly into sec.
    ```
*   **Secret Key Duplication (`sec cp` / `sec copy`)**:
    ```bash
    sec cp project/dev/db-pass project/staging/db-pass
    sec cp project/dev/ project/staging/ --prefix
    # Duplicates keys or namespace trees into a new target path.
    ```
*   **Bulk Vault Payload Importer (`sec import`)**:
    ```bash
    sec import secrets.json --format doppler --prefix project/acceptance/
    # Bulk imports Doppler, AWS, or custom JSON key-value files.
    ```

### 3.4. Expiration Policy & Recovery (`--show-expired`)
When a secret reaches its expiration timestamp:
- Normal queries (e.g. `sec get database/test/key`) will block, outputting `Error: Secret has expired` and returning exit code `1`.
- To recover or read an expired secret value, pass the `--show-expired` flag:
  ```bash
  sec get database/test/key --show-expired
  # temporary-value
  ```

#### Pipeline Examples:

*   **Bash/Zsh**:
    ```bash
    export DB_PASS=$(sec get database/prod/password)
    ```
*   **Python**:
    ```python
    import subprocess
    db_pass = subprocess.check_output(["sec", "get", "database/prod/password"]).decode().strip()
    ```

### 3.4. Close/Lock Session (`sec clear` / `sec close` / `sec lock`)
Wipes the active decrypted secrets from memory and locks the store. Subsequent reads will fail until `sec open` is run again.

```bash
sec close
# or
sec lock
# or
sec clear
# Session locked. Memory cache cleared.
```

### 3.5. Portable KeePassXC Backup (`sec backup`)
Decrypts all secrets from the active session cache and compiles them into a standard KeePassXC `.kdbx` file. 

You can run it interactively (which prompts for password twice) or script it using the `--password` (`-p`) parameter.

#### Interactive:
```bash
sec backup my_backup.kdbx
# Enter KeePassXC master password for backup: 
# Confirm KeePassXC master password: 
# Backup created successfully at: /Users/username/my_backup.kdbx
```

#### Scripted / Automated:
```bash
sec backup my_backup.kdbx -p "my-automated-vault-pass"
# or
sec backup my_backup.kdbx --password "my-automated-vault-pass"
# Backup created successfully at: /Users/username/my_backup.kdbx
```

### 3.6. Portable KeePassXC Restore (`sec restore`)
Imports secrets, comments, and custom metadata fields from a KeePassXC `.kdbx` database back into your active session database. If keys conflict, the backup file's values will overwrite the active session's entries.

Similar to backup, it can be run interactively or automated.

#### Interactive:
```bash
sec restore my_backup.kdbx
# Enter KeePassXC master password for restore: 
# Secrets restored successfully. Merged 5 entries into active session.
```

#### Scripted / Automated:
```bash
sec restore my_backup.kdbx -p "my-automated-vault-pass"
# or
sec restore my_backup.kdbx --password "my-automated-vault-pass"
# Secrets restored successfully. Merged 5 entries into active session.
```

### 3.7. Multi-Project Isolation Profiles (`--profile` / `-P`)
For strict logical and physical cryptographic isolation of secrets (such as separating freelance client work from corporate work), you can run multiple independent databases, sockets, and daemon sessions concurrently using profiles.

To configure and route commands to a specific profile, you can either pass the `--profile` (`-P`) flag globally or set the `SEC_PROFILE` environment variable.

#### Examples:

*   **Open isolated profile (starts a dedicated daemon and Keychain key)**:
    ```bash
    sec open --profile client-x
    # or
    sec open -P client-x
    ```
*   **Write secret to profile**:
    ```bash
    sec set db/pass "value-x" --profile client-x
    ```
*   **Read secret from profile**:
    ```bash
    sec get db/pass --profile client-x
    ```
*   **Environment Variable Fallback**:
    If you set the `SEC_PROFILE` variable, all commands automatically route to that profile without needing the CLI flag:
    ```bash
    export SEC_PROFILE="client-x"
    sec get db/pass
    # value-x
    ```
*   **Default Profile**:
    If no flag is passed and `SEC_PROFILE` is not set, the tool falls back to the default profile (`default`) using `secrets.enc` and `sec.sock`.

### 3.8. Process Environment Wrapper (`sec run`)
To avoid writing credentials to files on disk, `sec run` launches any shell process (tests, deployment wrappers, or compilation scripts) with decrypted session secrets injected directly as uppercase environment variables in child process memory.

#### 1. Which File Secrets Are Read From:
Secrets are NOT read from plaintext files on disk. Instead, all credentials are read from the active session daemon memory, which loads the encrypted vault database:
*   **Default Profile Store**: `~/.config/sec/secrets.enc`
*   **Named Profile Store**: `~/.config/sec/profiles/<profile_name>/secrets.enc`
*   **Decryption Master Key**: Hardware-sealed in the **macOS Secure Enclave** via the macOS Keychain (`SecAccessControl`).

#### 2. Key Selection Algorithm (Which Keys are Injected):
`sec run` selects which keys to load using the following resolution hierarchy:
1.  **Group Prefix (`--group <prefix>`)**: If `--group <prefix>` is passed, `sec run` fetches only secrets matching `<prefix>/*`. The prefix is trimmed off for cleaner variable names (e.g. `velocloud-provider/vco_token` $\rightarrow$ `VCO_TOKEN`). Prints: `[INFO] Injecting 3 secret(s) matching group "velocloud-provider" into child process environment.`
2.  **Workspace File (`.secrc`)**: If a `.secrc` or `.sec.json` file is present in the repository root, `sec run` automatically applies the configured `profile` and `prefix`.
3.  **All Vault Secrets (Fallback)**: If no `--group` or `.secrc` is specified, `sec run` fetches **all active, non-expired keys** in the profile vault and prints an informational notice to `stderr`:
    `[INFO] No --group or .secrc specified: Injecting all 14 active vault secret(s) into child process environment.`

#### 3. Path-to-Environment-Variable Name Conversion:
*   If a secret entry contains a custom **`env_alias`** metadata field (e.g., `env_alias = "VCO_TOKEN"`), that alias is used verbatim as the environment variable name.
*   Otherwise, the secret path string is sanitized: converted to uppercase, slashes (`/`) and hyphens (`-`) are replaced with underscores (`_`), and non-alphanumeric characters are stripped (e.g. `database/prod/password` $\rightarrow$ `DATABASE_PROD_PASSWORD`).

#### 4. Real-Time Stream Log Redaction (Default-On):
*   By default, `sec run` intercepts child `stdout` and `stderr` streams in real time and replaces any occurrences of active vault secret strings with `[REDACTED_BY_SEC]`.
*   Pass `--no-redact` if raw output is required for debugging.

#### Usage:
```bash
sec run [--profile <name>] [--group <prefix>] [--no-redact] -- <command> [args...]
```

#### Example:
```bash
sec run --profile velocloud-provider --group orchestrator -- go test -v ./...
# Executes test process with VCO_URL and VCO_TOKEN environment variables injected in memory and auto-redacted in logs
```

### 3.9. Shell Environment Exporter (`sec env`)
Outputs standard POSIX-compliant shell exports for a specific namespace, facilitating one-command shell overrides.

#### Usage:
```bash
sec env [<prefix>] [--profile <name>]
```

#### Example:
```bash
eval $(sec env velocloud-provider)
# Loads all secrets matching the 'velocloud-provider' prefix as shell exports
```

### 3.10. Plaintext Database Exporter (`sec export`)
Outputs the decrypted database in standard formats to support zero-friction tool decoupling and backup migrations to AWS Secrets Manager, Doppler, or standard environment exports.

#### Options:
*   `--format <json|env|aws|doppler>` / `-f <json|env|aws|doppler>`: Output format choice. Defaults to `json`.

#### Format Specifications:
*   `json` (Default): Returns full decrypted database entries JSON map.
*   `env`: Outputs flat POSIX environment variables definitions.
*   `aws`: Outputs a JSON list matching the bulk imports format for the `aws secretsmanager` CLI: `[{"SecretId": "key", "SecretString": "val"}]`.
*   `doppler`: Outputs a flat JSON key-value map matching `doppler secrets upload` payload requirements.

#### Example:
```bash
sec export --format doppler
# {
#   "DATABASE_PROD_PASSWORD": "value",
#   "STRIPE_API_KEY": "value"
# }
```

### 3.11. Onboarding Dotenv Migration (`sec migrate-local`)
To safely onboard existing projects and clean up local configurations, `sec migrate-local` automatically scans a dotenv file, extracts key-value credentials, imports them into the enclave daemon, and sanitizes the file on disk.

#### Options:
*   `--prefix <namespace>`: Prefix namespace path to store the credentials under (defaults to `env`).

#### Example:
```bash
sec migrate-local .env --prefix app-secrets --profile my-project
# Successfully migrated 2 secret(s) to sec (profile: my-project). Dotenv file ".env" sanitized.
```
*   **Resulting `.env` content**:
    ```ini
    # Migrated to sec. Run your commands using: sec run --profile my-project -- <command>
    DATABASE_PASSWORD="<migrated_to_sec>"
    STRIPE_KEY="<migrated_to_sec>"
    ```

### 3.12. AI-Friendly Structured Help & Errors
To allow AI coding agents to interact with `sec` cleanly and diagnose failures programmatically, the tool supports structured inputs/outputs:
*   **JSON Schema Specification**: Run `sec help --format json` to get a structured JSON definition of all commands, flags, arguments, and exit error codes.
*   **JSON Structured Errors**: Pass the global flag `--json-errors` to output any execution failures as a JSON string to `stderr` with programmatic error codes and remediation tips:
    ```bash
    sec get database/prod/password --json-errors
    # Stderr output:
    # {"success":false,"error":{"code":"SESSION_LOCKED","message":"Session locked or expired.","remediation":"Please run 'eval $(sec open)' to authorize your shell session."}}
    ```

---

### 3.13. Environment Isolation & Safety Guards (v1.4.0)
To prevent running development tools against production orchestrators or cloud accounts, `sec` supports profile environment tagging and execution guards:

#### Profile Environment Tagging (`sec profile set-env`)
Bind an explicit environment tier (`dev`, `dta`/`staging`, `prod`) to a vault profile:
```bash
sec profile set-env prod --profile velocloud-provider-prod
sec profile set-env dev --profile velocloud-provider-dev
```

#### Terminal Visual Color Badges
Commands executed against tagged profiles render color-coded headers:
- `dev`: `🟢 [ENV: DEV]` (Green header)
- `dta` / `staging`: `🟡 [ENV: STAGING]` (Yellow header)
- `prod`: `🔴 [ENV: PROD - CAUTION!]` (Red header)

#### Production Confirmation Guard (`--confirm-prod`)
When running `sec run` or `sec get` against a profile tagged as `prod`:
- **Interactive Mode**: Prompts for physical Touch ID or explicit confirmation before executing commands.
- **Non-Interactive / CI Mode**: Requires passing `--confirm-prod` flag:
  ```bash
  sec run --confirm-prod --profile velocloud-provider-prod -- terraform apply
  ```

---

### 3.14. Automated Token Rotation & Expiring Inventory (v1.6.0)
To ensure zero-downtime token management, `sec` supports registering custom rotation commands and inspecting expiring vault entries:

#### Secret Rotation Hook Registration (`sec set --rotate-cmd`)
Bind a custom rotation script command and rotation TTL duration to a secret entry:
```bash
sec set velocloud-provider-dev/vco_token "eyJhbGci..." --expires 30d \
  --rotate-cmd "sec run --profile velocloud-provider-dev -- curl -s -X POST \$VCO_URL/portal/rest/login/enterpriseLogin -d '{\"username\":\"admin\",\"password\":\"\$VCO_PASSWORD\"}' | jq -r .token" \
  --rotate-ttl 30d
```

#### Automated Token Rotation (`sec rotate <path>`)
Triggers execution of the registered rotation script in a memory-isolated process container, captures the new token string from stdout, updates the vault entry, and resets the expiration timer:
```bash
sec rotate velocloud-provider-dev/vco_token
# [INFO] Executing rotation hook for 'velocloud-provider-dev/vco_token'...
# [✓] Secret 'velocloud-provider-dev/vco_token' successfully rotated!
# [✓] Expiration timer updated to: 2026-08-22T20:00:00Z
```

#### Expiring Vault Inventory (`sec ls --expiring [days]`)
List all secret entries expiring within N days (default 7 days) across your profile:
```bash
sec ls --expiring 14d
# ⚠️ EXPIRATION WARNING: 2 secret key(s) expiring within the next 14 day(s)!
# KEY PATH                            EXPIRATION DATE           REMAINING
# ---------------------------------------------------------------------------
# velocloud-provider-dev/vco_token      2026-07-26T18:00:00Z      3 day(s)
```

---

## 4. Troubleshooting & Verification

### Verifying Hardened Runtime
Ensure the binary signature flags have the `runtime` attribute:
```bash
codesign -d --verbose sec
# CodeDirectory v=20500 size=10797 flags=0x10002(adhoc,runtime)
```

### Resetting Configuration
To reset all keys and clear configuration states, delete the local `sec` directory:
```bash
rm -rf ~/.config/sec/
```
The next `sec open` run will automatically generate a new master key and set up a new store.
