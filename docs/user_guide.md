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
To avoid writing credentials to files on disk, `sec run` launches any shell process (tests, deployment wrappers, or compilation scripts) with all decrypted session secrets injected directly as uppercase environment variables in process memory.

Paths like `database/prod/password` are automatically sanitized and converted to `DATABASE_PROD_PASSWORD`.

#### Usage:
```bash
sec run [--profile <name>] -- <command> [args...]
```

#### Example:
```bash
sec run --profile cloud-service-api -- go test -v ./...
# Executes test process with API_URL and API_TOKEN variables available
```

### 3.9. Shell Environment Exporter (`sec env`)
Outputs standard POSIX-compliant shell exports for a specific namespace, facilitating one-command shell overrides.

#### Usage:
```bash
sec env [<prefix>] [--profile <name>]
```

#### Example:
```bash
eval $(sec env cloud-service-api)
# Loads all secrets matching the 'cloud-service-api' prefix as shell exports
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
