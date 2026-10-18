# Enclave Session Agent (`sec-agent`) — Operations Manual & Parameter Reference

This manual provides human operators, system administrators, and security auditors with a complete operational reference guide, CLI parameter matrix, environment variable catalog, and step-by-step work instructions for managing local developer workstation credentials using `sec-agent`.

---

## 1. Complete CLI Command & Parameter Matrix

All CLI operations are invoked via the `sec` or `sec-agent` binary. Below is the authoritative reference for all commands, parameters, and flags:

### 1.1. Session Management

#### `sec open`
Initializes the background session daemon and prompts for Touch ID physical presence.
*   `--ttl <duration>` / `-t <duration>`: Hard session expiration limit (e.g. `8h`, `12h`, `24h`). Default: `8h`.
*   `--grace <duration>` / `-g <duration>`: Sliding inactivity grace period. Secret queries within this window extend active session reachability. Default: `30m`.
*   `--timeout <duration>`: Active prompt timeout before automatic dismissal (e.g. `120s`, `2m`). Configurable in `.secrc` (`"prompt_timeout"`) or `SEC_PROMPT_TIMEOUT`. Default: `120s`.
*   **Biometric Exit Code Contract**:
    * `0`: Success (Vault unlocked)
    * `1`: User Canceled (Prompt dismissed with Escape or Cancel button)
    * `2`: Invalid CLI syntax or biometrics unavailable
    * `3`: Vault locked / daemon not running
    * `4`: `ERR_BIOMETRIC_TIMEOUT` (120s timeout expired, operator AFK — triggers agent task deferral)
    * `5`: `ERR_BIOMETRIC_LOCKOUT` (macOS requires password unlock before Touch ID can re-arm)
    * `6`: `ERR_BIOMETRIC_FAILED` (Sensor rejected presented fingerprint)
*   **Operator AFK Signaling**: Upon timeout, an audio alert plays and a macOS desktop notification is posted alerting the returning operator to resume via `sec open`.
*   **Usage**: `eval $(sec open -t 10h -g 45m --timeout 120s)`

#### `sec lock`
Immediately purges all decrypted session keys from background daemon RAM and invalidates the active `SEC_SESSION_TOKEN`.
*   **Usage**: `sec lock`


---

### 1.2. Secret Ingestion & Storage

#### `sec set <path> [<value>]`
Encrypts and saves a secret key-value record to disk.
*   `--stdin`: Reads value from standard input (fail-safe protected against copied command lines and shell prompts).
*   `--allow-command-string`: Explicitly allows storing text that starts with a shell command or terminal prompt via stdin.
*   `--desc <text>`: Adds a concise, 1-line description of what the secret is used for.
*   `--notes <text>`: Attaches multiline operational runbooks, renewal URLs, and rotation steps.
*   `--comment <text>`: Adds administrative comment note.
*   `--meta <key=value>`: Attaches custom key-value metadata tags (can be repeated multiple times).
*   `--expires <duration|ISO8601>`: Sets relative duration (e.g., `30d`, `12h`) or absolute UTC timestamp (e.g., `2026-12-31T23:59:59Z`).
*   `--env-alias <alias>`: Maps secret to a specific environment variable name during `sec run` or `sec export`.
*   **Usage**: `sec set database/prod/password "pass123" --desc "Production DB" --meta owner=devops --expires 30d`

#### `sec relabel <path>` / `sec edit-meta`
Updates metadata (description, operational notes, expiry, tags, alias) without altering the secret value or re-entering plaintext.
*   `--desc <text>`: Updates 1-line description.
*   `--notes <text>`: Updates multiline operational runbook.
*   `--expires <ttl>`: Updates expiration timestamp (or `clear` to remove).
*   `--meta <key=value>`: Sets or updates custom metadata tags.
*   **Usage**: `sec relabel api/stripe --expires 90d --desc "Stripe Live Key" --notes "Rotate quarterly"`

#### `sec gen <path>`
Generates a cryptographically strong random password (`crypto/rand`) and saves it directly to the vault.
*   `--length <N>`: Specifies character length. Default: `32`.
*   `--no-symbols`: Restricts generated characters to alphanumeric only.
*   **Usage**: `sec gen API_KEY --length 64 --no-symbols`

#### `sec migrate-local <path>`
Scans local `.env` files, ingests raw plaintext passwords into vault storage, and replaces local secrets with safe `<migrated_to_sec>` placeholders.
*   `--prefix <path>`: Vault destination path prefix.
*   `--profile <name>`: Target vault profile.
*   **Usage**: `sec migrate-local .env --prefix my-app --profile dev`

---

### 1.3. Secret Retrieval & Injection

#### `sec get <path>`
Retrieves a secret record from daemon RAM cache.
*   `--json`: Emits complete structured JSON record (value, comment, metadata, creation/expiration dates).
*   `--comment`: Emits only the record comment field.
*   `--meta <key>`: Emits only the specified metadata value.
*   `--prefix`: Queries and returns all secrets matching the prefix tree.
*   `--show-expired`: Overrides expiration blocks to recover expired keys.
*   **Usage**: `sec get database/prod/password`

#### `sec load <prefix>`
Outputs `export KEY="value"` shell statements for all secrets matching the path prefix.
*   **Usage**: `eval $(sec load project/dev/)`

#### `sec run [--profile <name>] [--group <prefix>] [--allow-keys <keys>] -- <command>`
Spawns a child process with vault credentials injected directly into process RAM.
*   `--profile <name>`: Selects profile vault.
*   `--group <prefix>`: Filters injected secrets by prefix subtree.
*   `--allow-keys <key1,key2>`: Enforces least-privilege scoping (only allowed keys are exposed; all other keys are suppressed).
*   `--ssh-key-secret <vault-key>` / `--key-secret <vault-key>`: Spawns ephemeral in-memory SSH agent directly populated from vault private key bytes (zero disk files), exporting `SSH_AUTH_SOCK` to the child command.
*   `--ssh-key <file>` / `-i <file>`: Spawns ephemeral in-memory SSH agent loaded from a local filesystem private key.
*   `--ssh-passphrase-key <vault-key>`: Resolves passphrase from vault to unlock encrypted private keys in memory.
*   `--stdin-key <vault-key>`: Streams vault secret directly into child process stdin.
*   `--temp-file <ENV=vault/key>`: Ephemerally materializes vault secret as a mode-0600 temp file shredded with zeroes upon child termination.
*   `--redact`: Automatically redacts injected vault secrets and derived encodings from child stdout/stderr.
*   **Usage**: `sec run --profile dev --allow-keys VCO_URL,VCO_ID -- npm test`
*   **Usage (Zero-Disk SSH)**: `sec run --ssh-key-secret ssh/switch/key -- git fetch origin`

---

### 1.4. Remote SSH Execution & Target Lifecycle (`sec ssh`)

#### `sec ssh [target | user@host] [-- <command>]`
Connects to remote hosts using credentials stored in the active vault. Defaults to native pure Go SSH execution (`golang.org/x/crypto/ssh`), ensuring zero host disk exposure and eliminating external tools like `sshpass`.

*   `--ssh-key-secret <vault-key>` / `--key-secret <vault-key>`: Vault path to private key (PEM / OpenSSH format). If omitted, `sec-agent` auto-resolves `ssh/<target>/key` or `ssh/<target>/private_key` from the active profile.
*   `--ssh-key <path>` / `-i <path>` / `--identity <path>`: Local filesystem identity file path.
*   `--ssh-passphrase-key <vault-key>`: Vault path containing passphrase for encrypted private keys.
*   `--password <pass>`: Explicit password override for target connection.
*   `--port <port>` / `-p <port>`: Overrides SSH destination port.
*   `--openssh` / `--fallback-openssh`: Delegates execution to system `/usr/bin/ssh` binary via an ephemeral in-memory `ssh-agent`.
*   `--no-trace`: Used with `--openssh` to suppress saving host keys to disk by injecting `-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentitiesOnly=yes`.
*   `--tofu` / `--trust-first-use`: Headless auto-pinning; automatically saves presented host key fingerprint to vault on initial connection without interactive prompt.
*   `--insecure` / `--no-verify`: Connects without verifying or mutating vault host key fingerprints (skips TOFU and mismatch checks).
*   `--update-host-key`: Replaces existing vault-pinned fingerprint with the newly presented host key fingerprint.

#### `sec ssh host-key show <target>`
Displays the pinned SHA-256 host public key fingerprint stored in the active vault under `ssh/<target>/host_fingerprint`.

#### `sec ssh reset-host-key <target>`
Removes the pinned host key fingerprint secret from the vault to reset TOFU trust after remote host re-installation.

#### `sec ssh init <target> --host <host> --user <user> [--port <port>] [--password <pass> | --key <path> | --key-secret <vault-key>]`
Interactively configures a named SSH target and persists configuration to `.secrc` and vault storage.

*   **Usage (Interactive)**: `sec ssh router`
*   **Usage (Remote Command)**: `sec ssh ax3600 -- uci show wireless`
*   **Usage (Headless TOFU)**: `sec ssh root@192.168.31.1 --tofu -- "uptime"`
*   **Usage (Zero-Trace OpenSSH)**: `sec ssh ax3600 --openssh --no-trace -- "uname -a"`
*   **Usage (Host Key Management)**: `sec ssh host-key show ax3600` and `sec ssh reset-host-key ax3600`

---

### 1.5. Refactoring & Maintenance

#### `sec mv <src> <dst>` / `sec rename`
Renames a secret or entire prefix subtree while preserving metadata and creation timestamps.
*   `--prefix`: Performs batch refactoring on prefix subtrees.
*   **Usage**: `sec mv legacy/ dev/ --prefix`

#### `sec cp <src> <dst>` / `sec copy`
Duplicates a secret or prefix subtree into a new target path.
*   `--prefix`: Duplicates entire prefix subtree.
*   **Usage**: `sec cp project/dev/ project/staging/ --prefix`

#### `sec rm <path>` / `sec delete`
Deletes a secret or batch prefix subtree.
*   `--prefix`: Batch deletes matching prefix tree.
*   **Usage**: `sec rm temp/ --prefix`

#### `sec ls [<prefix>]` / `sec list`
Lists stored secret paths, hygiene audits, or expiring keys without exposing raw values.
*   `--incomplete` / `--hygiene`: Scans vault secrets for missing lifecycle metadata (expiration date, description, operational notes).
*   `--expiring [N]`: Lists secrets expiring within N days (default: 7).
*   `--stale [N]`: Lists secrets unaccessed for N days (default: 30).
*   `--long`, `-l`: Displays detailed metadata table with versions and timestamps.
*   `--trash`: Lists soft-deleted secrets in the trash bin.
*   `--json`: Outputs JSON format.
*   **Usage**: `sec ls --incomplete` or `sec ls project/ --long`

---

### 1.5. Audit, Diagnostics & System Health

#### `sec status`
Prints daemon health, session status, stored secret counts, and active profile tier.
*   `--json`: Outputs machine-readable status JSON.
*   **Usage**: `sec status`

#### `sec audit` / `sec log`
Inspects security audit logs (`~/.config/sec/audit.log`).
*   `--limit <N>`: Restricts log output length.
*   `--json`: Outputs JSON array of audit events.
*   **Usage**: `sec audit --limit 50`

#### `sec doctor`
Performs automated pre-flight security checks (Secure Enclave biometrics, Keychain access, Unix socket permissions, runtime code signatures).
*   **Usage**: `sec doctor`

#### `sec diff`
Compares secret key paths between profiles or local `.env` files.
*   `--other-profile <name>`: Compares against specified target profile.
*   `--prefix <path>`: Restricts comparison to path subtree.
*   **Usage**: `sec diff --other-profile prod`

---

## 2. Environment Variables Catalog

| Environment Variable | Description | Scope / Behavior |
| :--- | :--- | :--- |
| `SEC_SESSION_TOKEN` | Cryptographically generated RAM-only session token | Required for CLI queries (`sec get`, `sec run`). Isolated to terminal process tree. |
| `SEC_PROFILE` | Default active secret profile | Overrides default profile scope (`default`, `prod`, `dev`). |
| `SEC_DAEMON_SOCKET` | Path to Unix Domain Socket | Defaults to `~/.config/sec/sec.sock`. |
| `SEC_VAULT_PATH` | Path to encrypted database store | Defaults to `~/.config/sec/secrets.enc`. |

---

## 3. Human Operator Work Instructions

### Work Instruction 1: Daily Workstation Startup
1. Open your terminal application (Terminal, iTerm2, Warp, VS Code).
2. Execute the single-step Touch ID session unlock:
   ```bash
   eval $(sec open)
   ```
3. Tap your Mac's Touch ID sensor when prompted. Your session is now authorized for the entire workday (8 hours TTL).

---

### Work Instruction 2: 30-Second Local `.env` Migration
1. Navigate to your local project directory:
   ```bash
   cd ~/projects/my-web-app
   ```
2. Run the automated migration command:
   ```bash
   sec migrate-local .env --prefix my-app --profile dev
   ```
3. Inspect your `.env` file to verify that raw passwords have been replaced with `<migrated_to_sec>` placeholders.

---

### Work Instruction 3: Executing Scoped AI Subagents
When delegating work to autonomous AI coding assistants (Antigravity, Cursor, Claude Code, Windsurf):
1. Restrict secret exposure strictly to required test keys using `--allow-keys`:
   ```bash
   sec run --profile dev --allow-keys VCO_URL,VCO_ENTERPRISE_ID -- make test
   ```
2. Any attempt by the subagent to read database passwords or cloud master keys will be suppressed and denied.

---

### Work Instruction 4: Accessing the Hardened Web UI (`SecAgent.app`)
1. Launch `/Applications/SecAgent.app` from Finder or Spotlight (or run `sec-agent gui` in your terminal).
2. Open `http://127.0.0.1:9876` in your browser.
3. Authenticate profile access via in-browser Touch ID.
4. **Single-Tab Security Note**: Do not open the URL in multiple tabs. Secondary tabs will return `403 Forbidden: Tab Lock Active` to prevent tab-hijacking.

---

### Work Instruction 5: Emergency Recovery & Daemon Restart
If the background daemon becomes unreachable or needs an emergency reset:
1. Run emergency socket cleanup and lock:
   ```bash
   sec lock
   rm -f ~/.config/sec/sec.sock
   ```
2. Re-initialize the daemon:
   ```bash
   eval $(sec open)
   ```

---

### Work Instruction 6: Upgrading to v2.0 Dual-Slot Vault

**Prerequisite**: An interactive terminal (not a script, not an AI agent context).

1. Run the migration command:
   ```bash
   sec migrate-v2
   ```
2. Read the 24 words displayed on screen and write them on paper. Do NOT photograph or copy them.
3. Pass the 3-word verification challenge when prompted.
4. Vault is atomically upgraded — no data loss is possible.
5. Create a KDBX backup immediately:
   ```bash
   sec backup vault_$(date +%Y%m%d).kdbx
   ```
   When prompted, enter your 24-word mnemonic. The KDBX will be locked with the same seed.

---

### Work Instruction 7: BIP39 Mnemonic Recovery

Use when Touch ID stops working (hardware failure, new fingerprints enrolled, OS reinstall):

1. Open an interactive terminal (physical keyboard, direct SSH, or local terminal).
2. Run:
   ```bash
   sec session recover
   ```
3. Enter your 24-word mnemonic at the prompt (one line, space-separated words).
4. Wait ~5 seconds for Argon2id derivation.
5. Touch ID to re-enroll the key in Keychain when prompted.
6. Start a new session:
   ```bash
   eval $(sec open)
   ```

**Recovery is aborted (no changes made) if:**
- The mnemonic is wrong (wrong words or bad checksum)
- The vault payload cannot be decrypted with the recovered key
- The terminal is non-interactive (piped/scripted)

---

## 2. New Commands Reference (v2.0+)

### `sec migrate-v2 [--dry-run]`
Upgrades vault to v2.0 Dual-Slot format with BIP39 recovery key enrollment.
- `--dry-run`: Shows what would happen without making any changes.
- **Requires**: Interactive TTY. Exits 78 (EX_CONFIG) if non-interactive.
- **Safety**: Uses two-phase atomic commit. Safe to retry after interruption.

### `sec session recover`
Recovers vault access using the 24-word BIP39 mnemonic (Slot 1).
- **Requires**: Interactive TTY. Exits 78 (EX_CONFIG) if non-interactive.
- **Result**: Re-enrolls master key in macOS Keychain. Does NOT change the mnemonic.

### `sec backup <file.kdbx> [--custom-password | -p <password>]`
Exports secrets to a KeePassXC file.
- **Default (v2.0 vault)**: Prompts for 24-word mnemonic; KDBX locked with Argon2id-derived key.
- **`--custom-password`**: Use a custom password instead of the BIP39 seed.
- **Legacy (v1.0 vault)**: Always prompts for a custom password (unchanged behavior).

