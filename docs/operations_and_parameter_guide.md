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
*   **Usage**: `eval $(sec open -t 10h -g 45m)`

#### `sec lock`
Immediately purges all decrypted session keys from background daemon RAM and invalidates the active `SEC_SESSION_TOKEN`.
*   **Usage**: `sec lock`

---

### 1.2. Secret Ingestion & Storage

#### `sec set <path> <value>`
Encrypts and saves a secret key-value record to disk.
*   `--comment <text>`: Adds descriptive administrative notes.
*   `--meta <key=value>`: Attaches custom key-value metadata tags (can be repeated multiple times).
*   `--expires <duration|ISO8601>`: Sets relative duration (e.g., `30d`, `12h`) or absolute UTC timestamp (e.g., `2026-12-31T23:59:59Z`).
*   **Usage**: `sec set database/prod/password "pass123" --comment "Prod DB" --meta owner=devops --expires 30d`

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
*   **Usage**: `sec run --profile dev --allow-keys VCO_URL,VCO_ID -- npm test`

---

### 1.4. Refactoring & Maintenance

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
Lists stored secret paths without exposing raw values to terminal logs.
*   `--json`: Outputs JSON array of key paths.
*   **Usage**: `sec ls project/`

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

