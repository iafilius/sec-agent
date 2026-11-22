---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, install AI skills, inspect snapshots, and manage backups.
version: v2.17.0
---

# sec-agent Secrets Management Integration (v2.17.0)

This skill enables AI coding agents and autonomous assistants to use the `sec-agent` CLI tool (v1.9.4+) to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, install integration skills across IDEs, inspect point-in-time snapshots (`sec snapshot`), and manage KeePassXC `.kdbx` backups on macOS.

---

## 1. Quick Diagnostics, Guided Setup & Upfront Session Bootstrapping

### 1.1. Upfront Session Bootstrapping Protocol for AI Assistants

> [!IMPORTANT]
> **Autonomous Agent Biometric Protocol**: Never abort a task or conclude you cannot proceed simply because a session is locked. Calling `sec open` via a standard terminal command runner displays the native system Touch ID dialog on the human operator's screen. Once the operator touches the sensor, your tool call returns success with exit code 0.

When operating in a workspace that uses `sec-agent` (indicated by a `.secrc` file in the directory tree or tasks explicitly requiring environment secrets/credentials):

1. **Conditional Turn-1 Pre-Flight Check**:
   * If a `.secrc` file is detected or the user's task requires accessing secured secrets, run `sec status --quick` (<5ms execution) during turn 1 to check the daemon session state.
   * If the workspace does not use `.secrc` and the task does not involve secrets, do not run pre-flight checks or request authentication.
2. **Session Memory & Daemon Retention**:
   * `sec-agent` runs an enclave-bound background daemon that retains unlocked session secrets in RAM (default 8-hour TTL).
   * Touch ID / Biometric authorization is required only once per session. Once unlocked, all subsequent subagent tool calls, child processes, and background commands inherit access frictionlessly without further prompts.
3. **Session Unlock Guidance (Preventing Mid-Run Interruption)**:
   * **Daemon Active / Running**: Proceed frictionlessly throughout the task trajectory.
   * **Daemon Locked / Not Running**: If the task requires secrets, the agent SHALL directly execute `sec-agent open` (or `sec open`, or the target `sec run` command) directly in its terminal tool runner at Turn 1. macOS natively displays the system Touch ID biometric window on the operator's physical display outside chat channels. **Do NOT hesitate to execute `sec open` or conclude you cannot do Touch ID**; you are invoking the local CLI which prompts the local human operator on their physical screen. Once unlocked, the background daemon detaches into its own POSIX session and persists for 8 hours across separate subsequent tool turns and subprocesses without requiring command chaining (`eval $(sec open) && ...`).
   * **Decryption Authentication Errors**: If unlocking or recovery returns `cipher: message authentication failed`, immediately run `sec-agent doctor` to check for nested envelope depth anomalies before advising the user to re-enter their 24-word recovery seed.
4. **Long-Running & Unattended Task Longevity Protocol**:
   * **Anticipated Long Jobs**: When the agent is tasked with executing long-running, multi-step, batch, or unattended workflows (such as `/goal`, lengthy test suites, kernel/code compilation, data migrations, or overnight background tasks), the agent **MUST proactively verify remaining session TTL** at Turn 1 via `sec status` or `sec status --quick`.
   * **In-Flight Session Extension (`sec extend`)**: If the session is active but remaining TTL is insufficient for the anticipated workload, the agent SHALL run:
     ```bash
     sec extend --ttl <duration> # e.g. sec extend --ttl 24h
     ```
     This pushes back daemon expiration in memory **without triggering Touch ID**, preventing mid-run failures while the human operator is away or asleep.
   * **Automatic Low-TTL Extension (`--auto-extend`)**: Pass `--auto-extend` to `sec run` or `sec get` (or configure `"auto_extend": true` in `.secrc`). When remaining session TTL drops below 15 minutes, `sec-agent` automatically calls `sec extend` in the background prior to command execution.
   * **Sliding Hard TTL Refresh**: Active authenticated requests occurring within the daemon's inactivity grace period automatically slide hard session expiration forward, eliminating abrupt expirations during continuous background work.
   * **Upfront Extended Unlock**: If the session is currently locked and a long unattended task is about to begin, prompt the user or execute `sec open` with an explicit duration:
     ```bash
     sec open --ttl 24h # or configured in .secrc: {"ttl": "24h"}
     ```
5. **Graceful Biometric Timeout & Task Deferral Protocol (Operator AFK Handling)**:
   * **Active 120-Second Timeout**: Touch ID prompts enforce an active 120-second timeout (configurable via `--timeout <duration>`, `.secrc` `"prompt_timeout"`, or `SEC_PROMPT_TIMEOUT`). When an operator is away from keyboard (AFK), the system invalidates the prompt dialog, alerts the operator via desktop notification and audio cue, and exits with code 4 (`ERR_BIOMETRIC_TIMEOUT`).
   * **Autonomous Agent Action on Exit Code 4**:
     1. **Do NOT abort or fail the task trajectory**: Exit code 4 is non-fatal; it indicates the operator is temporarily away.
     2. **Partition Workload**: Immediately partition pending tasks into offline/vault-free steps vs. secret-dependent steps.
     3. **Execute Vault-Free Work**: Proceed with all offline tasks immediately (e.g. code editing, refactoring, local unit tests, linting, formatting, documentation, git staging).
     4. **Frictionless Resumption**: When secrets are required or the operator sends a message in chat, prompt:
        `"Biometric prompt timed out while you were away. Please run 'sec open' (or approve Touch ID) to proceed with [remaining tasks]."`
   * **Exit Code Reference**:
     * `0`: Success / Unlocked
     * `1`: User Canceled (`LAErrorUserCancel` / dialog dismissed)
     * `2`: Invalid CLI syntax or biometrics unavailable
     * `3`: Vault locked / daemon not running
     * `4`: `ERR_BIOMETRIC_TIMEOUT` (120s expired, operator AFK — trigger deferral protocol)
     * `5`: `ERR_BIOMETRIC_LOCKOUT` (OS requires passcode reset before biometrics re-arm)
     * `6`: `ERR_BIOMETRIC_FAILED` (sensor rejected fingerprint)

### 1.2. Pre-flight Initialization Guard (`sec-agent init`)
When running `sec-agent` on a fresh workstation or uninitialized environment:
* If `~/.config/sec-agent/` does not exist, commands will return:
  ```text
  Error: sec-agent configuration directory (~/.config/sec-agent/) is missing or uninitialized.

  Please initialize your vault environment by running:
      sec-agent init
  ```
* **Guided & Non-Interactive Onboarding**: Run `sec-agent init` (or `sec-agent setup`). Pass `--vault` to interactively enroll Touch ID and generate a 24-word recovery seed immediately. Pass `--non-interactive` (or `-y` / `--yes`) in non-interactive CI/CD setups to initialize configuration directories (`~/.config/sec-agent/` and `~/.config/sec-agent/snapshots/`) silently without terminal prompt menus.

### 1.3. Diagnostics & Fast-Path Status Verification
```bash
# Ultra-fast (<5ms) pre-flight socket permission & daemon PID check
sec-agent status --quick [-q]

# Check CLI binary version and query active background daemon status
sec-agent version [--json]

# View single-pane-of-glass status across all profiles
sec-agent status --all

# Run deep pre-flight vault envelope, keychain key, and system diagnostics
# (Pass --skip-keychain or run in headless/agent environments to skip live Touch ID challenge; pass --probe-keychain to opt-in)
sec-agent doctor [--skip-keychain] [--probe-keychain]

# Audit and automatically flatten multi-nested corrupted vault envelopes offline
sec-agent doctor --repair
```

* **Daemon "Active" / "Running"**: The session is unlocked and secrets are queryable. `Remaining TTL` is visible in `sec status`.
* **Daemon "Session locked" / "Not running"**: Tell the user to run `eval $(sec-agent open)` (or `sec open`).
* **Version Mismatch**: Advise user to run `sec-agent restart` and `eval $(sec-agent open)`.
* **Zero-Biometric Slot 1 Audit in Doctor**: `sec doctor` statically verifies that every vault envelope on disk has an enrolled Slot 1 (BIP39) recovery seed in both interactive and headless environments. Vaults lacking recovery keys are prominently flagged:
  `[🔴] Profile <name> Vault: NO Slot 1 Recovery Key Enrolled (CRITICAL RISK) — Run 'sec enroll-recovery --profile <name>' to protect.`
* **Multi-Nested Envelope Auto-Repair (`sec doctor --repair`)**: If diagnostic output reports `Depth Anomaly Detected (nesting_depth > 1)` on any `.enc` vault, running `sec doctor --repair` safely writes a `.bak_nested` backup and flattens all affected profile envelopes down to single-layer format offline without requiring Keychain biometrics or seed phrases.

### 1.4. Skill Version Synchronization & Dynamic Re-Read Protocol
When `sec-agent` is updated on the workstation (e.g. via Homebrew or source rebuild), the CLI detects version differences against `skills_manifest.json`. To prevent unexpected disk churn or IDE reloads during read-only commands, the CLI emits an advisory notice to stderr prompting the operator or agent to update.

**CRITICAL RULE FOR AI ASSISTANTS**:
1. **Dynamic Version Drift Detection**: When executing `sec status`, `sec status --quick`, or any CLI command, if the CLI output indicates:
   * An advisory upgrade notice (`[sec-agent] 💡 Active workspace AI skill instructions trail CLI version ... Run 'sec-agent skill update' to refresh.`), or
   * A CLI version newer than this document's declared version (`v2.14.4`),
2. **Immediate Update & Re-Read Obligation**:
   * Execute `sec-agent skill update` to refresh installed skills to the latest binary version.
   * Then **IMMEDIATELY INVOKE your file viewing tool** (e.g. `view_file`) on the installed skill path (such as `.agents/skills/sec-agent-integration/SKILL.md` or `~/.gemini/config/skills/sec-agent-integration/SKILL.md`) before taking further action. This purges stale cached instructions from the LLM conversation context and equips the agent with new commands, flags, and security rules.

### 1.5. Guided Profile Onboarding Wizard & Profile Summaries (`sec profile`)
Creating a new isolated profile previously required multiple steps (`init`, `set`, and `migrate-v2`). Now you can provision a complete Dual-Slot vault in a single guided step with an optional human-readable profile summary:
```bash
# Interactively choose between generating a new seed or linking an existing master recovery seed
sec profile new <profile-name>

# Provision a new profile with an unencrypted human-readable summary
sec profile new <profile-name> --summary "Production Kubernetes cluster secrets"

# Directly link an existing 24-word master recovery seed phrase (skips menu and throwaway seed generation)
sec profile new <profile-name> --reuse-seed   # alias: --existing-seed

# Non-interactive / pre-supplied recovery seed
sec profile new <profile-name> --seed "<24-word mnemonic>" [--secrc | --no-secrc]

# Inspect unencrypted profile metadata, vault path, format, and summary without Touch ID biometrics
sec profile describe <profile-name> [--json]

# Update or clear unencrypted profile summary without unlocking biometrics or modifying cryptographic payload
# Aliases: --comment, --description
sec profile describe <profile-name> --summary "Updated cluster secrets description"
sec profile describe <profile-name> --clear-summary

# Inspect all discovered profile vaults, schema health, and summaries in a formatted columnar table
sec profile ls [--long] [--json] # alias: sec profile list

# Statelessly resolve which workspace profile, tier, and .secrc file apply to any directory tree
sec which [<path>] [--json] # alias: sec profile which [<path>]

# Enroll or re-wrap a BIP39 recovery seed on an existing profile vault (first-class replacement for migrate-v2)
sec enroll-recovery [--profile <name>] [--seed <seed>] [--dry-run] [--no-single-line]
```
* **Stateless Workspace Resolution (`sec which [path]`)**: Resolves workspace `.secrc` / `.secenv` / `.sec.json` configurations on-demand for any given path or current working directory without persistent file caching. Output includes target directory, resolved profile, config file path, workspace root, environment alias, and tier.
* **First-Class Recovery Enrollment (`sec enroll-recovery`)**: Dedicated command to enroll or re-wrap Slot 1 (BIP39) recovery seed phrases on existing vaults without legacy migration terminology.
* **Unencrypted Profile Summaries (`sec profile describe`)**: Vault profiles (`secrets_<profile>.enc`) contain an unencrypted `summary` field in their outer `VaultEnvelope`. This enables instant, zero-biometric inspection (`sec profile describe <name>`, `sec profile ls --long`, `sec profile ls --json`) across multiple repositories and projects before unlocking. Supports `--comment` and `--description` aliases.
* **Upfront Recovery Seed Choice**: When invoked interactively without `--seed`, `sec profile new` offers a clear choice before generating anything:
  * `[1] Generate a new 24-word recovery seed (Default)`: Generates a new 24-word mnemonic, displays the security warning and word grid, and verifies words #4, #12, and #20.
  * `[2] Link an existing 24-word master recovery seed phrase`: Prompts directly for your existing 24-word seed without generating or printing any throwaway mnemonic, ensuring zero confusion.
* **Direct Linking Flag (`--reuse-seed` / `--existing-seed`)**: Pass `--reuse-seed` to skip the menu and immediately prompt for your existing master recovery seed phrase.
* **Word Verification Fallback**: If you selected Option 1 to generate a new seed, entering `r` or `reuse` during word verification still allows switching to link an existing seed phrase instead.
* **Cryptographic Independence**: Reusing the same master 24-word recovery seed across profiles is 100% secure. Each profile envelope retains an independent 32-byte master key and a unique random Argon2id salt.
* Automatically validates profile name invariants (rejecting slashes, spaces, and path traversals).
* Outputs both a 4-column reading table and a raw single-line space-separated mnemonic string (`📋 Raw Mnemonic`) for direct password manager copying across `sec profile new`, `sec migrate-v2`, `sec enroll-recovery`, and `sec session rotate-seed` (pass `--no-single-line` to suppress the single line for strict paper-only workflows).
* Automatically offers to generate a workspace `.secrc` (`{"profile": "<name>"}`) binding the active directory to the new vault, echoing the resolved path and warning if outside a git repository.

---

## 2. Multi-IDE Skill Installer & Manifest Auto-Sync (`sec-agent skill`)

`sec-agent` embeds its canonical `SKILL.md` directly inside the Go binary via `//go:embed` and tracks installed skill target locations in `~/.config/sec-agent/skills_manifest.json`.

### 2.1. Skill Subcommands & Multi-IDE Target Matrix
```bash
# Install AI skill for a specific IDE target and scope
sec-agent skill install --target <target> [--scope global|workspace]

# View status of installed skills, scopes, and live disk integrity
sec-agent skill status

# Update all manifest-tracked and discovered workspace skills to current binary version
sec-agent skill update
```

* **Scope Definitions**:
  * `global`: Machine-wide in user home directory (`~/.gemini/config/skills/`, `~/.cursor/rules/`, `~/.claude/skills/`). Applies across all projects on this machine.
  * `workspace`: Project-bound in current repository (`.github/copilot-instructions.md`, `.agents/skills/`, `.cursor/rules/`, `.windsurfrules`). Committed and shared with project source code.
* **Live Filesystem Scanning**: `skill status` automatically discovers unmanifested workspace skill files in the active working directory and validates byte-level integrity against the running binary.

| IDE Target | Scope | Destination Path |
| :--- | :--- | :--- |
| `antigravity` | `global` | `~/.gemini/config/skills/sec-agent-integration/SKILL.md` |
| `antigravity` | `workspace` | `.agents/skills/sec-agent-integration/SKILL.md` |
| `copilot` | `workspace` | `.github/copilot-instructions.md` |
| `cursor` | `global` | `~/.cursor/rules/sec-agent.mdc` |
| `cursor` | `workspace` | `.cursor/rules/sec-agent.mdc` |
| `claude` | `global` | `~/.claude/skills/sec-agent.md` |
| `claude` | `workspace` | `.claude/skills/sec-agent.md` |
| `windsurf` | `workspace` | `.windsurfrules` |

### 2.2. Skill Sync & Upgrade Protocol (`skills_manifest.json`)
When `sec-agent` is updated (e.g. via `brew upgrade sec-agent`), the CLI compares `skills_manifest.json` manifest version with binary `Version`. Read-only commands (`--version`, `--help`) remain strictly non-mutating and will not touch installed skills or manifest files. To update all installed skill files across tracked IDE locations in-place, run:
```bash
sec-agent skill update
```
The CLI verifies SHA-256 integrity hashes, updates files to the current binary release, and updates `skills_manifest.json`.

---

## 3. Point-in-Time Vault Snapshots & Disaster Recovery (`sec-agent snapshot`)

### 3.1. Vault Snapshot Inspection & Restoration
`sec-agent` maintains indexed `.enc` snapshots in `~/.config/sec-agent/snapshots/<profile>/` with master key SHA-256 fingerprinting (`sha256:16hex`) and secret count metadata.

```bash
# List all point-in-time snapshots with key matching & secret counts
sec-agent snapshot list (alias: sec snapshots)

# Create a manual point-in-time snapshot
sec-agent snapshot create [--comment "note"]

# Restore an internal point-in-time snapshot (creates pre-restore safety copy automatically)
sec-agent snapshot restore <SNAPSHOT_ID> [--force]

# Import external portable KeePassXC archives (.kdbx, .json, .csv)
sec-agent backup import <file.kdbx> [--merge | --overwrite]
```

### 3.2. 4-Step Disaster Recovery Protocol
When vault corruption or session state issues occur, follow this 4-step recovery process:
1. **Inspect Available Snapshots**: Run `sec-agent snapshot list`.
2. **Restore Target Snapshot**: Run `sec-agent snapshot restore <SNAPSHOT_ID> --force`.
3. **Reset Daemon Socket State**: Run `sec-agent restart`.
4. **Re-authenticate Shell Session**: Run `eval $(sec-agent open)`.

### 3.3. Dual-Slot Biometric & 24-Word Recovery Seed Governance (v2.0+)
sec-agent v2.0+ utilizes a **LUKS-Style Dual Key-Slot Architecture**:
* **Slot 0**: Master key protected by macOS Keychain Touch ID under `kSecAccessControlBiometryCurrentSet`. Invalidated automatically if any fingerprint is added or removed in macOS System Settings.
* **Slot 1**: Master key wrapped with AES-256-GCM using an Argon2id key derived from an offline 24-word BIP39 Recovery Seed.

**CRITICAL RULES FOR AI ASSISTANTS & AGENTS**:
1. **NO Seed Handling in Non-Interactive TTYs**: `sec profile new`, `sec migrate-v2`, and `sec session recover` enforce a TTY safety lock (`isatty`). They WILL EXIT WITH CODE 78 (`EX_CONFIG`) if executed in headless, piped, or subagent tool call environments.
2. **Actionable Framed Blocker on Exit Code 78**:
   When physical terminal intervention is required, `sec-agent` prints a clear ASCII action frame before exiting with code 78:
   ```text
   +------------------------------------------+
   | 🔒 INTERACTIVE TERMINAL REQUIRED         |
   +------------------------------------------+
     Reason: Vault migration enrolls a 24-word recovery seed
     Please run this in your physical terminal:

       sec-agent migrate-v2 --profile <profile>

   +------------------------------------------+
   ```
   **DO NOT retry the command in a loop.** Instead, immediately relay the enclosed command to the human user and pause execution until they confirm completion in their physical terminal.
3. **NEVER Request or Log Recovery Seeds**: AI agents MUST NOT prompt for, parse, store, or output 24-word seed phrases.
4. **Emergency Un-Bricking Protocol**: If Touch ID authentication fails due to hardware change or OS update, inform the human user: *"Touch ID is invalidated. Please open your physical terminal and run `sec session recover` to restore access with your 24-word paper seed."*

---

## 4. Operational Best Practices & Protocol Governance

### 4.1. MFA Web Login vs. API Token Protocol Distinction
* **Interactive Web UI Logins**: Interactive Web UI session logins (e.g., logging into web portals) trigger SMS/push 2FA challenges requiring manual user Touch ID / 2FA code entry.
* **Automated API Execution**: For automated scripts, CI/CD pipelines, and AI agent execution, use long-lived API JWT Tokens (`Authorization: Token <jwt>`) stored in `sec-agent` (e.g., `sec-agent set project/api_token`). API tokens bypass interactive 2FA challenges entirely and are designed for headless process execution.

### 4.2. Centralized Source Governance & Feedback Protocol
* **NEVER edit installed `SKILL.md` files directly** inside target installation folders (e.g., `~/.gemini/config/skills/`, `.agents/skills/`, or `.cursor/rules/`).
* **Record Improvements Centrally**: When an AI assistant or developer discovers skill improvements, record suggestions in `docs/SEC_TOOL_FEEDBACK.md` within the `secure_secrets` repository. Canonical changes are made centrally in `secure_secrets/docs/skills/sec-agent-integration/SKILL.md` and propagated via `sec-agent skill update`.

---

## 5. Common Operations

### 5.1. Executing Applications & Pipelines with Secrets
Instead of reading from unencrypted `.env` files, wrap process executions:
```bash
sec-agent run [--profile <profile-name>] [--auto-open] -- <command-line>
```

### 5.2. Batch Loading Scoped Secrets for Purpose/Environment
```bash
sec-agent run --group my-project/terraform/acceptance -- terraform plan
eval $(sec-agent load my-project/terraform/acceptance)
```

### 5.3. Storing Secrets Securely (Interactive Prompt & Stdin)
```bash
# Hidden prompt (prevents shell history leakage)
sec-agent set app-secrets/db-pass

# Pipe secret value from Stdin (trailing newlines trimmed automatically)
echo "secret-value" | sec-agent set app-secrets/db-pass --stdin

# Pipe multiline secrets (e.g. PEM private keys, TLS certs) preserving exact raw byte stream
cat id_ed25519 | sec-agent set ssh/private_key --stdin --no-trim

# Direct value with concise description and multiline notes (two-tier metadata)
sec-agent set app-secrets/db-pass "secret-value" --desc "Primary DB password" --notes "Rotated monthly by DBA"

# Direct value with custom environment alias and metadata
sec-agent set app-secrets/db-pass "secret-value" --env-alias DB_PASSWORD --comment "Production DB password"
```

### 5.4. Formatted Metadata Inspection (`sec-agent describe`)
Inspect full metadata, timestamps, versioning, access metrics, and multiline notes:
```bash
# Formatted human-readable overview with structured sections
sec-agent describe app-secrets/db-pass

# Machine-readable JSON output
sec-agent describe app-secrets/db-pass --json
```

### 5.5. Editing Secret Notes Interactively (`sec-agent edit-notes`)
Launch `$EDITOR` using a secure 0600 temporary file to edit multiline operational notes without altering the secret value:
```bash
sec-agent edit-notes app-secrets/db-pass
```

### 5.6. Subprocess Stdin Secret Streaming (`sec run --stdin-key` & `sec pipe`)
Orchestrate external CLI utilities (e.g. `keepassxc-cli`, `gpg`, `docker login`) without temporary files or shell pipes:
```bash
# In-memory stdin injection (appends newline '\n' by default for interactive password prompts)
sec-agent run --stdin-key kdbx/master_key -- keepassxc-cli merge -s target.kdbx incoming.kdbx

# In-memory stdin injection without trailing newline (pure raw bytes)
sec-agent run --stdin-key token/raw --stdin-raw -- ./service_consumer

# Pure binary stream to stdout with zero decoration (exit codes 0: success, 2: not found, 3: locked)
sec-agent pipe kdbx/master_key | keepassxc-cli ls target.kdbx
```

### 5.7. Relabeling & Metadata Updates Without Plaintext Exposure (`sec-agent relabel`)
Update environment aliases, descriptions, multiline notes, comments, expiration timestamps, or custom metadata tags on an existing secret without retyping or exposing the secret plaintext:

```bash
# Update description and notes without altering secret value or re-authenticating biometrics
sec-agent relabel myapp/token --desc "Production API Token" --notes "Created by CI pipeline; rotated quarterly"

# Update environment alias (controls variable name during 'sec export' and 'sec run')
sec-agent relabel myapp/token --env-alias MYAPP_API_TOKEN

# Update comment and custom metadata tags
sec-agent relabel myapp/token --comment "Production API Token" --meta owner=devops --meta tier=critical

# Update expiration timestamp
sec-agent relabel myapp/token --expires 2026-12-31T23:59:59Z

# Clear environment alias, description, or notes
sec-agent relabel myapp/token --clear-alias --clear-desc --clear-notes
```

### 5.8. Secret Lifecycle Metadata & Proactive Enrichment Protocol

> [!IMPORTANT]
> **Autonomous Agent Rule: Never Leave Ingested Secrets Bare**:
> When an autonomous assistant stores a secret (via `sec set`, `.env` migration, or script generation), it MUST proactively offer to complete the entry with an expiration date, renewal dashboard URL, or rotation runbook using `sec relabel`:
> `"Stored <key>. Would you like to attach an expiration date (e.g. 90d), renewal URL, or rotation instructions?"`

#### Standardized Renewal Runbook Template for `--notes`:
When adding renewal instructions to `--notes`, format as structured Markdown:
```markdown
### Renewal Runbook: <key>
* **Owner:** Team or alert email (e.g. devops@company.com)
* **Console URL:** https://console.cloud.google.com/apis/credentials
* **Rotation Cadence:** 90 days (or quarterly)
* **Rotation Steps:**
  1. Generate replacement credential in Console URL.
  2. Test with `sec pipe <key> | <validation-command>`
  3. Update vault: `sec set <key> --stdin`
  4. Decommission previous credential.
```

### 5.9. Secret Hygiene Scanning & Remediation (`sec list --incomplete`)
Audit all secrets in a vault profile for missing lifecycle metadata (expiration dates, descriptions, or operational notes):

```bash
# Formatted columnar terminal report of incomplete or bare secrets
sec list --incomplete    # alias: sec ls --hygiene

# Structured machine-readable JSON for autonomous agents
sec list --incomplete --json
```

### 5.10. Querying & Renaming Secrets
```bash
sec-agent get my-project/terraform/acceptance/ --prefix [--json]
sec-agent mv old-path/ new-path/ --prefix
```
* **`sec get` always prints the real value to stdout, in any context** — there is no automatic masking for non-interactive/piped consumers (including AI agent tool-call terminals). Prefer `sec run -- <cmd>` or env-injection for scripts/agents; reserve `sec get` for deliberate human/`--raw` use.

### 5.9. Environment Isolation & Safety Badges
```bash
sec-agent profile set-env prod --profile my-project-prod
sec-agent run --confirm-prod --profile my-project-prod -- terraform apply
```

### 5.10. Time-Bound Secret Leases & Revocation (`sec-agent lease`)
```bash
# Grant a 15-minute temporary lease token for an AI subagent
lease_token=$(sec-agent lease my-project-dev/vco_token --ttl 15m)

# Revoke temporary lease token immediately upon task completion
sec-agent lease revoke $lease_token
```
Delegate temporary credential access to subagents with **zero credential lingering**.

### 5.11. Real-Time Secret Redaction, Derived Encodings & Hex Protection (`sec-agent run --redact` & `sec-agent redact`)
```bash
# Dynamic stream redaction: Automatically replaces all injected vault secrets in child stdout/stderr
# with '[REDACTED_BY_SEC]' using buffer-boundary-aware sliding window streaming
sec-agent run --redact -- make testacc

# Run with key filters and stream redaction
sec-agent run --allow-keys VCO_URL,VCO_TOKEN --redact -- make test-unit

# Inline URI replacement: In-memory argument replacement for legacy tools requiring password flags (-p)
sec-agent run -- ./legacy_tool -p "sec://db/password"

# Pipe subprocess streams through standalone stream redactor
cat application.log | sec-agent redact
```
* **Derived Encodings Redaction (Base64 & URL-Encoded)**: In both `sec run --redact` and `sec redact`, `sec-agent` automatically expands active profile secrets into their standard Base64-encoded strings (`Authorization: Basic ...`, `Bearer ...`) and URL-encoded query/path variants (`%2F`, `%2B`, `%3D`). Subprocess stdout/stderr containing these derived encodings are sanitized automatically (`[REDACTED_BY_SEC]` in `sec run`, or `[REDACTED_SEC_SECRET:<name> (base64)]` / `[REDACTED_SEC_SECRET:<name> (url-encoded)]` in `sec redact`), preventing credential exposure during verbose HTTP client traces.
* **Hex Collision & Git SHA Protection**: When a vault secret consists of hexadecimal characters (e.g. `c0ffee` or an 8-char hex token), word boundary heuristics verify adjacent characters. Matches that are substrings of longer 40-character Git commit SHAs or 64-character SHA-256 package digests are recognized as collisions and preserved intact, preventing log corruption and false-positive pre-commit blocks.

### 5.12. Ephemeral Temporary File Injection (`sec-agent run --temp-file`)
Many production tools (`curl`, `kubectl`, `helm`, Docker, cloud SDKs) require physical credential files on disk rather than environment variables or command-line arguments:

```bash
# Inject temporary mode-0600 .netrc file populated from vault key into $NETRC:
sec-agent run --temp-file NETRC=auth/netrc -- curl --netrc-file "$NETRC" https://api.internal/v1/metrics

# Inject temporary kubeconfig configuration for kubectl:
sec-agent run --temp-file KUBECONFIG=clusters/dev-kubeconfig -- kubectl get pods -A

# Inject multiple temporary files (e.g. client mTLS certificate and private key):
sec-agent run \
  --temp-file CLIENT_CERT=certs/client.pem \
  --temp-file CLIENT_KEY=certs/client.key \
  -- curl --cert "$CLIENT_CERT" --key "$CLIENT_KEY" https://mtls.internal

# Inject file rendered from template file or inline mustache syntax:
sec-agent run --temp-file CONFIG_FILE=templates/agent.yaml.tmpl -- ./agent-daemon
```

* **Guaranteed Zero-Fill Shredding**: Temporary files are created in `$TMPDIR` with strict mode `0600` permissions. Upon process completion or signal termination (`SIGINT`, `SIGTERM`, `SIGHUP`), `sec-agent` immediately overwrites all temporary file bytes with zeroes before unlinking them from disk, ensuring **zero disk credential residue**.
* **Flexible Target Resolution**: Targets can be a direct vault key (`auth/netrc`), an inline mustache template (`{{auth/username}}:{{auth/password}}`), or a local template file on disk.
* **Stream Redaction Integration**: Contents of all generated temporary files are automatically registered with the stream redactor so accidental echoes or verbose traces are masked in stdout/stderr.

### 5.13. Native Pure Go SSH Client, Automated Key Ingestion & Host Sanitizer (`sec-agent ssh`)
`sec-agent` provides a built-in pure Go SSH client that authenticates directly using credentials stored in the active vault—completely eliminating the need for external `sshpass` utilities on macOS/Linux. Native Go SSH execution is the default engine for both password and private key authentication, executing entirely in memory without writing keys to disk or `/tmp`.

```bash
# Ingest OpenSSH private key directly into vault, record metadata, and shred source file and companion .pub:
sec-agent ssh import-key switch1 ~/.ssh/id_ed25519 --shred

# Ingest private key and shred source file, but preserve companion .pub on disk:
sec-agent ssh import-key switch1 ~/.ssh/id_ed25519 --shred --keep-pub

# Ingest shared administrative deployment key into vault (ssh/shared/<name>/private_key):
sec-agent ssh import-key --shared sonic_fabric ~/.ssh/id_ed25519_fabric --shred

# Ingest passphrase-protected key using passphrase from vault:
sec-agent ssh import-key switch1 ~/.ssh/id_rsa --passphrase-key ssh/switch1/passphrase --shred

# Scrub workstation ~/.ssh/known_hosts of target host/IP (both cleartext and HMAC-SHA1 hashed entries):
sec-agent ssh sanitize switch1

# Batch scrub all registered SSH targets from ~/.ssh/known_hosts and delete known_hosts.old:
sec-agent ssh sanitize --all

# Initialize target, ingest private key directly into vault, shred source file, and sanitize known_hosts:
sec-agent ssh init switch1 --host 192.168.122.10 --user admin --import-key ~/.ssh/id_switch --shred

# Initialize target referencing a shared vault key ($O(1) single-point rotation across switches):
sec-agent ssh init leaf-01 --host 192.168.122.11 --user admin --key-secret sonic_fabric

# Connect to named target (auto-resolves vault key ssh/<target>/key, ssh/<target>/private_key, or shared pointer):
sec-agent ssh switch1

# Explicit vault key path override:
sec-agent ssh root@192.168.31.1 --ssh-key-secret ssh/homelab/admin_key -- "uptime"

# Execute non-interactive remote command with zero disk exposure:
sec-agent ssh switch1 -- "uname -a"

# Automated / headless host key verification (Trust-On-First-Use pins fingerprint to vault):
sec-agent ssh switch1 --tofu -- "uptime"

# Inspect pinned host key fingerprint in vault:
sec-agent ssh host-key show switch1

# Reset pinned host key fingerprint after remote reflash or rebuild:
sec-agent ssh reset-host-key switch1

# Update pinned host key fingerprint in-flight:
sec-agent ssh switch1 --update-host-key -- "uptime"

# Insecure bypass (ignores host key verification; does not mutate vault):
sec-agent ssh switch1 --insecure -- "uptime"

# Delegated OpenSSH fallback with zero-trace known_hosts suppression:
sec-agent ssh switch1 --openssh --no-trace -- "uptime"
```
* **Native Pure Go Default**: Connects directly in-process via `golang.org/x/crypto/ssh` for both password and key authentication without invoking external `/usr/bin/ssh` or `sshpass`.
* **Zero Disk Private Keys**: Decrypts OpenSSH/PEM keys directly from vault storage in memory. No temporary files are ever created on disk or in `/tmp`.
* **Automated Key Ingestion & Secure Shredding (`sec ssh import-key --shred [--keep-pub]`)**: Loads private key into memory, validates PEM/OpenSSH format, commits to `ssh/<target>/private_key` with fingerprint metadata, and (only after verified vault commit) overwrites source file with pseudo-random bytes and zeros via `f.Sync()` before unlinking. Companion public key files (`<path>.pub` and `<path>-cert.pub`) are automatically discovered and multi-pass shredded unless `--keep-pub` is specified. If validation or vault write fails, all physical source files are preserved intact.
* **Shared Vault Key References (`sec ssh init --key-secret <key>`, `sec ssh import-key --shared <name>`)**: Allows entire multi-switch fabrics or server clusters to reference a single administrative key in `ssh/shared/<name>/private_key`. Target credential resolution automatically dereferences `ssh/<target>/key_secret` pointers in memory, achieving $O(1)$ single-point key rotation without duplicate vault copies or target re-initialization.
* **Workstation `known_hosts` Forensic Sanitizer (`sec ssh sanitize [<target>] [--all]`)**: Purges target hostnames, IPs, and port variants from `~/.ssh/known_hosts`. Accurately evaluates and scrubs both cleartext entries and OpenSSH HMAC-SHA1 hashed entries (`|1|<salt>|<hash>`) and unlinks lingering `~/.ssh/known_hosts.old` backups.
* **Single-Step Remote Onboarding (`sec ssh init --import-key <path> [--shred] [--keep-pub]`)**: Onboards remote nodes, stores private keys directly into vault, shreds plaintext key and companion `.pub` files from disk, and sanitizes historical `known_hosts` in a single command without persisting local filesystem paths in `.secrc`.
* **Vault-Backed Host Key Pinning (TOFU)**: Public host key SHA-256 fingerprints are pinned into encrypted vault storage (`ssh/<target>/host_fingerprint`). If a host key changes, connection aborts immediately with `HOST_KEY_MISMATCH` to prevent MitM attacks.
* **Zero-Trace OpenSSH Delegation (`--no-trace`)**: When delegating to system OpenSSH via `--openssh`, `--no-trace` injects `-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentitiesOnly=yes`, leaving zero host traces in `~/.ssh/known_hosts`.
* **Exit Code Propagation**: Remote command exit codes (`exitErr.ExitStatus()`) propagate directly to the calling shell.

### 5.14. Companion Metadata Environment Variables
Stored secret metadata (e.g. `subnet=192.168.31.0/24`, `gateway=192.168.31.1`) is automatically exported as companion environment variables (`<KEY>_<META_KEY>`) during `sec run`:
- `ROUTER_ADMIN="<secret>"`
- `ROUTER_ADMIN_SUBNET="192.168.31.0/24"`
- `ROUTER_ADMIN_GATEWAY="192.168.31.1"`

### 5.14. Remote Configuration Drift Verification (`sec-agent check --remote`)
```bash
# Compare live remote OpenWrt UCI settings or environment variables against vault keys (zero plaintext leak)
sec-agent check --remote root@192.168.31.1 --uci wireless.wifinet_dev_5g.key=wifi/passphrase
sec-agent check --remote deploy@api.prod --env API_TOKEN=prod/api_token
```

### 5.15. Ephemeral SSH Agent & Vault Key Injection (`sec-agent run --ssh-key` & `--ssh-key-secret`)
```bash
# Launch ephemeral in-memory SSH agent with filesystem key and vault passphrase:
sec-agent run --ssh-key ~/.ssh/id_ed25519_ax3600 \
              --ssh-passphrase-key router-ax3600-prod/ssh/key_passphrase \
              -- ssh root@192.168.31.1 "uci show"

# Launch ephemeral in-memory SSH agent directly from vault-stored private key (zero disk files):
sec-agent run --ssh-key-secret ssh/ax3600/key -- git clone git@github.com:org/repo.git
```
* **In-Memory Agent**: Spins up an in-process ephemeral SSH agent, populates it from vault bytes in RAM, sets `SSH_AUTH_SOCK` for the child command, and cleanly terminates the agent on exit.

### 5.16. Stdin Stream Injection & Redaction (`sec-agent stream`)
```bash
# Evaluate {{key_path}} placeholders in-memory without process table (ps aux) exposure
sec-agent stream --template "uci set network.wg0.private_key='{{router-ax3600-prod/nordvpn/private_key}}'" \
  | ssh root@192.168.31.1 "cat | sh"
```

### 5.17. Multi-Profile Inheritance (`extends` in `.secrc`)
```json
{
  "profile": "router-ax3600-prod",
  "extends": "global-shared"
}
```
Child profiles recursively fallback to parent profile stores for missing keys.

### 5.18. Dynamic Flag Aliases (`flag_aliases` in `.secrc`)
```json
{
  "flag_aliases": {
    "router-ax3600-prod/nordvpn/access_token": "-t"
  }
}
```
Automatically injects credentials as command-line flags into subprocess arguments.

### 5.19. Network Host Reachability Guard (`sec-agent check --ping-host`)
```bash
# Pre-flight TCP connectivity verification (<50ms)
sec-agent check --ping-host 192.168.31.1:22
```

### 5.20. Full Record Metadata Preservation Standard
When migrating credentials from external vaults (KeePassXC, 1Password, Bitwarden) into `sec-agent`:
1. **Never limit extraction to `username` and `password` alone.**
2. **Preserve URLs and Notes:** Store `<profile>/<entry>/url` and `<profile>/<entry>/notes`.
3. **Preserve Custom Attributes:** Store custom key-value pairs under `<profile>/<entry>/<attribute_name>` (e.g. `totp_secret`, `pin`, `recovery_code`).
4. **Single-Record Query:** Use `sec-agent get <prefix> --record --json` to fetch complete record sub-namespaces as structured JSON objects in a single call.
5. **Full KDBX Import:** Use `sec-agent restore <file.kdbx> --merge --full-metadata --profile <p>` to preserve all `URL`, `Notes`, and `StringData` attributes.
6. **Zero-Disk Exposure Stdin Import:** Pass `-` as the file path (`cat vault.kdbx | sec-agent restore - --password <pass> --full-metadata --merge`) to stream and parse raw KeePassXC databases directly in memory without writing intermediate files to disk.

### 5.21. AI & User Feedback Guidance Protocol (`sec-agent feedback`)
When users request new features or report friction during tool usage:
1. **Run `sec-agent feedback` / `sec-agent feedback --example`**: Fetch structured feedback guidelines, client environment fingerprint, situation sketch format, and impact tier template.
2. **Always Document Operational Rationale & Diagnostics:** Capture the exact problem statement, client runtime telemetry (code editor, AI assistant/extension, model, tool execution mode), an ASCII situation sketch of the flow and friction point, impact classification (Critical Security Leak vs. Boundary vs. Agent Friction vs. Token Waste), and real-world usecases.
3. **High Quality OpenSpec Proposals:** Create clear, well-motivated OpenSpec proposals (`proposal.md`, `design.md`, `specs/`, `tasks.md`) detailing the operational motivation before implementing.
4. **Proactive Feedback Escalation Directive**: Whenever an AI agent encounters unexpected CLI errors, unhandled edge-cases (e.g. envelope nesting anomalies), process lockouts, or has to perform an undocumented workaround, the agent **MUST** surface the friction point to the user and offer to generate a structured feedback proposal using `sec-agent feedback --example`. Never silently swallow or ignore tooling friction.

### 5.22. Secret Version History & Soft-Delete Recovery Protocol
1. **View Secret History:** Use `sec-agent history <path>` to review past version snapshots, timestamps, and comments before updating or troubleshooting.
2. **Non-Destructive Rollbacks:** Use `sec-agent rollback <path> --version N` to revert a secret key to a previous version snapshot without losing current data.
3. **Soft-Delete Safety:** `sec-agent rm <path>` soft-deletes keys by default. List soft-deleted secrets using `sec-agent ls --trash` and un-delete keys using `sec-agent restore-deleted <path>`. Use `sec-agent rm <path> --permanent` only when hard erasure is explicitly requested.

### 5.23. High-Volume Performance & Memory Guardrail Protocol
1. **Scoped Prefix Queries:** For vaults containing over 10,000 secret keys, always pass `<prefix>` namespace arguments to `sec-agent ls <prefix>` or `sec-agent get <prefix> --record` to leverage pre-allocated capacity maps and reduce IPC buffer memory spikes.
2. **RAM Guardrail Protection:** The background daemon operates under a 256 MB soft memory limit (`debug.SetMemoryLimit`). If a query triggers `RESOURCE_EXHAUSTED` error, break down bulk exports using scoped prefix filters (`sec-agent ls prod/services`).

### 5.24. macOS MenuBar GUI Utility & Access Hygiene Protocol
1. **Menu Bar GUI (`sec-agent-gui`)**: Launch `sec-agent-gui` for visual secret hierarchy inspection, real-time TTL countdown timer, active profile selector dropdown (`default`, `dev`, `staging`, `prod`), and single-click copy actions with 15s clipboard auto-wipe.
2. **Detailed Audit Dump (`sec-agent ls -l`)**: Execute `sec-agent ls -l` to display creation, modification, and last access timestamps (`LastAccessed`), version numbers, and read counts in a clean terminal table.
3. **Stale Credential Audit (`sec-agent ls --stale <days>`)**: Run `sec-agent ls --stale 30` to identify credentials unread for >30 days for routine vault hygiene and soft-delete cleanup.
4. **Profile-Aware Export (`sec-agent export --all-profiles --format json`)**: Use `--all-profiles` or `--envelope` to include top-level envelope metadata (`profile`, `database_file`, `exported_at`) so exported backups preserve database origin when imported into different environments.

### 5.25. Workspace Vault Isolation & High-Level Schema Design Protocol
When initializing secret management for a new workspace or migrating an existing project:
1. **Design High-Level Schema First**: Establish a domain taxonomy (`<domain>/<entity>/<attribute>`, e.g., `orchestrator/vco_url`, `bgp/inbound_password`) before populating secrets.
2. **Dedicated Workspace Profile**: Always create a `.secrc` file in the project root targeting a dedicated profile (`"profile": "<project>-dev"`).
3. **Use Relative Keys (`"prefix": ""`)**: Set `"prefix": ""` in `.secrc` so keys resolve to clean relative paths inside dedicated stores (`secrets_<profile>.enc`) without double-scoping.
444: 4. **Hygienic Migration & Context Purge Protocol**: Once credentials are enrolled in `sec-agent`, the agent must immediately offer to sanitize and delete any temporary plaintext files (e.g. `prompt.txt`, `.env`, temporary notes) and commit to zero in-memory plaintext string retention, exclusively relying on dynamic `sec-agent run` environment injection. Follow `docs/VAULT_DESIGN_AND_PROJECT_MIGRATION_GUIDE.md` to purge legacy keys from `secrets.enc` (default profile) and remove old socket files.

### 5.26. Granular Storage Cleanup & Security Scorecard Protocol (v2.3.0)
1. **Preview Before Deleting (`sec cleanup --dry-run`)**: Execute `sec cleanup --dry-run` to preview all historical rolling backup snapshots (`secrets*.enc.<timestamp>`), legacy `.bak` files, and orphaned `.sock` / `.pid` files along with a list of `🛡️ Protected Active Vaults` that are guaranteed to remain untouched.
2. **Purge Obsolete Snapshots (`sec cleanup`)**: Execute `sec cleanup` to delete identified snapshot files and reclaim disk space.
3. **Inspect Security Scorecard (`sec status`)**: Check vault schema (`v2.0 Dual-Slot Envelope` vs `v1.0 Legacy`) and active Secure Enclave policy (`BiometryCurrentSet`).
4. **Offline Recovery Seed Preparation**: Ensure users save their 24-word Argon2id recovery seed phrase generated during `sec init` or `sec session recover` in an offline safe location.

### 5.27. v2.0 Unified Seed Migration & Seed Rotation Protocol
1. **Unified Seed Migration (`sec migrate-v2 --seed "<mnemonic>"`)**: Use `--seed "<mnemonic>"` flag when performing v2.0 vault migrations to bind all workstation profile stores (`default`, `dev`, `prod`, `router-ax3600-prod`) to a single 24-word BIP39 recovery seed.
2. **Seed Rotation (`sec session rotate-seed`)**: Rotate or change recovery seed phrases across all active v2.0 profile stores in a single operation without invalidating Touch ID Keychain items.
3. **Actionable Un-bricking (`sec session recover --profile <name>`)**: When biometric sets change, use `sec session recover` to un-brick vault envelopes using the single 24-word seed.

### 5.28. Workspace `.secrc` Auto-Open & Native Cross-Profile Copy (`sec copy`)
1. **Workspace `.secrc` Auto-Open**: Place a `.secrc` (or `.secenv` / `.sec.json`) file in your repository root to configure workspace profile binding:
   ```json
   {
     "profile": "router-ax3600-prod"
   }
   ```
   Running `eval $(sec open)` inside the repository auto-detects `.secrc` and unlocks both `default` and `router-ax3600-prod` profile daemons concurrently in a single Touch ID prompt.
2. **Native Cross-Profile Copy (`sec copy` / `sec cp`)**: Copy credentials between different profile vaults in memory without shell process leaks:
   ```bash
   sec copy wifi/passphrase router/wifi_passphrase --from-profile default --to-profile router-ax3600-prod
   ```

### 5.29. One-Click Shell Integration & Workspace Binding Indicators (v2.4.0)
1. **One-Click Shell Installer (`sec init-shell`)**: Run `sec-agent init-shell [zsh|bash]` to idempotently add `alias sec=sec-agent` and Zsh/Bash autocompletions to `~/.zshrc` or `~/.bashrc`.
2. **Workspace Profile Binding Indicator**: `sec status` and `sec status --all` display explicit active workspace `.secrc` bindings (e.g. `📌 Active Workspace Profile: router-ax3600-prod (bound via .secrc in /path/to/dir)`).
3. **Auto-Target Workspace Profile in `sec copy`**: Omit `--to-profile` when passing `--from-profile` to automatically target the active workspace profile bound by `.secrc`.

### 5.30. CLI Safety, Profile Ergonomics & AI Skill Drift Detection (v2.9.0)
1. **Universal Subcommand `--help`**: Any subcommand executed with `--help`, `-h`, or `help` (e.g. `sec-agent migrate-v2 --help`, `sec-agent rm --help`) exits 0 and prints usage without side effects or mutations.
2. **Dynamic Shell Profile Binding**: Unlocking a named profile via `sec-agent --profile <name> open` outputs `export SEC_PROFILE="<name>"` alongside `SEC_SESSION_TOKEN` so subshells bind to the target profile immediately. Tip advice dynamically reflects `eval $(sec --profile <name> open)`.
3. **Unified Profile Discovery**: `sec-agent status --all` inspects all physical vault stores (`secrets_*.enc`) via `store.ListVaultFiles()` regardless of configuration subdirectories.
4. **Transparent Multi-Profile Migration**: `sec-agent migrate-v2` supports `--profile <name>` and `--all-profiles`, logs individual vault progress, and displays actionable Keychain access warnings.
5. **AI Skill Drift Diagnostics**: `sec-agent status` and `sec-agent version` automatically warn when an installed AI assistant skill document trails the CLI version and recommend running `sec-agent skill update`.

### 5.31. Multi-Environment Workspace Contexts & Zero-Disk Switching (v2.14.0)
1. **Schema v2 Multi-Environment Configuration (`.secrc`)**:
   Projects can declare multiple environment aliases and safety tiers in `.secrc` while preserving 100% backward compatibility for legacy v1 files (`{"profile": "<name>"}`):
   ```json
   {
     "environments": {
       "sandbox": { "profile": "proj-sandbox", "tier": "dev" },
       "staging": { "profile": "proj-staging", "tier": "staging" },
       "prod": { "profile": "proj-prod", "tier": "prod" }
     },
     "default": "sandbox"
   }
   ```
2. **Process-Isolated Switching (`sec use`)**:
   Zero disk files are written. Context switching strictly modifies calling process environment variables:
   ```bash
   # Switch active shell context to an environment alias
   eval $(sec use staging)
   # Exports: SEC_ENV="staging" and SEC_PROFILE="proj-staging"

   # Clear environment context back to workspace default
   eval $(sec use --clear)
   ```
3. **Workspace Environment Inspection (`sec env ls` / `sec env`)**:
   ```bash
   # Inspect discovered environments with active indicator (*) and tier badges
   sec env ls
   # Output:
   #   ALIAS     PROFILE       TIER      STATUS
   # * sandbox   proj-sandbox  dev       active
   #   staging   proj-staging  staging
   #   prod      proj-prod     prod 🔴

   # Machine-readable JSON output for scripts and AI tooling
   sec env ls --json
   ```
   *Note*: If executed with an argument that matches a secret namespace path or in a legacy workspace, `sec env <prefix>` safely falls back to exporting secrets as environment variables.
4. **Command-Level Environment Flag Overrides (`-E` / `--env`)**:
   Pass `-E <alias>` or `--env <alias>` to direct any command to a specific environment alias without altering shell context:
   ```bash
   sec -E staging run -- npm test
   sec -E prod get db/password
   ```

### 5.32. Production Blast-Radius Mutation Guardrails (v2.14.0)
1. **Protected Mutating Commands**:
   Any operation that modifies or deletes vault state (`set`, `rm`, `mv`, `rollback`, `restore-deleted`, `rotate`) targeting an environment or profile with `tier: "prod"` is strictly intercepted.
2. **Non-Interactive Abort Protocol**:
   * In scripts, CI/CD runners, and AI agent tool invocations (non-TTY), mutations targeting production fail immediately with **exit code 2** and structured JSON error code `PROD_MUTATION_CONFIRMATION_REQUIRED`.
   * To proceed, callers must supply the explicit `--confirm-prod` flag or set `SEC_CONFIRM_PROD=1`:
   ```bash
   sec set app/key "val" --confirm-prod
   sec rm app/key --confirm-prod
   ```
3. **Interactive TTY Safeguards**:
   In human interactive terminals, `sec-agent` prints a warning badge (`⚠️ PRODUCTION MUTATION`) and requires typing the confirmation string `yes` before committing mutations.
4. **Read Operations Pass Freely**:
   Read commands (`get`, `ls`, `history`, `export`, `run`, `stream`) never prompt or block, ensuring automation pipelines inspect safely without friction.

### 5.33. Cross-Profile Template Interpolation in `sec stream` (v2.14.0)
`sec stream` supports cross-profile placeholder syntax using the `@<alias_or_profile>:` namespace prefix:
```bash
# Stream template interpolating both local environment and cross-profile secrets
sec stream --template "export APP_KEY='{{db/password}}' GLOBAL_CA='{{@global-shared:pki/ca_cert}}'" | sh
```
* If the target profile daemon is stopped or locked, `sec stream` halts execution before outputting partial templates and prints actionable diagnostic remediation directing the operator to run `sec -P <target> open`.
* **Executable Command Disambiguation**: When an operator or agent mistakenly executes `sec stream <command>` (such as `sec stream python3 -m ...`), `sec-agent` inspects `$PATH` via `exec.LookPath`. If the argument matches an executable, it emits a tailored remediation hint: `"<cmd>" matches an executable on $PATH. Did you mean 'sec run -- <cmd>' or 'sec pipe <key>'?`.

### 5.34. Standard Machine-Readable Exit Codes & Seed Diagnostics (v2.14.4)
1. **Standard Machine-Readable Exit Status Codes**:
   Automated orchestrators and AI subagents can programmatically classify operational outcomes without string parsing:
   * **`0`**: Success — Operation completed cleanly.
   * **`1`**: General / Syntax Error — Invalid flags, syntax errors, or unhandled internal faults.
   * **`2`**: Secret Not Found (`ErrSecretNotFound`) — Requested secret key does not exist in the active profile.
   * **`3`**: Daemon Offline or Locked (`DAEMON_NOT_RUNNING`) — Daemon process is inactive or locked; run `sec open` to authorize.
   * **`78`**: Interactive Terminal Barrier (`EX_CONFIG`) — TTY safety lock reached in non-interactive environment (requires physical terminal).
2. **Actionable Recovery Seed Diagnostics**:
   When entering recovery mnemonics in `sec profile new`, `sec migrate-v2`, or `sec backup`, validation errors detail the exact failure root cause:
   * Word count mismatch (e.g. `mnemonic must have 24 words, got 23`).
   * Unknown BIP39 word with offending string (e.g. `mnemonic word "aple" is not in BIP39 wordlist`).
   * Checksum failure (`mnemonic checksum verification failed — mnemonic may be corrupted`).
3. **Universal Community Feedback Pointers**:
   All root and subcommand `--help` pages, error remediation banners, and `--version` screens provide direct pointers to `sec feedback` and upstream issue trackers.

### 5.37. Keychain Biometric Binding & Downgrade Attack Prevention (`sec-agent keychain`) (v2.15.0)
1. **The Downgrade Attack Vector**:
   On macOS, ad-hoc signed binaries (`codesign -s -`) identify authorized applications in the Keychain item's Access Control List (ACL) via their individual `CDHash`. When an operator upgrades `sec-agent` and clicks "Always Allow", macOS adds the new binary's hash to the ACL, but **never purges older versions**. If an attacker replaces the binary with an older, vulnerable version, macOS prompts for Touch ID without requesting the macOS login password.
2. **Automatic Re-Sealing & Daemon Restart on Version Upgrade**:
   Upon the first `sec open` after an upgrade, `ensureDaemonRunning` automatically detects any older-version background daemon, evicts and restarts it on the new binary, and `checkAndAutoReseal` re-seals the Keychain item in memory (synchronous delete and add under `BiometryCurrentSet`) and updates `.last_version`, immediately purging all historical binary authorizations.
3. **Explicit Operator Pruning & Status**:
   ```bash
   # Re-seal Keychain item to active binary, purging stale historical authorizations
   sec-agent keychain prune [--profile <name>] [--all]

   # Inspect Keychain binding mode, presence, and version alignment
   sec-agent keychain status [--profile <name>] [--json]
   ```

### 5.38. Hybrid Workspace & Directory Security Scanner (`sec scan` & `sec check --scan`)
1. **Multi-Engine Plaintext Credential Discovery**:
   `sec scan [path]` (or `sec check --scan [path]`) audits any project workspace, folder, git repository (`--git-history`), or `$HOME` directory (`~`, automatically skipping `~/Library`, `.Trash`, `node_modules`, and cache folders) using a 3-engine pipeline:
   * **`sec-native` (Built-In)**: Detects unmigrated `.env*` / `.npmrc` / `.netrc` / `.pgpass` files, insecure CLI password flags (`-p`, `--password`), static configuration secrets, and **exact matches against active unlocked `sec-agent` vault values** (with 100% `[REDACTED_BY_SEC]` masking).
   * **`gitleaks` (Homebrew)**: Automatically invoked when installed for 160+ token rules and base64/hex decoding.
   * **`trufflehog` (Homebrew, opt-in via `--deep` or `--verify-live`)**: Invokes 700+ credential detectors and optional live API verification.
2. **Homebrew Package Management & Permitted Auto-Installation (`--install-tools`)**:
   * If `gitleaks` or `trufflehog` is not installed, `sec scan` outputs a `brew install <tool>` hint.
   * When an AI coding agent has permission to install Homebrew packages, pass `--install-tools` (`sec scan . --install-tools`) to automatically install missing scanners via `brew install` without unmanaged curl installers.
3. **Reusable Security Improvement Action List & 3-Tier Integration Advisor**:
   ```bash
   # Human-readable terminal Security Improvement Action List
   sec scan .

   # Export machine-readable JSON Action List for automated processing
   sec scan . --output .sec-audit-actions.json
   sec scan . --json

   # Deep scan with Git commit history and live credential verification
   sec scan . --git-history --deep --verify-live
   ```
   Every finding is classified into one of three integration tiers:
   * **`READY_NOW` (Tier 1)**: Directly remediable with existing `sec-agent` commands (e.g., `sec migrate-local .env --profile <profile>`).
   * **`NEEDS_WORKSPACE_ADAPTATION` (Tier 2)**: Includes step-by-step `workspace_advice` to refactor hardcoded scripts, source literals, or static config files to consume `$ENV_VAR`, `--stdin-key`, `sec stream`, or `--temp-file`.
   * **`SEC_AGENT_EXTENSION_OPPORTUNITY` (Tier 3)**: Identifies rigid ecosystem files (e.g. `.netrc`, `.npmrc`, fixed-path configs) and emits `sec_agent_extension_idea` proposals for extending `sec-agent` itself.

### 5.39. Zero-Trace Command Execution (`sec exec`)
Store and execute shell commands or multi-line scripts directly from the encrypted vault without leaving traces on the local host:
```bash
# Store a command or script in exec/<name> inside the encrypted vault via stdin
echo 'rsync -a ~/Documents backup@host:/vol/docs' | sec exec save daily-sync --stdin

# List, inspect, or remove stored executable scripts
sec exec list
sec exec show daily-sync
sec exec rm daily-sync

# Execute a stored script in memory (optionally forwarding positional arguments)
sec exec daily-sync
sec exec daily-sync -- --dry-run --verbose
```
* **In-Memory Stdin Pipe Execution**: `sec exec <name> [-- <args...>]` fetches `exec/<name>` from the unlocked daemon with `NoTrace: true` and streams the script directly into `/bin/sh -s -- <args...>` over an in-memory stdin pipe (`cmd.Stdin`).
* **Zero Host Artifacts**: Nothing from the stored script body appears in `.zsh_history`, temporary files on disk, `ps aux` wrapper arguments, or `~/.config/sec-agent/audit.log` (and `secrets.enc` modification timestamps remain untouched during execution).

### 5.40. Stealth Multi-Folder `rsync` Backups (`sec backup`)
Configure and run encrypted, zero-trace multi-folder `rsync` backups over `sec-agent`'s native pure-Go SSH transport without exposing folder names, remote volume paths, usernames, IP addresses, or SSH keepalive options in shell history or the local process table:
```bash
# Initialize a stealth backup job stored in backup/<name> inside the vault
# (optional --timeout, --server-alive-interval, and --server-alive-count-max are stored in the vault, never hardcoded in code)
sec backup init home-nas \
  --target backup@10.0.0.50 \
  --local-base ~ \
  --remote-base /Volumes/MediaArchive/Backups \
  --timeout 120 \
  --server-alive-interval 30 \
  --server-alive-count-max 4

# Or import a declarative multi-folder JSON manifest directly from a file or stdin (also via `sec backup batch`)
sec backup init home-nas --file batch.json
sec backup batch define home-nas --file batch.json

# Register one or more relative folders (with spaces, --sparse, custom --backup-dir / --log-file templates, or custom excludes) into the job
sec backup add-folder home-nas "Photos - 2026" --sparse

# Or register the entire home directory (~/) into a custom remote folder name with per-folder timeout & SSH keepalive in the vault
sec backup add-folder home-nas "~/" \
  --dest "home-archive" \
  --timeout 180 \
  --server-alive-interval 30 \
  --server-alive-count-max 4

# Inspect a backup job configuration or list all registered backup jobs
sec backup show home-nas
sec backup jobs

# Execute all folders in the backup job (default: privacy-preserving summary, zero filenames/paths)
sec backup run home-nas
sec backup run home-nas "Photos - 2026" --max-attempts 5 --tofu
sec backup batch run home-nas
```
* **The 6 Zero-Trace Guarantees**:
  1. **Zero `.zsh_history` Command/Path Exposure**: The operator or agent only runs `sec backup run <name>`, keeping sensitive folder names, IP addresses, and remote volume paths completely out of shell history.
  2. **Zero Local `ps aux` Exposure**: Local `rsync` executes inside working directory `.` (`local_base/<folder>`) with compact flags (`-rt --partial --stats` in normal mode; `-rtvP` / `-rtvPS` only when `--verbose` is passed), `--exclude-from=/dev/fd/3` (fed via an anonymous pipe, including default `.DS_Store`, `.Trash*`, and macOS AppleDouble `._*` exclusions), opaque target `. s:t`, and transport/partial-dir passed privately via `RSYNC_RSH` and `RSYNC_PARTIAL_DIR` in `cmd.Env`. No folder names, volume paths, history paths, usernames, IP addresses, or `-e` transport flags appear in `ps aux`; `sec-agent` intercepts and rewrites the remote `rsync --server` command over the encrypted Go SSH channel. *(Note on unavoidable residual `ps` tokens: generic flags without `rsync` env-var equivalents — such as `--modify-window`, `--timeout`, `--partial`, `--stats`, `--exclude-from=/dev/fd/3` — and `rsync`'s own `rsync --server ... . t` invocation of `$RSYNC_RSH` remain visible in `ps aux`, containing zero sensitive paths, hosts, or credentials.)*
  3. **Zero Filename/Path Exposure in Default Output & Opt-In `--verbose` / `--log-file`**:
     * **BREAKING**: Normal mode pipes local `rsync` `stdout`/`stderr` and remote SSH `stderr` in memory, omits `-v` and `--progress`, counts skipped non-regular files, redacts paths/hosts on error lines (`<path>` / `<host>` while keeping error classes), and outputs only a concise per-folder summary (`alias`, `status`, `transferred`, `skipped_non_regular`, `exit`).
     * `--verbose` is the only way to stream per-file output and `--progress`, and emits an upfront privacy warning on `stderr`.
     * No local log file is created unless `--log-file <path>` is explicitly passed (created with `0700` parent directory and `0600` file permissions, with a runtime warning advising tmpfs and immediate deletion).
     * **AI Agent Privacy Directive**: AI agents **SHOULD NOT** pass `--verbose` or `--log-file` during routine `sec backup run` / `sec backup batch run` invocations to prevent filesystem metadata leaks into agent transcripts or local disks. Only use `--verbose` or `--log-file` when explicitly requested for troubleshooting, prefer a tmpfs/RAM-backed path if `--log-file` is needed, and delete any temporary log immediately after inspection.
  4. **Automatic "One Level Higher" Naming Derivation & Template Overrides Inside `remote_base`**: For each backed-up `<folder>`, `sec-agent` automatically derives the destination and history layout one level higher inside `remote_base` (or expands custom `--backup-dir` / `--log-file` `{date}` and `{datetime}` templates):
     * Primary mirror: `<remote_base>/<folder>/`
     * Incremental deleted/modified file history (`--backup --backup-dir`): `<remote_base>/<Prefix>-History/<YYYY-MM-DD>`
     * Remote transfer log (`--log-file`): `<remote_base>/rsync_<slug>_<YYYY-MM-DD_HHMM>.log`
  5. **Diskless SSH Authentication & Vault-Driven In-Memory SSH Keepalive**: Authenticates in Go memory via `golang.org/x/crypto/ssh` using either `ssh/<target>/password` or `ssh/<target>/private_key` from the vault—with zero private keys on the host filesystem, SSH host fingerprints pinned in the vault (`ssh/<target>/host_fingerprint`) instead of `~/.ssh/known_hosts`, and optional vault-stored `timeout`, `server_alive_interval`, and `server_alive_count_max` (at the folder, job, `ssh/<target>/server_alive_*` — supporting both named targets and `user@host` / `<host>` targets — or profile-wide `ssh/server_alive_*` vault level) sending encrypted `keepalive@openssh.com` probes in memory with zero `-o ServerAliveInterval` exposure in `ps aux`.
  6. **Daemon `NoTrace` Audit Suppression**: All secret and job config lookups during `sec backup run` and `sec ssh-stdio` set `NoTrace: true`, leaving `~/.config/sec-agent/audit.log` and `secrets.enc` `mtime` completely untouched during execution.
* **Built-In Multi-Folder Resilience & Long-Run Keepalive**:
  * **Exit-Code-Aware Retry with Exponential Backoff (`max_attempts`)**: Each folder transfer retries transient network, SSH, and timeout failures up to `max_attempts` (default `5`), doubling backoff from `5s` up to a `30m` cap and re-establishing the in-memory SSH session on transient connection drops. Treats `rsync` exit code `24` (vanished source files) as non-fatal without retry, and stops retrying immediately on `rsync` exit code `23` (local permission/TCC error) or syntax/configuration errors so TCC-blocked folders do not waste multi-attempt tree re-walks before continuing to the remaining folders in the manifest.
  * **Automatic 10m Background Session Keepalive & TTL Extension (`NoTrace: true`)**: Verifies the target vault profile is unlocked before starting any transfer and runs a background ticker every `10m` (`NoTrace: true`) that automatically extends the active daemon session (`8h`) whenever remaining TTL drops below `30m`.
  * **Sparse File Handling, `openrsync` Detection & Declarative Batch Compatibility**: Pass `--sparse` for VM/container disk images, and use `--file <batch.json>` or `sec backup batch <define|list|show|run>` for declarative batch workflows (automatically normalizing legacy `"rsync_timeout"`, `"ssh_options"`, and `backup-batch/<name>` vault keys, and emitting a non-fatal advisory when macOS `/usr/bin/rsync` `openrsync` is detected).

---

## 6. Key Takeaways for AI Assistants

1. **Always Favor `sec-agent run -- <cmd>`**: Never ask users to write plaintext secrets to `.env` files.
2. **UPFRONT SESSION BOOTSTRAPPING & REUSABLE SESSIONS**:
   * **Pre-flight Check at Turn 1**: AI agents MUST run `sec status --quick` at the very beginning of a session or task requiring workspace execution or secrets.
   * **Turn-1 Touch ID Execution**: If session is locked, execute `sec open` directly in your terminal tool to trigger the native macOS Touch ID window for operator approval: *"🔑 Executing sec open to prompt Touch ID on your display for session authorization."*
   * **Daemon Session Memory**: Once unlocked, the background daemon retains session secrets in RAM (8-hour TTL). All subagent tool calls, subshells, and background pipeline runs inherit access frictionlessly without further prompts.
   * **DO NOT pass `--auto-open` or set `SEC_AUTO_OPEN=1` in AI agent tool calls**.
3. **Use Scoped Profiles**: Always pass `--profile` or check `.secrc`.
4. **Use Interactive Prompts or Stdin for `sec-agent set`**: Avoid outputting raw secret strings in command arguments.
5. **Zero Disk Tokens & Automatic Subshell Resolution**: Zero token files are written to disk. The daemon automatically authorizes subshell executions via socket peer credentials (`LOCAL_PEERCRED`) and unlocked RAM state. Never attempt to read `session_*.token` files from disk.
6. **In-Memory Hot-Reload (`sec restart --hot-reload`)**: During CLI upgrades, execute `sec restart --hot-reload` to hot-reload the daemon process image in memory via kernel pipe handoff without clearing active session state or requiring Touch ID re-authentication.
7. **Workspace `.secrc` Auto-Open & Native Cross-Profile Copy**: `eval $(sec open)` auto-detects workspace `.secrc` / `.secenv` targets to unlock `default` and workspace target profiles in 1 Touch ID tap. Use `sec copy <src> <dst> --from-profile <p1> --to-profile <p2>` to safely copy credentials across vault profiles in memory.
8. **Long-Running & Autonomous Job Safety**: Before launching unattended or long tasks (e.g. `/goal`, multi-hour builds, batch migrations), AI agents MUST check session TTL via `sec status` and proactively run `sec extend --ttl <dur>` (e.g. `24h`) without Touch ID or guide the user to unlock with sufficient duration at Turn 1 to avoid mid-session timeouts.
9. **Process-Isolated Context Switching**: Use `eval $(sec use <alias>)` to switch subshell contexts across multi-environment `.secrc` setups, or pass `-E <alias>` for one-off commands. Inspect environments with `sec env ls --json`.
10. **Production Mutation Guardrail Awareness**: When modifying secrets in production tiers (`tier: "prod"`), automated scripts and AI tools MUST explicitly pass `--confirm-prod` to avoid non-interactive failure (`PROD_MUTATION_CONFIRMATION_REQUIRED`, exit code 2).
11. **Machine-Readable Exit Code Handling**: Check exit codes in automated scripts: code 2 indicates missing keys (safe to initialize or skip), code 3 indicates daemon offline/locked (prompt or run `sec open`), code 78 indicates interactive blocker requiring operator terminal intervention.
12. **Keychain ACL Hygiene & Downgrade Prevention**: On newly upgraded systems, run `sec keychain status` or `sec doctor` to verify that the macOS Keychain Access Control List is strictly sealed to the active binary version. If version drift is reported, run `sec keychain prune --all` to purge historical binary hashes.


---

## 7. Insecure Password Flag Prevention & AI Coding Guidelines (v2.6.0)

### 7.1. Zero Plaintext Password Arguments Policy
AI coding agents and autonomous assistants **MUST NEVER** generate, suggest, or execute CLI commands or scripts containing plaintext credentials in command-line arguments (e.g. `-p <password>`, `-p=<password>`, `--password <password>`, `--token=<secret>`).

* **Process Table Exposure**: Command-line arguments are visible system-wide to all local processes via `ps aux`, `top`, and `/proc/<pid>/cmdline`.
* **History Leaks**: Plaintext credentials are saved to shell history (`.zsh_history`, `.bash_history`) and agent logs.

### 7.2. Recommended Secure Patterns for AI Assistants
1. **Process Isolation (`sec-agent run`)**: Wrap execution with `sec-agent run -- <cmd>` to inject credentials into process environment directly from vault memory.
2. **Environment Variable Fallback**: When authoring or refactoring scripts, configure them to read credentials from environment variables (e.g., `PASSWORD="${PASSWORD:-$1}"` or `os.Getenv("PASSWORD")`).
3. **Stdin / Stream Injection (`sec-agent stream`)**: Pipe secrets via stdin or `sec-agent stream --template "..."` rather than command arguments.

### 7.3. Automated Script Auditing (`sec-agent check --scripts`)
```bash
# Scan workspace or specific script for plaintext credential flags
sec-agent check --scripts [path]
```

### 7.4. Zero Plaintext Credentials in Agent Output & Chat Transcripts
AI coding agents and autonomous assistants **MUST NEVER** print, echo, or tabulate unmasked secret values in chat responses, summary tables, diffs, or markdown artifacts.

* **Transcript & Context Leakage**: Writing plaintext secrets into chat responses permanently records sensitive credentials in chat transcripts, IDE session logs, and LLM context windows.
* **Required Masking Pattern**: In summary tables, tool output descriptions, or setup reports, always mask credentials using `[REDACTED]`, `[STORED VIA STDIN]`, or `********`.


