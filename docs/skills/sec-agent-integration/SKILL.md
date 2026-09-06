---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, install AI skills, inspect snapshots, and manage backups.
version: v2.10.0
---

# sec-agent Secrets Management Integration (v2.10.0)

This skill enables AI coding agents and autonomous assistants to use the `sec-agent` CLI tool (v1.9.4+) to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, install integration skills across IDEs, inspect point-in-time snapshots (`sec snapshot`), and manage KeePassXC `.kdbx` backups on macOS.

---

## 1. Quick Diagnostics, Guided Setup & Upfront Session Bootstrapping

### 1.1. Upfront Session Bootstrapping Protocol for AI Assistants
When operating in a workspace that uses `sec-agent` (indicated by a `.secrc` file in the directory tree or tasks explicitly requiring environment secrets/credentials):

1. **Conditional Turn-1 Pre-Flight Check**:
   * If a `.secrc` file is detected or the user's task requires accessing secured secrets, run `sec status --quick` (<5ms execution) during turn 1 to check the daemon session state.
   * If the workspace does not use `.secrc` and the task does not involve secrets, do not run pre-flight checks or request authentication.
2. **Session Memory & Daemon Retention**:
   * `sec-agent` runs an enclave-bound background daemon that retains unlocked session secrets in RAM (default 8-hour TTL).
   * Touch ID / Biometric authorization is required only once per session. Once unlocked, all subsequent subagent tool calls, child processes, and background commands inherit access frictionlessly without further prompts.
3. **Session Unlock Guidance (Preventing Mid-Run Interruption)**:
   * **Daemon Active / Running**: Proceed frictionlessly throughout the task trajectory.
   * **Daemon Locked / Not Running**: If the task requires secrets, the agent can directly execute `sec-agent open` (or `sec open`) with an appropriate timeout (~15s). On macOS, the operating system natively displays the system Touch ID biometric window on screen; the user approves via fingerprint, and the command completes with zero terminal context switching required. Alternatively, prompt the user:
     > 🔑 **`sec-agent` session is currently locked.**
     > Please approve the Touch ID prompt (or run `eval $(sec open)`) to retain session access for the execution run.

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
sec-agent doctor
```

* **Daemon "Active" / "Running"**: The session is unlocked and secrets are queryable.
* **Daemon "Session locked" / "Not running"**: Tell the user to run `eval $(sec-agent open)`.
* **Version Mismatch**: Advise user to run `sec-agent restart` and `eval $(sec-agent open)`.

### 1.4. Skill Version Synchronization & Dynamic Re-Read Protocol
When `sec-agent` is updated on the workstation (e.g. via Homebrew or source rebuild), the CLI automatically updates installed skill files across all configured IDE locations on its next execution.

**CRITICAL RULE FOR AI ASSISTANTS**:
1. **Dynamic Version Drift Detection**: When executing `sec status`, `sec status --quick`, or any CLI command, if the CLI output indicates:
   * A structured upgrade notice (`[sec-agent] ⚡ Upgraded AI agent skill from ... to v2.10.0`), or
   * A CLI version newer than this document's declared version (`v2.10.0`),
2. **Immediate Re-Read Obligation**: The AI agent **MUST IMMEDIATELY INVOKE its file viewing tool** (e.g. `view_file`) on the installed skill path (such as `.agents/skills/sec-agent-integration/SKILL.md` or `~/.gemini/config/skills/sec-agent-integration/SKILL.md`) before taking further action. This purges stale cached instructions from the LLM conversation context and equips the agent with new commands, flags, and security rules.

### 1.5. Guided Profile Onboarding Wizard (`sec profile new <name>`)
Creating a new isolated profile previously required multiple steps (`init`, `set`, and `migrate-v2`). Now you can provision a complete Dual-Slot vault in a single guided step:
```bash
# Interactively generate Touch ID (Slot 0) + 24-word recovery seed (Slot 1) and bind workspace .secrc
sec profile new <profile-name>

# Non-interactive / pre-supplied recovery seed
sec profile new <profile-name> --seed "<24-word mnemonic>" [--secrc | --no-secrc]

# Inspect all discovered profile vaults and their schema health
sec profile ls (alias: sec profile list)
```
* Automatically validates profile name invariants (rejecting slashes, spaces, and path traversals).
* Interactively verifies recovery seed words 4, 12, and 20 to ensure offline backup safety.
* Automatically offers to generate a workspace `.secrc` (`{"profile": "<name>"}`) binding the active directory to the new vault.

---

## 2. Multi-IDE Skill Installer & Manifest Auto-Sync (`sec-agent skill`)

`sec-agent` embeds its canonical `SKILL.md` directly inside the Go binary via `//go:embed` and tracks installed skill target locations in `~/.config/sec-agent/skills_manifest.json`.

### 2.1. Skill Subcommands & Multi-IDE Target Matrix
```bash
# Install AI skill for a specific IDE target and scope
sec-agent skill install --target <target> [--scope global|workspace]

# View status of installed skills tracked in skills_manifest.json
sec-agent skill status

# Update all manifest-tracked skills to current binary version
sec-agent skill update
```

| IDE Target | Scope | Destination Path |
| :--- | :--- | :--- |
| `antigravity` | `global` | `~/.gemini/config/skills/sec-agent-integration/SKILL.md` |
| `antigravity` | `workspace` | `.agents/skills/sec-agent-integration/SKILL.md` |
| `copilot` | `workspace` | `.github/copilot-instructions.md` |
| `copilot-agent` | `workspace` | `.github/agents/sec-agent.md` |
| `cursor` | `global` | `~/.cursor/rules/sec-agent-integration.mdc` |
| `cursor` | `workspace` | `.cursor/rules/sec-agent-integration.mdc` |
| `claude` | `global` | `~/.claude/skills/sec-agent/SKILL.md` |
| `claude` | `workspace` | `.claude/skills/sec-agent/SKILL.md` |
| `windsurf` | `workspace` | `.windsurfrules` |

### 2.2. Automatic Upgrade Sync (`skills_manifest.json`)
When `sec-agent` is updated (e.g. via `brew upgrade sec-agent`), the next CLI execution compares `skills_manifest.json` manifest version with binary `Version` and automatically updates installed skill files across all tracked IDE locations in-place, printing:
`[sec-agent] Automatically upgraded AI agent skills (v2.9.0) across N location(s).`

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

# Direct value with custom environment alias and metadata
sec-agent set app-secrets/db-pass "secret-value" --env-alias DB_PASSWORD --comment "Production DB password"
```

### 5.4. Relabeling & Metadata Updates Without Plaintext Exposure (`sec-agent relabel`)
Update environment aliases, comments, expiration timestamps, or custom metadata tags on an existing secret without retyping or exposing the secret plaintext:

```bash
# Update environment alias (controls variable name during 'sec export' and 'sec run')
sec-agent relabel myapp/token --env-alias MYAPP_API_TOKEN

# Update comment and custom metadata tags
sec-agent relabel myapp/token --comment "Production API Token" --meta owner=devops --meta tier=critical

# Update expiration timestamp
sec-agent relabel myapp/token --expires 2026-12-31T23:59:59Z

# Clear environment alias (reverts export mapping to default path-derived variable name)
sec-agent relabel myapp/token --clear-alias
```

### 5.5. Querying & Renaming Secrets
```bash
sec-agent get my-project/terraform/acceptance/ --prefix [--json]
sec-agent mv old-path/ new-path/ --prefix
```

### 5.6. Environment Isolation & Safety Badges
```bash
sec-agent profile set-env prod --profile my-project-prod
sec-agent run --confirm-prod --profile my-project-prod -- terraform apply
```

### 5.7. Time-Bound Secret Leases & Revocation (`sec-agent lease`)
```bash
# Grant a 15-minute temporary lease token for an AI subagent
lease_token=$(sec-agent lease my-project-dev/vco_token --ttl 15m)

# Revoke temporary lease token immediately upon task completion
sec-agent lease revoke $lease_token
```
Delegate temporary credential access to subagents with **zero credential lingering**.

### 5.8. Real-Time Secret Redaction & Inline `sec://` Placeholders (`sec-agent run`)
```bash
# Dynamic stream redaction: Automatically replaces all injected vault secrets in child stdout/stderr
# with '[REDACTED_BY_SEC]' using buffer-boundary-aware sliding window streaming
sec-agent run --redact -- make testacc

# Run with key filters and stream redaction
sec-agent run --allow-keys VCO_URL,VCO_TOKEN --redact -- make test-unit

# Inline URI replacement: In-memory argument replacement for legacy tools requiring password flags (-p)
sec-agent run -- ./legacy_tool -p "sec://db/password"
```

### 5.9. Native Pure Go SSH Client & Target Wizard (`sec-agent ssh`)
`sec-agent` provides a built-in pure Go SSH client that authenticates directly using credentials stored in the active vault—completely eliminating the need for external `sshpass` utilities on macOS/Linux.

```bash
# Setup remote SSH target interactively into vault and workspace .secrc:
sec-agent ssh init ax3600 --host 192.168.31.1 --user root --port 22 [--password <pass> | --key <path>]

# Connect to named target from .secrc ("ssh_targets") or vault ("ssh/<target>/..."):
sec-agent ssh ax3600

# Execute non-interactive remote command with vault password/key injected in memory:
sec-agent ssh ax3600 -- uci show wireless

# Direct connection via user@host using active profile vault credentials:
sec-agent ssh root@192.168.31.1 -- "uptime"
```
* **Zero Disk Passwords**: Passwords and key passphrases are decrypted in-memory and passed to Go's `ssh.ClientConfig` without touching disk or process argument lists.
* **Exit Code Propagation**: Remote command exit codes (`exitErr.ExitStatus()`) propagate directly to the calling shell.

### 5.10. Companion Metadata Environment Variables
Stored secret metadata (e.g. `subnet=192.168.31.0/24`, `gateway=192.168.31.1`) is automatically exported as companion environment variables (`<KEY>_<META_KEY>`) during `sec run`:
- `ROUTER_ADMIN="<secret>"`
- `ROUTER_ADMIN_SUBNET="192.168.31.0/24"`
- `ROUTER_ADMIN_GATEWAY="192.168.31.1"`

### 5.11. Remote Configuration Drift Verification (`sec-agent check --remote`)
```bash
# Compare live remote OpenWrt UCI settings or environment variables against vault keys (zero plaintext leak)
sec-agent check --remote root@192.168.31.1 --uci wireless.wifinet_dev_5g.key=wifi/passphrase
sec-agent check --remote deploy@api.prod --env API_TOKEN=prod/api_token
```

### 5.12. Ephemeral SSH Agent & Passphrase Injection (`sec-agent run --ssh-key`)
```bash
# Launch ephemeral in-memory SSH agent with vault passphrase for SSH/Rsync/Git automation
sec-agent run --ssh-key ~/.ssh/id_ed25519_ax3600 \
              --ssh-passphrase-key router-ax3600-prod/ssh/key_passphrase \
              -- ssh root@192.168.31.1 "uci show"
```

### 5.13. Stdin Stream Injection & Redaction (`sec-agent stream`)
```bash
# Evaluate {{key_path}} placeholders in-memory without process table (ps aux) exposure
sec-agent stream --template "uci set network.wg0.private_key='{{router-ax3600-prod/nordvpn/private_key}}'" \
  | ssh root@192.168.31.1 "cat | sh"
```

### 5.14. Multi-Profile Inheritance (`extends` in `.secrc`)
```json
{
  "profile": "router-ax3600-prod",
  "extends": "global-shared"
}
```
Child profiles recursively fallback to parent profile stores for missing keys.

### 5.15. Dynamic Flag Aliases (`flag_aliases` in `.secrc`)
```json
{
  "flag_aliases": {
    "router-ax3600-prod/nordvpn/access_token": "-t"
  }
}
```
Automatically injects credentials as command-line flags into subprocess arguments.

### 5.16. Network Host Reachability Guard (`sec-agent check --ping-host`)
```bash
# Pre-flight TCP connectivity verification (<50ms)
sec-agent check --ping-host 192.168.31.1:22
```

### 5.17. Full Record Metadata Preservation Standard
When migrating credentials from external vaults (KeePassXC, 1Password, Bitwarden) into `sec-agent`:
1. **Never limit extraction to `username` and `password` alone.**
2. **Preserve URLs and Notes:** Store `<profile>/<entry>/url` and `<profile>/<entry>/notes`.
3. **Preserve Custom Attributes:** Store custom key-value pairs under `<profile>/<entry>/<attribute_name>` (e.g. `totp_secret`, `pin`, `recovery_code`).
4. **Single-Record Query:** Use `sec-agent get <prefix> --record --json` to fetch complete record sub-namespaces as structured JSON objects in a single call.
5. **Full KDBX Import:** Use `sec-agent restore <file.kdbx> --merge --full-metadata --profile <p>` to preserve all `URL`, `Notes`, and `StringData` attributes.
6. **Zero-Disk Exposure Stdin Import:** Pass `-` as the file path (`cat vault.kdbx | sec-agent restore - --password <pass> --full-metadata --merge`) to stream and parse raw KeePassXC databases directly in memory without writing intermediate files to disk.

### 5.18. AI & User Feedback Guidance Protocol (`sec-agent feedback`)
When users request new features or report friction during tool usage:
1. **Run `sec-agent feedback` / `sec-agent feedback --example`**: Fetch structured feedback guidelines, client environment fingerprint, situation sketch format, and impact tier template.
2. **Always Document Operational Rationale & Diagnostics:** Capture the exact problem statement, client runtime telemetry (code editor, AI assistant/extension, model, tool execution mode), an ASCII situation sketch of the flow and friction point, impact classification (Critical Security Leak vs. Boundary vs. Agent Friction vs. Token Waste), and real-world usecases.
3. **High Quality OpenSpec Proposals:** Create clear, well-motivated OpenSpec proposals (`proposal.md`, `design.md`, `specs/`, `tasks.md`) detailing the operational motivation before implementing.

### 5.19. Secret Version History & Soft-Delete Recovery Protocol
1. **View Secret History:** Use `sec-agent history <path>` to review past version snapshots, timestamps, and comments before updating or troubleshooting.
2. **Non-Destructive Rollbacks:** Use `sec-agent rollback <path> --version N` to revert a secret key to a previous version snapshot without losing current data.
3. **Soft-Delete Safety:** `sec-agent rm <path>` soft-deletes keys by default. List soft-deleted secrets using `sec-agent ls --trash` and un-delete keys using `sec-agent restore-deleted <path>`. Use `sec-agent rm <path> --permanent` only when hard erasure is explicitly requested.

### 5.20. High-Volume Performance & Memory Guardrail Protocol
1. **Scoped Prefix Queries:** For vaults containing over 10,000 secret keys, always pass `<prefix>` namespace arguments to `sec-agent ls <prefix>` or `sec-agent get <prefix> --record` to leverage pre-allocated capacity maps and reduce IPC buffer memory spikes.
2. **RAM Guardrail Protection:** The background daemon operates under a 256 MB soft memory limit (`debug.SetMemoryLimit`). If a query triggers `RESOURCE_EXHAUSTED` error, break down bulk exports using scoped prefix filters (`sec-agent ls prod/services`).

### 5.21. macOS MenuBar GUI Utility & Access Hygiene Protocol
1. **Menu Bar GUI (`sec-agent-gui`)**: Launch `sec-agent-gui` for visual secret hierarchy inspection, real-time TTL countdown timer, active profile selector dropdown (`default`, `dev`, `staging`, `prod`), and single-click copy actions with 15s clipboard auto-wipe.
2. **Detailed Audit Dump (`sec-agent ls -l`)**: Execute `sec-agent ls -l` to display creation, modification, and last access timestamps (`LastAccessed`), version numbers, and read counts in a clean terminal table.
3. **Stale Credential Audit (`sec-agent ls --stale <days>`)**: Run `sec-agent ls --stale 30` to identify credentials unread for >30 days for routine vault hygiene and soft-delete cleanup.
4. **Profile-Aware Export (`sec-agent export --all-profiles --format json`)**: Use `--all-profiles` or `--envelope` to include top-level envelope metadata (`profile`, `database_file`, `exported_at`) so exported backups preserve database origin when imported into different environments.

### 5.22. Workspace Vault Isolation & High-Level Schema Design Protocol
When initializing secret management for a new workspace or migrating an existing project:
1. **Design High-Level Schema First**: Establish a domain taxonomy (`<domain>/<entity>/<attribute>`, e.g., `orchestrator/vco_url`, `bgp/inbound_password`) before populating secrets.
2. **Dedicated Workspace Profile**: Always create a `.secrc` file in the project root targeting a dedicated profile (`"profile": "<project>-dev"`).
3. **Use Relative Keys (`"prefix": ""`)**: Set `"prefix": ""` in `.secrc` so keys resolve to clean relative paths inside dedicated stores (`secrets_<profile>.enc`) without double-scoping.
4. **Hygienic Migration & Context Purge Protocol**: Once credentials are enrolled in `sec-agent`, the agent must immediately offer to sanitize and delete any temporary plaintext files (e.g. `prompt.txt`, `.env`, temporary notes) and commit to zero in-memory plaintext string retention, exclusively relying on dynamic `sec-agent run` environment injection. Follow `docs/VAULT_DESIGN_AND_PROJECT_MIGRATION_GUIDE.md` to purge legacy keys from `secrets.enc` (default profile) and remove old socket files.

### 5.23. Granular Storage Cleanup & Security Scorecard Protocol (v2.3.0)
1. **Preview Before Deleting (`sec cleanup --dry-run`)**: Execute `sec cleanup --dry-run` to preview all historical rolling backup snapshots (`secrets*.enc.<timestamp>`), legacy `.bak` files, and orphaned `.sock` / `.pid` files along with a list of `🛡️ Protected Active Vaults` that are guaranteed to remain untouched.
2. **Purge Obsolete Snapshots (`sec cleanup`)**: Execute `sec cleanup` to delete identified snapshot files and reclaim disk space.
3. **Inspect Security Scorecard (`sec status`)**: Check vault schema (`v2.0 Dual-Slot Envelope` vs `v1.0 Legacy`) and active Secure Enclave policy (`BiometryCurrentSet`).
4. **Offline Recovery Seed Preparation**: Ensure users save their 24-word Argon2id recovery seed phrase generated during `sec init` or `sec session recover` in an offline safe location.

### 5.24. v2.0 Unified Seed Migration & Seed Rotation Protocol
1. **Unified Seed Migration (`sec migrate-v2 --seed "<mnemonic>"`)**: Use `--seed "<mnemonic>"` flag when performing v2.0 vault migrations to bind all workstation profile stores (`default`, `dev`, `prod`, `router-ax3600-prod`) to a single 24-word BIP39 recovery seed.
2. **Seed Rotation (`sec session rotate-seed`)**: Rotate or change recovery seed phrases across all active v2.0 profile stores in a single operation without invalidating Touch ID Keychain items.
3. **Actionable Un-bricking (`sec session recover --profile <name>`)**: When biometric sets change, use `sec session recover` to un-brick vault envelopes using the single 24-word seed.

### 5.25. Workspace `.secrc` Auto-Open & Native Cross-Profile Copy (`sec copy`)
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

### 5.26. One-Click Shell Integration & Workspace Binding Indicators (v2.4.0)
1. **One-Click Shell Installer (`sec init-shell`)**: Run `sec-agent init-shell [zsh|bash]` to idempotently add `alias sec=sec-agent` and Zsh/Bash autocompletions to `~/.zshrc` or `~/.bashrc`.
2. **Workspace Profile Binding Indicator**: `sec status` and `sec status --all` display explicit active workspace `.secrc` bindings (e.g. `📌 Active Workspace Profile: router-ax3600-prod (bound via .secrc in /path/to/dir)`).
3. **Auto-Target Workspace Profile in `sec copy`**: Omit `--to-profile` when passing `--from-profile` to automatically target the active workspace profile bound by `.secrc`.

### 5.27. CLI Safety, Profile Ergonomics & AI Skill Drift Detection (v2.9.0)
1. **Universal Subcommand `--help`**: Any subcommand executed with `--help`, `-h`, or `help` (e.g. `sec-agent migrate-v2 --help`, `sec-agent rm --help`) exits 0 and prints usage without side effects or mutations.
2. **Dynamic Shell Profile Binding**: Unlocking a named profile via `sec-agent --profile <name> open` outputs `export SEC_PROFILE="<name>"` alongside `SEC_SESSION_TOKEN` so subshells bind to the target profile immediately. Tip advice dynamically reflects `eval $(sec --profile <name> open)`.
3. **Unified Profile Discovery**: `sec-agent status --all` inspects all physical vault stores (`secrets_*.enc`) via `store.ListVaultFiles()` regardless of configuration subdirectories.
4. **Transparent Multi-Profile Migration**: `sec-agent migrate-v2` supports `--profile <name>` and `--all-profiles`, logs individual vault progress, and displays actionable Keychain access warnings.
5. **AI Skill Drift Diagnostics**: `sec-agent status` and `sec-agent version` automatically warn when an installed AI assistant skill document trails the CLI version and recommend running `sec-agent skill update`.

---

## 6. Key Takeaways for AI Assistants

1. **Always Favor `sec-agent run -- <cmd>`**: Never ask users to write plaintext secrets to `.env` files.
2. **UPFRONT SESSION BOOTSTRAPPING & REUSABLE SESSIONS**:
   * **Pre-flight Check at Turn 1**: AI agents MUST run `sec status --quick` at the very beginning of a session or task requiring workspace execution or secrets.
   * **Turn-1 Touch ID Prompting**: If session is locked, prompt the user ONCE at Turn 1 before starting work: *"🔑 The sec-agent session is locked. Please approve Touch ID (or run `eval $(sec open)`) to retain session access for our run."*
   * **Daemon Session Memory**: Once unlocked, the background daemon retains session secrets in RAM (8-hour TTL). All subagent tool calls, subshells, and background pipeline runs inherit access frictionlessly without further prompts.
   * **DO NOT pass `--auto-open` or set `SEC_AUTO_OPEN=1` in AI agent tool calls**.
3. **Use Scoped Profiles**: Always pass `--profile` or check `.secrc`.
4. **Use Interactive Prompts or Stdin for `sec-agent set`**: Avoid outputting raw secret strings in command arguments.
5. **Zero Disk Tokens & Automatic Subshell Resolution**: Zero token files are written to disk. The daemon automatically authorizes subshell executions via socket peer credentials (`LOCAL_PEERCRED`) and unlocked RAM state. Never attempt to read `session_*.token` files from disk.
6. **In-Memory Hot-Reload (`sec restart --hot-reload`)**: During CLI upgrades, execute `sec restart --hot-reload` to hot-reload the daemon process image in memory via kernel pipe handoff without clearing active session state or requiring Touch ID re-authentication.
7. **Workspace `.secrc` Auto-Open & Native Cross-Profile Copy**: `eval $(sec open)` auto-detects workspace `.secrc` / `.secenv` targets to unlock `default` and workspace target profiles in 1 Touch ID tap. Use `sec copy <src> <dst> --from-profile <p1> --to-profile <p2>` to safely copy credentials across vault profiles in memory.

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


