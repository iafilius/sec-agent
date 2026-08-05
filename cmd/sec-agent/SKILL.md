---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, install AI skills, inspect snapshots, and manage backups.
version: v2.3.0
---

# sec-agent Secrets Management Integration (v2.3.0)

This skill enables AI coding agents and autonomous assistants to use the `sec-agent` CLI tool (v1.9.4+) to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, install integration skills across IDEs, inspect automatic snapshots, and manage KeePassXC `.kdbx` backups on macOS.

---

## 1. Quick Diagnostics, Guided Setup & Vault Pre-flight Guard

### 1.1. Pre-flight Initialization Guard (`sec-agent init`)
When running `sec-agent` on a fresh workstation or uninitialized environment:
* If `~/.config/sec-agent/` does not exist, commands will return:
  ```text
  Error: sec-agent configuration directory (~/.config/sec-agent/) is missing or uninitialized.

  Please initialize your vault environment by running:
      sec-agent init
  ```
* **Guided & Non-Interactive Onboarding**: Run `sec-agent init` (or `sec-agent setup`). Pass `--non-interactive` (or `-y` / `--yes`) in non-interactive CI/CD setups to initialize configuration directories (`~/.config/sec-agent/` and `~/.config/sec-agent/backups/`) silently without terminal prompt menus.

### 1.2. Diagnostics & Fast-Path Status Verification
```bash
# Ultra-fast (<5ms) pre-flight socket permission & daemon PID check
sec-agent status --quick [-q]

# Check CLI binary version and query active background daemon status
sec-agent version [--json]

# View single-pane-of-glass status across all profiles
sec-agent status --all
```

* **Daemon "Active" / "Running"**: The session is unlocked and secrets are queryable.
* **Daemon "Session locked" / "Not running"**: Tell the user to run `eval $(sec-agent open)`.
* **Version Mismatch**: Advise user to run `sec-agent restart` and `eval $(sec-agent open)`.

---

## 2. Multi-IDE Skill Installer & Manifest Auto-Sync (`sec-agent skill`)

`sec-agent` embeds its canonical `SKILL.md` directly inside the Go binary via `//go:embed` and tracks installed skill target locations in `~/.config/sec-agent/skills.json`.

### 2.1. Skill Subcommands & Multi-IDE Target Matrix
```bash
# Install AI skill for a specific IDE target and scope
sec-agent skill install --target <target> [--scope global|workspace]

# View status of installed skills tracked in skills.json manifest
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

### 2.2. Automatic Upgrade Sync (`skills.json`)
When `sec-agent` is updated (e.g. via `brew upgrade sec-agent`), the next CLI execution compares `skills.json` manifest version with binary `Version` and automatically updates installed skill files across all tracked IDE locations in-place, printing:
`[sec-agent] Automatically upgraded AI agent skills (v1.9.1) across N location(s).`

---

## 3. Disaster Recovery & Snapshot Restoration (`sec-agent backup list`)

### 3.1. Vault Backup Inspection & Snapshot Restoration
`sec-agent` creates automatic atomic `.enc` snapshots in `~/.config/sec-agent/backups/<profile>/` before every database mutation, alongside manual KeePassXC `.kdbx` exports.

```bash
# Inspect all automatic write snapshots and local KeePassXC backups
sec-agent backup list

# Restore from an automatic write snapshot (.enc) or KeePassXC export (.kdbx)
sec-agent restore <file-path> [--merge | --overwrite]
```

### 3.2. 4-Step Disaster Recovery Protocol
When vault corruption or session state issues occur, follow this 4-step recovery process:
1. **Inspect Available Snapshots**: Run `sec-agent backup list`.
2. **Restore Database Payload**: Run `sec-agent restore ~/.config/sec-agent/backups/secrets_<timestamp>.enc --overwrite`.
3. **Reset Daemon Socket State**: Run `sec-agent restart`.
4. **Re-authenticate Shell Session**: Run `eval $(sec-agent open)`.

### 3.3. Dual-Slot Biometric & 24-Word Recovery Seed Governance (v2.0+)
sec-agent v2.0+ utilizes a **LUKS-Style Dual Key-Slot Architecture**:
* **Slot 0**: Master key protected by macOS Keychain Touch ID under `kSecAccessControlBiometryCurrentSet`. Invalidated automatically if any fingerprint is added or removed in macOS System Settings.
* **Slot 1**: Master key wrapped with AES-256-GCM using an Argon2id key derived from an offline 24-word BIP39 Recovery Seed.

**CRITICAL RULES FOR AI ASSISTANTS & AGENTS**:
1. **NO Seed Handling in Non-Interactive TTYs**: `sec migrate-v2` and `sec session recover` enforce a TTY safety lock (`isatty`). They WILL EXIT WITH CODE 78 (`EX_CONFIG`) if executed in headless, piped, or subagent tool call environments.
2. **NEVER Request or Log Recovery Seeds**: AI agents MUST NOT prompt for, parse, store, or output 24-word seed phrases.
3. **Emergency Un-Bricking Protocol**: If Touch ID authentication fails due to hardware change or OS update, inform the human user: *"Touch ID is invalidated. Please open your physical terminal and run `sec session recover` to restore access with your 24-word paper seed."*

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

# Pipe secret value from Stdin
echo "secret-value" | sec-agent set app-secrets/db-pass --stdin

# Direct value with custom environment alias and metadata
sec-agent set app-secrets/db-pass "secret-value" --env-alias DB_PASSWORD --comment "Production DB password"
```

### 5.4. Querying & Renaming Secrets
```bash
sec-agent get my-project/terraform/acceptance/ --prefix [--json]
sec-agent mv old-path/ new-path/ --prefix
```

### 5.5. Environment Isolation & Safety Badges
```bash
sec-agent profile set-env prod --profile my-project-prod
sec-agent run --confirm-prod --profile my-project-prod -- terraform apply
```

### 5.6. Time-Bound Secret Leases & Revocation (`sec-agent lease`)
```bash
# Grant a 15-minute temporary lease token for an AI subagent
lease_token=$(sec-agent lease my-project-dev/vco_token --ttl 15m)

# Revoke temporary lease token immediately upon task completion
sec-agent lease revoke $lease_token
```
Delegate temporary credential access to subagents with **zero credential lingering**.

### 5.7. Real-Time Secret Redaction (`sec-agent run`)
```bash
sec-agent run -- make testacc
sec-agent run --allow-keys VCO_URL,VCO_TOKEN -- make test-unit
```

### 5.8. Ephemeral SSH Agent & Passphrase Injection (`sec-agent run --ssh-key`)
```bash
# Launch ephemeral in-memory SSH agent with vault passphrase for SSH/Rsync/Git automation
sec-agent run --ssh-key ~/.ssh/id_ed25519_ax3600 \
              --ssh-passphrase-key router-ax3600-prod/ssh/key_passphrase \
              -- ssh root@192.168.31.1 "uci show"
```

### 5.9. Stdin Stream Injection & Redaction (`sec-agent stream`)
```bash
# Evaluate {{key_path}} placeholders in-memory without process table (ps aux) exposure
sec-agent stream --template "uci set network.wg0.private_key='{{router-ax3600-prod/nordvpn/private_key}}'" \
  | ssh root@192.168.31.1 "cat | sh"
```

### 5.10. Multi-Profile Inheritance (`extends` in `.secrc`)
```json
{
  "profile": "router-ax3600-prod",
  "extends": "global-shared"
}
```
Child profiles recursively fallback to parent profile stores for missing keys.

### 5.11. Dynamic Flag Aliases (`flag_aliases` in `.secrc`)
```json
{
  "flag_aliases": {
    "router-ax3600-prod/nordvpn/access_token": "-t"
  }
}
```
Automatically injects credentials as command-line flags into subprocess arguments.

### 5.12. Network Host Reachability Guard (`sec-agent check --ping-host`)
```bash
# Pre-flight TCP connectivity verification (<50ms)
sec-agent check --ping-host 192.168.31.1:22
```

### 5.13. Full Record Metadata Preservation Standard
When migrating credentials from external vaults (KeePassXC, 1Password, Bitwarden) into `sec-agent`:
1. **Never limit extraction to `username` and `password` alone.**
2. **Preserve URLs and Notes:** Store `<profile>/<entry>/url` and `<profile>/<entry>/notes`.
3. **Preserve Custom Attributes:** Store custom key-value pairs under `<profile>/<entry>/<attribute_name>` (e.g. `totp_secret`, `pin`, `recovery_code`).
4. **Single-Record Query:** Use `sec-agent get <prefix> --record --json` to fetch complete record sub-namespaces as structured JSON objects in a single call.
5. **Full KDBX Import:** Use `sec-agent restore <file.kdbx> --merge --full-metadata --profile <p>` to preserve all `URL`, `Notes`, and `StringData` attributes.
6. **Zero-Disk Exposure Stdin Import:** Pass `-` as the file path (`cat vault.kdbx | sec-agent restore - --password <pass> --full-metadata --merge`) to stream and parse raw KeePassXC databases directly in memory without writing intermediate files to disk.

### 5.14. AI & User Feedback Guidance Protocol (`sec-agent feedback`)
When users request new features or report friction during tool usage:
1. **Run `sec-agent feedback` / `sec-agent feedback --example`**: Fetch structured feedback guidelines and proposal motivation templates.
2. **Always Document Operational Rationale:** Capture the exact problem statement, why the feature is needed now, real-world usecase examples (e.g. router HTTPS/SSH ports, custom attributes, Dropbear flags), and CLI workflow impact.
3. **High Quality OpenSpec Proposals:** Create clear, well-motivated OpenSpec proposals (`proposal.md`, `design.md`, `specs/`, `tasks.md`) detailing the operational motivation before implementing.

### 5.15. Secret Version History & Soft-Delete Recovery Protocol
1. **View Secret History:** Use `sec-agent history <path>` to review past version snapshots, timestamps, and comments before updating or troubleshooting.
2. **Non-Destructive Rollbacks:** Use `sec-agent rollback <path> --version N` to revert a secret key to a previous version snapshot without losing current data.
3. **Soft-Delete Safety:** `sec-agent rm <path>` soft-deletes keys by default. List soft-deleted secrets using `sec-agent ls --trash` and un-delete keys using `sec-agent restore-deleted <path>`. Use `sec-agent rm <path> --permanent` only when hard erasure is explicitly requested.

### 5.16. High-Volume Performance & Memory Guardrail Protocol
1. **Scoped Prefix Queries:** For vaults containing over 10,000 secret keys, always pass `<prefix>` namespace arguments to `sec-agent ls <prefix>` or `sec-agent get <prefix> --record` to leverage pre-allocated capacity maps and reduce IPC buffer memory spikes.
2. **RAM Guardrail Protection:** The background daemon operates under a 256 MB soft memory limit (`debug.SetMemoryLimit`). If a query triggers `RESOURCE_EXHAUSTED` error, break down bulk exports using scoped prefix filters (`sec-agent ls prod/services`).

### 5.17. macOS MenuBar GUI Utility & Access Hygiene Protocol
1. **Menu Bar GUI (`sec-agent-gui`)**: Launch `sec-agent-gui` for visual secret hierarchy inspection, real-time TTL countdown timer, active profile selector dropdown (`default`, `dev`, `staging`, `prod`), and single-click copy actions with 15s clipboard auto-wipe.
2. **Detailed Audit Dump (`sec-agent ls -l`)**: Execute `sec-agent ls -l` to display creation, modification, and last access timestamps (`LastAccessed`), version numbers, and read counts in a clean terminal table.
3. **Stale Credential Audit (`sec-agent ls --stale <days>`)**: Run `sec-agent ls --stale 30` to identify credentials unread for >30 days for routine vault hygiene and soft-delete cleanup.
4. **Profile-Aware Export (`sec-agent export --all-profiles --format json`)**: Use `--all-profiles` or `--envelope` to include top-level envelope metadata (`profile`, `database_file`, `exported_at`) so exported backups preserve database origin when imported into different environments.

### 5.18. Workspace Vault Isolation & High-Level Schema Design Protocol
When initializing secret management for a new workspace or migrating an existing project:
1. **Design High-Level Schema First**: Establish a domain taxonomy (`<domain>/<entity>/<attribute>`, e.g., `orchestrator/vco_url`, `bgp/inbound_password`) before populating secrets.
2. **Dedicated Workspace Profile**: Always create a `.secrc` file in the project root targeting a dedicated profile (`"profile": "<project>-dev"`).
3. **Use Relative Keys (`"prefix": ""`)**: Set `"prefix": ""` in `.secrc` so keys resolve to clean relative paths inside dedicated stores (`secrets_<profile>.enc`) without double-scoping.
4. **Hygienic Migration Protocol**: Follow `docs/VAULT_DESIGN_AND_PROJECT_MIGRATION_GUIDE.md` to purge legacy keys from `secrets.enc` (default profile) and remove old socket files.

### 5.19. Granular Storage Cleanup & Security Scorecard Protocol (v2.3.0)
1. **Preview Before Deleting (`sec cleanup --dry-run`)**: Execute `sec cleanup --dry-run` to preview all historical rolling backup snapshots (`secrets*.enc.<timestamp>`), legacy `.bak` files, and orphaned `.sock` / `.pid` files along with a list of `🛡️ Protected Active Vaults` that are guaranteed to remain untouched.
2. **Purge Obsolete Snapshots (`sec cleanup`)**: Execute `sec cleanup` to delete identified snapshot files and reclaim disk space.
3. **Inspect Security Scorecard (`sec status`)**: Check vault schema (`v2.0 Dual-Slot Envelope` vs `v1.0 Legacy`) and active Secure Enclave policy (`BiometryCurrentSet`).
4. **Offline Recovery Seed Preparation**: Ensure users save their 24-word Argon2id recovery seed phrase generated during `sec init` or `sec session recover` in an offline safe location.

### 5.20. v2.0 Unified Seed Migration & Seed Rotation Protocol
1. **Unified Seed Migration (`sec migrate-v2 --seed "<mnemonic>"`)**: Use `--seed "<mnemonic>"` flag when performing v2.0 vault migrations to bind all workstation profile stores (`default`, `dev`, `prod`, `router-ax3600-prod`) to a single 24-word BIP39 recovery seed.
2. **Seed Rotation (`sec session rotate-seed`)**: Rotate or change recovery seed phrases across all active v2.0 profile stores in a single operation without invalidating Touch ID Keychain items.
3. **Actionable Un-bricking (`sec session recover --profile <name>`)**: When biometric sets change, use `sec session recover` to un-brick vault envelopes using the single 24-word seed.

### 5.21. Workspace `.secrc` Auto-Open & Native Cross-Profile Copy (`sec copy`)
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

---

## 6. Key Takeaways for AI Assistants

1. **Always Favor `sec-agent run -- <cmd>`**: Never ask users to write plaintext secrets to `.env` files.
2. **REUSABLE SESSIONS (Strictly Forbidden to use `--auto-open` in AI Automation)**:
   * **DO NOT pass `--auto-open` or set `SEC_AUTO_OPEN=1` in AI agent tool calls**.
   * If a session is locked, ask the user **once**: *"The sec-agent session is locked. Please run `eval $(sec-agent open)` in your terminal to authorize."*
   * Reuses the single Touch ID authorization for all subsequent subagent tool calls.
3. **Use Scoped Profiles**: Always pass `--profile` or check `.secrc`.
4. **Use Interactive Prompts or Stdin for `sec-agent set`**: Avoid outputting raw secret strings in command arguments.
5. **Zero Disk Tokens & Automatic Subshell Resolution**: Zero token files are written to disk. The daemon automatically authorizes subshell executions via socket peer credentials (`LOCAL_PEERCRED`) and unlocked RAM state. Never attempt to read `session_*.token` files from disk.
6. **In-Memory Hot-Reload (`sec restart --hot-reload`)**: During CLI upgrades, execute `sec restart --hot-reload` to hot-reload the daemon process image in memory via kernel pipe handoff without clearing active session state or requiring Touch ID re-authentication.
7. **Workspace `.secrc` Auto-Open & Native Cross-Profile Copy**: `eval $(sec open)` auto-detects workspace `.secrc` / `.secenv` targets to unlock `default` and workspace target profiles in 1 Touch ID tap. Use `sec copy <src> <dst> --from-profile <p1> --to-profile <p2>` to safely copy credentials across vault profiles in memory.


