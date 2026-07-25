---
name: sec-agent-integration
description: Use the sec-agent CLI utility to start background daemons, store secrets, run applications in isolated environments, migrate dotenv files, install AI skills, inspect snapshots, and manage backups.
version: v1.9.3
---

# sec-agent Secrets Management Integration (v1.9.3)

This skill enables AI coding agents and autonomous assistants to use the `sec-agent` CLI tool (v1.9.3+) to securely retrieve credentials, run application build/test/terraform pipelines in isolated process environments, migrate dotenv configuration files, install integration skills across IDEs, inspect automatic snapshots, and manage KeePassXC `.kdbx` backups on macOS.

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

---

## 6. Key Takeaways for AI Assistants

1. **Always Favor `sec-agent run -- <cmd>`**: Never ask users to write plaintext secrets to `.env` files.
2. **REUSABLE SESSIONS (Strictly Forbidden to use `--auto-open` in AI Automation)**:
   * **DO NOT pass `--auto-open` or set `SEC_AUTO_OPEN=1` in AI agent tool calls**.
   * If a session is locked, ask the user **once**: *"The sec-agent session is locked. Please run `eval $(sec-agent open)` in your terminal to authorize."*
   * Reuses the single Touch ID authorization for all subsequent subagent tool calls.
3. **Use Scoped Profiles**: Always pass `--profile` or check `.secrc`.
4. **Use Interactive Prompts or Stdin for `sec-agent set`**: Avoid outputting raw secret strings in command arguments.
