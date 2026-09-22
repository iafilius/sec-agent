---
sec-agent-version: v2.14.0
report-date: 2026-09-22T21:52:00Z
rfc-id: RFC-20260922-ONBOARDING-AND-AGENT-EXPERIENCE-POLISH
target-repository: secure_secrets
author: Arjan Filius & Sovereign Fleet Core Team
status: PROPOSED
---

# RFC: Onboarding Ergonomics, Agent Autonomy & Scanner Polish

**Target Repository:** `secure_secrets` (`sec-agent`)  
**Target Components:** CLI | Profile Provisioner | Staging Scanner (`githook`) | Stream Engine | Agent Skill  
**Evaluation Date:** 2026-09-22  

---

## Executive Summary

While `sec-agent` v2.14.0 introduces groundbreaking multi-environment workspace management (`.secrc` Schema v2) and hardware-bound Secure Enclave isolation, field testing in complex multi-tier cloud repositories (`klus_7_poc2_k8s`) revealed four specific friction points that affect both **first-time human operators** and **autonomous AI coding assistants**.

This RFC proposes:
1. **Explicit Path Logging & Home/Bin Warning for `sec profile new --secrc`**: Prevent user confusion regarding global vs directory-scoped profiles.
2. **Dual-Audience Remediation for Locked Sessions**: Explicitly guide AI agents to trigger `sec open` directly for macOS Touch ID sensor interaction.
3. **Native Filepath Support for `sec stream` (`-f / --file`)**: Allow streaming templates directly from files without requiring stdin pipelines (`cat | sec stream`).
4. **Gitignore Glob Parity & Template Awareness in Privacy Guard**: Enable standard wildcard matching (`*.tmpl`) across subdirectories and eliminate false-positive entropy alerts on template references (`{{namespace/key}}`).

---

## Impact & Friction Classification

- [ ] 🔴 **Tier 0: Critical Security Leak**
- [ ] 🟠 **Tier 1: Architectural / Boundary Violation**
- [x] 🟡 **Tier 2: Agent Friction / Stall** (Agent hesitancy on Touch ID; unexpected `stream` string output)
- [x] 🟢 **Tier 3: Ergonomics / Operator Confusion** (Ambiguous `.secrc` destination; false-positive pre-commit warnings)

---

## 1. Problem Statements & Live Field Observations

### Friction 1: Ambiguous `.secrc` Placement during Profile Provisioning
* **Observation**: An operator ran a setup script while their shell working directory was `$HOME/bin`. Executing `sec profile new xuntos-dev --secrc` quietly placed `.secrc` in `/Users/arjan/bin/.secrc`.
* **Consequence**: The operator concluded that `sec-agent` only supports a single global profile across the entire operating system, as the tool did not disclose *where* `.secrc` was written or how directory-scoping works.
* **Root Cause**: `sec profile new` writes `$PWD/.secrc` without logging the absolute target path or its cascading directory semantics.

### Friction 2: AI Agent Hesitancy on Locked Session Remediation
* **Observation**: When a locked daemon was queried, `sec` emitted:
  ```text
  Error: Daemon for profile "xuntos-dev" is not running. Please run 'sec open' to unlock the session.
  Remediation: Run 'eval $(sec --profile xuntos-dev open)' to start/unlock the session.
  ```
* **Consequence**: Autonomous agents running non-interactive tool commands often conclude: *"I am an AI assistant and cannot perform biometric Touch ID, so I must stop and ask the human to run this command."*
* **Root Cause**: The remediation directs human interactive shells (`eval $(...)`), failing to clarify that running `sec open` as a headless subprocess triggers macOS's native graphical Secure Enclave biometric prompt on the operator's physical display.

### Friction 3: Template Streaming String vs Filepath Ambiguity
* **Observation**: Running `sec stream --template manifest.yaml.tmpl` outputted the literal text `manifest.yaml.tmpl`.
* **Consequence**: The operator/agent had to discover that `--template` expects the raw string payload rather than a path, forcing an extra `cat manifest.yaml.tmpl | sec stream` subprocess pipeline.
* **Root Cause**: Lack of a `-f / --file` flag or automatic file-existence detection in `cmd_stream.go`.

### Friction 4: Go `filepath.Match` Quirk & False Positive Entropy in Pre-Commit Guard
* **Observation**: Adding `*.tmpl` to `.secignore` failed to suppress checks on `terraform/.ovh-secrets.tmpl`. Furthermore, `IsHighEntropyString` flagged template lines such as `OVH_S3_UPLOAD_ACCESS_KEY="{{ovh/s3_upload_access_key}}"`.
* **Consequence**: Git pre-commit checks aborted commits on valid, secure template definitions.
* **Root Cause**:
  1. Go's `filepath.Match(pattern, path)` does not allow `*` to traverse directory slashes (`/`), unlike standard `.gitignore` globbing.
  2. `IsHighEntropyString` evaluates whitespace-separated tokens. A 50-character assignment containing braces, slashes, and quotes triggers the Shannon entropy threshold (`> 4.6`), despite being an unrendered placeholder.

---

## 2. Situation Sketch

```
[Developer / AI Agent Workflow]
        │
        ├──> 'sec profile new dev --secrc' (executed in ~/bin)
        │       └──! Silently writes ~/bin/.secrc
        │            (Operator assumes tool only supports 1 profile globally!)
        │
        ├──> 'sec status' (Daemon Locked)
        │       └──! "Remediation: Run 'eval $(sec open)'"
        │            (Agent halts: "I have no fingers, user must do this!")
        │
        ├──> 'sec stream --template deploy.yaml.tmpl'
        │       └──! Outputs literal string "deploy.yaml.tmpl" instead of content
        │
        └──> 'git commit' -> 'sec githook check'
                └──! Rejects '*.tmpl' (Go globbing fails on subdirectories)
                └──! Rejects 'KEY="{{placeholder}}"' (False-positive High Entropy)
```

---

## 3. Concrete Architectural Proposals

### Proposal 1: Explicit Path Logging & Sensitive Directory Guard
In `cmd_profile.go`:
1. When `--secrc` writes a file, log the absolute path and scope:
   ```text
   ✓ Created profile 'xuntos-dev' [v2.0 Dual-Slot]
   📁 Bound workspace config: /Users/arjan/work/Xuntos/klus_7_poc2_k8s/.secrc
      Scope: Active for this directory and all subdirectories.
   ```
2. If `$PWD` is `$HOME`, `$HOME/bin`, `/usr/local/bin`, or `/tmp`, emit an advisory warning:
   ```text
   ⚠️  Notice: Creating .secrc in a home/system directory (/Users/arjan/bin).
      All child projects without their own .secrc will inherit this profile.
      Consider running 'sec profile new' inside your specific project repository.
   ```

---

### Proposal 2: Dual-Audience Remediation Hints
In `main.go` / `daemon.go`:
Update the standardized remediation string for locked sessions:
```text
Error: Daemon for profile "xuntos-dev" is not running.
Remediation:
  • Interactive Shell: Run 'eval $(sec open)' to unlock and export session variables.
  • AI Assistant / IDE: Execute 'sec open' directly — macOS Secure Enclave will prompt the console operator for Touch ID on their display.
```

In `cmd/sec-agent/SKILL.md` (and global assistant skills):
Add a prominent callout in Section 1:
> **Autonomous Agent Biometric Protocol**: Never abort a task simply because a session is locked. Calling `sec open` via a standard terminal command runner displays the system Touch ID dialog on the human operator's screen. Once the operator touches the sensor, your tool call returns success with exit code 0.

---

### Proposal 3: Native Filepath Support in `sec stream`
In `cmd_stream.go`:
1. Add `-f` / `--file <path>` flag:
   ```bash
   sec stream -f template.yaml.tmpl
   # or direct positional argument:
   sec stream template.yaml.tmpl
   ```
2. Update `--template <string>`: If the provided value corresponds to an existing readable file on disk, automatically read the file contents or prompt a deprecation warning:
   ```go
   if info, err := os.Stat(tmplFlag); err == nil && !info.IsDir() {
       data, err := os.ReadFile(tmplFlag)
       // use file contents
   }
   ```

---

### Proposal 4: `.secignore` Glob Parity & Template Entropy Normalization
In `internal/audit/ignore.go`:
1. **Gitignore-Style Globbing**: If a rule contains no `/` (e.g. `*.tmpl` or `*.md`), match against `filepath.Base(file)`:
   ```go
   func ShouldIgnoreFile(file string, rules []string) bool {
       base := filepath.Base(file)
       for _, rule := range rules {
           if !strings.Contains(rule, "/") {
               if matched, _ := filepath.Match(rule, base); matched {
                   return true
               }
           }
           if matched, _ := filepath.Match(rule, file); matched {
               return true
           }
           if strings.Contains(file, rule) {
               return true
           }
       }
       return false
   }
   ```

In `internal/audit/entropy.go`:
2. **Mustache Token Stripping**: Before evaluating entropy in `IsHighEntropyString`:
   ```go
   // Strip mustache template placeholders e.g. {{tenants/firmo/umbraco_db_dsn}}
   reMustache := regexp.MustCompile(`\{\{[^}]+\}\}`)
   cleaned := reMustache.ReplaceAllString(s, "")
   ```
   This guarantees that template files can be scanned for hardcoded vault leaks without triggering false-positive alerts on variable references.

---

## 4. Implementation Effort & Verification Plan

| Component | Target File | Complexity | Test Strategy |
| :--- | :--- | :--- | :--- |
| Profile Creation | `cmd/sec-agent/cmd_profile.go` | Low (15 lines) | Verify output logs absolute path and emits home warning. |
| Daemon Remediation | `cmd/sec-agent/main.go` | Low (10 lines) | Assert stderr output on locked session query. |
| Stream Engine | `cmd/sec-agent/cmd_stream.go` | Low (25 lines) | Add tests for `sec stream -f <file>` and positional argument. |
| Ignore Globbing | `internal/audit/ignore.go` | Low (15 lines) | Test `*.tmpl` matching `nested/dir/manifest.tmpl`. |
| Entropy Stripping | `internal/audit/entropy.go` | Low (10 lines) | Test assignment containing `{{...}}` produces low entropy. |

---

## 5. Conclusion

Implementing these four ergonomic enhancements will bridge the gap between human intuition, autonomous AI agent workflows, and hardened Secure Enclave security. It makes `sec-agent` completely friction-free upon fresh installation, eliminating onboarding confusion and enabling fully autonomous agentic execution.
