# 📣 LinkedIn Announcement Post Drafts for `sec-agent`

> **Note**: This file is created as a private workspace reference (`docs/linkedin_announcement.md`) for your personal review.

---

## 🎯 Option 1: Problem-Solving Story (Recommended)
*Best for: Authentic developer engagement, high readability, modest tone with strong technical value.*

```markdown
Over 12 million plaintext secrets were leaked to GitHub last year alone. For most developers, local credential hygiene is a constant compromise between security and friction: plaintext `.env` files in root directories, hardcoded credentials in scripts, or heavy cloud SaaS tools that interrupt terminal workflows.

To solve this on macOS, I built **sec-agent** — an open-source, 100% offline session agent that seals local development secrets inside Apple Silicon hardware while keeping terminal workflows seamless.

Key technical design choices:
🔒 **Secure Enclave & Touch ID**: Hardware-bound AES-256-GCM encryption. Zero plaintext secrets written to disk.
🛡️ **Active Session Hijack Intercepts**: Monitors client process ancestry (`SSH_CLIENT`, `SSH_TTY`, `screensharingd`). If a remote session attempts to access cached memory, the daemon instantly self-locks.
🚀 **Zero-Codebase Process Injection**: `sec run -- <cmd>` injects credentials into process memory on the fly and overrides `.env` placeholders without altering codebase files.
📜 **Version History & Soft-Delete Trash Bin**: Non-destructive rollbacks, KeePassXC `.kdbx` metadata preservation, and soft-delete recovery.
⚡ **Performance & Safety**: Sub-millisecond execution with a 256 MB RAM soft-cap and OOM protection guardrails.

Built in Go for macOS (Apple Silicon). Installed via Homebrew in one line:
`brew install iafilius/tap/sec-agent`

Source code, architecture docs, and technical specs are open on GitHub:
👉 https://github.com/iafilius/sec-agent

Would love to hear feedback or thoughts from fellow macOS developers, SREs, and security engineers!

#macOS #CyberSecurity #GoLang #OpenSource #DevOps #AppSec #HardwareSecurity
```

---

## ⚡ Option 2: Short & Punchy (High Engagement)
*Best for: Quick scrolling feed, mobile readers, direct call to action.*

```markdown
If you work on macOS and deal with `.env` files, API tokens, or hardware credentials, local secret security usually comes with annoying friction.

I created **sec-agent** to fix that — an open-source, 100% offline macOS session agent that couples Apple Silicon Secure Enclave & Touch ID hardware security with zero-friction terminal execution.

What makes it different:
• **Zero Plaintext Files**: Secrets remain sealed in hardware memory.
• **Process Injection**: Run `sec run -- terraform plan` to inject credentials without leaving files on disk.
• **Remote Hijack Intercept**: Automatically purges RAM if remote SSH or screen-sharing sessions are detected.
• **Soft-Delete & Rollbacks**: Built-in 10-version history and soft-delete trash bin recovery.
• **100% Offline**: Zero cloud dependencies, zero SaaS subscriptions.

Install via Homebrew:
`brew install iafilius/tap/sec-agent`

Check out the project and docs on GitHub:
👉 https://github.com/iafilius/sec-agent

Feedback and PRs welcome!

#OpenSource #macOS #DevOps #AppSec #GoLang
```

---

## 🔬 Option 3: Technical & Architectural Focus
*Best for: Security researchers, Staff/Principal Engineers, AppSec communities.*

```markdown
Standard developer secret tools often suffer from the "Secret Zero" problem — storing unencrypted API tokens on local disks where InfoStealers (RedLine, Vidar) can target them.

I've released **sec-agent**, an enclave-bound session daemon written in Go for macOS that addresses local workstation threat models:

1. **Hardware Root of Trust**: Master keys are sealed via macOS `SecAccessControl` inside Apple Silicon Secure Enclave, requiring physical Touch ID verification.
2. **Active Hijack Interception**: Daemon checks BSD peer environment variables (`SSH_CLIENT`, `SSH_TTY`, `AppleVNCServer`). Remote SSH shells or active screen-sharing sessions trigger immediate RAM memory wipes.
3. **Zero-Codebase Dotenv Overrides**: Intercepts `<migrated_to_sec>` placeholders in memory without modifying application codebases.
4. **Memory Safeguards**: Pre-allocated map/slice memory bounds, `sync.Pool` cipher buffer reuse, and `debug.SetMemoryLimit` OOM protection (sub-1ms benchmarks).

Project repository:
👉 https://github.com/iafilius/sec-agent

Install via Homebrew:
`brew install iafilius/tap/sec-agent`

Contributions and security discussions are very welcome!

#AppSec #Cryptography #macOS #GoLang #InfoSec #CyberSecurity
```

---

## 💡 Practical LinkedIn Publishing Tips

1. **Where to put the GitHub link**:
   - LinkedIn algorithm currently neutralizes reach for external links in the main post body. 
   - *Best Practice*: Include the link in the post body as shown above, OR add a comment right after publishing saying: *"🔗 GitHub repo & documentation: https://github.com/iafilius/sec-agent"*.
2. **Visual Asset**:
   - Post a high-resolution screenshot or GIF of `sec-agent` running in the terminal (`sec status` or `sec run -- terraform plan`). Visual terminal posts perform ~3x better on developer LinkedIn feeds.
3. **Optimal Posting Time**:
   - Tuesday or Thursday between 08:30 AM and 10:00 AM (local time).
