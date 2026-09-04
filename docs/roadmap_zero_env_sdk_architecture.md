# 🚀 Architecture Roadmap: "Zero-ENV" Direct-to-Memory SDK & Library Ecosystem

> **Status**: Strategic Roadmap (Unscheduled / Future Architecture)  
> **Goal**: Provide military-grade secret delivery directly into application process RAM, eliminating environment variable (`ENV`) leakage vectors while maintaining profile-level vault segregation.

---

## 1. The Fundamental Flaw of Environment Variable Secret Delivery

While `sec-agent` elevates secret storage security from unencrypted plaintext `.env` files to an **AES-256-GCM hardware-secured vault with RAM-based daemon TTLs**, injecting secrets via Environment Variables (`ENV`) carries inherent operating system limitations:

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                    ENVIRONMENT VARIABLE LEAKAGE VECTOR MATRIX                   │
 └─────────────────────────────────────────────────────────────────────────────────┘

     Process Space
  ┌───────────────────────┐
  │ Application Process   │
  ├───────────────────────┤
  │ OS Environment Array  │ ────▶ 1. Process Listings (`ps aux`, `/proc/<pid>/environ`)
  │ `process.env` / `os.Environ`│ ────▶ 2. Unhandled Exception Crash Dumps & Diagnostic Logs
  └───────────────────────┘ ────▶ 3. Child Process Inheritance (`fork`/`exec`)
                            ────▶ 4. Supply-Chain Dependencies (npm / PyPI / cargo)
```

### Key Risks of `ENV` Injection:
1. **Process Inspection**: On UNIX systems without hardened ptrace restrictions, environment blocks can be inspected by privileged processes or local users via process listing tools.
2. **Third-Party Package Exfiltration**: Malicious or compromised open-source packages (npm, pip, crates.io) executing within the same runtime automatically gain full read access to `process.env`.
3. **Log & Crash Dump Exposure**: Diagnostic loggers or unhandled exception reporting tools (Sentry, Bugsnag, Datadog) frequently serialize environment variables in error stack traces.

---

## 2. The "Zero-ENV" High-Assurance Architecture

The **Zero-ENV Architecture** completely bypasses environment variables by delivering secrets directly into private application process RAM over an encrypted, peer-authenticated local socket connection.

```
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │                      ZERO-ENV DIRECT-TO-MEMORY SECRET DELIVERY                   │
 └──────────────────────────────────────────────────────────────────────────────────┘

   Application Process Space                         Local Daemon Space
  ┌─────────────────────────────────┐             ┌──────────────────────────────────┐
  │ App Code                        │             │ `sec-agent` Ephemeral Daemon     │
  │   client := sec.New("prod-db")  │  UNIX Socket│ (RAM Master Key + AES-256-GCM)   │
  │   pass := client.Get("db/pass") │ ───────────▶│                                  │
  ├─────────────────────────────────┤ SO_PEERCRED │ ┌──────────────────────────────┐ │
  │ Private RAM Pointer             │ Peer Auth   │ │ Profile: "prod-db"           │ │
  │ (Auto-Scrubbed on GC/Exit)      │             │ │ (Restricted Scope Isolation) │ │
  └─────────────────────────────────┘             │ └──────────────────────────────┘ │
                                                  └──────────────────────────────────┘
```

---

## 3. Core Architectural Principles

### Principle 1: Profile-Level Segregation & Scope Isolation
- Applications are initialized with a scoped **Profile Token** or **App Profile ID** (e.g. `sec.NewClient("payment-service")`).
- The local `sec-agent` daemon restricts the SDK client strictly to the secrets declared within that specific profile. An application cannot query or read keys belonging to other vault profiles.

### Principle 2: Local Peer PID Verification (`SO_PEERCRED`)
- The UNIX domain socket connection uses OS-level peer authentication (`SO_PEERCRED` on macOS / Linux).
- The daemon validates the connecting process UID and PID before serving any requested secret payload.

### Principle 3: Ephemeral RAM Buffers & Secure Memory Scrubbing
- SDK clients return wrapped secret pointers (`sec.SecretString`) that zero-fill memory buffers when garbage collected or closed (`store.ZeroBytes`).

### Principle 4: Transparent Production Fallback
- In local development, the SDK talks to the local `sec-agent` daemon.
- In production cloud environments (AWS, GCP, Kubernetes), the SDK seamlessly falls back to native cloud secret managers (AWS Secrets Manager, GCP Secret Manager, Vault) with zero application code changes.

---

## 4. Proposed SDK Client Ecosystem

```
               ┌─────────────────────────────────────────┐
               │    `sec-agent` Multi-Platform SDKs      │
               └────────────────────┬────────────────────┘
                                    │
         ┌──────────────────┬───────┴──────────┬──────────────────┐
         ▼                  ▼                  ▼                  ▼
┌──────────────────┐┌───────────────┐┌──────────────────┐┌──────────────────┐
│ `sec-sdk-go`     ││ `sec-sdk-node`││ `sec-sdk-python`││ `sec-sdk-rust`   │
│ Native Go Lib    ││ TypeScript    ││ Python PyPI      ││ Rust Crate       │
└──────────────────┘└───────────────┘└──────────────────┘└──────────────────┘
```

### Go SDK Example:
```go
package main

import (
	"fmt"
	"log"
	"github.com/iafilius/sec-agent-sdk-go/sec"
)

func main() {
	// Connect to local sec-agent daemon scoped strictly to "billing-service" profile
	client, err := sec.NewClient(sec.Config{
		Profile: "billing-service",
	})
	if err != nil {
		log.Fatalf("Failed to connect to sec-agent daemon: %v", err)
	}

	// Fetch secret directly into private RAM variable (zero ENV variables populated)
	apiKey, err := client.Get("stripe/api_key")
	if err != nil {
		log.Fatalf("Failed to fetch key: %v", err)
	}
	defer apiKey.Zero() // Auto-scrub memory

	fmt.Println("Billing service started securely.")
}
```

---

## 5. Strategic Roadmap

- [ ] **Phase 1 (Current)**: Low-friction CLI & subshell injection (`sec run`, `sec stream`) with AES-256-GCM + Touch ID daemon.
- [ ] **Phase 2 (Future - Roadmap)**: Formalize Zero-ENV C-CGo/Unix IPC protocol contract.
- [ ] **Phase 3 (Future - Roadmap)**: Release native Go (`sec-sdk-go`) and TypeScript (`sec-sdk-node`) client libraries.
- [ ] **Phase 4 (Future - Roadmap)**: Release Python (`sec-sdk-python`) and Rust (`sec-sdk-rust`) SDK packages.
