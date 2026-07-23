# Development & Publishing Workflows

This document outlines the workflows for developing `sec` within your local workspace sandbox and publishing the clean, anonymized `sec-agent` codebase to GitHub.

---

## 1. Repository Architecture

We maintain a dual-layer repository layout:

```
/path/to/workspace/secure_secrets (Local Workspace Sandbox)
├── .git/ (Local Sandbox history)
├── openspec/ (OpenSpec specifications & changes history)
├── [Core codebase and documentation with your local configuration context]
│
└── sec-agent/ (Standalone Public Repository Sub-folder)
    ├── .git/ (Public GitHub history)
    └── [Clean codebase, public README, and anonymized documentation]
```

*   **Local Workspace Sandbox**: Used for local coding, profile configurations, running tests, and managing requirements via OpenSpec.
*   **sec-agent Sub-repository**: A clean subfolder containing only open-source-safe directories, generic configurations, and anonymized guides. It has its own isolated `.git` history.

---

## 2. Development Workflow (How to develop)

To introduce new features, fix bugs, or update specifications:

### Step 2.1. Implement and Test Locally
1. Implement your modifications inside the workspace root (e.g. `main.go`, `daemon/daemon.go`).
2. Run functional test suites and safety analysis:
   ```bash
   make test
   make sec-check
   ```
3. Sync specification rules using the OpenSpec pipeline (`openspec`).

### Step 2.2. Sync and Verify codebase with `make sync`
To automate copying all Go source directories, build targets, and testing modules to the publishable sub-repository, run:
```bash
make sync
```
This single command automatically:
1. Copies core files and packages to `sec-agent/` (without overwriting your public anonymized `README.md` or `docs/`).
2. Moves into `sec-agent/`, triggers compile verification and AST security validation.
3. Executes the full functional test suite.
If any errors, compiler warning, or test failures occur during copying, the sync command will fail immediately, safeguarding your public repository.

---

## 3. Publication Workflow (How to publish)

Because `sec-agent` is an independent Git repository nested inside your workspace, you can publish it directly to a public GitHub repository.

### Step 3.1. Link Remote Origin
*(Perform once)* Link the sub-repository to your public GitHub target:
```bash
cd sec-agent
git remote add origin git@github.com:<your-username>/sec-agent.git
```

### Step 3.2. Commit and Push Changes
Commit the clean codebase and push to GitHub:
```bash
cd sec-agent

# Stage all files
git add .

# Commit changes
git commit -m "feat: release new features"

# Push to main branch
git branch -M main
git push -u origin main
```
This ensures your private folders, local profiles, and OpenSpec local development history remain completely isolated in the parent directory and are never leaked to the public.
