# Developer Migration & Lock-in Free Integration Guide

This guide details:
1. How to integrate the `sec` enclave agent into external workspaces.
2. How to avoid tool lock-in, ensuring a seamless transition between local development (enclave-bound), CI/CD runner environments, and cloud vaults (OVH, AWS, HashiCorp Vault).

---

## 1. Local Workspace Integration Patterns

### 1.1. Kubernetes Deployment Workspaces (`production-deployments`)
In deployment setups (e.g., executing Helm charts, patching databases, or managing enclaves), developers frequently keep credentials in plaintext logs or fetch them from active cluster secrets.
*   **The Plaintext Risk**: Scripts like `patch_secrets.py` read secrets via `kubectl get secret` and write them to unencrypted YAML templates on disk.
*   **The `sec` Solution**: Store database connection strings, tokens, and certificates under namespaced paths in `sec` (e.g. `--profile k8s-cluster` with paths like `billing-app/database-secrets`).
*   **Frictionless Pipeline Spawner**:
    Instead of hardcoding `sec` calls inside python, execute the script inside the process wrapper:
    ```bash
    sec run --profile k8s-cluster -- python3 patch_secrets.py
    ```
    Inside `patch_secrets.py`, read the variables directly from `os.environ`, making the Python script 100% decoupled from the secret provider:
    ```python
    import os
    
    # Read the automatically injected environment variable
    db_secrets = os.getenv("BILLING_APP_DATABASE_SECRETS")
    ```

### 1.2. Terraform Provider Workspaces (`terraform-provider-workspace`)
To run Terraform acceptance tests (`TF_ACC=1`), developers must configure API tokens and target URLs (e.g. `API_URL`, `API_TOKEN` in `.env`). Sourcing plaintext `.env` files exposes tokens in shell history and file backups.
*   **The `sec` Solution**: Load these env values into `sec` under the profile `cloud-service-api`.
*   **One-Command Test Execution**:
    Directly run tests with all environment variables dynamically resolved in memory:
    ```bash
    TF_ACC=1 sec run --profile cloud-service-api -- go test -v ./...
    ```
    No files are created on disk, and the Go test suite reads standard `os.Getenv("API_URL")` calls seamlessly.

### 1.3. Embedded Device Development Workspaces (`embedded-iot-devices`)
Flashing or downloading partition backups requires administrative credentials or SSH keys.
*   **The `sec` Solution**: Save credentials under `device-profile/admin-password` to execute scp/ssh automation cleanly.
*   **Example Wrapper**:
    ```bash
    sec run --profile device-profile -- sshpass -e ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1
    ```
    (`sshpass -e` reads the password directly from the `DEVICE_PROFILE_ADMIN_PASSWORD` variable injected by `sec run`).

### 1.4. Dotenv Placeholder Override Pattern
When onboarding a repository using `sec migrate-local <dotenv-file>`, raw secrets inside the dotenv file are absorbed by `sec` and replaced on disk with a placeholder string (`"<migrated_to_sec>"`).
*   **The Dotenv Library Constraint**: Almost all programming language dotenv libraries (e.g., Node.js `dotenv`, Python `python-dotenv`, Go `godotenv`, Ruby `dotenv`) default to **not overriding variables that are already defined in the process environment**.
*   **How to Enable `sec`**: By prefixing your run script with the wrapper:
    ```bash
    sec run --profile <profile> -- <run-command>
    ```
    `sec run` injects the decrypted secret values (e.g., `DATABASE_PASSWORD="my-actual-pass"`) directly into the process environment variables. When the application boots and loads the dotenv file, the library detects that `DATABASE_PASSWORD` is already defined in the environment, ignores the `"<migrated_to_sec>"` placeholder, and the application uses the authentic credentials with zero code changes.

---

## 2. Lock-in Free Compatibility Architecture

To prevent lock-in to the macOS Secure Enclave (allowing deployment on Linux servers, CI/CD runners, or migration to AWS/OVH Cloud Secrets), implement the **Abstract Secret Loader Pattern**.

### 2.1. The Abstract Shell Loader Wrapper (`get_secret.sh`)
This shell function automatically selects the best secret provider based on the environment (CI container vs. local Mac vs. Cloud VMs):

```bash
#!/bin/bash

get_secret() {
    local path=$1
    # Convert path "database/prod/password" to env name "DATABASE_PROD_PASSWORD"
    local env_var_name=$(echo "$path" | tr '/' '_' | tr '-' '_' | tr 'a-z' 'A-Z')

    # 1. Environment Variable Check (Standard for CI/CD, Kubernetes pods, and GHA)
    if [ -n "${!env_var_name}" ]; then
        echo "${!env_var_name}"
        return 0
    fi

    # 2. Local Enclave Session Agent Check (Standard for local macOS developer setups)
    if command -v sec &>/dev/null && sec ping --profile "${SEC_PROFILE:-default}" &>/dev/null; then
        sec get "$path"
        return 0
    fi

    # 3. AWS Secrets Manager Fallback (Standard for AWS cloud deployments)
    if command -v aws &>/dev/null; then
        aws secretsmanager get-secret-value --secret-id "$path" --query SecretString --output text 2>/dev/null
        return $?
    fi

    # 4. OVH/OpenStack Barbican Fallback (Standard for OVH cloud deployments)
    if command -v openstack &>/dev/null && [ -n "$OS_AUTH_URL" ]; then
        openstack secret order get --payload -f value "$path" 2>/dev/null
        return $?
    fi

    echo "Error: Secret path '$path' could not be resolved by any local or cloud provider" >&2
    return 1
}
```

### 2.2. Standard Exporters (Zero Database Lock-in)
Your database content is completely yours. If you want to migrate away from `sec` to a raw non-enclave file, environment configurations, or another vault tool, you can do so instantly:

1.  **Migrate to KeePassXC (Standard File)**:
    ```bash
    sec backup my_secrets.kdbx
    ```
    This yields a standard, open KDBX file readable by KeePass, Bitwarden, or 1Password.
2.  **Migrate to Decrypted JSON (For Cloud APIs)**:
    ```bash
    sec export --format json
    ```
    This outputs the complete structured database in plaintext JSON, allowing simple custom scripting to upload secrets to AWS Secrets Manager or cloud enclaves.
3.  **Migrate to Shell Exports**:
    ```bash
    # Instantly output environment variables for standard scripts
    sec export --format json | jq -r 'to_entries[] | "export \(.key | gsub("[/-]"; "_") | upcase)=\(.value.value)"'
    # Generates: export DATABASE_PROD_PASSWORD="value"
    ```
