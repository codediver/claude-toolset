# Infrastructure-as-Code Detector Suite

## Scope

Terraform, OpenTofu, CloudFormation, Kubernetes manifests, Helm charts, Kustomize, Docker Compose, Ansible. IAM policies, bucket policies, security groups, RBAC — the stuff that produces findings like "public S3 bucket" or "pod runs as root".

## Suite composition and rationale

| Tool | Why it's in the suite |
|---|---|
| **Trivy** (`config` + `k8s` + `fs`) | Broad — Terraform / CFN / K8s / Helm / Dockerfile misconfig, plus SBOM/CVE overlap. Active development (Aquasec), ships with AVD (Aqua Vulnerability Database) policies. **Preferred all-in-one default.** |
| **Checkov** | Deeper policy depth for Terraform / CFN / K8s. ~1000+ built-in checks, custom-policy friendly (Python/YAML). Use alongside Trivy — coverage is complementary, not redundant. |
| **kube-score** | K8s manifest best-practice checks: resource limits, readiness probes, pod disruption budgets, securityContext. Complements Trivy's CIS-focused checks with workload-health checks. |
| **Hadolint** | Dockerfile linter — catches `apt-get install` without `--no-install-recommends`, `ADD` instead of `COPY`, latest-tag base images, missing `USER` directive. |
| **Semgrep** (`p/terraform`, `p/dockerfile`, `p/kubernetes`) | Custom org-specific policies; fast for grep-like rules. |
| **Gitleaks** | Secrets in IaC files (hardcoded AWS keys, DB passwords in values.yaml). Universal — already running. |

## Install commands

```bash
# Trivy (primary)
brew install trivy

# Checkov
pipx install checkov

# kube-score
brew install kube-score

# Hadolint
brew install hadolint

# Semgrep — already installed for code scanning
```

## Running

```bash
# Trivy — config misconfigurations (Terraform, CFN, K8s, Dockerfile)
trivy config . --format sarif --output security-scan-report/raw-findings/trivy-config.sarif

# Trivy — filesystem / SBOM (catches library CVEs in Dockerfiles' base images if present)
trivy fs . --format sarif --output security-scan-report/raw-findings/trivy-fs.sarif --scanners vuln,secret,misconfig

# Trivy — live Kubernetes cluster (only if user opts in — it hits the cluster)
# trivy k8s --report summary cluster --format sarif --output security-scan-report/raw-findings/trivy-k8s.sarif

# Checkov
checkov -d . -o sarif --output-file security-scan-report/raw-findings/checkov.sarif --quiet || true

# kube-score (JSON output; SARIF not native)
kube-score score --output-format json $(find . -name "*.yaml" -o -name "*.yml" | xargs grep -l "^kind:" 2>/dev/null) \
  > security-scan-report/raw-findings/kube-score.json 2>/dev/null || true

# Hadolint
find . -name "Dockerfile*" -not -path "*/node_modules/*" -not -path "*/.git/*" | \
  xargs hadolint --format sarif > security-scan-report/raw-findings/hadolint.sarif 2>/dev/null || true

# Semgrep IaC rulesets
semgrep scan --config p/terraform --config p/dockerfile --config p/kubernetes \
  --sarif --output security-scan-report/raw-findings/semgrep-iac.sarif --metrics=off .
```

## File detection (Phase 00 inventory additions)

| Category | Signal |
|---|---|
| Terraform | `*.tf`, `*.tfvars`, `terraform.lock.hcl`, `.terraform/` |
| OpenTofu | `*.tofu` (same tools work) |
| CloudFormation | `*.yaml`/`*.yml`/`*.json` containing `AWSTemplateFormatVersion` or `Resources:` with `AWS::` types |
| K8s manifests | `*.yaml`/`*.yml` with `apiVersion:` + `kind:` at root |
| Helm chart | `Chart.yaml` + `templates/` + `values.yaml` |
| Kustomize | `kustomization.yaml` |
| Docker | `Dockerfile`, `Dockerfile.*`, `.dockerfile` |
| Docker Compose | `docker-compose.yml`, `compose.yaml` |
| Ansible | `playbook.yml` / `roles/*/tasks/main.yml` — optional, partial coverage |

The inventory `languages` field gains `iac` and `container` entries when any of these are present.

## Entry points (for cross-phase integration)

IaC "entry points" are **exposure vectors**, not HTTP routes. They're what the context-bundle layer treats as the "source of untrusted reach":

| Exposure | Detection |
|---|---|
| Public S3 / GCS / Azure Blob | `acl = "public-read"`, `block_public_acls = false`, `--public-access-prevention=inherited` |
| Public load balancer / ingress | `internal = false`, `type = "LoadBalancer"`, `kind: Ingress` with public hostname |
| Public RDS / Cloud SQL | `publicly_accessible = true` |
| Security group open to 0.0.0.0/0 | any CIDR with `0.0.0.0/0` on a non-HTTP port |
| K8s `NodePort` / `LoadBalancer` Service | `type: LoadBalancer` without restricted source ranges |
| Privileged container | `privileged: true`, `allowPrivilegeEscalation: true`, runAsUser 0, host{PID,Network,IPC} |
| IAM wildcards | `"Action": "*"`, `"Resource": "*"` in the same policy statement |

A finding is Must Fix when: sensitive resource (secrets volume, production data, cluster admin) is exposed via a public vector AND not gated by authentication/authorization.

## Known gaps

- **Drift** — IaC tools see the declared desired state, not what's actually deployed. A finding "S3 bucket is public" is a declaration; the cluster may have manual overrides. Treat findings as "this will ship" warnings, not "this is running" assertions.
- **Secret references vs. literals** — Trivy/Checkov catch plaintext secrets but not "env var fetched from a generic `env` block where the value comes from a non-secret-manager source". LLM validator must check whether `AWS_SECRET_ACCESS_KEY` is sourced from Secrets Manager / GitHub OIDC / equivalent.
- **CDK / Pulumi / Troposphere** — these generate IaC from code. Scan the **synthesized** output (`cdk synth`, `pulumi preview --json`) not the source code; the source can look fine while the output is broken.
- **Helm with complex values** — when a single chart ships to multiple envs with different `values-*.yaml`, scan each env's rendered output (`helm template -f values-prod.yaml`).
- **Policy-as-Code (OPA/Gatekeeper/Kyverno)** — out of scope; those are the validators, not the targets.

## Validator-relevant signals to extract for the context bundle

When a finding's file is IaC, the context bundle adds:
- **Resource kind and name** — `aws_s3_bucket.data_lake`, `Deployment/payments-api`
- **Public exposure chain** — which siblings make this resource reachable (e.g., bucket + IAM + route53 + CloudFront)
- **Downstream consumers** — for K8s, which other resources reference this (ServiceAccount → Deployment → Service)
- **Environment hint** — filename convention (`prod.tf`, `dev.yaml`), dir (`envs/prod/`), Helm values suffix. Prod findings should not be suppressed; dev findings may be.

The validator then classifies like code findings: `reachable-exploitable` (public + sensitive), `reachable-conditional` (public but gated by auth), `unreachable` (internal-only + no public route), `insufficient-context` (unknown environment or unclear network boundary).
