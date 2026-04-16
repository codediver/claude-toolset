---
name: security-scan
description: Context-aware security scan for Java, Node.js/TypeScript, Python, Infrastructure-as-Code (Terraform, Kubernetes, CloudFormation, Helm, Docker Compose), and container images. Runs SAST (Semgrep, CodeQL, language-native SAST), SCA (osv-scanner), secret scan (Gitleaks), IaC/container misconfig (Trivy, Checkov, Hadolint, kube-score), then uses Claude to validate each finding against real usage and exposure. Suppresses unreachable/theoretical issues and produces a triaged Must/Should/Info report with evidence chains. Supports cross-service flow tracing in multi-repo scope. Use when user asks for a security scan, security audit, vulnerability review, SAST run, IaC scan, or container scan.
---

# security-scan

A three-layer pipeline:

1. **Detect** — run SAST tools, normalize to a canonical finding schema
2. **Validate** — build a deterministic context bundle per finding (callgraph slice + entry-point classification + taint sources), then ask Claude to classify reachability with required quoted evidence
3. **Triage** — segment into **Must Fix** / **Should Fix** / **Informational** with full evidence chains

The key idea: **the LLM never reasons about a finding in isolation**. Deterministic code extracts the context (who calls this? from where? is the input user-controlled?) and the LLM reasons over that structured evidence. This is what suppresses false positives.

## When to invoke

Trigger phrases: "security scan", "security audit", "SAST", "vulnerability scan", "find security issues", "security review" — when the target is a Java / Node.js / TypeScript / Python project (single language or mixed).

Do NOT invoke this skill for:
- Languages outside {Java, Node/TS, Python} — tell the user which detector packs exist; Rust/Go/Ruby/PHP are not yet adapted
- Reviewing a single PR diff for security issues — use the `security-reviewer` agent instead
- Secret-only scans — use `gitleaks` directly

## Workflow

Execute these in order during a user-invoked scan. Each workflow file is self-contained.

1. [00-scope-and-inventory.md](workflows/00-scope-and-inventory.md) — detect languages, identify modules, frameworks, entry points
2. [01-run-detectors.md](workflows/01-run-detectors.md) — run the language-appropriate SAST suite(s) in parallel
3. [02-normalize-findings.md](workflows/02-normalize-findings.md) — canonical schema + dedup
4. [03-build-context-bundles.md](workflows/03-build-context-bundles.md) — callgraph slice per finding
5. [04-validate-findings.md](workflows/04-validate-findings.md) — LLM reachability classification (temp 0 + quoted evidence)
6. [05-cross-service-trace.md](workflows/05-cross-service-trace.md) — **conditional**: for findings with internal entry points in multi-repo scope, trace upstream across service boundaries (HTTP + async)
7. [06-triage-and-report.md](workflows/06-triage-and-report.md) — Must/Should/Info report with cross-service evidence chains where applicable

### Regression testing (not invoked during a user scan)

7. [07-benchmark-and-cache.md](workflows/07-benchmark-and-cache.md) — run the skill against the labeled corpus, measure precision/recall, track drift. Use after skill changes or on a schedule.

## Output

A `security-scan-report/` directory at the project root:

```
security-scan-report/
  triage-report.json         # machine-readable
  triage-report.md           # human-readable
  raw-findings/              # per-tool output (SARIF/JSON)
  context-bundles/           # per-finding evidence
  suppressions.log           # every suppressed finding + reason
  versions.lock              # tool + model versions for reproducibility
```

## Scope

- **Languages:** Java, Node.js/TypeScript, Python. Per-language tool suites defined in `detectors/<lang>.md`.
- **Infra:** Terraform, CloudFormation, Kubernetes manifests, Helm, Kustomize, Docker Compose, Ansible (partial). Suite in `detectors/iac.md`.
- **Containers:** Dockerfile (default) + optional image scanning. Suite in `detectors/container.md`.
- **Universal tools:** Semgrep (language-native rulesets), CodeQL (optional, best taint), osv-scanner (SCA, preferred), Gitleaks (secrets), Trivy (IaC + image all-rounder).
- **Per-layer add-ons:** Java — SpotBugs+FindSecBugs · Node/TS — eslint-plugin-security, npm audit · Python — Bandit, pip-audit · IaC — Checkov, kube-score, Hadolint · Containers — Grype/syft (optional).
- **Deferred:** Rust/Go/Ruby/PHP language adapters, service-mesh policy parsing (Istio/Linkerd), live cloud-API auditing (AWS Config, GCP SCC).

### Per-language dispatch

During Phase 00 (inventory), detect which languages are present and run only those adapter suites. A monorepo with both Java and Node runs both. The validator and triage layers are language-agnostic — only the detector and context-bundle phases care about language.

### Multi-repo / cross-service mode

By default the skill scans a single repo. To follow flows across services (HTTP + async messaging), supply a scope file:

```yaml
# .security-scan-scope.yaml at the invocation root
scope:
  - id: public-api
    path: /abs/path/to/public-api
  - id: orders-api
    path: /abs/path/to/orders-api
  - id: billing-api
    path: /abs/path/to/billing-api
```

Or: `/security-scan --scope public-api:/path,orders-api:/path,billing-api:/path`.

With scope > 1, Phase 5 runs: findings with internal entry points get traced upstream (default 3 hops). A SQL injection behind an `@KafkaListener` whose topic is produced by a public HTTP handler is classified Must Fix; the same finding behind a topic only fed by a trusted batch job stays Info.

## Determinism

- All LLM calls at temperature 0
- Verdicts cached by `sha256(prompt + context_bundle + model_id)` in `.security-scan-cache/verdicts/`
- Context bundles cached by `sha256(finding_fingerprint + source_files_hash)` in `.security-scan-cache/bundles/`
- CodeQL databases cached by source tree hash in `.security-scan-cache/codeql-dbs/`
- Tool versions pinned in `versions.lock`
- Every suppression logged with the rule id that fired

Full cache spec and drift-detection strategy: [`workflows/07-benchmark-and-cache.md`](workflows/07-benchmark-and-cache.md).

## Quality gates

Skill changes must pass the benchmark corpus before shipping:

- Must Fix precision ≥ 90%
- Must Fix recall ≥ 80%
- FP rate on known-unreachable fixtures ≤ 10%
- Cache hit rate on unchanged re-run = 100%

See [`benchmarks/README.md`](benchmarks/README.md) for the corpus and how to contribute fixtures.

## Key invariants

- Every **Must Fix** finding MUST carry a complete evidence chain from entry point to sink with quoted source lines
- Every **unreachable** verdict MUST include quoted evidence supporting the claim
- Disagreement between validator and adversarial pass auto-escalates to **Should Fix**
- Unresolved callgraph edges (reflection, dynamic dispatch) MUST be marked explicitly — the LLM is instructed to downgrade confidence when unresolved edges lie on the path

## Non-goals

- Not a replacement for a full pentest or red-team engagement
- Not a compliance audit (SOC2/PCI) — finding severity uses CWE, not control mappings
- Not for runtime / DAST findings
