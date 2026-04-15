---
name: security-scan
description: Context-aware security scan for Java projects. Runs SAST tooling (Semgrep, CodeQL, SpotBugs/FindSecBugs, OWASP Dependency-Check, Gitleaks), then uses Claude to validate each finding against real usage (callgraph, entry points, taint sources). Suppresses unreachable/theoretical issues and produces a triaged Must/Should/Info report with evidence chains. Use when user asks for a security scan, security audit, vulnerability review, or SAST run on a Java codebase.
---

# security-scan (Java MVP)

A three-layer pipeline:

1. **Detect** — run SAST tools, normalize to a canonical finding schema
2. **Validate** — build a deterministic context bundle per finding (callgraph slice + entry-point classification + taint sources), then ask Claude to classify reachability with required quoted evidence
3. **Triage** — segment into **Must Fix** / **Should Fix** / **Informational** with full evidence chains

The key idea: **the LLM never reasons about a finding in isolation**. Deterministic code extracts the context (who calls this? from where? is the input user-controlled?) and the LLM reasons over that structured evidence. This is what suppresses false positives.

## When to invoke

Trigger phrases: "security scan", "security audit", "SAST", "vulnerability scan", "find security issues", "security review" — when the target is a Java project.

Do NOT invoke this skill for:
- Non-Java projects (MVP is Java-only; tell the user Node/Python are deferred)
- Reviewing a single PR diff for security issues — use the `security-reviewer` agent instead
- Secret-only scans — use `gitleaks` directly

## Workflow

Execute these in order. Each workflow file is self-contained.

1. [00-scope-and-inventory.md](workflows/00-scope-and-inventory.md) — identify Java modules, frameworks, entry points
2. [01-run-detectors.md](workflows/01-run-detectors.md) — run the Java SAST suite in parallel
3. [02-normalize-findings.md](workflows/02-normalize-findings.md) — canonical schema + dedup
4. [03-build-context-bundles.md](workflows/03-build-context-bundles.md) — callgraph slice per finding
5. [04-validate-findings.md](workflows/04-validate-findings.md) — LLM reachability classification
6. [06-triage-and-report.md](workflows/06-triage-and-report.md) — Must/Should/Info report (Phase 5 cross-service tracing deferred)

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

## Scope (MVP)

- **Languages:** Java only. Reject Node/Python politely and stop.
- **Tools:** Semgrep, CodeQL, SpotBugs + FindSecBugs, OWASP Dependency-Check, Gitleaks
- **Deferred:** Cross-service flow tracing (Phase D), adversarial re-validation can be toggled with `--adversarial`, non-Java language adapters

## Determinism

- All LLM calls at temperature 0
- Verdicts cached by `sha256(prompt + context_bundle + model_id)` in `.security-scan-cache/`
- Tool versions pinned in `versions.lock`
- Every suppression logged with the rule id that fired

## Key invariants

- Every **Must Fix** finding MUST carry a complete evidence chain from entry point to sink with quoted source lines
- Every **unreachable** verdict MUST include quoted evidence supporting the claim
- Disagreement between validator and adversarial pass auto-escalates to **Should Fix**
- Unresolved callgraph edges (reflection, dynamic dispatch) MUST be marked explicitly — the LLM is instructed to downgrade confidence when unresolved edges lie on the path

## Non-goals

- Not a replacement for a full pentest or red-team engagement
- Not a compliance audit (SOC2/PCI) — finding severity uses CWE, not control mappings
- Not for runtime / DAST findings
