# 06 — Triage and Report

**Goal:** Segment verdicts into Must/Should/Info and render the final report.

## Segmentation rules

Apply in order. First match wins.

### Must Fix
All of:
- `classification == "reachable-exploitable"`
- At least one `entry_points_reached` entry with `type ∈ {http-public, grpc}` AND `auth_required == false`, OR the sink yields RCE/auth-bypass/secret-disclosure regardless of entry point
- CWE base severity in `severity-matrix.yaml` is `high` or `critical`
- Adversarial pass agrees (if it ran)

### Should Fix
Any of:
- `classification == "reachable-conditional"` (requires auth, specific role, feature flag)
- Validator and adversarial pass disagreed
- `classification == "insufficient-context"` AND CWE severity ≥ high
- `classification == "reachable-exploitable"` but entry point is internal (`http-internal`, `kafka`, `jms`, `scheduled`) — lower blast radius but still real
- CWE severity `medium` with confirmed reachability

### Informational
- `classification == "unreachable"` with strong evidence
- `classification == "insufficient-context"` AND CWE severity `low`
- CWE severity `low` or `info` regardless of classification
- Dead-code / test-only (already pre-suppressed, but if any slip through)

### Edge cases
- Dependency-Check CVE findings (transitive/direct CVEs) bypass the reachability validator — they are **Must Fix** if CVSS ≥ 7 AND the dependency is on the runtime classpath, **Should Fix** otherwise. Reachability validation for library CVEs is out of MVP scope.
- Gitleaks findings are always **Must Fix** if the secret is in the current tree; history-only exposures are **Should Fix** with a note to rotate.

## Output

### triage-report.json

Matches [`schemas/triage-report.schema.json`](../schemas/triage-report.schema.json). One entry per finding:

```json
{
  "summary": {
    "must_fix": 3,
    "should_fix": 12,
    "info": 41,
    "suppressed": 87,
    "scan_timestamp": "2026-04-15T12:00:00Z",
    "scan_root": "/abs/path"
  },
  "findings": [
    {
      "id": "...",
      "category": "must_fix",
      "title": "SQL injection via @RequestParam in /api/search",
      "cwe": ["CWE-89"],
      "severity": "critical",
      "location": {
        "file": "src/main/java/com/example/Repo.java",
        "line_start": 42,
        "line_end": 43,
        "module": "app"
      },
      "entry_point": {
        "type": "http-public",
        "path": "/api/search",
        "http_method": "GET",
        "auth_required": false
      },
      "evidence_chain": [ /* copied from verdict */ ],
      "validator_verdict": {
        "classification": "reachable-exploitable",
        "confidence": "high",
        "assumptions": [...]
      },
      "detected_by": ["codeql", "semgrep"],
      "remediation": {
        "summary": "Use a parameterized PreparedStatement; never concatenate request input into SQL.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"]
      },
      "justification": "Must Fix: SQL injection reachable from unauthenticated public HTTP endpoint. Two tools agree; validator verified taint path without sanitization. Adversarial pass concurred.",
      "reproducibility": {
        "tool_versions_lock": "security-scan-report/versions.lock",
        "context_bundle_hash": "sha256:...",
        "prompt_hash": "sha256:...",
        "model": "claude-opus-4-6"
      }
    }
  ]
}
```

### triage-report.md

Human-readable rendering. Suggested layout:

```markdown
# Security Scan Report — <project name>
Scanned: 2026-04-15T12:00:00Z · Root: /abs/path

## Summary
| Category | Count |
|---|---|
| Must Fix | 3 |
| Should Fix | 12 |
| Informational | 41 |
| Suppressed (pre-filter) | 87 |

## Must Fix (3)

### 1. SQL injection via @RequestParam in /api/search — CWE-89
**Location:** `src/main/java/com/example/Repo.java:42-43` (module: app)
**Entry point:** `GET /api/search` (no auth)
**Detected by:** CodeQL, Semgrep (agree)

**Evidence chain:**
1. `src/main/java/com/example/Api.java:22-25` — entry point binds user input
   ```java
   @GetMapping("/api/search") public List<Item> search(@RequestParam String q) {
   ```
2. `src/main/java/com/example/Repo.java:42-43` — unsanitized concat into SQL
   ```java
   String sql = "SELECT * FROM items WHERE name = '" + q + "'";
   ```

**Justification:** Reachable from unauthenticated public endpoint. Two tools agree; validator and adversarial pass both confirm exploitability.

**Remediation:** Use a parameterized PreparedStatement.

---

## Should Fix (12)
...

## Informational (41)
...

## Methodology
- Detectors: Semgrep, CodeQL, SpotBugs+FindSecBugs, OWASP Dependency-Check, Gitleaks
- Validator: Claude at temperature 0 with structured context bundles; adversarial re-validation on high-severity unreachable verdicts
- See `versions.lock` for tool versions and `context-bundles/` for per-finding evidence
```

## Final output layout

```
security-scan-report/
  triage-report.json
  triage-report.md
  inventory.json
  findings.normalized.json
  verdicts.json
  raw-findings/*.sarif
  context-bundles/*.json
  suppressions.log
  versions.lock
  tool-status.json
```

## Tell the user

After writing, summarize to the user:
- Counts per category
- Top 3 Must Fix with one-line each
- Path to the full report
- Any detectors that failed or timed out (degraded coverage)
