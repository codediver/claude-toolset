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
- Dependency-Check / osv-scanner CVE findings (transitive/direct CVEs) bypass the reachability validator — they are **Must Fix** if CVSS ≥ 7 AND the dependency is on the runtime classpath, **Should Fix** otherwise. Reachability validation for library CVEs is out of MVP scope.
- Gitleaks findings are always **Must Fix** if the secret is in the current tree; history-only exposures are **Should Fix** with a note to rotate.
- **Cross-service findings (Phase 5):** apply the Phase 5 verdict in place of the Phase 4 verdict. An internal-entry finding that Phase 5 classifies `reachable-exploitable` via a public upstream endpoint is **Must Fix**; an internal-entry finding that Phase 5 classifies `unreachable` (trusted-input upstream with validation) drops to **Info**. The evidence chain in the report spans every service hop.
- **External-boundary (Phase 5):** when the upstream trace hits a third-party or unmapped service, classify as **Should Fix** with the `external-boundary` precondition noted. Recommend the user either expand scope (if the service was just missed) or confirm the third party's input trust model.
- **IaC misconfig findings** use a slightly different reachability model: the "entry point" is an **exposure vector** (public LB, public bucket, open security group, public RDS). Must Fix = sensitive resource + public vector + no auth gate. Should Fix = public vector but auth gate exists or sensitivity unclear. Info = internal-only exposure. Always quote the specific IaC lines that create the public exposure as the evidence chain.
- **Container CVE findings** become Must Fix only when the image is deployed in a workload that IaC shows is publicly exposed (see cross-phase note in `detectors/container.md`). CVE alone with no deployment context → Should Fix with a note to confirm runtime. CVE in a build-stage layer not copied to the final image → Info.
- **Cloud secret findings** (IaC references that route credentials via env vars rather than a secret manager): CWE-522. Must Fix if the env var sources from a non-secret-manager location (plain ConfigMap, hardcoded Helm value). Should Fix if sourced from a secret manager but without rotation/least-privilege evidence.

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

Human-readable rendering. In cross-service mode (Phase 5), evidence chains span services — render them with explicit service headers. Suggested layout:

```markdown
# Security Scan Report — <scope name>
Scanned: 2026-04-15T12:00:00Z · Scope: [public-api, orders-api, billing-api]

## Summary
| Category | Count |
|---|---|
| Must Fix | 3 |
| Should Fix | 12 |
| Informational | 41 |
| Suppressed (pre-filter) | 87 |

## Must Fix (3)

### 1. SQL injection in orders-api/Repo.java reached from public unauthenticated endpoint in public-api — CWE-89
**Sink:** `orders-api/src/main/java/com/example/Repo.java:42-43`
**Ultimate entry point:** `public-api · POST /submit` (no auth)
**Hops:** 2  ·  **Detected by:** CodeQL + Semgrep (agree)

**Evidence chain (cross-service):**

_Service: public-api_
1. `public-api/Controller.java:10-12` — public unauthenticated endpoint
   ```java
   @PostMapping("/submit") public Resp submit(@RequestBody Payload p) {
   ```
2. `public-api/Controller.java:14-15` — payload forwarded unchanged
   ```java
   restTemplate.postForObject("http://orders.internal/internal/order", p, Resp.class);
   ```

_Service: orders-api_
3. `orders-api/OrderApi.java:20-23` — internal endpoint consumes payload
   ```java
   @PostMapping("/internal/order") Order create(@RequestBody Payload p) { return repo.find(p.name()); }
   ```
4. `orders-api/Repo.java:42-43` — unsanitized SQL concat
   ```java
   String sql = "SELECT * FROM orders WHERE name = '" + name + "'";
   ```

**Justification:** Reachable from unauthenticated public endpoint in public-api across 2 hops. Phase 5 cross-service trace terminated at the public boundary with no validation. Two tools agree at the sink; adversarial pass concurred.

**Remediation:** Parameterize the query in orders-api/Repo.java. Additionally, add request-body validation at public-api/Controller.java to narrow taint before forwarding.

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
