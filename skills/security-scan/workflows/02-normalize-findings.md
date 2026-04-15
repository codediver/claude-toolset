# 02 — Normalize Findings

**Goal:** Convert heterogeneous SARIF/JSON outputs into a canonical finding list and dedupe.

## Canonical finding schema

See [`schemas/finding.schema.json`](../schemas/finding.schema.json). Required fields:

```json
{
  "id": "stable-uuid",
  "tool": "semgrep|codeql|spotbugs|dependency-check|gitleaks",
  "rule_id": "tool-native-rule-id",
  "cwe": ["CWE-89"],
  "severity_raw": "critical|high|medium|low|info",
  "file": "app/src/main/java/com/example/Repo.java",
  "line_start": 42,
  "line_end": 45,
  "code_snippet": "...",
  "message": "Possible SQL injection via string concatenation",
  "data_flow": [
    { "file": "...", "line": 10, "kind": "source", "note": "@RequestParam String q" },
    { "file": "...", "line": 42, "kind": "sink",   "note": "Statement.executeQuery" }
  ],
  "fingerprint": "sha256(cwe + file + normalized-line-range + normalized-snippet)"
}
```

## Normalization rules

- **Severity mapping** — lookup in `rules/severity-matrix.yaml` by `cwe`. Tool-reported severity is informational only; the matrix is authoritative.
- **CWE enrichment** — if a tool doesn't emit CWE, map from rule id using a known table (Semgrep rules, SpotBugs patterns → CWE).
- **Data flow** — extract SARIF `codeFlows` where present (CodeQL emits these). For tools without dataflow, leave `data_flow` empty — the validator will reconstruct.
- **Path normalization** — all paths relative to project root, forward slashes.

## Deterministic pre-suppression

Before dedup, drop findings that match `rules/suppression-rules.yaml` patterns:

- Test paths (`**/src/test/**`, `**/*Test.java`, `**/*IT.java`)
- Generated code (`**/target/generated-sources/**`, `**/build/generated/**`)
- Vendored code (`**/node_modules/**` — unlikely in pure Java but included for safety)
- Explicit baseline (optional `.security-scan-baseline.json` listing accepted risks)

Log every suppression to `security-scan-report/suppressions.log` with:
```
{finding_id, rule_matched, file, reason}
```

## Dedup

Group findings by fingerprint. Within a group, keep the richest variant using this priority:

1. `codeql` (has dataflow)
2. `semgrep`
3. `spotbugs`
4. others

Attach a `duplicates: [{tool, rule_id}]` list to the winner so the triage report shows cross-tool agreement (useful as a signal).

## Output

Write `security-scan-report/findings.normalized.json`:
```json
{
  "findings": [ /* canonical findings after dedup */ ],
  "suppressed_count": 123,
  "input_counts_by_tool": { "semgrep": 50, "codeql": 80, ... }
}
```
