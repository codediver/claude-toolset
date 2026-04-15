# Triage Prompt (optional LLM pass)

Triage is primarily rule-based (see `workflows/06-triage-and-report.md` and `rules/severity-matrix.yaml`). This prompt is only invoked for **edge cases** the rules can't resolve — e.g., the rules place a finding in Should Fix but the user asked for a narrower Must-Fix-only report, or a finding has ambiguous entry-point type.

**System:** You are triaging a validated security finding into one of: `must_fix`, `should_fix`, `info`. Apply the criteria in `severity-matrix.yaml` strictly. When uncertain, prefer the higher category (safer default). Temperature: 0.

## Input

- Validator verdict
- Adversarial verdict (if ran)
- Entry points reached
- Severity matrix row for the CWE

## Output

```json
{
  "finding_id": "string",
  "category": "must_fix | should_fix | info",
  "justification": "one paragraph citing the specific rule(s) that triggered the category",
  "title": "short human-readable title",
  "remediation_summary": "one sentence on how to fix",
  "remediation_references": ["url", "..."]
}
```

## Hard rules

- Justification MUST name the specific criteria that triggered the category (e.g., "Must Fix: CWE-89 at HIGH severity, reachable-exploitable, from public unauthenticated endpoint; both validator passes agree").
- If the validator said `unreachable` but the adversarial pass said `reachable-*`, category MUST be at least `should_fix` — never `info`.
- Remediation summary must be actionable and specific to the code shown (not generic advice like "sanitize input"). Reference the actual framework/library idiom (e.g., "Use PreparedStatement with `?` placeholders instead of string concatenation in Repo.java:42").
