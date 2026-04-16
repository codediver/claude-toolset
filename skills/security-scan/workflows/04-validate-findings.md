# 04 — Validate Findings (LLM)

**Goal:** For each finding + context bundle, produce a structured verdict with quoted evidence.

## Validator loop

For each finding:

1. Load `context-bundles/{finding_id}.json`
2. Call Claude with [`prompts/validator-prompt.md`](../prompts/validator-prompt.md), temperature 0, structured JSON output
3. If verdict is `unreachable` AND `--adversarial` flag is set (or CWE severity ≥ high), run [`prompts/adversarial-prompt.md`](../prompts/adversarial-prompt.md) as a second pass
4. If the two passes disagree, auto-escalate classification to at least `reachable-conditional` (Should Fix territory)
5. For concurrency/race CWEs, the validator prompt includes extra instructions to check `concurrency_signals` — suppress race findings when all callers are demonstrably single-threaded
6. Cache the verdict by `sha256(prompt + bundle + model_id)` in `.security-scan-cache/verdicts/`

## Verdict schema

```json
{
  "finding_id": "...",
  "classification": "reachable-exploitable | reachable-conditional | unreachable | insufficient-context",
  "confidence": "high | medium | low",
  "assumptions": [
    "No WAF or API gateway sanitizes input before reaching the app",
    "Tomcat serves this endpoint with default multi-threaded concurrency"
  ],
  "evidence_chain": [
    {
      "step": 1,
      "claim": "Entry point accepts user-controlled String without auth",
      "file": "src/main/java/com/example/Api.java",
      "lines": [22, 25],
      "quote": "@GetMapping(\"/api/search\") public List<Item> search(@RequestParam String q) {"
    },
    {
      "step": 2,
      "claim": "Param `q` flows unsanitized to SQL concat",
      "file": "src/main/java/com/example/Repo.java",
      "lines": [42, 43],
      "quote": "String sql = \"SELECT * FROM items WHERE name = '\" + q + \"'\";"
    }
  ],
  "preconditions": ["Attacker can reach the public endpoint"],
  "unresolved_edges_on_path": [],
  "adversarial_pass": { "ran": true, "classification": "reachable-exploitable", "agrees": true }
}
```

## Hard requirements on the LLM output

- Every `unreachable` verdict MUST include quoted evidence supporting the claim (e.g., a `@PreAuthorize` blocking the flow, an input validator rejecting bad data, a short-circuit in the caller). Verdicts without evidence get downgraded to `insufficient-context`.
- Every `reachable-exploitable` verdict MUST have at least 2 evidence chain entries (source + sink), each with file/lines/quote.
- When `unresolved_edges_on_path` is non-empty, `confidence` MUST be ≤ `medium` — an unresolved edge means the LLM doesn't actually know if the path is complete.
- Assumptions MUST be listed explicitly. If an assumption sounds load-bearing and questionable (e.g., "input is already validated upstream"), the classification is capped at `reachable-conditional`.

## Handoff to Phase 5 (cross-service)

When the user supplied a multi-repo scope AND a verdict is `reachable-*` AND the entry point type is internal (`http-internal`, `kafka`, `jms`, `sqs`, `grpc-internal`), defer final classification to [`workflows/05-cross-service-trace.md`](./05-cross-service-trace.md). Phase 5 may upgrade (finding is ultimately reachable from a public endpoint in an upstream service) or downgrade (finding is reached only from a trusted internal source) the verdict.

In single-repo mode, Phase 5 is skipped and the triage layer treats internal entry points per its standard rules.

## Output

Write `security-scan-report/verdicts.json`:
```json
{
  "verdicts": [ /* one per validated finding */ ],
  "cache_hits": 42,
  "cache_misses": 18,
  "adversarial_disagreements": 3,
  "deferred_to_phase5": 7
}
```
