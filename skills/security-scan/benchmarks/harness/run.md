# Benchmark Harness — Execution Spec

The harness is the thing that actually runs fixtures through the skill and scores the results. This document is the spec — the implementation is intentionally deferred to MVP+1 so the format is fixed before code is written.

## Invocation

```bash
# Run all fixtures
security-scan-benchmark run

# Run one language
security-scan-benchmark run --language java

# Run one fixture
security-scan-benchmark run --fixture java/sqli-reachable-requestparam

# Bypass cache (audit mode)
security-scan-benchmark run --no-cache
```

## Per-fixture flow

For each `fixtures/<lang>/<case>/`:

1. **Prepare** — copy the fixture tree to a temp directory
2. **First run** — invoke the skill end-to-end with cache empty; record wall-clock and LLM token counts
3. **Second run** — invoke again on the same tree; record cache hit rates
4. **Parse** — load `security-scan-report/triage-report.json`
5. **Find the matching finding** — by CWE + location; if no finding matches `case.yaml.cwe`, this is a **false negative** (expected a detection; got nothing)
6. **Compare** against `case.yaml.expected`:
   - `category` match?
   - `classification` match?
   - `entry_point_type` match?
   - `evidence_chain` length ≥ `min_evidence_chain_length`?
   - Every string in `must_mention_in_evidence` appears in the serialized evidence?
   - No string in `must_not_mention` appears?
7. **Record** pass/fail with a reason

## Scoring

For category metrics, treat each category as a binary classification:

- **TP (Must Fix):** fixture.expected.category == "must_fix" AND actual.category == "must_fix"
- **FP (Must Fix):** fixture.expected.category != "must_fix" AND actual.category == "must_fix"
- **FN (Must Fix):** fixture.expected.category == "must_fix" AND actual.category != "must_fix"
- **TN (Must Fix):** both != "must_fix"

Same for should_fix and info. Compute precision/recall/F1 per category.

## Output

Write `benchmarks/results/<ISO8601>.json` matching `metrics.schema.json`. Update symlink `benchmarks/results/latest.json`.

Print a human-readable summary to stdout:

```
security-scan benchmark v1
7 fixtures · java=2 node=2 python=2 cross=1

By category:
  must_fix       precision 0.86  recall 0.92  F1 0.89
  should_fix     precision 1.00  recall 0.50  F1 0.67
  info           precision 0.88  recall 1.00  F1 0.94

Cache hit rate (run 2): bundle=1.00  verdict=1.00

Failures:
  ✗ node/ssrf-zod-validated
    expected category=info  actual=should_fix
    reason: missed Zod refine() as sanitizer; validator emitted
            "reachable-conditional" with preconditions=[URL allow-list]

3 pass · 1 fail
```

Exit code: 0 if all targets met, 1 otherwise. Suitable for CI.

## Integration points

- **CI:** run on every PR that touches `~/.claude/skills/security-scan/`
- **Scheduled:** `/schedule` weekly to catch model / tool-version drift
- **Post-incident:** when a real scan produced a wrong verdict, add a fixture reproducing it before shipping the fix

## Implementation notes (for whoever wires this up)

- The harness itself can be a Python script, a Node script, or a Claude Code skill invocation. What matters is that it reads `case.yaml`, runs the skill, and emits `metrics.schema.json`.
- LLM cost tracking needs hooks into the model call layer; if not available, leave the `cost` field empty in the output.
- For cache hit rate measurement, the skill needs to expose cache stats in its output (already specified in `workflows/04-validate-findings.md`: `{cache_hits, cache_misses, adversarial_disagreements}`). Parse those.
- Keep the harness dumb — no heuristic matching of "close enough" categories. Exact match or fail. Fuzzy matching hides drift.
