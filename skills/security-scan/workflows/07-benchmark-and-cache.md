# 07 — Benchmark Corpus, Reproducibility Cache, Precision/Recall Tracking

**Goal:** Prove the skill is actually getting better, not just running. Measure precision/recall on a curated corpus of known-labeled findings, and cache expensive artifacts so re-runs are deterministic and cheap.

This workflow is **not** invoked during a regular user scan. It's invoked:
- After skill changes — regression-test before shipping
- Periodically — to detect drift when tool versions or the Claude model updates
- When adding a new detector or prompt — to confirm no regression

## Benchmark corpus layout

```
benchmarks/
  README.md                 # how to run, how to contribute
  fixtures/
    <language>/
      <case-name>/
        case.yaml           # metadata + ground-truth labels (required)
        <source tree>       # minimal reproducer (e.g., pom.xml + src/main/java/... for Java)
        .security-scan-baseline.json   # optional — expected suppressions
  harness/
    metrics.schema.json     # output format
    run.md                  # how the harness drives the skill
```

Each fixture is a tiny self-contained repo (~10–50 lines of source). Fixtures exist to exercise ONE behavior each:

- **True positives** — a real reachable-exploitable issue. Harness expects `must_fix`.
- **True negatives** — the same vulnerability class but sanitized / behind auth / in dead code. Harness expects `info` (unreachable).
- **Conditional reachability** — e.g., SQL injection behind `@PreAuthorize("hasRole('ADMIN')")`. Harness expects `should_fix`.
- **Cross-entry-point** — e.g., a CLI-only sink that would be exploitable if web-exposed. Harness expects `info` or `should_fix` depending on entry-point type.
- **Concurrency false positives** — e.g., a "race condition" flagged by SpotBugs on code that's only invoked from a single-threaded `@Scheduled` method. Harness expects `info`.

## case.yaml schema

```yaml
name: sqli-reachable-requestparam          # unique within language dir
language: java | node | python
cwe: [CWE-89]
vulnerability: "SQL injection via unparameterized Statement.executeQuery"

# Ground truth — what the skill SHOULD produce
expected:
  category: must_fix | should_fix | info
  classification: reachable-exploitable | reachable-conditional | unreachable | insufficient-context
  entry_point_type: http-public | http-authn | http-internal | kafka | jms | scheduled | cli | grpc
  min_evidence_chain_length: 2             # Must Fix requires >= 2

# Why this fixture matters — informs reviewers
rationale: >
  Baseline positive case: @RequestParam String q flows unsanitized to
  Statement.executeQuery in a controller method with no Spring Security.
  If the skill misses this, it's broken. If it suppresses this, it's broken.

# Notes for triage — the harness may compare against these
must_mention_in_evidence:
  - "Api.java"         # the entry point file
  - "@RequestParam"    # the taint source
  - "executeQuery"     # the sink
must_not_mention:
  - "sanitized"        # would indicate the LLM hallucinated a validator
```

## Harness (run.md)

1. For each fixture:
   a. Copy to a temp directory
   b. Run the skill end-to-end (`/security-scan`) with `--no-cache` the first time, then a second run with cache to measure cache hit rate
   c. Parse `security-scan-report/triage-report.json`
   d. Compare against `case.yaml.expected`
2. Aggregate into `metrics.schema.json`:
   - **Per category:** precision = TP / (TP + FP), recall = TP / (TP + FN)
   - **Per language:** same
   - **Per CWE class:** same (useful for finding tool coverage gaps)
   - **Latency:** p50 / p95 wall-clock per fixture
   - **Cache efficiency:** hit rate on second run
   - **LLM cost:** total tokens in + out (if the model call layer exposes it)

3. Write `benchmarks/results/<timestamp>.json` and update `benchmarks/results/latest.json`.

## Targets

Baseline targets the skill must hit to be considered shipping-quality:

| Metric | Target |
|---|---|
| Must Fix precision | ≥ 90% (few false alarms) |
| Must Fix recall | ≥ 80% (few missed real issues) |
| FP rate on known-unreachable fixtures | ≤ 10% |
| Cache hit rate on unchanged re-run | = 100% |
| Adversarial-disagree escalation correctness | ≥ 80% |

Miss a target → do not merge skill changes.

## Reproducibility cache

### Directory layout (in the **project being scanned**, not the skill dir)

```
<project-root>/.security-scan-cache/
  bundles/
    <finding_fingerprint>--<source_files_hash>.json
  verdicts/
    <bundle_hash>--<prompt_hash>--<model_id>.json
  codeql-dbs/
    <lang>--<source_tree_hash>/     # CodeQL database (slowest thing to rebuild)
  versions.lock                      # tool + model versions at time of cache write
```

### Cache keys

- **Context bundle:** `sha256(finding_fingerprint + sha256(concat of all source files on the call path))`. Rebuilds when ANY file on the path changes.
- **Verdict:** `sha256(bundle_json + prompt_text + model_id)`. Invalidates when the bundle changes, the validator prompt changes, or the model is bumped.
- **CodeQL database:** `sha256(sha256(concat of all source files for that language))`. Invalidates when any source file changes. In practice, re-create on every run for small repos; cache for repos > ~10k LOC where CodeQL takes more than a minute.

### Cache policies

- **Write on every miss** — cache entries are write-once; never update.
- **Validate before use** — before reading a cached verdict, recompute the key and check. If any input drifted, treat as miss.
- **TTL** — none. Caches are invalidated only by content change, not time.
- **Size limit** — soft cap of 500 MB per `.security-scan-cache/`. Evict LRU when over.
- **Git exclusion** — add `.security-scan-cache/` to `.gitignore` on first run (don't commit caches).

### Determinism guarantees

With cache warm:
- Same skill version + same source tree + same tool versions + same model → **exactly identical** triage-report.json
- Changing any input invalidates the minimum set of downstream cache entries
- `--no-cache` flag bypasses for audit runs

## Drift detection

Schedule a weekly benchmark run (via `/schedule` or a CI job). Compare to `benchmarks/results/latest.json`:

- Metric drop > 5% → open an issue automatically
- New CVE in the model vendor's advisories → force re-run without cache
- Tool version bump in `versions.lock` → force re-run; diff results

## Contributing fixtures

When you find a real-world case where the skill is wrong (false positive or false negative):

1. Minimize the reproducer to its smallest form
2. Add it under `fixtures/<language>/<name>/`
3. Fill in `case.yaml` with the ground truth (what the skill SHOULD say)
4. Run the benchmark harness — confirm the case currently fails
5. Fix the skill (update prompts, detector config, callgraph rules)
6. Run again — confirm it now passes AND no other fixture regressed

This is how the skill gets monotonically better instead of just different.
